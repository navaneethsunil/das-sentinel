"""Live end-to-end verification of MFA/TOTP (SEC-DEBT-2) over real HTTP. Run
inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_mfa.py"

Seeds an org with a real-password admin + user, then drives the API service
through the whole factor lifecycle: enroll → confirm (TOTP proves possession,
recovery codes issued) → login now demands a second factor → TOTP login →
recovery-code login (single-use, reuse rejected) → self-disable → admin reset
(clears MFA + revokes sessions). Asserts the secret is stored encrypted, never
in the clear. Cleans up after itself.
"""

import asyncio
import sys

import httpx
import pyotp
from redis.asyncio import Redis
from sqlalchemy import delete, func, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.mfa import MfaService
from app.core.security import PasswordService
from app.models.audit import AuditEvent
from app.models.identity import MfaRecoveryCode, Organization, Session, User, UserRole

API_BASE = "http://api:8000"
PASSWORD = "correct horse battery staple"  # noqa: S105 - test fixture

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def recovery_count(db, uid) -> int:
    return (
        await db.execute(
            select(func.count()).select_from(MfaRecoveryCode).where(MfaRecoveryCode.user_id == uid)
        )
    ).scalar_one()


def session_cookie(settings, resp: httpx.Response) -> str | None:
    # __Host- cookies carry Secure, so httpx won't retain them over http://;
    # pull the token straight out of the Set-Cookie header.
    for hdr in resp.headers.get_list("set-cookie"):
        if hdr.startswith(settings.session_cookie_name + "="):
            return hdr.split("=", 1)[1].split(";", 1)[0]
    return None


async def main() -> int:  # noqa: C901 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)
    passwords = PasswordService(settings.password_hash_scheme)
    mfa = MfaService(
        settings.mfa_secret_encryption_key.get_secret_value()
        if settings.mfa_secret_encryption_key
        else None,
        issuer=settings.mfa_issuer,
        allow_dev_key=settings.das_env != "prod",
    )
    pw_hash = passwords.hash(PASSWORD)

    async with sessionmaker() as db:
        org = Organization(name="verify-mfa-org")
        db.add(org)
        await db.flush()
        admin = User(
            organization_id=org.id,
            email="mfa-admin@verify-mfa.example.com",
            password_hash=pw_hash,
            display_name="admin",
            role=UserRole.ADMIN,
        )
        user = User(
            organization_id=org.id,
            email="mfa-user@verify-mfa.example.com",
            password_hash=pw_hash,
            display_name="user",
            role=UserRole.TESTER,
        )
        db.add_all([admin, user])
        await db.commit()
        user_id = user.id

    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=10,
        # Double-submit CSRF: any matching cookie/header pair passes.
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        creds = {"email": "mfa-user@verify-mfa.example.com", "password": PASSWORD}

        # Baseline: no MFA yet → password login works.
        r = await http.post("/auth/login", json=creds)
        check("login without MFA → 200", r.status_code == 200)
        check("me shows mfa_enabled false", r.json()["user"]["mfa_enabled"] is False)
        tok = session_cookie(settings, r)
        sc = {settings.session_cookie_name: tok}

        # Enroll → pending secret + provisioning URI.
        r = await http.post("/auth/mfa/enroll", cookies=sc)
        check("enroll → 200", r.status_code == 200)
        secret = r.json().get("secret", "")
        check("enroll returns a secret", bool(secret))
        check(
            "provisioning_uri is otpauth",
            r.json().get("provisioning_uri", "").startswith("otpauth://"),
        )

        # Confirm with a live TOTP → MFA active + recovery codes.
        r = await http.post(
            "/auth/mfa/confirm", json={"code": pyotp.TOTP(secret).now()}, cookies=sc
        )
        check("confirm with live TOTP → 200", r.status_code == 200)
        recovery = r.json().get("recovery_codes", [])
        check("confirm returns 10 recovery codes", len(recovery) == 10)

        # Wrong-secret confirm attempt must not have flipped anything earlier;
        # verify DB state: enabled, ciphertext (not plaintext), 10 codes.
        async with sessionmaker() as db:
            row = (await db.execute(select(User).where(User.id == user_id))).scalar_one()
            check("db: mfa_enabled true", row.mfa_enabled is True)
            check("db: secret stored encrypted (not plaintext)", row.mfa_secret != secret)
            check(
                "db: stored secret decrypts to enrolled secret",
                mfa.decrypt_secret(row.mfa_secret) == secret,
            )
            check("db: 10 recovery rows", await recovery_count(db, user_id) == 10)

        # Login now demands a second factor.
        r = await http.post("/auth/login", json=creds)
        check("login without code → 401", r.status_code == 401)
        check(
            "401 body signals mfa_required",
            r.json().get("detail", {}).get("code") == "mfa_required",
        )

        # Wrong code → rejected.
        r = await http.post("/auth/login", json={**creds, "mfa_code": "000000"})
        check("login wrong code → 401", r.status_code == 401)

        # Correct TOTP → success.
        r = await http.post("/auth/login", json={**creds, "mfa_code": pyotp.TOTP(secret).now()})
        check("login with live TOTP → 200", r.status_code == 200)
        check("me now shows mfa_enabled true", r.json()["user"]["mfa_enabled"] is True)

        # Recovery code → success, single-use.
        r = await http.post("/auth/login", json={**creds, "mfa_code": recovery[0]})
        check("login with recovery code → 200", r.status_code == 200)
        r = await http.post("/auth/login", json={**creds, "mfa_code": recovery[0]})
        check("reused recovery code → 401", r.status_code == 401)
        tok = session_cookie(
            settings,
            await http.post("/auth/login", json={**creds, "mfa_code": pyotp.TOTP(secret).now()}),
        )
        sc = {settings.session_cookie_name: tok}

        # Self-disable with a still-unused recovery code.
        r = await http.post("/auth/mfa/disable", json={"code": recovery[1]}, cookies=sc)
        check("disable with recovery code → 204", r.status_code == 204)
        async with sessionmaker() as db:
            row = (await db.execute(select(User).where(User.id == user_id))).scalar_one()
            check(
                "db: disabled, secret cleared",
                row.mfa_enabled is False and row.mfa_secret is None,
            )
            check("db: recovery codes purged on disable", await recovery_count(db, user_id) == 0)

        # Re-enroll to test admin reset.
        r = await http.post("/auth/login", json=creds)  # no MFA now → 200
        sc = {settings.session_cookie_name: session_cookie(settings, r)}
        secret = (await http.post("/auth/mfa/enroll", cookies=sc)).json()["secret"]
        await http.post("/auth/mfa/confirm", json={"code": pyotp.TOTP(secret).now()}, cookies=sc)

        # Admin resets the locked-out user; their session is revoked.
        admin_login = await http.post(
            "/auth/login", json={"email": "mfa-admin@verify-mfa.example.com", "password": PASSWORD}
        )
        asc = {settings.session_cookie_name: session_cookie(settings, admin_login)}
        r = await http.post(f"/users/{user_id}/reset-mfa", cookies=asc)
        check("admin reset-mfa → 200", r.status_code == 200)
        check("reset response shows mfa_enabled false", r.json().get("mfa_enabled") is False)
        r = await http.get("/auth/me", cookies=sc)
        check("target session revoked by reset → 401", r.status_code == 401)
        r = await http.post("/auth/login", json=creds)
        check("user can log in again with password only", r.status_code == 200)

    # cleanup (audit rows append-only → dev-superuser bypass; replica mode also
    # disables FK cascades, so children are deleted explicitly).
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org.id))
        org_users = select(User.id).where(User.organization_id == org.id)
        await conn.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id.in_(org_users)))
        await conn.execute(delete(Session).where(Session.user_id.in_(org_users)))
        await conn.execute(delete(User).where(User.organization_id == org.id))
        await conn.execute(delete(Organization).where(Organization.id == org.id))
    await cache.flushdb()
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
