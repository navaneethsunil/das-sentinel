"""Live end-to-end verification of M1-SEC2: the /auth surface + double-submit
CSRF over real HTTP. Run inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_auth_csrf.py"

Proves: generic 401 on unknown-email/wrong-password/deactivated (no account
enumeration); login regenerates the session id (fixation defense) and mints
session + CSRF cookies with the right attributes; state-changing requests
without/with-mismatched CSRF are 403 (the cross-origin attacker case) and with
a matching pair succeed; logout and logout-all revoke immediately; the whole
flow is audited. Cleans up after itself.
"""

import asyncio
import sys

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.audit import AuditEvent
from app.models.engagement import Engagement
from app.models.identity import Organization, Session, User, UserRole

API_BASE = "http://api:8000"
PASSWORD = "correct horse battery staple"  # noqa: S105 - fixture credential

failures: list[str] = []
seen_tokens: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def main() -> int:  # noqa: C901, PLR0915 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)
    passwords = PasswordService(settings.password_hash_scheme)
    cn = settings.session_cookie_name
    csrf_cn = settings.csrf_cookie_name
    csrf_hn = settings.csrf_header_name

    async with sessionmaker() as db:
        org = Organization(name="verify-auth-org")
        db.add(org)
        await db.flush()
        tester = User(
            organization_id=org.id,
            email="tester@verify-auth.example.com",
            password_hash=passwords.hash(PASSWORD),
            display_name="tester",
            role=UserRole.TESTER,
        )
        inactive = User(
            organization_id=org.id,
            email="inactive@verify-auth.example.com",
            password_hash=passwords.hash(PASSWORD),
            display_name="inactive",
            role=UserRole.TESTER,
            is_active=False,
        )
        db.add_all([tester, inactive])
        await db.flush()
        # Pre-login session: the fixation token an attacker could have planted.
        svc = SessionService(db, cache, settings)
        fixation_token = await svc.create_session(tester.id, UserRole.TESTER, now=utcnow())
        seen_tokens.append(fixation_token)
        await db.commit()
        org_id, tester_id = org.id, tester.id
        user_ids = [tester.id, inactive.id]

    async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as http:
        # ── login failures: one generic 401, no enumeration ──
        r_unknown = await http.post(
            "/auth/login", json={"email": "ghost@verify-auth.example.com", "password": PASSWORD}
        )
        check("unknown email → 401", r_unknown.status_code == 401)
        r_wrong = await http.post(
            "/auth/login",
            json={"email": "tester@verify-auth.example.com", "password": "wrong-password-here"},
        )
        check("wrong password → 401", r_wrong.status_code == 401)
        check(
            "identical detail for unknown vs wrong (no enumeration)",
            r_unknown.json().get("detail") == r_wrong.json().get("detail"),
        )
        r = await http.post(
            "/auth/login", json={"email": "inactive@verify-auth.example.com", "password": PASSWORD}
        )
        check("deactivated account → 401", r.status_code == 401)

        # ── successful login: cookies, regeneration, CSRF mint ──
        r = await http.post(
            "/auth/login",
            json={"email": "tester@verify-auth.example.com", "password": PASSWORD},
            cookies={cn: fixation_token},
        )
        check("valid login → 200", r.status_code == 200)
        session_token = r.cookies.get(cn) or ""
        csrf_token = r.cookies.get(csrf_cn) or ""
        seen_tokens.append(session_token)
        check("login sets session cookie", bool(session_token))
        check("login sets CSRF cookie", bool(csrf_token))
        check("session id regenerated on login (fixation)", session_token != fixation_token)
        check("body csrf_token matches CSRF cookie", r.json().get("csrf_token") == csrf_token)
        check("response omits password_hash", "password_hash" not in r.json().get("user", {}))
        set_cookies = "\n".join(r.headers.get_list("set-cookie"))
        session_line = next(line for line in set_cookies.splitlines() if line.startswith(cn))
        csrf_line = next(line for line in set_cookies.splitlines() if line.startswith(csrf_cn))
        check("session cookie is HttpOnly", "httponly" in session_line.lower())
        check("CSRF cookie is NOT HttpOnly (SPA must read it)", "httponly" not in csrf_line.lower())
        check(
            "both cookies Secure + SameSite=Strict",
            all(
                "secure" in line.lower() and "samesite=strict" in line.lower()
                for line in (session_line, csrf_line)
            ),
        )

        # the planted pre-login token is dead
        async with sessionmaker() as db:
            svc = SessionService(db, cache, settings)
            check(
                "pre-login (fixation) token revoked",
                await svc.validate_session(fixation_token, now=utcnow()) is None,
            )

        # ── GET needs no CSRF; state changes do ──
        r = await http.get("/auth/me", cookies={cn: session_token})
        check("GET /auth/me with session only → 200", r.status_code == 200)
        check("me returns the logged-in user", r.json().get("id") == str(tester_id))
        check("last_login_at stamped", r.json().get("last_login_at") is not None)

        payload = {"name": "csrf-eng", "client_system_name": "sys"}
        r = await http.post("/engagements", json=payload, cookies={cn: session_token})
        check("state change without CSRF token → 403 (cross-origin attacker)", r.status_code == 403)
        r = await http.post(
            "/engagements",
            json=payload,
            cookies={cn: session_token, csrf_cn: csrf_token},
            headers={csrf_hn: "attacker-guess"},
        )
        check("state change with mismatched CSRF header → 403", r.status_code == 403)
        r = await http.post(
            "/engagements",
            json=payload,
            cookies={cn: session_token, csrf_cn: csrf_token},
            headers={csrf_hn: csrf_token},
        )
        check("state change with matching CSRF pair → 201", r.status_code == 201)

        # ── logout revokes immediately ──
        r = await http.post(
            "/auth/logout",
            cookies={cn: session_token, csrf_cn: csrf_token},
            headers={csrf_hn: csrf_token},
        )
        check("logout → 204", r.status_code == 204)
        r = await http.get("/auth/me", cookies={cn: session_token})
        check("session invalid after logout → 401", r.status_code == 401)

        # ── logout-all kills every session ──
        r = await http.post(
            "/auth/login",
            json={"email": "tester@verify-auth.example.com", "password": PASSWORD},
        )
        session_token = r.cookies.get(cn) or ""
        csrf_token = r.cookies.get(csrf_cn) or ""
        seen_tokens.append(session_token)
        async with sessionmaker() as db:
            svc = SessionService(db, cache, settings)
            other_token = await svc.create_session(tester_id, UserRole.TESTER, now=utcnow())
            seen_tokens.append(other_token)
            await db.commit()
        r = await http.post(
            "/auth/logout-all",
            cookies={cn: session_token, csrf_cn: csrf_token},
            headers={csrf_hn: csrf_token},
        )
        check(
            "logout-all → 200 and revokes ≥2 sessions",
            r.status_code == 200 and r.json().get("revoked_sessions", 0) >= 2,
        )
        r = await http.get("/auth/me", cookies={cn: other_token})
        check("other session dead after logout-all → 401", r.status_code == 401)

    # ── audit trail ──
    async with sessionmaker() as db:
        actions = set(
            (
                await db.execute(
                    select(AuditEvent.action).where(AuditEvent.organization_id == org_id)
                )
            ).scalars()
        )
    for action in ("auth.login", "auth.login_failed", "auth.logout", "auth.logout_all"):
        check(f"audit event {action} recorded", action in actions)

    # cleanup (audit rows are append-only → dev-superuser bypass)
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await conn.execute(delete(Session).where(Session.user_id.in_(user_ids)))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    for token in seen_tokens:
        await cache.delete(f"session:{hash_token(token).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
