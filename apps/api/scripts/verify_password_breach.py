"""Live verification of set-time breached-password rejection (SEC-DEBT-3) over
real HTTP. Run inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_password_breach.py"

Exercises the THREE shipped set-time paths (SEC-08 expected result):
  * first-login set  — forced-change session → POST /auth/me/password
  * self-service change — normal session (current_password) → POST /auth/me/password
  * admin-triggered reset — POST /users/{id}/reset-password mints a temporary
    password; admins no longer choose one, so this leg proves the minted secret
    is NOT in the corpus and forces a change (a breached password cannot enter
    this way by construction).

At each path a corpus password (>=12 so it isn't merely length-blocked) is 422'd,
a strong password succeeds, and a short password still 422s on length. Admin
`POST /users` takes no password field at all (temp-password onboarding, ebf67c2),
so there is no create-with-password leg to test. Cleans up after itself.
"""

import asyncio
import sys

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.password_policy import get_breach_checker
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.audit import AuditEvent
from app.models.identity import Organization, Session, User, UserRole

API_BASE = "http://api:8000"
STRONG = "Zt9!mq-Vx2_Lp7wRa3q"  # noqa: S105 - >=12, not in the corpus
STRONG2 = "Qw4$np-Bz8_Kd1vYh6t"  # noqa: S105
BREACHED = "passwordpassword"  # noqa: S105 - in the bundled corpus, 16 chars
BREACHED_CHANGE = "letmein123456"  # noqa: S105 - in the corpus, 13 chars

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


def cookie(settings, token: str) -> dict[str, str]:
    return {settings.session_cookie_name: token}


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)

    async with sessionmaker() as db:
        org = Organization(name="verify-breach-org")
        db.add(org)
        await db.flush()
        admin = User(
            organization_id=org.id,
            email="breach-admin@verify-breach.example.com",
            password_hash="x",  # noqa: S106 - seeded session, no login here
            display_name="admin",
            role=UserRole.ADMIN,
        )
        db.add(admin)
        await db.flush()
        token = await SessionService(db, cache, settings).create_session(
            admin.id, UserRole.ADMIN, now=utcnow()
        )
        await db.commit()
        org_id = org.id

    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=10,
        cookies={settings.csrf_cookie_name: "c"},
        headers={settings.csrf_header_name: "c"},
    ) as http:
        # Admin creates a user — POST /users mints a one-time temp password and
        # forces a change; it takes NO password field (temp-password onboarding).
        r = await http.post(
            "/users",
            json={
                "email": "created@verify-breach.example.com",
                "display_name": "created",
                "role": "tester",
            },
            cookies=cookie(settings, token),
        )
        check("admin create user → 201 (temp password, no password field)", r.status_code == 201)
        created_id = r.json()["user"]["id"] if r.status_code == 201 else None

        # A session for the created user (still in forced-change), so the
        # first-login set path can be driven at POST /auth/me/password.
        async with sessionmaker() as db:
            user_token = await SessionService(db, cache, settings).create_session(
                created_id, UserRole.TESTER, now=utcnow()
            )
            await db.commit()

        # 1) First-login set (forced change → current_password waived).
        r = await http.post(
            "/auth/me/password",
            json={"new_password": BREACHED},
            cookies=cookie(settings, user_token),
        )
        check("first-login set breached → 422", r.status_code == 422)
        check(
            "breach 422 detail mentions known-breach",
            "breach" in str(r.json().get("detail", "")).lower(),
        )
        r = await http.post(
            "/auth/me/password",
            json={"new_password": "short"},
            cookies=cookie(settings, user_token),
        )
        check("first-login set short → 422 (length)", r.status_code == 422)
        r = await http.post(
            "/auth/me/password",
            json={"new_password": STRONG},
            cookies=cookie(settings, user_token),
        )
        check("first-login set strong → 200", r.status_code == 200)

        # 2) Self-service change (must_change cleared → current_password required).
        r = await http.post(
            "/auth/me/password",
            json={"current_password": STRONG, "new_password": BREACHED_CHANGE},
            cookies=cookie(settings, user_token),
        )
        check("self-service change to breached → 422", r.status_code == 422)
        r = await http.post(
            "/auth/me/password",
            json={"current_password": STRONG, "new_password": STRONG2},
            cookies=cookie(settings, user_token),
        )
        check("self-service change to strong → 200", r.status_code == 200)

        # 3) Admin reset mints a fresh temp password (admins can't choose one, so
        # a breached password cannot enter here); prove it is not in the corpus
        # and that it forces a change.
        r = await http.post(f"/users/{created_id}/reset-password", cookies=cookie(settings, token))
        check("admin reset-password → 200", r.status_code == 200)
        minted = r.json().get("temporary_password", "") if r.status_code == 200 else BREACHED
        breach = get_breach_checker(settings.breached_password_list_path)
        check("minted temp password is not in the breach corpus", not breach.is_breached(minted))
        async with sessionmaker() as db:
            forced = (
                await db.execute(select(User.must_change_password).where(User.id == created_id))
            ).scalar_one()
        check("admin reset forces a password change", forced is True)

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        org_users = select(User.id).where(User.organization_id == org_id)
        await conn.execute(delete(Session).where(Session.user_id.in_(org_users)))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    await cache.delete(f"session:{hash_token(token).hex()}")
    await cache.delete(f"session:{hash_token(user_token).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
