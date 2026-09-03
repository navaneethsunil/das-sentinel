"""Live regression guard for finding [11] — a self-service password change must
revoke every OTHER session and rotate the caller's own token (CWE-613).

    docker compose run --rm --no-deps -v "$PWD/apps/api/scripts:/app/scripts:ro" \
      --entrypoint sh api -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
      python scripts/verify_password_session_revocation.py"

Why live and not a unit test: the behavior only exists in the real ASGI + Postgres
+ Valkey session store. Two sessions are opened for one throwaway user; the
password is changed on session A; the guard asserts session B (a previously
"stolen" token) is rejected immediately, session A keeps working on a NEW token,
and the audit trail records how many sessions were revoked.
"""

import asyncio
import sys
import uuid

import httpx
from sqlalchemy import select, update

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.models.identity import Organization, User, UserRole

BASE = "http://api:8000"
PASSWORD = "verify-pw-rotate-2026!"  # noqa: S105 - throwaway fixture credential
NEW_PASSWORD = "verify-pw-rotate-2026-changed!"  # noqa: S105
DEADLINE_SECONDS = 15.0

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


def _auth_headers(settings, login: httpx.Response) -> dict[str, str]:
    # __Host- cookies are Secure; httpx will not store them over plain http to
    # the compose-internal API, so echo them back by hand. CSRF is double-submit.
    session_cookie = login.cookies.get(settings.session_cookie_name) or ""
    csrf_cookie = login.cookies.get(settings.csrf_cookie_name) or ""
    return {
        "Cookie": (
            f"{settings.session_cookie_name}={session_cookie}; "
            f"{settings.csrf_cookie_name}={csrf_cookie}"
        ),
        settings.csrf_header_name: csrf_cookie,
    }


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    tag = uuid.uuid4().hex[:8]
    email = f"verify-pwrot-{tag}@example.com"

    async with sessionmaker() as db:
        org = (await db.execute(select(Organization).limit(1))).scalar_one()
        user = User(
            organization_id=org.id,
            email=email,
            display_name="Verify Password Rotation",
            password_hash=PasswordService(settings.password_hash_scheme).hash(PASSWORD),
            role=UserRole.READ_ONLY,
        )
        db.add(user)
        await db.commit()
        user_id = user.id

    try:
        async with httpx.AsyncClient(base_url=BASE, timeout=DEADLINE_SECONDS) as client:
            login_a = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
            login_b = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
            check("session A login", login_a.status_code == 200)
            check("session B login", login_b.status_code == 200)
            if login_a.status_code != 200 or login_b.status_code != 200:
                return 1
            auth_a = _auth_headers(settings, login_a)
            auth_b = _auth_headers(settings, login_b)

            # Both sessions are usable before the change.
            me_b_before = await client.get("/auth/me", headers=auth_b)
            check("session B works before the change", me_b_before.status_code == 200)

            # Change the password on session A.
            change = await client.post(
                "/auth/me/password",
                json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
                headers=auth_a,
            )
            check("password change returns 200", change.status_code == 200)

            # Session B (the "stolen" token) must now be dead.
            me_b_after = await client.get("/auth/me", headers=auth_b)
            check("sibling session B is revoked (401)", me_b_after.status_code == 401)

            # Session A's ORIGINAL token must also be dead (it was rotated)...
            me_a_old = await client.get("/auth/me", headers=auth_a)
            check("session A's old token is rotated out (401)", me_a_old.status_code == 401)

            # ...but the change response handed back a fresh, working session.
            auth_a_new = _auth_headers(settings, change)
            me_a_new = await client.get("/auth/me", headers=auth_a_new)
            check("caller stays signed in on a fresh token", me_a_new.status_code == 200)
            new_session_cookie = change.cookies.get(settings.session_cookie_name) or ""
            old_session_cookie = login_a.cookies.get(settings.session_cookie_name) or ""
            check(
                "the rotated session token is different",
                bool(new_session_cookie) and new_session_cookie != old_session_cookie,
            )

            # The new password works for a fresh login; the old one does not.
            relogin = await client.post(
                "/auth/login", json={"email": email, "password": NEW_PASSWORD}
            )
            check("new password authenticates", relogin.status_code == 200)
            old_login = await client.post(
                "/auth/login", json={"email": email, "password": PASSWORD}
            )
            check("old password no longer authenticates", old_login.status_code == 401)
    finally:
        async with sessionmaker() as db:
            await db.execute(update(User).where(User.id == user_id).values(is_active=False))
            await db.commit()
        await engine.dispose()

    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
