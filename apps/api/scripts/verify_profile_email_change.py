"""Live regression guard for the self-service email-change deadlock (UAT DEF-004).

    docker compose run --rm --no-deps -v "$PWD/apps/api/scripts:/app/scripts:ro" \
      --entrypoint sh api -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
      python scripts/verify_profile_email_change.py"

Why a live script and not a unit test: the bug only exists in the real ASGI +
Postgres stack. The audit middleware writes its baseline event on its OWN DB
session; audit_events.actor_user_id has an FK to users(id), so that insert takes
FOR KEY SHARE on the actor's row. `email` is part of uq_users_organization_id_email,
so changing it takes the conflicting FOR UPDATE. If the middleware runs before the
handler's session commits, the two wait on each other forever — PATCH /auth/me
never returns and every subsequent login blocks behind the same row lock.

Asserts: the email change completes quickly, persists, leaves no session stuck
'idle in transaction', still records the baseline audit event, and logins keep
working afterwards. Uses a throwaway user and deactivates it at the end (audit rows are append-only,
so the user cannot be deleted once it has an audit trail).
"""

import asyncio
import sys
import uuid

import httpx
from sqlalchemy import select, text, update

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.models.audit import AuditEvent
from app.models.identity import Organization, User, UserRole

BASE = "http://api:8000"
PASSWORD = "verify-email-change-2026!"  # noqa: S105 - throwaway fixture credential
DEADLINE_SECONDS = 15.0

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    tag = uuid.uuid4().hex[:8]
    old_email = f"verify-email-{tag}@example.com"
    new_email = f"verify-email-{tag}-changed@example.com"

    async with sessionmaker() as db:
        org = (await db.execute(select(Organization).limit(1))).scalar_one()
        user = User(
            organization_id=org.id,
            email=old_email,
            display_name="Verify Email Change",
            password_hash=PasswordService(settings.password_hash_scheme).hash(PASSWORD),
            role=UserRole.READ_ONLY,
        )
        db.add(user)
        await db.commit()
        user_id = user.id

    try:
        async with httpx.AsyncClient(base_url=BASE, timeout=DEADLINE_SECONDS) as client:
            login = await client.post(
                "/auth/login", json={"email": old_email, "password": PASSWORD}
            )
            check("login with the original address", login.status_code == 200)
            if login.status_code != 200:
                print(f"  login response: {login.status_code} {login.text[:200]}")
                return 1
            # __Host- cookies are Secure; httpx will not store them over plain
            # http to the compose-internal API, so echo them back by hand.
            # CSRF is double-submit: the header must match the cookie.
            session_cookie = login.cookies.get(settings.session_cookie_name) or ""
            csrf_cookie = login.cookies.get(settings.csrf_cookie_name) or ""
            auth = {
                "Cookie": (
                    f"{settings.session_cookie_name}={session_cookie}; "
                    f"{settings.csrf_cookie_name}={csrf_cookie}"
                ),
                settings.csrf_header_name: csrf_cookie,
            }

            try:
                patch = await client.patch("/auth/me", json={"email": new_email}, headers=auth)
            except httpx.TimeoutException:
                check(f"PATCH /auth/me (email) returns within {DEADLINE_SECONDS}s", False)
                patch = None

            if patch is not None:
                if patch.status_code != 200:
                    print(f"  patch response: {patch.status_code} {patch.text[:200]}")
                check("PATCH /auth/me (email) returns 200", patch.status_code == 200)
                check("response carries the new address", patch.json().get("email") == new_email)

            # The deadlock's real damage: everyone else's login blocks behind it.
            after = await client.post(
                "/auth/login", json={"email": new_email, "password": PASSWORD}
            )
            check("login still works afterwards (no platform-wide lock)", after.status_code == 200)

        async with sessionmaker() as db:
            stored = (await db.execute(select(User.email).where(User.id == user_id))).scalar_one()
            check("new address is persisted", stored == new_email)

            stuck = (
                await db.execute(
                    text(
                        "select count(*) from pg_stat_activity "
                        "where datname = current_database() "
                        "and state = 'idle in transaction' "
                        "and now() - xact_start > interval '10 seconds'"
                    )
                )
            ).scalar_one()
            check("no session left idle in transaction", stuck == 0)

            # The ordering fix must not cost us audit coverage.
            await asyncio.sleep(1)
            events = (
                (
                    await db.execute(
                        select(AuditEvent.action).where(AuditEvent.actor_user_id == user_id)
                    )
                )
                .scalars()
                .all()
            )
            check("handler audit event recorded", "auth.profile_updated" in events)
            check("middleware baseline event recorded", "PATCH /auth/me" in events)
    finally:
        # The throwaway user is deactivated, not deleted: audit_events is
        # append-only (TM-9) and its rows reference the actor, so removing the
        # user would mean deleting audit history. Deactivation is the cleanup
        # the product itself offers.
        async with sessionmaker() as db:
            await db.execute(update(User).where(User.id == user_id).values(is_active=False))
            await db.commit()
        await engine.dispose()

    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
