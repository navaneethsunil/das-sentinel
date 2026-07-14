"""Live verification of the M1-B2 session lifecycle against real Postgres +
Valkey. Run inside the compose network:

    docker compose run --rm --entrypoint python api scripts/verify_sessions.py

Exercises create → validate (cache hit + DB miss) → idle/absolute expiry →
logout → kill-all, and asserts write-through cache invalidation makes
revocation instant. Rolls nothing back: it uses a throwaway org/user and
deletes them at the end. Prints PASS/FAIL per check; exits non-zero on failure.
"""

import asyncio
import sys
from datetime import timedelta

from redis.asyncio import Redis
from sqlalchemy import delete

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.identity import Organization, Session, User, UserRole

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)

    async with sessionmaker() as db:
        org = Organization(name="verify-sessions-org")
        db.add(org)
        await db.flush()
        user = User(
            organization_id=org.id,
            email="verify-sessions@example.test",
            password_hash="x",  # noqa: S106 — throwaway fixture row, not a credential
            display_name="verify",
            role=UserRole.TESTER,
            is_active=True,
        )
        db.add(user)
        await db.flush()

        svc = SessionService(db, cache, settings)
        now = utcnow()

        # create + validate on a warm cache
        token = await svc.create_session(user.id, UserRole.TESTER, now=now)
        cache_key = f"session:{hash_token(token).hex()}"
        check("cache populated on create", await cache.get(cache_key) is not None)
        v = await svc.validate_session(token, now=now)
        check("valid session resolves user+role", v is not None and v.role is UserRole.TESTER)

        # validate on a cold cache (DB is authoritative)
        await cache.delete(cache_key)
        v = await svc.validate_session(token, now=now)
        check("validates from DB after cache miss", v is not None)
        check("cache repopulated after DB validate", await cache.get(cache_key) is not None)

        # idle expiry
        idle_future = now + timedelta(seconds=settings.session_idle_ttl_seconds + 1)
        # slide happened on the last validate, so re-read from that point
        await cache.delete(cache_key)
        check(
            "idle-expired session rejected",
            await svc.validate_session(token, now=idle_future) is None,
        )

        # absolute expiry (fresh session, far-future now beats the sliding idle)
        token2 = await svc.create_session(user.id, UserRole.TESTER, now=now)
        abs_future = now + timedelta(seconds=settings.session_absolute_ttl_seconds + 1)
        check(
            "absolute-expired session rejected",
            await svc.validate_session(token2, now=abs_future) is None,
        )

        # logout = write-through revoke → instant
        token3 = await svc.create_session(user.id, UserRole.TESTER, now=now)
        key3 = f"session:{hash_token(token3).hex()}"
        await svc.revoke_session(token3, now=now)
        check("logout drops cache entry", await cache.get(key3) is None)
        check(
            "revoked session rejected even with warm path",
            await svc.validate_session(token3, now=now) is None,
        )

        # kill-all
        a = await svc.create_session(user.id, UserRole.TESTER, now=now)
        b = await svc.create_session(user.id, UserRole.TESTER, now=now)
        revoked = await svc.revoke_all_for_user(user.id, now=now)
        check("kill-all revokes remaining live sessions", revoked >= 2)
        check("killed session A rejected", await svc.validate_session(a, now=now) is None)
        check("killed session B rejected", await svc.validate_session(b, now=now) is None)

        # inactive user's session is rejected
        token4 = await svc.create_session(user.id, UserRole.TESTER, now=now)
        user.is_active = False
        await db.flush()
        await cache.delete(f"session:{hash_token(token4).hex()}")
        check(
            "session of deactivated user rejected",
            await svc.validate_session(token4, now=now) is None,
        )

        # cleanup
        await db.execute(delete(Session).where(Session.user_id == user.id))
        await db.execute(delete(User).where(User.id == user.id))
        await db.execute(delete(Organization).where(Organization.id == org.id))
        await db.commit()

    # scrub any residual cache keys
    for suffix in (token, token2, token3, a, b, token4):
        await cache.delete(f"session:{hash_token(suffix).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
