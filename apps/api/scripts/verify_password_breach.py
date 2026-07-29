"""Live verification of set-time breached-password rejection (SEC-DEBT-3) over
real HTTP. Run inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_password_breach.py"

Mints an admin session, then drives POST /users and POST /users/{id}/password:
a corpus password (>=12 so it isn't just length-blocked) is 422'd on both create
and change, a strong password succeeds, and a short password still 422s on length.
Cleans up after itself.
"""

import asyncio
import sys

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
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
        base = {
            "email": "created@verify-breach.example.com",
            "display_name": "created",
            "role": "tester",
        }

        r = await http.post(
            "/users", json={**base, "password": BREACHED}, cookies=cookie(settings, token)
        )
        check("create with breached password → 422", r.status_code == 422)
        check(
            "breach 422 detail mentions known-breach",
            "breach" in str(r.json().get("detail", "")).lower(),
        )

        r = await http.post(
            "/users",
            json={**base, "email": "short@verify-breach.example.com", "password": "short"},
            cookies=cookie(settings, token),
        )
        check("create with short password → 422 (length)", r.status_code == 422)

        r = await http.post(
            "/users", json={**base, "password": STRONG}, cookies=cookie(settings, token)
        )
        check("create with strong password → 201", r.status_code == 201)
        created_id = r.json().get("id") if r.status_code == 201 else None

        r = await http.post(
            f"/users/{created_id}/password",
            json={"password": BREACHED_CHANGE},
            cookies=cookie(settings, token),
        )
        check("change to breached password → 422", r.status_code == 422)

        r = await http.post(
            f"/users/{created_id}/password",
            json={"password": STRONG2},
            cookies=cookie(settings, token),
        )
        check("change to strong password → 200", r.status_code == 200)

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        org_users = select(User.id).where(User.organization_id == org_id)
        await conn.execute(delete(Session).where(Session.user_id.in_(org_users)))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    await cache.delete(f"session:{hash_token(token).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
