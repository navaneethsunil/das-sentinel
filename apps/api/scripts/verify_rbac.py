"""Live verification of M1-T2: per-role route access over HTTP + immediate
session revocation (cache AND DB). Run inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_rbac.py"

Drives a representative route with each of the four roles asserting the matrix's
allow/deny, then revokes a live session and proves the very next request is 401,
the Valkey cache entry is gone, and the DB row shows revoked_at set. Cleans up
via the dev-superuser trigger bypass.
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
from app.models.engagement import Engagement
from app.models.identity import Organization, Session, User, UserRole

API_BASE = "http://api:8000"
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
    tokens: dict[str, str] = {}

    async with sessionmaker() as db:
        org = Organization(name="verify-rbac-org")
        db.add(org)
        await db.flush()
        users = {}
        svc = SessionService(db, cache, settings)
        now = utcnow()
        for role in (UserRole.ADMIN, UserRole.TESTER, UserRole.REVIEWER, UserRole.READ_ONLY):
            u = User(
                organization_id=org.id,
                email=f"{role.value}@verify-rbac.test",
                password_hash="x",  # noqa: S106
                display_name=role.value,
                role=role,
            )
            db.add(u)
            await db.flush()
            users[role] = u.id
            tokens[role.value] = await svc.create_session(u.id, role, now=now)
        eng = Engagement(
            organization_id=org.id,
            created_by=users[UserRole.ADMIN],
            name="rbac-eng",
            client_system_name="sys",
        )
        db.add(eng)
        await db.flush()
        await db.commit()
        org_id = org.id
        user_ids = list(users.values())

    cn = settings.session_cookie_name

    async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as http:
        # MANAGE_ENGAGEMENTS (create engagement): Admin/Tester allow; Reviewer/RO deny.
        payload = {"name": "x", "client_system_name": "y"}
        expected_create = {"admin": 201, "tester": 201, "reviewer": 403, "read_only": 403}
        for role, want in expected_create.items():
            r = await http.post("/engagements", json=payload, cookies={cn: tokens[role]})
            check(f"create engagement: {role} → {want}", r.status_code == want)

        # VIEW (list engagements): every role allow.
        for role in expected_create:
            r = await http.get("/engagements", cookies={cn: tokens[role]})
            check(f"list engagements: {role} → 200", r.status_code == 200)

        # MANAGE_USERS (create user): Admin allow; all others deny.
        newu = {
            "email": "made@verify-rbac.example.com",
            "display_name": "m",
            "role": "read_only",
            "password": "correct horse battery staple",
        }
        expected_user = {"admin": 201, "tester": 403, "reviewer": 403, "read_only": 403}
        for role, want in expected_user.items():
            r = await http.post("/users", json=newu, cookies={cn: tokens[role]})
            # admin's second run would 409 on duplicate; only send once per role
            check(f"create user: {role} → {want}", r.status_code == want)
            newu["email"] = f"made-{role}@verify-rbac.example.com"

        # ── immediate revocation (cache + DB) ──
        ro_token = tokens["read_only"]
        r = await http.get("/engagements", cookies={cn: ro_token})
        check("read_only session valid before revoke (200)", r.status_code == 200)

    # revoke read_only's session
    async with sessionmaker() as db:
        svc = SessionService(db, cache, settings)
        await svc.revoke_session(ro_token, now=utcnow())
        await db.commit()

    cache_key = f"session:{hash_token(ro_token).hex()}"
    check("revoke dropped the Valkey cache entry", await cache.get(cache_key) is None)
    async with sessionmaker() as db:
        revoked_at = (
            await db.execute(
                select(Session.revoked_at).where(Session.token_hash == hash_token(ro_token))
            )
        ).scalar_one()
    check("revoke set revoked_at in the DB row", revoked_at is not None)

    async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as http:
        r = await http.get("/engagements", cookies={cn: ro_token})
        check("next request after revoke is 401", r.status_code == 401)

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        await conn.execute(delete(Session).where(Session.user_id.in_(user_ids)))
        await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    for token in tokens.values():
        await cache.delete(f"session:{hash_token(token).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
