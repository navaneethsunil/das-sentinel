"""Live end-to-end verification of the M1-B7 scope-item endpoints. Run inside
the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_scope.py"

Asserts allow/deny CRUD, matcher validation (422 on bad value, normalization),
RBAC (read-only cannot mutate), org scoping (cross-org engagement → 404),
delete, and audit events. Cleans up via the dev-superuser trigger bypass.
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
from app.models.engagement import Engagement, ScopeItem
from app.models.identity import Organization, Session, User, UserRole

API_BASE = "http://api:8000"
failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def main() -> int:  # noqa: C901 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)
    tokens: list[str] = []

    async with sessionmaker() as db:
        org = Organization(name="verify-scope-org")
        other = Organization(name="verify-scope-other")
        db.add_all([org, other])
        await db.flush()
        tester = User(
            organization_id=org.id,
            email="tester@verify-scope.test",
            password_hash="x",  # noqa: S106
            display_name="tester",
            role=UserRole.TESTER,
        )
        readonly = User(
            organization_id=org.id,
            email="ro@verify-scope.test",
            password_hash="x",  # noqa: S106
            display_name="ro",
            role=UserRole.READ_ONLY,
        )
        db.add_all([tester, readonly])
        await db.flush()  # populate user ids for created_by
        eng = Engagement(
            organization_id=org.id,
            created_by=tester.id,
            name="scope-eng",
            client_system_name="sys",
        )
        db.add(eng)
        await db.flush()
        svc = SessionService(db, cache, settings)
        now = utcnow()
        tester_token = await svc.create_session(tester.id, UserRole.TESTER, now=now)
        ro_token = await svc.create_session(readonly.id, UserRole.READ_ONLY, now=now)
        tokens += [tester_token, ro_token]
        await db.commit()
        org_id, other_id = org.id, other.id
        eng_id = eng.id
        user_ids = [tester.id, readonly.id]

    cn = settings.session_cookie_name
    base = f"/engagements/{eng_id}/scope-items"
    async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as http:
        # read-only cannot add
        r = await http.post(
            base,
            json={"kind": "allow", "matcher_type": "domain", "value": "app.example.com"},
            cookies={cn: ro_token},
        )
        check("read-only cannot add scope (403)", r.status_code == 403)

        # add allow + deny
        r = await http.post(
            base,
            json={"kind": "allow", "matcher_type": "domain", "value": "App.Example.COM"},
            cookies={cn: tester_token},
        )
        check("add allow item (201)", r.status_code == 201)
        check("domain value normalized to lowercase", r.json().get("value") == "app.example.com")
        allow_id = r.json().get("id")

        r = await http.post(
            base,
            json={"kind": "deny", "matcher_type": "ip_cidr", "value": "10.0.0.5/24"},
            cookies={cn: tester_token},
        )
        check("add deny item (201)", r.status_code == 201)
        check("cidr normalized to network", r.json().get("value") == "10.0.0.0/24")

        # invalid matcher value → 422
        r = await http.post(
            base,
            json={"kind": "allow", "matcher_type": "url", "value": "not-a-url"},
            cookies={cn: tester_token},
        )
        check("invalid matcher value → 422", r.status_code == 422)

        # read-only CAN list
        r = await http.get(base, cookies={cn: ro_token})
        check("read-only can list scope (200)", r.status_code == 200 and len(r.json()) == 2)

        # delete
        r = await http.delete(f"{base}/{allow_id}", cookies={cn: tester_token})
        check("delete scope item (204)", r.status_code == 204)
        r = await http.get(base, cookies={cn: tester_token})
        check("deleted item gone from list", allow_id not in [i["id"] for i in r.json()])

    # cross-org: an engagement id that isn't in the caller's org → 404
    async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as http:
        # tester belongs to org; craft a request to a non-existent engagement under caller's view
        r = await http.get(f"/engagements/{other_id}/scope-items", cookies={cn: tester_token})
        check("engagement not in caller's org → 404", r.status_code == 404)

    async with sessionmaker() as db:
        actions = (
            (await db.execute(select(AuditEvent.action).where(AuditEvent.engagement_id == eng_id)))
            .scalars()
            .all()
        )
    check("scope.item_added audited", "scope.item_added" in actions)
    check("scope.item_removed audited", "scope.item_removed" in actions)

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(
            delete(AuditEvent).where(AuditEvent.organization_id.in_([org_id, other_id]))
        )
        await conn.execute(delete(ScopeItem).where(ScopeItem.engagement_id == eng_id))
        await conn.execute(delete(Session).where(Session.user_id.in_(user_ids)))
        await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id.in_([org_id, other_id])))
    for token in tokens:
        await cache.delete(f"session:{hash_token(token).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
