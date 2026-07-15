"""Live end-to-end verification of the M1-B8 ROE acceptance flow. Run inside
the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_roe.py"

Asserts: render + accept, RBAC (read-only 403 accept / 200 view), stale-hash
409, re-acceptance required after a scope change AND after a term change, the
stored acknowledgement's hash verifies against its own frozen snapshots, and
roe.accepted is audited. Cleans up via the dev-superuser trigger bypass.
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
from app.models.engagement import (
    Engagement,
    ROEAcknowledgement,
    ScopeItem,
    ScopeKind,
    ScopeMatcher,
)
from app.models.identity import Organization, Session, User, UserRole
from app.services.roe import compute_content_hash

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
        org = Organization(name="verify-roe-org")
        db.add(org)
        await db.flush()
        tester = User(
            organization_id=org.id,
            email="tester@verify-roe.test",
            password_hash="x",  # noqa: S106
            display_name="tester",
            role=UserRole.TESTER,
        )
        readonly = User(
            organization_id=org.id,
            email="ro@verify-roe.test",
            password_hash="x",  # noqa: S106
            display_name="ro",
            role=UserRole.READ_ONLY,
        )
        db.add_all([tester, readonly])
        await db.flush()
        eng = Engagement(
            organization_id=org.id,
            created_by=tester.id,
            name="roe-eng",
            client_system_name="sys",
            rate_limit_rps=5,
        )
        db.add(eng)
        await db.flush()
        db.add(
            ScopeItem(
                engagement_id=eng.id,
                kind=ScopeKind.ALLOW,
                matcher_type=ScopeMatcher.DOMAIN,
                value="app.example.com",
            )
        )
        await db.flush()
        svc = SessionService(db, cache, settings)
        now = utcnow()
        tester_token = await svc.create_session(tester.id, UserRole.TESTER, now=now)
        ro_token = await svc.create_session(readonly.id, UserRole.READ_ONLY, now=now)
        tokens += [tester_token, ro_token]
        await db.commit()
        org_id, eng_id = org.id, eng.id
        user_ids = [tester.id, readonly.id]

    cn = settings.session_cookie_name
    base = f"/engagements/{eng_id}/roe"
    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=10,
        # Double-submit CSRF (M1-SEC2): any matching cookie/header pair passes.
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        r = await http.get(base, cookies={cn: tester_token})
        view = r.json()
        check("initial ROE requires acceptance", view["requires_reacceptance"] is True)
        check("initial ROE not yet accepted", view["is_accepted"] is False)
        hash1 = view["content_hash"]

        # read-only can view but not accept
        r = await http.get(base, cookies={cn: ro_token})
        check("read-only can view ROE (200)", r.status_code == 200)
        r = await http.post(
            f"{base}/accept", json={"acknowledged_content_hash": hash1}, cookies={cn: ro_token}
        )
        check("read-only cannot accept (403)", r.status_code == 403)

        # stale/wrong hash rejected
        r = await http.post(
            f"{base}/accept",
            json={"acknowledged_content_hash": "0" * 64},
            cookies={cn: tester_token},
        )
        check("stale hash rejected (409)", r.status_code == 409)

        # accept with correct hash
        r = await http.post(
            f"{base}/accept", json={"acknowledged_content_hash": hash1}, cookies={cn: tester_token}
        )
        check("accept succeeds (201)", r.status_code == 201)

        r = await http.get(base, cookies={cn: tester_token})
        check("after accept: is_accepted", r.json()["is_accepted"] is True)
        check("after accept: no re-acceptance", r.json()["requires_reacceptance"] is False)

        # scope change forces re-acceptance
        await http.post(
            f"/engagements/{eng_id}/scope-items",
            json={"kind": "deny", "matcher_type": "domain", "value": "secret.example.com"},
            cookies={cn: tester_token},
        )
        r = await http.get(base, cookies={cn: tester_token})
        check("scope change forces re-acceptance", r.json()["requires_reacceptance"] is True)
        hash2 = r.json()["content_hash"]
        check("scope change changed the hash", hash2 != hash1)

        # re-accept, then a term change forces re-acceptance again
        r = await http.post(
            f"{base}/accept", json={"acknowledged_content_hash": hash2}, cookies={cn: tester_token}
        )
        check("re-accept after scope change (201)", r.status_code == 201)
        await http.patch(
            f"/engagements/{eng_id}", json={"rate_limit_rps": 25}, cookies={cn: tester_token}
        )
        r = await http.get(base, cookies={cn: tester_token})
        check("term change forces re-acceptance", r.json()["requires_reacceptance"] is True)

        r = await http.get(f"{base}/acknowledgements", cookies={cn: tester_token})
        check("two acknowledgements recorded", len(r.json()) == 2)

    # stored hash verifies against the frozen snapshots (integrity, M1-T3)
    async with sessionmaker() as db:
        acks = (
            (
                await db.execute(
                    select(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id == eng_id)
                )
            )
            .scalars()
            .all()
        )
        integrity_ok = all(
            compute_content_hash(a.roe_text, a.scope_snapshot, a.terms_snapshot) == a.content_hash
            for a in acks
        )
        actions = (
            (await db.execute(select(AuditEvent.action).where(AuditEvent.engagement_id == eng_id)))
            .scalars()
            .all()
        )
    check("stored acknowledgement hashes verify", integrity_ok)
    check("roe.accepted audited", "roe.accepted" in actions)

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        await conn.execute(
            delete(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id == eng_id)
        )
        await conn.execute(delete(ScopeItem).where(ScopeItem.engagement_id == eng_id))
        await conn.execute(delete(Session).where(Session.user_id.in_(user_ids)))
        await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    for token in tokens:
        await cache.delete(f"session:{hash_token(token).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
