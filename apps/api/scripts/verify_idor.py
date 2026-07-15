"""M1-SEC1: cross-engagement IDOR/BOLA (TM-3, OWASP A01:2025). Run inside the
compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_idor.py"

Two orgs each own an engagement + scope item + target + ROE + approval. As
org-A's users we attack org-B's objects two ways: (1) directly under B's
engagement path, and (2) the subtler BOLA — a foreign object id nested under
A's OWN engagement path. Every attempt must be 404 (never data, never 200/204).
A same-org control read confirms the objects are otherwise reachable. Cleans up
via the dev-superuser trigger bypass.
"""

import asyncio
import sys
from datetime import timedelta

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.scope import Operation, OperationKind, compute_operation_digest
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.audit import AuditEvent
from app.models.engagement import (
    ApprovalGate,
    ApprovalStatus,
    Engagement,
    ROEAcknowledgement,
    ScanIntensity,
    ScopeItem,
    ScopeKind,
    ScopeMatcher,
)
from app.models.identity import Organization, Session, User, UserRole
from app.models.target import Target, TargetType
from app.services.roe import render_current_roe

API_BASE = "http://api:8000"
failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def _seed(db, cache, settings, slug: str) -> dict:
    org = Organization(name=f"idor-{slug}")
    db.add(org)
    await db.flush()
    tester = User(
        organization_id=org.id,
        email=f"tester@idor-{slug}.test",
        password_hash="x",  # noqa: S106
        display_name="tester",
        role=UserRole.TESTER,
    )
    reviewer = User(
        organization_id=org.id,
        email=f"reviewer@idor-{slug}.test",
        password_hash="x",  # noqa: S106
        display_name="reviewer",
        role=UserRole.REVIEWER,
    )
    db.add_all([tester, reviewer])
    await db.flush()
    eng = Engagement(
        organization_id=org.id,
        created_by=tester.id,
        name=f"eng-{slug}",
        client_system_name="sys",
    )
    db.add(eng)
    await db.flush()
    scope = ScopeItem(
        engagement_id=eng.id,
        kind=ScopeKind.ALLOW,
        matcher_type=ScopeMatcher.DOMAIN,
        value=f"{slug}.example.com",
    )
    target = Target(
        engagement_id=eng.id,
        name="web",
        target_type=TargetType.WEB_APP,
        primary_value=f"https://{slug}.example.com",
    )
    db.add_all([scope, target])
    await db.flush()
    _, _, terms, content_hash = render_current_roe(eng, [scope])
    roe = ROEAcknowledgement(
        engagement_id=eng.id,
        accepted_by=tester.id,
        roe_text="frozen",
        scope_snapshot=[],
        terms_snapshot=terms,
        content_hash=content_hash,
    )
    db.add(roe)
    await db.flush()
    op = Operation(target_id=target.id, kind=OperationKind.EXPLOIT_VALIDATION)
    approval = ApprovalGate(
        engagement_id=eng.id,
        target_id=target.id,
        requested_by=tester.id,
        action_type="exploit_validation",
        justification="j",
        operation_digest=compute_operation_digest(eng.id, op, ScanIntensity.HIGH_RISK),
        roe_ack_id=roe.id,
        policy_version="1",
        status=ApprovalStatus.PENDING,
        expires_at=utcnow() + timedelta(hours=1),
    )
    db.add(approval)
    await db.flush()
    svc = SessionService(db, cache, settings)
    now = utcnow()
    return {
        "org_id": org.id,
        "eng_id": eng.id,
        "scope_id": scope.id,
        "target_id": target.id,
        "approval_id": approval.id,
        "user_ids": [tester.id, reviewer.id],
        "tester_token": await svc.create_session(tester.id, UserRole.TESTER, now=now),
        "reviewer_token": await svc.create_session(reviewer.id, UserRole.REVIEWER, now=now),
    }


async def main() -> int:  # noqa: C901 - linear adversarial script
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)

    async with sessionmaker() as db:
        a = await _seed(db, cache, settings, "a")
        b = await _seed(db, cache, settings, "b")
        await db.commit()

    cn = settings.session_cookie_name
    at = {cn: a["tester_token"]}
    ar = {cn: a["reviewer_token"]}
    beng, bscope, btgt, bappr = b["eng_id"], b["scope_id"], b["target_id"], b["approval_id"]
    aeng = a["eng_id"]

    async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as http:
        # same-org control: A can read its own engagement
        r = await http.get(f"/engagements/{aeng}", cookies=at)
        check("control: A reads own engagement (200)", r.status_code == 200)

        # (1) direct — B's objects under B's engagement path, as A
        direct = [
            ("GET", f"/engagements/{beng}"),
            ("PATCH", f"/engagements/{beng}"),
            ("DELETE", f"/engagements/{beng}"),
            ("GET", f"/engagements/{beng}/scope-items"),
            ("GET", f"/engagements/{beng}/targets"),
            ("GET", f"/engagements/{beng}/targets/{btgt}"),
            ("PATCH", f"/engagements/{beng}/targets/{btgt}"),
            ("DELETE", f"/engagements/{beng}/targets/{btgt}"),
            ("GET", f"/engagements/{beng}/roe"),
            ("GET", f"/engagements/{beng}/approvals"),
            ("GET", f"/engagements/{beng}/approvals/{bappr}"),
        ]
        for method, path in direct:
            r = await http.request(method, path, json={}, cookies=at)
            check(f"direct {method} {path} → 404", r.status_code == 404)

        # POST scope-items with a VALID body, so the org-scoping 404 (not body
        # validation) is what blocks the write into B's engagement.
        r = await http.post(
            f"/engagements/{beng}/scope-items",
            json={"kind": "allow", "matcher_type": "domain", "value": "evil.example.com"},
            cookies=at,
        )
        check("direct POST scope-items (valid body) → 404", r.status_code == 404)

        # (2) BOLA — B's object ids nested under A's OWN engagement path
        bola = [
            ("GET", f"/engagements/{aeng}/targets/{btgt}"),
            ("PATCH", f"/engagements/{aeng}/targets/{btgt}"),
            ("DELETE", f"/engagements/{aeng}/targets/{btgt}"),
            ("DELETE", f"/engagements/{aeng}/scope-items/{bscope}"),
            ("GET", f"/engagements/{aeng}/approvals/{bappr}"),
        ]
        for method, path in bola:
            r = await http.request(method, path, json={}, cookies=at)
            check(f"BOLA {method} {path} → 404", r.status_code == 404)

        # decide/revoke need APPROVE_HIGH_RISK — use A's reviewer so RBAC passes
        # and the object-scoping (not the role guard) is what yields 404.
        for path in (f"/engagements/{aeng}/approvals/{bappr}/decide",):
            r = await http.post(path, json={"approve": True}, cookies=ar)
            check(f"BOLA decide {path} → 404", r.status_code == 404)
        r = await http.post(f"/engagements/{aeng}/approvals/{bappr}/revoke", json={}, cookies=ar)
        check("BOLA revoke under A → 404", r.status_code == 404)

        # never leak: no attack response body contains B's identifying value
        r = await http.get(f"/engagements/{beng}", cookies=at)
        check("no data leak in cross-org 404 body", "b.example.com" not in r.text)

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        for party in (a, b):
            oid, eid = party["org_id"], party["eng_id"]
            await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == oid))
            await conn.execute(delete(ApprovalGate).where(ApprovalGate.engagement_id == eid))
            await conn.execute(
                delete(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id == eid)
            )
            await conn.execute(delete(ScopeItem).where(ScopeItem.engagement_id == eid))
            await conn.execute(delete(Target).where(Target.engagement_id == eid))
            await conn.execute(delete(Session).where(Session.user_id.in_(party["user_ids"])))
            await conn.execute(delete(Engagement).where(Engagement.organization_id == oid))
            await conn.execute(delete(User).where(User.organization_id == oid))
            await conn.execute(delete(Organization).where(Organization.id == oid))
    for party in (a, b):
        for token in (party["tester_token"], party["reviewer_token"]):
            await cache.delete(f"session:{hash_token(token).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
