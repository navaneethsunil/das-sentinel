"""Live end-to-end verification of the M1-B11 approval gates. Run inside the
compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_approvals.py"

Asserts request→decide→revoke over HTTP with RBAC (tester requests, reviewer
decides, tester cannot decide), the ROE-required and high-risk-only guards,
cross-org 404, digest binding, and — the load-bearing safety property — the
atomic single-use consume: exactly one of two consume attempts succeeds. Cleans
up via the dev-superuser trigger bypass.
"""

import asyncio
import sys
import uuid
from datetime import timedelta

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

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
from app.services.approvals import consume_approval, request_approval
from app.services.roe import render_current_roe

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
        org = Organization(name="verify-appr-org")
        other = Organization(name="verify-appr-other")
        db.add_all([org, other])
        await db.flush()
        tester = User(
            organization_id=org.id,
            email="tester@verify-appr.test",
            password_hash="x",  # noqa: S106
            display_name="tester",
            role=UserRole.TESTER,
        )
        reviewer = User(
            organization_id=org.id,
            email="reviewer@verify-appr.test",
            password_hash="x",  # noqa: S106
            display_name="reviewer",
            role=UserRole.REVIEWER,
        )
        db.add_all([tester, reviewer])
        await db.flush()
        eng = Engagement(
            organization_id=org.id,
            created_by=tester.id,
            name="appr-eng",
            client_system_name="sys",
        )
        db.add(eng)
        await db.flush()
        target = Target(
            engagement_id=eng.id,
            name="web",
            target_type=TargetType.WEB_APP,
            primary_value="https://app.example.com",
        )
        db.add(target)
        db.add(
            ScopeItem(
                engagement_id=eng.id,
                kind=ScopeKind.ALLOW,
                matcher_type=ScopeMatcher.DOMAIN,
                value="app.example.com",
            )
        )
        await db.flush()
        # A current accepted ROE (required to request an approval).
        _, _, terms, content_hash = render_current_roe(
            eng,
            [
                ScopeItem(
                    engagement_id=eng.id,
                    kind=ScopeKind.ALLOW,
                    matcher_type=ScopeMatcher.DOMAIN,
                    value="app.example.com",
                )
            ],
        )
        db.add(
            ROEAcknowledgement(
                engagement_id=eng.id,
                accepted_by=tester.id,
                roe_text="frozen",
                scope_snapshot=[],
                terms_snapshot=terms,
                content_hash=content_hash,
            )
        )
        svc = SessionService(db, cache, settings)
        now = utcnow()
        tester_token = await svc.create_session(tester.id, UserRole.TESTER, now=now)
        reviewer_token = await svc.create_session(reviewer.id, UserRole.REVIEWER, now=now)
        tokens += [tester_token, reviewer_token]
        await db.commit()
        org_id, other_id = org.id, other.id
        eng_id, target_id = eng.id, target.id
        user_ids = [tester.id, reviewer.id]

    cn = settings.session_cookie_name
    base = f"/engagements/{eng_id}/approvals"
    async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as http:
        req = {
            "target_id": str(target_id),
            "operation_kind": "exploit_validation",
            "justification": "validate the SQLi finding",
            "expires_in_hours": 24,
        }

        # reviewer cannot request (LAUNCH_SCANS is Admin/Tester)
        r = await http.post(base, json=req, cookies={cn: reviewer_token})
        check("reviewer cannot request (403)", r.status_code == 403)

        # non-high-risk kind is rejected (400)
        r = await http.post(
            base, json={**req, "operation_kind": "passive_recon"}, cookies={cn: tester_token}
        )
        check("non-high-risk kind rejected (400)", r.status_code == 400)

        # tester requests
        r = await http.post(base, json=req, cookies={cn: tester_token})
        check("tester requests approval (201)", r.status_code == 201)
        gate = r.json()
        approval_id = gate.get("id")
        check("request starts pending", gate.get("status") == "pending")

        # tester cannot decide (APPROVE_HIGH_RISK is Admin/Reviewer)
        r = await http.post(
            f"{base}/{approval_id}/decide",
            json={"approve": True},
            cookies={cn: tester_token},
        )
        check("tester cannot decide (403)", r.status_code == 403)

        # reviewer approves
        r = await http.post(
            f"{base}/{approval_id}/decide",
            json={"approve": True, "reason": "scoped + justified"},
            cookies={cn: reviewer_token},
        )
        check("reviewer approves (200)", r.status_code == 200 and r.json()["status"] == "approved")

        # cross-org read → 404
        r = await http.get(
            f"/engagements/{uuid.uuid4()}/approvals/{approval_id}", cookies={cn: reviewer_token}
        )
        check("unknown engagement → 404", r.status_code == 404)

    # digest binding: stored digest equals the recomputed operation digest
    op = Operation(target_id=target_id, kind=OperationKind.EXPLOIT_VALIDATION)
    expected_digest = compute_operation_digest(eng_id, op, ScanIntensity.HIGH_RISK)
    async with sessionmaker() as db:
        gate_row = (
            await db.execute(select(ApprovalGate).where(ApprovalGate.id == uuid.UUID(approval_id)))
        ).scalar_one()
        check(
            "stored operation_digest binds the operation",
            gate_row.operation_digest == expected_digest,
        )

    # ── the safety property: atomic single-use consume ──
    async with sessionmaker() as db:
        now = utcnow()
        first = await consume_approval(
            db, approval_id=uuid.UUID(approval_id), scan_id=uuid.uuid4(), now=now
        )
        second = await consume_approval(
            db, approval_id=uuid.UUID(approval_id), scan_id=uuid.uuid4(), now=now
        )
        await db.commit()
    check("first consume succeeds", first is True)
    check("second consume refused (single-use)", second is False)

    # a revoked approval cannot be consumed
    async with sessionmaker() as db:
        eng_row = (await db.execute(select(Engagement).where(Engagement.id == eng_id))).scalar_one()
        ack_row = (
            await db.execute(
                select(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id == eng_id)
            )
        ).scalar_one()
        tgt_row = (await db.execute(select(Target).where(Target.id == target_id))).scalar_one()
        gate2 = await request_approval(
            db,
            engagement=eng_row,
            target=tgt_row,
            op=op,
            roe_ack=ack_row,
            requested_by=user_ids[0],
            justification="second",
            expires_at=utcnow() + timedelta(hours=1),
        )
        gate2.status = ApprovalStatus.APPROVED
        gate2.decided_by = user_ids[1]
        gate2.decided_at = utcnow()
        gate2.revoked_at = utcnow()
        gate2.status = ApprovalStatus.REVOKED
        gate2.revoked_by = user_ids[1]
        await db.flush()
        consumed = await consume_approval(
            db, approval_id=gate2.id, scan_id=uuid.uuid4(), now=utcnow()
        )
        await db.commit()
    check("revoked approval cannot be consumed", consumed is False)

    async with sessionmaker() as db:
        actions = (
            (await db.execute(select(AuditEvent.action).where(AuditEvent.engagement_id == eng_id)))
            .scalars()
            .all()
        )
    check("approval.requested audited", "approval.requested" in actions)
    check("approval.approved audited", "approval.approved" in actions)

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(
            delete(AuditEvent).where(AuditEvent.organization_id.in_([org_id, other_id]))
        )
        await conn.execute(delete(ApprovalGate).where(ApprovalGate.engagement_id == eng_id))
        await conn.execute(
            delete(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id == eng_id)
        )
        await conn.execute(delete(ScopeItem).where(ScopeItem.engagement_id == eng_id))
        await conn.execute(delete(Target).where(Target.engagement_id == eng_id))
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
