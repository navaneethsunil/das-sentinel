"""Live verification of M2-W1 scan orchestration against real Postgres. Run:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_scans.py"

Proves end to end: launch freezes an execution envelope; the worker re-derives
the authorization from the live DB and (a) runs a clean SAFE_ACTIVE scan to
completion (envelope digest matches, runner_ref recorded, start/complete
audited); (b) REFUSES when the scope drifts after launch (scan failed, audit
blocked with reason); (c) honours a pre-launch cancel without ever launching the
run; (d) atomically CONSUMES a high-risk approval on a good run; (e) REFUSES a
high-risk run whose approval was revoked after launch. Uses the StubOwner (real
sandbox + suites arrive in M2-W3/B3). Cleans up after itself.
"""

import asyncio
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.scope import Operation, OperationKind, compute_operation_digest
from app.core.security import PasswordService
from app.models.audit import AuditEvent, AuditOutcome
from app.models.engagement import (
    ApprovalGate,
    ApprovalStatus,
    Engagement,
    EngagementStatus,
    ROEAcknowledgement,
    ScanIntensity,
    ScopeItem,
    ScopeKind,
    ScopeMatcher,
)
from app.models.identity import Organization, User
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus
from app.models.target import Target, TargetType
from app.services.approvals import ACTIVE_POLICY_VERSION
from app.services.roe import render_current_roe
from app.services.scans import launch_scan
from app.workers.execution import StubOwner
from app.workers.orchestration import orchestrate_scan

failures: list[str] = []
NOW = datetime.now(UTC)


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


class _SpyOwner(StubOwner):
    def __init__(self) -> None:
        self.launched = False

    async def launch(self, *, scan_id, envelope):
        self.launched = True
        return await super().launch(scan_id=scan_id, envelope=envelope)


async def _seed_engagement(session, *, org_id, user_id, max_intensity=ScanIntensity.SAFE_ACTIVE):
    eng = Engagement(
        organization_id=org_id,
        name="w1-eng",
        client_system_name="acme",
        status=EngagementStatus.ACTIVE,
        test_window_start=NOW - timedelta(days=1),
        test_window_end=NOW + timedelta(days=1),
        rate_limit_rps=5,
        max_intensity=max_intensity,
        created_by=user_id,
    )
    session.add(eng)
    await session.flush()
    scope = ScopeItem(
        engagement_id=eng.id,
        kind=ScopeKind.ALLOW,
        matcher_type=ScopeMatcher.DOMAIN,
        value="app.example.com",
    )
    target = Target(
        engagement_id=eng.id,
        name="web",
        target_type=TargetType.WEB_APP,
        primary_value="https://app.example.com/",
    )
    session.add_all([scope, target])
    await session.flush()
    _, _, terms, content_hash = render_current_roe(eng, [scope])
    ack = ROEAcknowledgement(
        engagement_id=eng.id,
        accepted_by=user_id,
        accepted_at=NOW - timedelta(hours=1),
        roe_text="frozen",
        scope_snapshot=[],
        terms_snapshot=terms,
        content_hash=content_hash,
    )
    session.add(ack)
    await session.flush()
    return eng, target, ack


async def _audit_actions(session, scan_id) -> list[tuple[str, AuditOutcome]]:
    rows = (
        await session.execute(
            select(AuditEvent.action, AuditEvent.outcome).where(AuditEvent.object_id == scan_id)
        )
    ).all()
    return [(r[0], r[1]) for r in rows]


async def main() -> int:  # noqa: C901, PLR0915 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    owner = StubOwner()
    org_id = None

    async with sm() as s:
        org = Organization(name="verify-scans-org")
        s.add(org)
        await s.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-scans@example.com",
            password_hash=pw.hash("verify-scans-throwaway"),
            display_name="Verify Scans",
        )
        s.add(user)
        await s.flush()
        user_id = user.id
        await s.commit()

    safe_op = lambda tid: Operation(target_id=tid, kind=OperationKind.SAFE_ACTIVE_SCAN)  # noqa: E731
    hr_op = lambda tid: Operation(target_id=tid, kind=OperationKind.EXPLOIT_VALIDATION)  # noqa: E731

    # (a) happy SAFE_ACTIVE → completed
    async with sm() as s:
        eng, target, ack = await _seed_engagement(s, org_id=org_id, user_id=user_id)
        scope_items = list(
            (await s.execute(select(ScopeItem).where(ScopeItem.engagement_id == eng.id))).scalars()
        )
        scan = await launch_scan(
            s,
            engagement=eng,
            target=target,
            scope_items=scope_items,
            op=safe_op(target.id),
            roe_ack=ack,
            initiated_by=user_id,
            now=NOW,
            config={"suites": ["prompt_injection"]},
        )
        await s.commit()
        happy_id = scan.id
    status = await orchestrate_scan(sm, scan_id=happy_id, owner=owner, now=NOW)
    check("happy: scan completed", status is ScanStatus.COMPLETED)
    async with sm() as s:
        row = await s.get(Scan, happy_id)
        env = (
            await s.execute(
                select(ExecutionAuthorization).where(ExecutionAuthorization.scan_id == happy_id)
            )
        ).scalar_one()
        check("happy: runner_ref recorded", row.runner_ref == f"stub:{happy_id}")
        check("happy: heartbeat set", row.last_heartbeat_at is not None)
        check(
            "happy: envelope digest matches keystone",
            env.operation_digest
            == compute_operation_digest(
                row.engagement_id, safe_op(row.target_id), ScanIntensity.SAFE_ACTIVE
            ),
        )
        actions = await _audit_actions(s, happy_id)
        check(
            "happy: start + complete audited",
            ("scan.started", AuditOutcome.SUCCESS) in actions
            and ("scan.completed", AuditOutcome.SUCCESS) in actions,
        )

    # (b) scope drift after launch → refuse (roe_stale)
    async with sm() as s:
        eng, target, ack = await _seed_engagement(s, org_id=org_id, user_id=user_id)
        scope_items = list(
            (await s.execute(select(ScopeItem).where(ScopeItem.engagement_id == eng.id))).scalars()
        )
        scan = await launch_scan(
            s,
            engagement=eng,
            target=target,
            scope_items=scope_items,
            op=safe_op(target.id),
            roe_ack=ack,
            initiated_by=user_id,
            now=NOW,
        )
        await s.commit()
        drift_id = scan.id
        eng_id_drift = eng.id
    async with sm() as s:  # mutate scope after authorization
        s.add(
            ScopeItem(
                engagement_id=eng_id_drift,
                kind=ScopeKind.DENY,
                matcher_type=ScopeMatcher.DOMAIN,
                value="evil.example.com",
            )
        )
        await s.commit()
    status = await orchestrate_scan(sm, scan_id=drift_id, owner=owner, now=NOW)
    check("drift: scan refused (failed)", status is ScanStatus.FAILED)
    async with sm() as s:
        row = await s.get(Scan, drift_id)
        check(
            "drift: error records refusal",
            (row.error_summary or "").startswith("refused: roe_stale"),
        )
        check("drift: never launched (no runner_ref)", row.runner_ref is None)
        actions = await _audit_actions(s, drift_id)
        check("drift: refusal audited blocked", ("scan.refused", AuditOutcome.BLOCKED) in actions)

    # (c) pre-launch cancel → cancelled, owner never launches
    async with sm() as s:
        eng, target, ack = await _seed_engagement(s, org_id=org_id, user_id=user_id)
        scope_items = list(
            (await s.execute(select(ScopeItem).where(ScopeItem.engagement_id == eng.id))).scalars()
        )
        scan = await launch_scan(
            s,
            engagement=eng,
            target=target,
            scope_items=scope_items,
            op=safe_op(target.id),
            roe_ack=ack,
            initiated_by=user_id,
            now=NOW,
        )
        await s.commit()
        cancel_id = scan.id
    async with sm() as s:
        (await s.get(Scan, cancel_id)).cancel_requested = True
        await s.commit()
    spy = _SpyOwner()
    status = await orchestrate_scan(sm, scan_id=cancel_id, owner=spy, now=NOW)
    check("cancel: scan cancelled", status is ScanStatus.CANCELLED)
    check("cancel: owner never launched", spy.launched is False)
    async with sm() as s:
        check("cancel: no runner_ref", (await s.get(Scan, cancel_id)).runner_ref is None)

    # (d) high-risk happy → completed + approval consumed
    async with sm() as s:
        eng, target, ack = await _seed_engagement(
            s, org_id=org_id, user_id=user_id, max_intensity=ScanIntensity.HIGH_RISK
        )
        digest = compute_operation_digest(eng.id, hr_op(target.id), ScanIntensity.HIGH_RISK)
        approval = ApprovalGate(
            engagement_id=eng.id,
            target_id=target.id,
            requested_by=user_id,
            action_type="exploit_validation",
            justification="ok",
            operation_digest=digest,
            roe_ack_id=ack.id,
            policy_version=ACTIVE_POLICY_VERSION,
            status=ApprovalStatus.APPROVED,
            decided_by=user_id,
            decided_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(hours=1),
        )
        s.add(approval)
        await s.flush()
        scope_items = list(
            (await s.execute(select(ScopeItem).where(ScopeItem.engagement_id == eng.id))).scalars()
        )
        scan = await launch_scan(
            s,
            engagement=eng,
            target=target,
            scope_items=scope_items,
            op=hr_op(target.id),
            roe_ack=ack,
            initiated_by=user_id,
            now=NOW,
            approval=approval,
        )
        await s.commit()
        hr_id = scan.id
        approval_id = approval.id
    status = await orchestrate_scan(sm, scan_id=hr_id, owner=owner, now=NOW)
    check("high-risk: scan completed", status is ScanStatus.COMPLETED)
    async with sm() as s:
        appr = await s.get(ApprovalGate, approval_id)
        check("high-risk: approval consumed", appr.status is ApprovalStatus.CONSUMED)
        check("high-risk: approval bound to scan", appr.consumed_by_scan_id == hr_id)

    # (e) high-risk with approval revoked after launch → refuse
    async with sm() as s:
        eng, target, ack = await _seed_engagement(
            s, org_id=org_id, user_id=user_id, max_intensity=ScanIntensity.HIGH_RISK
        )
        digest = compute_operation_digest(eng.id, hr_op(target.id), ScanIntensity.HIGH_RISK)
        approval = ApprovalGate(
            engagement_id=eng.id,
            target_id=target.id,
            requested_by=user_id,
            action_type="exploit_validation",
            justification="ok",
            operation_digest=digest,
            roe_ack_id=ack.id,
            policy_version=ACTIVE_POLICY_VERSION,
            status=ApprovalStatus.APPROVED,
            decided_by=user_id,
            decided_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(hours=1),
        )
        s.add(approval)
        await s.flush()
        scope_items = list(
            (await s.execute(select(ScopeItem).where(ScopeItem.engagement_id == eng.id))).scalars()
        )
        scan = await launch_scan(
            s,
            engagement=eng,
            target=target,
            scope_items=scope_items,
            op=hr_op(target.id),
            roe_ack=ack,
            initiated_by=user_id,
            now=NOW,
            approval=approval,
        )
        await s.commit()
        hr_bad_id = scan.id
        revoke_id = approval.id
    async with sm() as s:
        appr = await s.get(ApprovalGate, revoke_id)
        appr.revoked_at = NOW
        await s.commit()
    status = await orchestrate_scan(sm, scan_id=hr_bad_id, owner=owner, now=NOW)
    check("high-risk revoked: scan refused", status is ScanStatus.FAILED)
    async with sm() as s:
        row = await s.get(Scan, hr_bad_id)
        check(
            "high-risk revoked: reason recorded",
            (row.error_summary or "").startswith("refused: high_risk_not_approved"),
        )

    # cleanup (insert-only tables → dev-superuser trigger bypass)
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        await conn.execute(
            delete(ExecutionAuthorization).where(
                ExecutionAuthorization.engagement_id.in_(
                    select(Engagement.id).where(Engagement.organization_id == org_id)
                )
            )
        )
        await conn.execute(
            delete(Scan).where(
                Scan.engagement_id.in_(
                    select(Engagement.id).where(Engagement.organization_id == org_id)
                )
            )
        )
        await conn.execute(
            delete(ApprovalGate).where(
                ApprovalGate.engagement_id.in_(
                    select(Engagement.id).where(Engagement.organization_id == org_id)
                )
            )
        )
        await conn.execute(
            delete(ROEAcknowledgement).where(
                ROEAcknowledgement.engagement_id.in_(
                    select(Engagement.id).where(Engagement.organization_id == org_id)
                )
            )
        )
        await conn.execute(
            delete(ScopeItem).where(
                ScopeItem.engagement_id.in_(
                    select(Engagement.id).where(Engagement.organization_id == org_id)
                )
            )
        )
        await conn.execute(
            delete(Target).where(
                Target.engagement_id.in_(
                    select(Engagement.id).where(Engagement.organization_id == org_id)
                )
            )
        )
        await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
