"""Scan orchestration (M2-W1): re-derive, refuse-on-divergence, consume, run.

The worker carries only a `scan_id`. It re-reads the frozen envelope, re-derives
the authorization from the *live* DB (re-running the scope keystone), recomputes
the operation digest, and **refuses to launch on any divergence** — the envelope
cannot be trusted as authority, only as the record to reconcile against
(TR-11.5). For a high-risk scan it then **atomically consumes** the bound
approval (approved→consumed; a 0-row update means already used/expired/revoked ⇒
refuse). Only then does it claim the scan `running` and spawn the run through the
uniform execution owner (M2-W3's real sandbox replaces the stub), recording the
runner ref and heartbeating.

Every terminal transition is audited: a refusal is `outcome=blocked` with the
machine reason; start/complete/cancel are `success`. Fail-closed throughout — an
unexpected error marks the scan failed and surfaces, never silently completes.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.audit import AuditService
from app.core.scope import (
    ExecutionAuthorization as ScopeAuthorization,
)
from app.core.scope import (
    Operation,
    OperationKind,
    ScopeError,
    authorize_operation,
)
from app.models.audit import AuditOutcome
from app.models.engagement import (
    ApprovalGate,
    Engagement,
    ROEAcknowledgement,
    ScanIntensity,
    ScopeItem,
)
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus
from app.models.target import Target
from app.services.approvals import consume_approval
from app.workers.execution import ExecutionOwner


class OrchestrationError(Exception):
    """A precondition the worker cannot proceed past (missing scan/envelope)."""


@dataclass(frozen=True)
class _Loaded:
    scan: Scan
    envelope: ExecutionAuthorization
    engagement: Engagement


def divergence_reason(auth: ScopeAuthorization, envelope: ExecutionAuthorization) -> str | None:
    """Return a machine reason if the freshly-derived authorization disagrees
    with the frozen envelope on any load-bearing field, else None. Even a change
    that still *authorizes* (e.g. intensity downgraded) is a divergence: the
    worker must run exactly what was authorized, not something re-authorized."""
    if auth.operation_digest != envelope.operation_digest:
        return "operation_digest_mismatch"
    if auth.effective_intensity != envelope.effective_intensity:
        return "intensity_mismatch"
    if auth.target_id != envelope.target_id:
        return "target_mismatch"
    if auth.roe_ack_id != envelope.roe_ack_id:
        return "roe_ack_mismatch"
    if auth.approval_id != envelope.approval_gate_id:
        return "approval_mismatch"
    return None


async def _rederive(db: AsyncSession, loaded: _Loaded, now: datetime) -> ScopeAuthorization:
    """Re-run the scope keystone against live rows. Raises ScopeError on any
    authorization failure (inactive engagement, ROE drift, out-of-window,
    out-of-scope, intensity, missing approval)."""
    scan, envelope, engagement = loaded.scan, loaded.envelope, loaded.engagement
    target = await db.get(Target, scan.target_id)
    if target is None:
        raise OrchestrationError(f"target {scan.target_id} missing")
    scope_items = list(
        (
            await db.execute(select(ScopeItem).where(ScopeItem.engagement_id == engagement.id))
        ).scalars()
    )
    roe_ack = await db.get(ROEAcknowledgement, envelope.roe_ack_id)
    approval = (
        await db.get(ApprovalGate, scan.approval_gate_id)
        if scan.approval_gate_id is not None
        else None
    )
    op = Operation(target_id=scan.target_id, kind=OperationKind(envelope.normalized_config["kind"]))
    return authorize_operation(
        engagement=engagement,
        target=target,
        scope_items=scope_items,
        op=op,
        roe_ack=roe_ack,
        now=now,
        approval=approval,
        policy_version=envelope.policy_version,
    )


async def _load(db: AsyncSession, scan_id: uuid.UUID) -> _Loaded:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise OrchestrationError(f"scan {scan_id} missing")
    envelope = (
        await db.execute(
            select(ExecutionAuthorization).where(ExecutionAuthorization.scan_id == scan_id)
        )
    ).scalar_one_or_none()
    if envelope is None:
        raise OrchestrationError(f"execution envelope for scan {scan_id} missing")
    engagement = await db.get(Engagement, scan.engagement_id)
    if engagement is None:
        raise OrchestrationError(f"engagement {scan.engagement_id} missing")
    return _Loaded(scan=scan, envelope=envelope, engagement=engagement)


async def _audit(
    db: AsyncSession,
    loaded: _Loaded,
    *,
    action: str,
    outcome: AuditOutcome,
    detail: dict | None = None,
) -> None:
    await AuditService(db).log(
        organization_id=loaded.engagement.organization_id,
        action=action,
        object_type="scan",
        object_id=loaded.scan.id,
        engagement_id=loaded.scan.engagement_id,
        actor_user_id=loaded.scan.initiated_by,
        outcome=outcome,
        detail=detail,
    )


async def _refuse(db: AsyncSession, loaded: _Loaded, *, reason: str, now: datetime) -> ScanStatus:
    loaded.scan.status = ScanStatus.FAILED
    loaded.scan.finished_at = now
    loaded.scan.error_summary = f"refused: {reason}"
    await _audit(
        db, loaded, action="scan.refused", outcome=AuditOutcome.BLOCKED, detail={"reason": reason}
    )
    await db.commit()
    return ScanStatus.FAILED


async def orchestrate_scan(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    scan_id: uuid.UUID,
    owner: ExecutionOwner,
    now: datetime,
) -> ScanStatus:
    # ── Phase 1: re-derive, refuse-on-divergence, consume, claim running ──
    async with sessionmaker() as db:
        loaded = await _load(db, scan_id)
        if loaded.scan.status != ScanStatus.QUEUED:
            return loaded.scan.status  # idempotent: already claimed/finished

        if loaded.scan.cancel_requested:
            loaded.scan.status = ScanStatus.CANCELLED
            loaded.scan.finished_at = now
            await _audit(db, loaded, action="scan.cancelled", outcome=AuditOutcome.SUCCESS)
            await db.commit()
            return ScanStatus.CANCELLED

        try:
            auth = await _rederive(db, loaded, now)
        except ScopeError as exc:
            return await _refuse(db, loaded, reason=exc.reason, now=now)

        reason = divergence_reason(auth, loaded.envelope)
        if reason is not None:
            return await _refuse(db, loaded, reason=reason, now=now)

        if loaded.envelope.effective_intensity == ScanIntensity.HIGH_RISK:
            claimed = await consume_approval(
                db,
                approval_id=loaded.envelope.approval_gate_id,
                scan_id=loaded.scan.id,
                now=now,
            )
            if not claimed:
                return await _refuse(db, loaded, reason="approval_unavailable", now=now)

        loaded.scan.status = ScanStatus.RUNNING
        loaded.scan.started_at = now
        loaded.scan.last_heartbeat_at = now
        await _audit(db, loaded, action="scan.started", outcome=AuditOutcome.SUCCESS)
        await db.commit()

    # ── Phase 2: launch through the execution owner; record the runner ref ──
    handle = await owner.launch(scan_id=scan_id, envelope=loaded.envelope)
    async with sessionmaker() as db:
        scan = await db.get(Scan, scan_id)
        scan.runner_ref = handle.runner_ref
        scan.last_heartbeat_at = now
        cancel_mid_run = scan.cancel_requested
        await db.commit()

    # ── Phase 3: run (or honour a mid-run cancel), then finalize + teardown ──
    outcome_ok = True
    outcome_detail: str | None = None
    try:
        if cancel_mid_run:
            await owner.cancel(handle)
        else:
            outcome = await owner.await_completion(handle)
            outcome_ok, outcome_detail = outcome.ok, outcome.detail
    finally:
        await owner.teardown(handle)

    async with sessionmaker() as db:
        loaded = await _load(db, scan_id)
        if cancel_mid_run:
            status, action = ScanStatus.CANCELLED, "scan.cancelled"
        elif outcome_ok:
            status, action = ScanStatus.COMPLETED, "scan.completed"
        else:
            status, action = ScanStatus.FAILED, "scan.failed"
            loaded.scan.error_summary = outcome_detail
        loaded.scan.status = status
        loaded.scan.finished_at = now
        loaded.scan.last_heartbeat_at = now
        await _audit(db, loaded, action=action, outcome=AuditOutcome.SUCCESS)
        await db.commit()
        return status
