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

import asyncio
import contextlib
import shutil
import uuid
from collections.abc import Callable
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
from app.core.sessions import utcnow
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
from app.workers.execution import CancelToken, ExecutionOwner, RunHandle, RunSpec

# Default worker poll cadence for scans.cancel_requested (overridden from
# Settings by the Celery task). See config.scan_cancel_poll_seconds.
_DEFAULT_CANCEL_POLL_S = 2.0

# Absolute path to a no-op binary — the MVP placeholder payload. Real run specs
# (PyRIT suites, scanners) are built from the envelope's suite config at M2-B3/M3;
# until then the orchestrator still exercises the real execution owner end to end.
_NOOP_BIN = shutil.which("true") or "/bin/true"


class OrchestrationError(Exception):
    """A precondition the worker cannot proceed past (missing scan/envelope)."""


def _placeholder_run_spec(scan_id: uuid.UUID) -> RunSpec:
    """A no-op run spec: proves the launch/await/teardown path through the owner
    with an empty (secret-free) env. Replaced by real suite specs at M2-B3."""
    return RunSpec(label=str(scan_id), argv=[_NOOP_BIN], env={})


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


@dataclass(frozen=True)
class _RunResult:
    status: ScanStatus  # COMPLETED | FAILED | CANCELLED
    detail: str | None = None


async def signal_cancellation(owner: ExecutionOwner, handle: RunHandle, token: CancelToken) -> None:
    """The uniform emergency-stop action for one run (§2.10, M2-W2).

    Both halt paths fire so a run stops regardless of how it executes:
      - `token.cancel()` trips the cooperative CancelToken an *in-process* suite
        checks between prompts/turns (PyRIT is an embedded library with no
        subprocess, so `killpg` cannot select it — M2-B3 runs it under this
        token).
      - `owner.cancel(handle)` terminates the owner's process tree
        (SIGTERM→SIGKILL and confirms the tree is gone — SubprocessOwner).
    """
    token.cancel()
    await owner.cancel(handle)


async def _poll_cancel_and_beat(
    sessionmaker: async_sessionmaker[AsyncSession],
    scan_id: uuid.UUID,
    clock: Callable[[], datetime],
) -> bool:
    """Re-read scans.cancel_requested on a fresh session and beat the heartbeat.
    Returns True iff cancellation has been requested."""
    async with sessionmaker() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            return False
        scan.last_heartbeat_at = clock()
        requested = scan.cancel_requested
        await db.commit()
        return requested


async def supervise_run(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    scan_id: uuid.UUID,
    owner: ExecutionOwner,
    handle: RunHandle,
    token: CancelToken,
    poll_s: float,
    clock: Callable[[], datetime],
) -> _RunResult:
    """Await one in-flight run while polling scans.cancel_requested between
    checks (the "heartbeat + check the cancellation flag between steps" of
    CLAUDE.md §6a / TM-12). An emergency stop requested *after* the run has
    started — while a single `await_completion` would otherwise block until the
    run ends — is caught here and halted within the poll cadence.

    The flag is checked first, so a cancel that landed in the window between the
    running-claim and this supervisor still terminates the just-launched run.
    """
    completion: asyncio.Task[object] = asyncio.ensure_future(owner.await_completion(handle))
    try:
        while True:
            if await _poll_cancel_and_beat(sessionmaker, scan_id, clock):
                await signal_cancellation(owner, handle, token)
                return _RunResult(ScanStatus.CANCELLED)
            done, _pending = await asyncio.wait({completion}, timeout=poll_s)
            if completion in done:
                outcome = completion.result()
                if outcome.ok:
                    return _RunResult(ScanStatus.COMPLETED)
                return _RunResult(ScanStatus.FAILED, outcome.detail)
    finally:
        # Reap the completion task so a cancelled/killed run leaves nothing
        # pending (await_completion returns once the process is gone).
        if not completion.done():
            completion.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await completion


async def orchestrate_scan(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    scan_id: uuid.UUID,
    owner: ExecutionOwner,
    now: datetime,
    cancel_poll_s: float = _DEFAULT_CANCEL_POLL_S,
    clock: Callable[[], datetime] = utcnow,
    run_spec: RunSpec | None = None,
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
    handle = await owner.launch(run_spec or _placeholder_run_spec(scan_id))
    async with sessionmaker() as db:
        scan = await db.get(Scan, scan_id)
        scan.runner_ref = handle.runner_ref
        scan.last_heartbeat_at = now
        await db.commit()

    # ── Phase 3: supervise (await while polling for emergency stop), finalize ──
    token = CancelToken()
    try:
        result = await supervise_run(
            sessionmaker,
            scan_id=scan_id,
            owner=owner,
            handle=handle,
            token=token,
            poll_s=cancel_poll_s,
            clock=clock,
        )
    finally:
        await owner.teardown(handle)

    _FINALIZE_ACTION = {
        ScanStatus.CANCELLED: "scan.cancelled",
        ScanStatus.COMPLETED: "scan.completed",
        ScanStatus.FAILED: "scan.failed",
    }
    async with sessionmaker() as db:
        loaded = await _load(db, scan_id)
        loaded.scan.status = result.status
        loaded.scan.finished_at = now
        loaded.scan.last_heartbeat_at = now
        if result.status is ScanStatus.FAILED:
            loaded.scan.error_summary = result.detail
        await _audit(
            db, loaded, action=_FINALIZE_ACTION[result.status], outcome=AuditOutcome.SUCCESS
        )
        await db.commit()
        return result.status
