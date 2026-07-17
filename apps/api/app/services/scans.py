"""Scan launch (M2-W1): authorize → create scan → freeze the envelope.

The launch path is where the scope gate runs and its result is frozen into the
immutable `execution_authorizations` row (TR-9.1). The worker later re-reads
that envelope, re-derives every field from the live DB, and refuses on any
divergence (`app/workers/orchestration.py`) — so the envelope is the
reconstructable authorization the ID-only job cannot carry.

No HTTP endpoint here yet (that arrives with the LLM target connector / launcher,
M2-B6/F1). `launch_scan` raises the scope keystone's typed `ScopeError` when the
operation is not authorized; the caller audits and surfaces it.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.dialects.postgresql import Range
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.scope import Operation, authorize_operation
from app.models.engagement import (
    ApprovalGate,
    Engagement,
    ROEAcknowledgement,
    ScopeItem,
)
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus
from app.models.target import Target
from app.services.approvals import ACTIVE_POLICY_VERSION


def _window_range(engagement: Engagement) -> Range | None:
    """Freeze the engagement's authorized window into the envelope (inclusive
    bounds). NULL when the engagement has no window set."""
    if engagement.test_window_start is None or engagement.test_window_end is None:
        return None
    return Range(engagement.test_window_start, engagement.test_window_end, bounds="[]")


async def launch_scan(
    db: AsyncSession,
    *,
    engagement: Engagement,
    target: Target,
    scope_items: list[ScopeItem],
    op: Operation,
    roe_ack: ROEAcknowledgement | None,
    initiated_by: uuid.UUID,
    now: datetime,
    approval: ApprovalGate | None = None,
    config: dict[str, Any] | None = None,
    policy_version: str = ACTIVE_POLICY_VERSION,
) -> Scan:
    """Authorize the operation, create the queued scan, and write its immutable
    execution envelope. Returns the flushed (not committed) scan so it commits
    atomically with the caller's transaction; the caller enqueues the worker
    after commit. Raises ScopeError if the operation is not authorized."""
    auth = authorize_operation(
        engagement=engagement,
        target=target,
        scope_items=scope_items,
        op=op,
        roe_ack=roe_ack,
        now=now,
        approval=approval,
        policy_version=policy_version,
    )

    scan = Scan(
        engagement_id=engagement.id,
        target_id=target.id,
        intensity=auth.effective_intensity,
        status=ScanStatus.QUEUED,
        approval_gate_id=auth.approval_id,
        initiated_by=initiated_by,
    )
    db.add(scan)
    await db.flush()

    # normalized_config carries the OperationKind so the worker can reconstruct
    # the Operation for re-derivation. Redacted by contract: callers pass only
    # typed, non-secret config (targets hold auth *references*, not secrets).
    normalized_config: dict[str, Any] = {
        **(config or {}),
        "kind": op.kind.value,
        "target_id": str(target.id),
    }
    envelope = ExecutionAuthorization(
        scan_id=scan.id,
        engagement_id=engagement.id,
        target_id=target.id,
        requested_by=initiated_by,
        effective_intensity=auth.effective_intensity,
        normalized_config=normalized_config,
        server_capabilities={
            "effective_intensity": auth.effective_intensity.value,
            "policy_version": policy_version,
        },
        roe_ack_id=auth.roe_ack_id,
        policy_version=policy_version,
        approval_gate_id=auth.approval_id,
        operation_digest=auth.operation_digest,
        test_window=_window_range(engagement),
    )
    db.add(envelope)
    await db.flush()
    return scan
