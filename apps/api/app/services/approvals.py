"""Approval-gate state machine (M1-B11) — DATABASE_SCHEMA §4, CLAUDE.md §2.4.

High-risk actions need an approval bound to ONE exact operation. Lifecycle:
    pending → approved → consumed        (the happy path)
            → denied / expired / revoked (terminal dead ends)

request() computes and stores the operation_digest (the same one the scope
keystone recomputes and requires equality against), binds the target, snapshots
the ROE acknowledgement + policy version, and sets a mandatory expiry. Approval
is SINGLE-USE: consume_approval is an atomic conditional UPDATE whose affected-
row count is checked — 0 rows means already used/expired/revoked, so the scan is
refused (the reuse guard). Transitions raise ApprovalStateError on an illegal
move; callers audit every transition.
"""

import uuid
from datetime import datetime

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.scope import Operation, compute_operation_digest, derive_effective_intensity
from app.models.engagement import (
    ApprovalGate,
    ApprovalStatus,
    Engagement,
    ROEAcknowledgement,
    ScanIntensity,
)
from app.models.target import Target

# Placeholder for the versioned authorization ruleset (a real policy engine is
# post-MVP). Snapshotted at request time; the keystone compares against it.
ACTIVE_POLICY_VERSION = "1"


class ApprovalStateError(Exception):
    """An illegal state-machine transition; the router maps this to 409."""


async def request_approval(
    db: AsyncSession,
    *,
    engagement: Engagement,
    target: Target,
    op: Operation,
    roe_ack: ROEAcknowledgement,
    requested_by: uuid.UUID,
    justification: str,
    expires_at: datetime,
    policy_version: str = ACTIVE_POLICY_VERSION,
) -> ApprovalGate:
    if derive_effective_intensity(op) != ScanIntensity.HIGH_RISK:
        raise ApprovalStateError("approval applies only to high-risk operations")
    digest = compute_operation_digest(engagement.id, op, ScanIntensity.HIGH_RISK)
    gate = ApprovalGate(
        engagement_id=engagement.id,
        target_id=target.id,
        requested_by=requested_by,
        action_type=op.kind.value,
        justification=justification,
        operation_digest=digest,
        roe_ack_id=roe_ack.id,
        policy_version=policy_version,
        status=ApprovalStatus.PENDING,
        expires_at=expires_at,
    )
    db.add(gate)
    await db.flush()
    return gate


def expire_if_due(gate: ApprovalGate, now: datetime) -> bool:
    """Auto-transition a pending/approved gate to expired once past its expiry.
    Idempotent; returns True if it flipped."""
    if gate.status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED) and now >= gate.expires_at:
        gate.status = ApprovalStatus.EXPIRED
        return True
    return False


def decide_approval(
    gate: ApprovalGate,
    *,
    decided_by: uuid.UUID,
    approve: bool,
    reason: str | None,
    now: datetime,
) -> None:
    if expire_if_due(gate, now):
        raise ApprovalStateError("approval request has expired")
    if gate.status != ApprovalStatus.PENDING:
        raise ApprovalStateError(f"cannot decide an approval in state {gate.status.value}")
    gate.status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
    gate.decided_by = decided_by
    gate.decided_at = now
    gate.decision_reason = reason


def revoke_approval(
    gate: ApprovalGate, *, revoked_by: uuid.UUID, reason: str | None, now: datetime
) -> None:
    if gate.status != ApprovalStatus.APPROVED:
        raise ApprovalStateError(f"cannot revoke an approval in state {gate.status.value}")
    gate.status = ApprovalStatus.REVOKED
    gate.revoked_at = now
    gate.revoked_by = revoked_by
    gate.revocation_reason = reason


async def consume_approval(
    db: AsyncSession, *, approval_id: uuid.UUID, scan_id: uuid.UUID, now: datetime
) -> bool:
    """Atomic single-use claim. Returns True iff this call transitioned the
    approval approved→consumed; False means it was already used/expired/revoked
    (⇒ the caller must refuse the scan). The WHERE clause + affected-row check IS
    the reuse guard — two racing scans cannot both succeed."""
    result = await db.execute(
        update(ApprovalGate)
        .where(
            ApprovalGate.id == approval_id,
            ApprovalGate.status == ApprovalStatus.APPROVED,
            ApprovalGate.expires_at > now,
            ApprovalGate.revoked_at.is_(None),
        )
        .values(
            status=ApprovalStatus.CONSUMED,
            consumed_at=now,
            consumed_by_scan_id=scan_id,
        )
    )
    await db.flush()
    return result.rowcount == 1


async def expire_all_due(db: AsyncSession, now: datetime) -> int:
    """Sweep pending/approved gates past expiry → expired (for a periodic job).
    Returns the number expired."""
    result = await db.execute(
        update(ApprovalGate)
        .where(
            ApprovalGate.status.in_([ApprovalStatus.PENDING, ApprovalStatus.APPROVED]),
            ApprovalGate.expires_at <= now,
        )
        .values(status=ApprovalStatus.EXPIRED)
    )
    await db.flush()
    return result.rowcount
