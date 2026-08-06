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

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import Range
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.scope import (
    Operation,
    Resolver,
    assert_resolved_ip_in_scope,
    authorize_operation,
    best_effort_resolver,
)
from app.models.engagement import (
    ApprovalGate,
    Engagement,
    ROEAcknowledgement,
    ScopeItem,
)
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus
from app.models.target import Target
from app.services.approvals import ACTIVE_POLICY_VERSION

# A scan is only stoppable while it is still queued or running; once terminal
# there is nothing to halt.
_ACTIVE_STATUSES = frozenset({ScanStatus.QUEUED, ScanStatus.RUNNING})


class ScanNotCancellableError(Exception):
    """Emergency stop was requested on a scan that has already finished."""


def _system_resolver() -> Resolver:
    """The real DNS resolver, imported lazily so this module stays free of the
    connector graph (and importable in the API process without it)."""
    from app.connectors import system_dns_resolver

    return system_dns_resolver


class ScanConcurrencyError(Exception):
    """Launch refused because an active-scan cap is already reached (abuse
    amplifier throttle, IMPLEMENTATION_PLAN §9 item 5). Router maps to 429."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


async def _count_active(
    db: AsyncSession, *, engagement_id: uuid.UUID | None, org_id: uuid.UUID
) -> int:
    q = select(func.count()).select_from(Scan).where(Scan.status.in_(_ACTIVE_STATUSES))
    if engagement_id is not None:
        q = q.where(Scan.engagement_id == engagement_id)
    else:
        q = q.join(Engagement, Scan.engagement_id == Engagement.id).where(
            Engagement.organization_id == org_id
        )
    return (await db.execute(q)).scalar_one()


async def _enforce_scan_concurrency(
    db: AsyncSession, engagement: Engagement, settings: Settings
) -> None:
    """Fail-closed active-scan caps. An org-scoped advisory xact lock serializes
    concurrent launches so the count→insert can't race past the cap."""
    per_eng = settings.max_concurrent_scans_per_engagement
    per_org = settings.max_concurrent_scans_per_org
    if per_eng <= 0 and per_org <= 0:
        return
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:k)::bigint)"),
        {"k": str(engagement.organization_id)},
    )
    if per_eng > 0:
        n = await _count_active(db, engagement_id=engagement.id, org_id=engagement.organization_id)
        if n >= per_eng:
            raise ScanConcurrencyError(f"engagement already has {n} active scans (max {per_eng})")
    if per_org > 0:
        n = await _count_active(db, engagement_id=None, org_id=engagement.organization_id)
        if n >= per_org:
            raise ScanConcurrencyError(f"organization already has {n} active scans (max {per_org})")


async def get_org_scan(
    db: AsyncSession, engagement_id: uuid.UUID, scan_id: uuid.UUID, org_id: uuid.UUID
) -> Scan | None:
    """Fetch a scan within an engagement that belongs to the caller's org, or
    None (router maps to 404 — no cross-org/cross-engagement leak)."""
    return (
        await db.execute(
            select(Scan)
            .join(Engagement, Scan.engagement_id == Engagement.id)
            .where(
                Scan.id == scan_id,
                Scan.engagement_id == engagement_id,
                Engagement.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()


async def request_scan_cancellation(db: AsyncSession, scan: Scan) -> bool:
    """Signal path for emergency stop (§2.10, M2-W2): set `cancel_requested` so
    the worker halts the run at its next poll (`supervise_run`). Returns True if
    this call flipped the flag, False if it was already set (idempotent —
    repeated stop requests are safe). Raises `ScanNotCancellableError` for a
    scan that has already finished."""
    if scan.status not in _ACTIVE_STATUSES:
        raise ScanNotCancellableError(f"scan is {scan.status.value}, not cancellable")
    already = scan.cancel_requested
    scan.cancel_requested = True
    await db.flush()
    return not already


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
    settings: Settings | None = None,
    resolve: Resolver | None = None,
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
    # Resolved-IP gate (TM-1): an allow rule naming a host or literal address must
    # never be enough to aim a tool at loopback, link-local/cloud-metadata, or
    # RFC-1918 space — only an explicit ip_cidr allow can authorize those. Runs on
    # EVERY launch, suite or scanner: the scanner path has no connector to gate it
    # later, so without this a scope entry for 169.254.169.254 would start a real
    # DAST run against the metadata service. Raises SSRFBlocked (a ScopeError), so
    # the caller's existing handler audits it and answers 403 ssrf_ip_blocked.
    assert_resolved_ip_in_scope(
        target,
        scope_items,
        resolve=best_effort_resolver(resolve or _system_resolver()),
    )

    await _enforce_scan_concurrency(db, engagement, settings or get_settings())

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
