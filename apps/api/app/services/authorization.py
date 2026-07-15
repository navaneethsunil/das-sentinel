"""Audited authorization wrapper (M1-T1).

The scope keystone (core/scope.authorize_operation) is intentionally PURE — it
raises typed ScopeErrors but performs no I/O. This thin wrapper is the vehicle
that satisfies the invariant "every authorization decision is audited"
(CLAUDE.md §2.8, and the M1-B9 note): it calls the keystone and writes an audit
event either way — outcome='blocked' with the failure's machine reason on a
raise (then re-raises), outcome='success' on a grant. Both the request-time
path (scan service, M4) and the worker re-check will call this.
"""

import uuid
from datetime import datetime

from app.core.audit import AuditService
from app.core.scope import ExecutionAuthorization, Operation, ScopeError, authorize_operation
from app.models.audit import AuditOutcome
from app.models.engagement import ApprovalGate, Engagement, ROEAcknowledgement, ScopeItem
from app.models.target import Target


async def authorize_audited(
    audit: AuditService,
    *,
    actor_user_id: uuid.UUID | None,
    organization_id: uuid.UUID,
    engagement: Engagement,
    target: Target,
    scope_items: list[ScopeItem],
    op: Operation,
    roe_ack: ROEAcknowledgement | None,
    now: datetime,
    approval: ApprovalGate | None = None,
    policy_version: str | None = None,
    ip_address: str | None = None,
) -> ExecutionAuthorization:
    """Authorize an operation and audit the decision. Raises the keystone's
    ScopeError (after writing a 'blocked' event) or returns the authorization."""
    try:
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
    except ScopeError as exc:
        await audit.log(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="operation.blocked",
            object_type="operation",
            object_id=target.id,
            engagement_id=engagement.id,
            outcome=AuditOutcome.BLOCKED,
            detail={"reason": exc.reason, "operation": op.kind.value},
            ip_address=ip_address,
        )
        raise

    await audit.log(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action="operation.authorized",
        object_type="operation",
        object_id=target.id,
        engagement_id=engagement.id,
        outcome=AuditOutcome.SUCCESS,
        detail={
            "effective_intensity": auth.effective_intensity.value,
            "operation_digest": auth.operation_digest.hex(),
            "approval_id": str(auth.approval_id) if auth.approval_id else None,
        },
        ip_address=ip_address,
    )
    return auth
