"""Approval-gate endpoints (M1-B11) — nested under an engagement.

request (LAUNCH_SCANS: Admin/Tester) → decide (APPROVE_HIGH_RISK: Admin/
Reviewer) → revoke (APPROVE_HIGH_RISK). All org/engagement-scoped (cross-org →
404). A request requires a CURRENT accepted ROE and a high-risk operation kind.
Illegal transitions → 409. Every transition is audited. Consumption is not an
endpoint — it is the worker's atomic single-use claim (services.approvals).
"""

import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.deps import Capability, Principal, get_audit_service, get_db, require
from app.core.scope import Operation
from app.core.sessions import utcnow
from app.models.engagement import ApprovalGate, ROEAcknowledgement, ScopeItem
from app.schemas.approvals import ApprovalDecision, ApprovalOut, ApprovalRequest, ApprovalRevoke
from app.services.approvals import (
    ApprovalStateError,
    decide_approval,
    request_approval,
    revoke_approval,
)
from app.services.engagements import get_org_engagement
from app.services.roe import render_current_roe
from app.services.targets import get_org_target

router = APIRouter(prefix="/engagements/{engagement_id}/approvals", tags=["approvals"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def _current_roe_ack(
    db: AsyncSession, engagement, engagement_id: uuid.UUID
) -> ROEAcknowledgement | None:
    """Latest ROE ack IFF it still matches the engagement's current scope/terms."""
    items = list(
        (await db.execute(select(ScopeItem).where(ScopeItem.engagement_id == engagement_id)))
        .scalars()
        .all()
    )
    _, _, _, current_hash = render_current_roe(engagement, items)
    latest = (
        await db.execute(
            select(ROEAcknowledgement)
            .where(ROEAcknowledgement.engagement_id == engagement_id)
            .order_by(ROEAcknowledgement.accepted_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if latest is not None and latest.content_hash == current_hash:
        return latest
    return None


async def _require_approval(
    db: AsyncSession, engagement_id: uuid.UUID, approval_id: uuid.UUID, org_id: uuid.UUID
) -> ApprovalGate:
    gate = (
        await db.execute(
            select(ApprovalGate)
            .join(ApprovalGate.engagement)
            .where(
                ApprovalGate.id == approval_id,
                ApprovalGate.engagement_id == engagement_id,
                ApprovalGate.engagement.has(organization_id=org_id),
            )
        )
    ).scalar_one_or_none()
    if gate is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="approval not found")
    return gate


@router.post("", response_model=ApprovalOut, status_code=status.HTTP_201_CREATED)
async def request_gate(
    engagement_id: uuid.UUID,
    body: ApprovalRequest,
    request: Request,
    principal: Principal = Depends(require(Capability.LAUNCH_SCANS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> ApprovalOut:
    engagement = await get_org_engagement(db, engagement_id, principal.organization_id)
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    target = await get_org_target(db, engagement_id, body.target_id, principal.organization_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    roe_ack = await _current_roe_ack(db, engagement, engagement_id)
    if roe_ack is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a current accepted ROE is required before requesting an approval",
        )

    now = utcnow()
    op = Operation(target_id=target.id, kind=body.operation_kind)
    try:
        gate = await request_approval(
            db,
            engagement=engagement,
            target=target,
            op=op,
            roe_ack=roe_ack,
            requested_by=principal.user_id,
            justification=body.justification,
            expires_at=now + timedelta(hours=body.expires_in_hours),
        )
    except ApprovalStateError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="approval.requested",
        object_type="approval_gate",
        object_id=gate.id,
        engagement_id=engagement_id,
        detail={"target_id": str(target.id), "action_type": gate.action_type},
        ip_address=_client_ip(request),
    )
    await db.refresh(gate)
    return ApprovalOut.from_model(gate)


@router.post("/{approval_id}/decide", response_model=ApprovalOut)
async def decide_gate(
    engagement_id: uuid.UUID,
    approval_id: uuid.UUID,
    body: ApprovalDecision,
    request: Request,
    principal: Principal = Depends(require(Capability.APPROVE_HIGH_RISK)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> ApprovalOut:
    gate = await _require_approval(db, engagement_id, approval_id, principal.organization_id)
    try:
        decide_approval(
            gate,
            decided_by=principal.user_id,
            approve=body.approve,
            reason=body.reason,
            now=utcnow(),
        )
    except ApprovalStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="approval.approved" if body.approve else "approval.denied",
        object_type="approval_gate",
        object_id=gate.id,
        engagement_id=engagement_id,
        detail={"reason": body.reason},
        ip_address=_client_ip(request),
    )
    await db.refresh(gate)
    return ApprovalOut.from_model(gate)


@router.post("/{approval_id}/revoke", response_model=ApprovalOut)
async def revoke_gate(
    engagement_id: uuid.UUID,
    approval_id: uuid.UUID,
    body: ApprovalRevoke,
    request: Request,
    principal: Principal = Depends(require(Capability.APPROVE_HIGH_RISK)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> ApprovalOut:
    gate = await _require_approval(db, engagement_id, approval_id, principal.organization_id)
    try:
        revoke_approval(gate, revoked_by=principal.user_id, reason=body.reason, now=utcnow())
    except ApprovalStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="approval.revoked",
        object_type="approval_gate",
        object_id=gate.id,
        engagement_id=engagement_id,
        detail={"reason": body.reason},
        ip_address=_client_ip(request),
    )
    await db.refresh(gate)
    return ApprovalOut.from_model(gate)


@router.get("", response_model=list[ApprovalOut])
async def list_gates(
    engagement_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[ApprovalOut]:
    if await get_org_engagement(db, engagement_id, principal.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    result = await db.execute(
        select(ApprovalGate)
        .where(ApprovalGate.engagement_id == engagement_id)
        .order_by(ApprovalGate.created_at.desc())
    )
    return [ApprovalOut.from_model(g) for g in result.scalars().all()]


@router.get("/{approval_id}", response_model=ApprovalOut)
async def get_gate(
    engagement_id: uuid.UUID,
    approval_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> ApprovalOut:
    gate = await _require_approval(db, engagement_id, approval_id, principal.organization_id)
    return ApprovalOut.from_model(gate)
