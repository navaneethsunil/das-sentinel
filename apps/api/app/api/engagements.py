"""Engagement CRUD + status transitions (M1-B6).

Create/edit/status require MANAGE_ENGAGEMENTS (Admin/Tester); reads require
VIEW (all roles). Every row is org-scoped — another org's engagement is 404,
never data (IDOR/BOLA, M1-SEC1). State changes go through the draft→active→
paused→closed machine (services.engagements). Domain audit events are written
transactionally alongside each mutation (in addition to the middleware net).
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.deps import (
    Capability,
    Principal,
    get_audit_service,
    get_db,
    require,
)
from app.models.audit import AuditOutcome
from app.models.engagement import Engagement
from app.schemas.engagements import (
    EngagementCreate,
    EngagementOut,
    EngagementUpdate,
    StatusChange,
    _check_window,
)
from app.services.engagements import can_transition

router = APIRouter(prefix="/engagements", tags=["engagements"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def _get_org_engagement(
    db: AsyncSession, engagement_id: uuid.UUID, org_id: uuid.UUID
) -> Engagement:
    engagement = (
        await db.execute(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.organization_id == org_id,
                Engagement.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    return engagement


@router.post("", response_model=EngagementOut, status_code=status.HTTP_201_CREATED)
async def create_engagement(
    body: EngagementCreate,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> Engagement:
    engagement = Engagement(
        organization_id=principal.organization_id,
        created_by=principal.user_id,
        name=body.name,
        client_system_name=body.client_system_name,
        test_window_start=body.test_window_start,
        test_window_end=body.test_window_end,
        rate_limit_rps=body.rate_limit_rps,
        max_intensity=body.max_intensity,
        hosted_models_allowed=body.hosted_models_allowed,
        coordination_contact=body.coordination_contact,
        emergency_stop_contact=body.emergency_stop_contact,
    )
    db.add(engagement)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="engagement.created",
        object_type="engagement",
        object_id=engagement.id,
        engagement_id=engagement.id,
        detail={"name": engagement.name},
        ip_address=_client_ip(request),
    )
    await db.refresh(engagement)
    return engagement


@router.get("", response_model=list[EngagementOut])
async def list_engagements(
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[Engagement]:
    result = await db.execute(
        select(Engagement)
        .where(
            Engagement.organization_id == principal.organization_id,
            Engagement.deleted_at.is_(None),
        )
        .order_by(Engagement.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{engagement_id}", response_model=EngagementOut)
async def get_engagement(
    engagement_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> Engagement:
    return await _get_org_engagement(db, engagement_id, principal.organization_id)


@router.patch("/{engagement_id}", response_model=EngagementOut)
async def update_engagement(
    engagement_id: uuid.UUID,
    body: EngagementUpdate,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> Engagement:
    engagement = await _get_org_engagement(db, engagement_id, principal.organization_id)
    changes = body.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(engagement, field, value)
    # Validate the resulting window (a PATCH may set only one side).
    _check_window(engagement.test_window_start, engagement.test_window_end)
    engagement.updated_at = datetime.now(engagement.created_at.tzinfo)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="engagement.updated",
        object_type="engagement",
        object_id=engagement.id,
        engagement_id=engagement.id,
        detail={"fields": sorted(changes)},
        ip_address=_client_ip(request),
    )
    await db.refresh(engagement)
    return engagement


@router.post("/{engagement_id}/status", response_model=EngagementOut)
async def change_status(
    engagement_id: uuid.UUID,
    body: StatusChange,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> Engagement:
    engagement = await _get_org_engagement(db, engagement_id, principal.organization_id)
    previous = engagement.status
    if body.status != previous and not can_transition(previous, body.status):
        # Audit the rejected transition, then refuse (409).
        await audit.log(
            organization_id=principal.organization_id,
            actor_user_id=principal.user_id,
            action="engagement.status_change_rejected",
            object_type="engagement",
            object_id=engagement.id,
            engagement_id=engagement.id,
            outcome=AuditOutcome.BLOCKED,
            detail={"from": previous.value, "to": body.status.value},
            ip_address=_client_ip(request),
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"cannot transition engagement from {previous.value} to {body.status.value}",
        )
    engagement.status = body.status
    engagement.updated_at = datetime.now(engagement.created_at.tzinfo)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="engagement.status_changed",
        object_type="engagement",
        object_id=engagement.id,
        engagement_id=engagement.id,
        detail={"from": previous.value, "to": body.status.value},
        ip_address=_client_ip(request),
    )
    await db.refresh(engagement)
    return engagement


@router.delete("/{engagement_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_engagement(
    engagement_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> None:
    engagement = await _get_org_engagement(db, engagement_id, principal.organization_id)
    engagement.deleted_at = datetime.now(engagement.created_at.tzinfo)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="engagement.deleted",
        object_type="engagement",
        object_id=engagement.id,
        engagement_id=engagement.id,
        ip_address=_client_ip(request),
    )
