"""Target inventory CRUD (M1-B10) — nested under an engagement.

Mutations require MANAGE_ENGAGEMENTS; reads require VIEW. Engagement- and
org-scoped (cross-org/engagement → 404, no IDOR leak). auth_config is validated
to hold credential references only (TR-23). target_type is immutable after
create (it fixes how primary_value is validated and matched). Mutations are
audited; findings_by_severity is a computed rollup, empty at M1.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.deps import Capability, Principal, get_audit_service, get_db, require
from app.models.engagement import ScopeMatcher
from app.models.target import Target, TargetType
from app.schemas.targets import TargetCreate, TargetOut, TargetUpdate
from app.services.engagements import get_org_engagement
from app.services.scope_matchers import validate_matcher
from app.services.targets import get_org_target

router = APIRouter(prefix="/engagements/{engagement_id}/targets", tags=["targets"])

_URL_TYPES = {
    TargetType.WEB_APP,
    TargetType.REST_API,
    TargetType.GRAPHQL_API,
    TargetType.AI_CHATBOT,
    TargetType.LLM_API_WRAPPER,
    TargetType.AI_AGENT,
}


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _revalidate_primary_value(target_type: TargetType, value: str) -> str:
    if target_type in _URL_TYPES:
        return validate_matcher(ScopeMatcher.URL, value)
    if target_type == TargetType.SOURCE_REPO:
        return validate_matcher(ScopeMatcher.REPO, value)
    return value


async def _require_engagement(
    db: AsyncSession, engagement_id: uuid.UUID, org_id: uuid.UUID
) -> None:
    if await get_org_engagement(db, engagement_id, org_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")


async def _require_target(
    db: AsyncSession, engagement_id: uuid.UUID, target_id: uuid.UUID, org_id: uuid.UUID
) -> Target:
    target = await get_org_target(db, engagement_id, target_id, org_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    return target


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
async def create_target(
    engagement_id: uuid.UUID,
    body: TargetCreate,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> TargetOut:
    await _require_engagement(db, engagement_id, principal.organization_id)
    target = Target(
        engagement_id=engagement_id,
        name=body.name,
        target_type=body.target_type,
        environment=body.environment,
        primary_value=body.primary_value,
        auth_status=body.auth_status,
        auth_config=body.auth_config,
    )
    db.add(target)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="target.created",
        object_type="target",
        object_id=target.id,
        engagement_id=engagement_id,
        detail={"target_type": target.target_type.value, "name": target.name},
        ip_address=_client_ip(request),
    )
    await db.refresh(target)
    return TargetOut.from_model(target)


@router.get("", response_model=list[TargetOut])
async def list_targets(
    engagement_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[TargetOut]:
    await _require_engagement(db, engagement_id, principal.organization_id)
    result = await db.execute(
        select(Target)
        .where(Target.engagement_id == engagement_id, Target.deleted_at.is_(None))
        .order_by(Target.created_at)
    )
    return [TargetOut.from_model(t) for t in result.scalars().all()]


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(
    engagement_id: uuid.UUID,
    target_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    target = await _require_target(db, engagement_id, target_id, principal.organization_id)
    return TargetOut.from_model(target)


@router.patch("/{target_id}", response_model=TargetOut)
async def update_target(
    engagement_id: uuid.UUID,
    target_id: uuid.UUID,
    body: TargetUpdate,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> TargetOut:
    target = await _require_target(db, engagement_id, target_id, principal.organization_id)
    changes = body.model_dump(exclude_unset=True)
    if "primary_value" in changes:
        changes["primary_value"] = _revalidate_primary_value(
            target.target_type, changes["primary_value"]
        )
    for field, value in changes.items():
        setattr(target, field, value)
    target.updated_at = datetime.now(target.created_at.tzinfo)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="target.updated",
        object_type="target",
        object_id=target.id,
        engagement_id=engagement_id,
        detail={"fields": sorted(changes)},
        ip_address=_client_ip(request),
    )
    await db.refresh(target)
    return TargetOut.from_model(target)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    engagement_id: uuid.UUID,
    target_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> None:
    target = await _require_target(db, engagement_id, target_id, principal.organization_id)
    target.deleted_at = datetime.now(target.created_at.tzinfo)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="target.deleted",
        object_type="target",
        object_id=target.id,
        engagement_id=engagement_id,
        ip_address=_client_ip(request),
    )
