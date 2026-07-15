"""Scope-item management (M1-B7) — nested under an engagement.

Allow AND deny items live here; the scope-enforcement keystone (M1-B9) applies
them with deny-wins precedence. Mutations require MANAGE_ENGAGEMENTS; reads
require VIEW. Everything is engagement-scoped through the caller's org, so a
scope item under another org's engagement is 404. Values are validated +
normalized per matcher_type at the schema layer. Mutations are audited.

Editing scope after a ROE is accepted does not re-open the ROE here — the ROE's
content_hash detects the drift and forces re-acceptance (M1-B8).
"""

import uuid

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
from app.models.engagement import ScopeItem
from app.schemas.scope import ScopeItemCreate, ScopeItemOut
from app.services.engagements import get_org_engagement

router = APIRouter(prefix="/engagements/{engagement_id}/scope-items", tags=["scope"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def _require_engagement(
    db: AsyncSession, engagement_id: uuid.UUID, org_id: uuid.UUID
) -> None:
    if await get_org_engagement(db, engagement_id, org_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")


@router.post("", response_model=ScopeItemOut, status_code=status.HTTP_201_CREATED)
async def add_scope_item(
    engagement_id: uuid.UUID,
    body: ScopeItemCreate,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> ScopeItem:
    await _require_engagement(db, engagement_id, principal.organization_id)
    item = ScopeItem(
        engagement_id=engagement_id,
        kind=body.kind,
        matcher_type=body.matcher_type,
        value=body.value,
        notes=body.notes,
    )
    db.add(item)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="scope.item_added",
        object_type="scope_item",
        object_id=item.id,
        engagement_id=engagement_id,
        detail={
            "kind": item.kind.value,
            "matcher_type": item.matcher_type.value,
            "value": item.value,
        },
        ip_address=_client_ip(request),
    )
    await db.refresh(item)
    return item


@router.get("", response_model=list[ScopeItemOut])
async def list_scope_items(
    engagement_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[ScopeItem]:
    await _require_engagement(db, engagement_id, principal.organization_id)
    result = await db.execute(
        select(ScopeItem)
        .where(ScopeItem.engagement_id == engagement_id)
        .order_by(ScopeItem.kind, ScopeItem.created_at)
    )
    return list(result.scalars().all())


@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_scope_item(
    engagement_id: uuid.UUID,
    item_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> None:
    await _require_engagement(db, engagement_id, principal.organization_id)
    item = (
        await db.execute(
            select(ScopeItem).where(
                ScopeItem.id == item_id, ScopeItem.engagement_id == engagement_id
            )
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scope item not found")
    detail = {
        "kind": item.kind.value,
        "matcher_type": item.matcher_type.value,
        "value": item.value,
    }
    await db.delete(item)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="scope.item_removed",
        object_type="scope_item",
        object_id=item_id,
        engagement_id=engagement_id,
        detail=detail,
        ip_address=_client_ip(request),
    )
