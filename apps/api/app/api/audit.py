"""Audit-log read endpoint (M1-F5) — read-only, VIEW_AUDIT (Admin/Reviewer).

Strictly org-scoped through the caller's principal: filtering by another
org's engagement_id just yields an empty page (the org predicate always
applies), never foreign rows. There is no mutation surface here at all —
audit_events stays append-only via the writer + DB trigger (M1-D4/TM-9).
"""

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import Capability, Principal, get_db, require
from app.models.audit import AuditEvent
from app.models.engagement import Engagement
from app.models.identity import User
from app.schemas.audit import AuditEventOut

router = APIRouter(prefix="/audit-events", tags=["audit"])


@router.get("", response_model=list[AuditEventOut])
async def list_audit_events(
    engagement_id: uuid.UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require(Capability.VIEW_AUDIT)),
    db: AsyncSession = Depends(get_db),
) -> list[AuditEventOut]:
    stmt = (
        select(AuditEvent, User.email, Engagement.name)
        .join(User, User.id == AuditEvent.actor_user_id, isouter=True)
        .join(Engagement, Engagement.id == AuditEvent.engagement_id, isouter=True)
        .where(AuditEvent.organization_id == principal.organization_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if engagement_id is not None:
        stmt = stmt.where(AuditEvent.engagement_id == engagement_id)
    rows = (await db.execute(stmt)).all()
    return [AuditEventOut.from_row(event, email, name) for event, email, name in rows]
