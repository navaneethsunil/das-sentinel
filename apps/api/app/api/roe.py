"""ROE acceptance endpoints (M1-B8) — nested under an engagement.

Accepting freezes the current ROE text + scope + terms into an immutable
roe_acknowledgements row with a content hash. Accept requires ACCEPT_ROE
(Admin/Tester); rendering/listing require VIEW. Acceptance is bound to what was
shown: the client sends the hash it saw and the server refuses (409) if the ROE
changed since. Re-acceptance is required whenever the recomputed hash of the
engagement's current scope/terms differs from the latest acknowledgement.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.deps import Capability, Principal, get_audit_service, get_db, require
from app.models.audit import AuditOutcome
from app.models.engagement import ROEAcknowledgement, ScopeItem
from app.schemas.roe import ROEAccept, ROEAcknowledgementOut, ROEView
from app.services.engagements import get_org_engagement
from app.services.roe import render_current_roe

router = APIRouter(prefix="/engagements/{engagement_id}/roe", tags=["roe"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def _engagement_or_404(db: AsyncSession, engagement_id: uuid.UUID, org_id: uuid.UUID):
    engagement = await get_org_engagement(db, engagement_id, org_id)
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    return engagement


async def _scope_items(db: AsyncSession, engagement_id: uuid.UUID) -> list[ScopeItem]:
    result = await db.execute(select(ScopeItem).where(ScopeItem.engagement_id == engagement_id))
    return list(result.scalars().all())


async def _latest_ack(db: AsyncSession, engagement_id: uuid.UUID) -> ROEAcknowledgement | None:
    return (
        await db.execute(
            select(ROEAcknowledgement)
            .where(ROEAcknowledgement.engagement_id == engagement_id)
            .order_by(ROEAcknowledgement.accepted_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


@router.get("", response_model=ROEView)
async def get_roe(
    engagement_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> ROEView:
    engagement = await _engagement_or_404(db, engagement_id, principal.organization_id)
    items = await _scope_items(db, engagement_id)
    roe_text, scope_snapshot, terms, content_hash = render_current_roe(engagement, items)
    latest = await _latest_ack(db, engagement_id)
    matches = latest is not None and latest.content_hash == content_hash
    return ROEView(
        roe_text=roe_text,
        scope_snapshot=scope_snapshot,
        terms_snapshot=terms,
        content_hash=content_hash.hex(),
        is_accepted=matches,
        requires_reacceptance=not matches,
        latest_acknowledgement_id=latest.id if latest else None,
        accepted_at=latest.accepted_at if latest else None,
    )


@router.post("/accept", response_model=ROEAcknowledgementOut, status_code=status.HTTP_201_CREATED)
async def accept_roe(
    engagement_id: uuid.UUID,
    body: ROEAccept,
    request: Request,
    principal: Principal = Depends(require(Capability.ACCEPT_ROE)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> ROEAcknowledgementOut:
    engagement = await _engagement_or_404(db, engagement_id, principal.organization_id)
    items = await _scope_items(db, engagement_id)
    roe_text, scope_snapshot, terms, content_hash = render_current_roe(engagement, items)

    if body.acknowledged_content_hash != content_hash.hex():
        await audit.log(
            organization_id=principal.organization_id,
            actor_user_id=principal.user_id,
            action="roe.accept_rejected",
            object_type="engagement",
            object_id=engagement_id,
            engagement_id=engagement_id,
            outcome=AuditOutcome.BLOCKED,
            detail={"reason": "content_hash_mismatch"},
            ip_address=_client_ip(request),
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ROE changed since it was rendered; re-review and accept the current version",
        )

    ack = ROEAcknowledgement(
        engagement_id=engagement_id,
        accepted_by=principal.user_id,
        roe_text=roe_text,
        scope_snapshot=scope_snapshot,
        terms_snapshot=terms,
        content_hash=content_hash,
        ip_address=_client_ip(request),
    )
    db.add(ack)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="roe.accepted",
        object_type="engagement",
        object_id=engagement_id,
        engagement_id=engagement_id,
        detail={"content_hash": content_hash.hex(), "acknowledgement_id": str(ack.id)},
        ip_address=_client_ip(request),
    )
    await db.refresh(ack)
    return ROEAcknowledgementOut.from_model(ack)


@router.get("/acknowledgements", response_model=list[ROEAcknowledgementOut])
async def list_acknowledgements(
    engagement_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[ROEAcknowledgementOut]:
    await _engagement_or_404(db, engagement_id, principal.organization_id)
    result = await db.execute(
        select(ROEAcknowledgement)
        .where(ROEAcknowledgement.engagement_id == engagement_id)
        .order_by(ROEAcknowledgement.accepted_at.desc())
    )
    return [ROEAcknowledgementOut.from_model(a) for a in result.scalars().all()]
