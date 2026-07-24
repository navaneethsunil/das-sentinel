"""CVSS scoring endpoints (M3-B3) — nested under a finding.

Scoring is a human action (CLAUDE.md §7: the LLM never sets a final CVSS), guarded
by VALIDATE_FINDINGS. Reading the current score + history is VIEW. Every route is
org/engagement-scoped through `get_org_finding` (cross-org → 404, no IDOR/BOLA).
Writing a score records an insert-only history row and audits the event.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.deps import (
    Capability,
    Principal,
    get_audit_service,
    get_db,
    require,
)
from app.core.sessions import utcnow
from app.schemas.cvss import CvssHistoryOut, CvssScoreIn, CvssScoreOut
from app.services.cvss import (
    CvssComputeError,
    get_current_score,
    list_score_history,
    set_cvss_score,
)
from app.services.findings_read import get_org_finding

router = APIRouter(prefix="/engagements/{engagement_id}/findings/{finding_id}/cvss", tags=["cvss"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("", response_model=CvssScoreOut, status_code=status.HTTP_201_CREATED)
async def set_score(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    body: CvssScoreIn,
    request: Request,
    principal: Principal = Depends(require(Capability.VALIDATE_FINDINGS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> CvssScoreOut:
    """Compute and record a new current CVSS score for a finding from a supplied
    vector (v4.0 or v3.1). A malformed vector or an override missing its
    justification is refused 422 with nothing written (fail-closed)."""
    finding = await get_org_finding(db, engagement_id, finding_id, principal.organization_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    try:
        score = await set_cvss_score(
            db,
            finding=finding,
            vector_string=body.vector_string,
            is_manual_override=body.is_manual_override,
            override_justification=body.override_justification,
            scored_by=principal.user_id,
            now=utcnow(),
        )
    except CvssComputeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="finding.cvss_scored",
        object_type="finding",
        object_id=finding.id,
        engagement_id=engagement_id,
        detail={
            "version": score.version.value,
            "base_score": float(score.base_score),
            "severity_band": score.severity_band.value,
            "is_manual_override": score.is_manual_override,
        },
        ip_address=_client_ip(request),
    )
    await db.commit()
    await db.refresh(score)
    return CvssScoreOut.from_model(score)


@router.get("", response_model=CvssHistoryOut)
async def get_scores(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> CvssHistoryOut:
    finding = await get_org_finding(db, engagement_id, finding_id, principal.organization_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    current = await get_current_score(db, finding.id)
    history = await list_score_history(db, finding.id)
    return CvssHistoryOut(
        current=CvssScoreOut.from_model(current) if current else None,
        history=[CvssScoreOut.from_model(s) for s in history],
    )
