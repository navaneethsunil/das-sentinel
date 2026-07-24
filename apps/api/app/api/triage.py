"""Triage overview endpoint (M4-B2) — deterministic ranking + grouping.

Read-only analysis over an engagement's canonical findings: no LLM, no mutation,
no status change (CLAUDE.md §2.6 — severity is deterministic; the model explains,
it does not decide). VIEW-guarded and org/engagement-scoped (cross-org → 404).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import Capability, Principal, get_db, require
from app.schemas.triage import FindingGroupOut, RankedFindingOut, TriageOverviewOut
from app.services.engagements import get_org_engagement
from app.services.triage_rank import triage_overview

router = APIRouter(prefix="/engagements/{engagement_id}/triage", tags=["triage"])


@router.get("", response_model=TriageOverviewOut)
async def get_triage_overview(
    engagement_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> TriageOverviewOut:
    if await get_org_engagement(db, engagement_id, principal.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    ranked, groups = await triage_overview(db, engagement_id)
    return TriageOverviewOut(
        ranked=[RankedFindingOut.from_obj(r) for r in ranked],
        groups=[FindingGroupOut.from_obj(g) for g in groups],
    )
