"""Scan-plan endpoint (M4) — deterministic next-scan recommendations from recon.

Read-only analysis: from a target's type + its recon facts it recommends which
scans to run next (no LLM, no mutation — it never launches a scan; that stays on
the authorized launch_scan path). VIEW-guarded and org/engagement/target-scoped
(cross-org → 404).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import Capability, Principal, get_db, require
from app.schemas.scan_plan import ScanPlanOut
from app.services.engagements import get_org_engagement
from app.services.scan_plan import scan_plan_for_target
from app.services.targets import get_org_target

router = APIRouter(prefix="/engagements/{engagement_id}/targets/{target_id}", tags=["scan-plan"])


@router.get("/scan-plan", response_model=ScanPlanOut)
async def get_scan_plan(
    engagement_id: uuid.UUID,
    target_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> ScanPlanOut:
    if await get_org_engagement(db, engagement_id, principal.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    target = await get_org_target(db, engagement_id, target_id, principal.organization_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    plan = await scan_plan_for_target(db, engagement_id, target)
    return ScanPlanOut.from_obj(plan)
