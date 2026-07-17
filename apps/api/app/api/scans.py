"""Scan endpoints (M2-W2) — nested under an engagement.

Only the emergency-stop signal path and a status read for now; scan launch is
the suite launcher's job (M2-B6/F1). Cancellation is authorized with
LAUNCH_SCANS (whoever may start a scan may stop it), org/engagement-scoped
(cross-org → 404), audited, and idempotent. The endpoint only *requests* the
stop by setting `scans.cancel_requested`; the worker effects it (terminates the
run's process tree, confirms it is gone) and audits `scan.cancelled` when done.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.deps import Capability, Principal, get_audit_service, get_db, require
from app.schemas.scans import ScanOut
from app.services.scans import ScanNotCancellableError, get_org_scan, request_scan_cancellation

router = APIRouter(prefix="/engagements/{engagement_id}/scans", tags=["scans"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    engagement_id: uuid.UUID,
    scan_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> ScanOut:
    scan = await get_org_scan(db, engagement_id, scan_id, principal.organization_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return ScanOut.model_validate(scan)


@router.post("/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(
    engagement_id: uuid.UUID,
    scan_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.LAUNCH_SCANS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> ScanOut:
    scan = await get_org_scan(db, engagement_id, scan_id, principal.organization_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    try:
        newly_requested = await request_scan_cancellation(db, scan)
    except ScanNotCancellableError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="scan.cancel_requested",
        object_type="scan",
        object_id=scan.id,
        engagement_id=engagement_id,
        detail={"newly_requested": newly_requested},
        ip_address=_client_ip(request),
    )
    await db.refresh(scan)
    return ScanOut.model_validate(scan)
