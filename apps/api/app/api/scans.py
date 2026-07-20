"""Scan endpoints (M2-W2, M2-F1) — nested under an engagement.

`POST ""` is the suite launcher (M2-F1): it validates the LLM target connector,
authorizes the operation through the scope keystone (audited either way), freezes
the immutable execution envelope, and enqueues the worker. Intensity is
server-derived from a typed operation kind, never caller-declared (M1-B9).

The emergency-stop signal path and status/list reads round out the surface.
Cancellation is authorized with LAUNCH_SCANS (whoever may start a scan may stop
it), org/engagement-scoped (cross-org → 404), audited, and idempotent — the
endpoint only *requests* the stop by setting `scans.cancel_requested`; the worker
effects it (terminates the run's process tree, confirms it is gone) and audits
`scan.cancelled` when done.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors import TargetConnectorError, build_llm_target_connector
from app.core.audit import AuditService
from app.core.deps import Capability, Principal, get_audit_service, get_db, require
from app.core.scope import Operation, ScopeError
from app.core.sessions import utcnow
from app.models.audit import AuditOutcome
from app.models.engagement import ROEAcknowledgement, ScopeItem
from app.models.scan import Scan
from app.schemas.scans import ScanLaunchIn, ScanOut
from app.services.engagements import get_org_engagement
from app.services.scans import (
    ScanNotCancellableError,
    get_org_scan,
    launch_scan,
    request_scan_cancellation,
)
from app.services.targets import get_org_target

router = APIRouter(prefix="/engagements/{engagement_id}/scans", tags=["scans"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def _latest_roe_ack(db: AsyncSession, engagement_id: uuid.UUID) -> ROEAcknowledgement | None:
    return (
        await db.execute(
            select(ROEAcknowledgement)
            .where(ROEAcknowledgement.engagement_id == engagement_id)
            .order_by(ROEAcknowledgement.accepted_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def _scope_items(db: AsyncSession, engagement_id: uuid.UUID) -> list[ScopeItem]:
    return list(
        (
            await db.execute(select(ScopeItem).where(ScopeItem.engagement_id == engagement_id))
        ).scalars()
    )


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def launch_scan_endpoint(
    engagement_id: uuid.UUID,
    body: ScanLaunchIn,
    request: Request,
    principal: Principal = Depends(require(Capability.LAUNCH_SCANS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> ScanOut:
    engagement = await get_org_engagement(db, engagement_id, principal.organization_id)
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    target = await get_org_target(db, engagement_id, body.target_id, principal.organization_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    scope_items = await _scope_items(db, engagement_id)

    # Pre-flight: build the connector to prove the target is a launchable LLM
    # connector (right type, parseable transport shape, resolvable auth ref).
    # No network call — the egress guard only fires when a suite actually sends.
    try:
        connector = build_llm_target_connector(target, scope_items)
    except TargetConnectorError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    await connector.aclose()

    suites = body.unique_suites()
    op = Operation(target_id=target.id, kind=body.operation_kind())
    roe_ack = await _latest_roe_ack(db, engagement_id)
    now = utcnow()

    try:
        scan = await launch_scan(
            db,
            engagement=engagement,
            target=target,
            scope_items=scope_items,
            op=op,
            roe_ack=roe_ack,
            initiated_by=principal.user_id,
            now=now,
            config={"suites": [s.value for s in suites]},
        )
    except ScopeError as exc:
        # The request tx will roll back on the 403, so the blocked event is
        # written on an independent, committed session (the login_failed idiom).
        sessionmaker = request.app.state.db_sessionmaker
        async with sessionmaker() as audit_db:
            await AuditService(audit_db).log(
                organization_id=principal.organization_id,
                actor_user_id=principal.user_id,
                action="scan.blocked",
                object_type="target",
                object_id=target.id,
                engagement_id=engagement_id,
                outcome=AuditOutcome.BLOCKED,
                detail={"reason": exc.reason, "intensity": body.intensity.value},
                ip_address=_client_ip(request),
            )
            await audit_db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.reason) from exc

    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="scan.launched",
        object_type="scan",
        object_id=scan.id,
        engagement_id=engagement_id,
        detail={
            "target_id": str(target.id),
            "suites": [s.value for s in suites],
            "intensity": scan.intensity.value,
        },
        ip_address=_client_ip(request),
    )
    # Commit the scan + envelope + audit before enqueuing so the worker can never
    # race ahead of a not-yet-visible row. Enqueue by task name so the API never
    # imports the worker/orchestration graph.
    await db.commit()
    from app.workers.celery_app import celery_app

    celery_app.send_task("app.run_scan", args=[str(scan.id)])
    await db.refresh(scan)
    return ScanOut.model_validate(scan)


@router.get("", response_model=list[ScanOut])
async def list_scans(
    engagement_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[ScanOut]:
    if await get_org_engagement(db, engagement_id, principal.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    result = await db.execute(
        select(Scan)
        .where(Scan.engagement_id == engagement_id)
        .order_by(Scan.queued_at.desc())
        .limit(50)
    )
    return [ScanOut.model_validate(s) for s in result.scalars().all()]


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
