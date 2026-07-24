"""Report endpoints (M3-B5) — nested under an engagement.

Generate a report (snapshot findings + CVSS + compliance into an editable body),
edit it while draft, finalize to lock it, and export it as POA&M CSV or Markdown.
Authoring/export is EXPORT_REPORTS; reads are VIEW. Every route is org/engagement-
scoped via get_org_engagement/get_org_report (cross-org → 404). Editing a finalized
report is refused (409). Exports render purely from the stored body.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
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
from app.reports import render_markdown_report, render_poam_csv
from app.schemas.reports import (
    ExportFormat,
    ReportCreateIn,
    ReportDetailOut,
    ReportOut,
    ReportUpdateIn,
)
from app.services.engagements import get_org_engagement
from app.services.reports import (
    ReportError,
    create_report,
    finalize_report,
    get_org_report,
    list_engagement_reports,
    soft_delete_report,
    update_report,
)

router = APIRouter(prefix="/engagements/{engagement_id}/reports", tags=["reports"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("", response_model=ReportDetailOut, status_code=status.HTTP_201_CREATED)
async def generate_report(
    engagement_id: uuid.UUID,
    body: ReportCreateIn,
    request: Request,
    principal: Principal = Depends(require(Capability.EXPORT_REPORTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> ReportDetailOut:
    engagement = await get_org_engagement(db, engagement_id, principal.organization_id)
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    report = await create_report(
        db,
        engagement,
        report_type=body.report_type,
        title=body.title,
        finding_ids=body.finding_ids,
        generated_by=principal.user_id,
        now=utcnow(),
    )
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="report.generated",
        object_type="report",
        object_id=report.id,
        engagement_id=engagement_id,
        detail={"report_type": report.report_type.value, "findings": len(body.finding_ids or [])},
        ip_address=_client_ip(request),
    )
    await db.commit()
    await db.refresh(report)
    return ReportDetailOut.from_model(report)


@router.get("", response_model=list[ReportOut])
async def list_reports(
    engagement_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[ReportOut]:
    if await get_org_engagement(db, engagement_id, principal.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    return [ReportOut.model_validate(r) for r in await list_engagement_reports(db, engagement_id)]


@router.get("/{report_id}", response_model=ReportDetailOut)
async def get_report(
    engagement_id: uuid.UUID,
    report_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> ReportDetailOut:
    report = await get_org_report(db, engagement_id, report_id, principal.organization_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found")
    return ReportDetailOut.from_model(report)


@router.patch("/{report_id}", response_model=ReportDetailOut)
async def edit_report(
    engagement_id: uuid.UUID,
    report_id: uuid.UUID,
    body: ReportUpdateIn,
    request: Request,
    principal: Principal = Depends(require(Capability.EXPORT_REPORTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> ReportDetailOut:
    report = await get_org_report(db, engagement_id, report_id, principal.organization_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found")
    try:
        await update_report(db, report, title=body.title, body=body.body, now=utcnow())
    except ReportError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="report.updated",
        object_type="report",
        object_id=report.id,
        engagement_id=engagement_id,
        ip_address=_client_ip(request),
    )
    await db.commit()
    await db.refresh(report)
    return ReportDetailOut.from_model(report)


@router.post("/{report_id}/finalize", response_model=ReportDetailOut)
async def finalize(
    engagement_id: uuid.UUID,
    report_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.EXPORT_REPORTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> ReportDetailOut:
    report = await get_org_report(db, engagement_id, report_id, principal.organization_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found")
    await finalize_report(db, report, now=utcnow())
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="report.finalized",
        object_type="report",
        object_id=report.id,
        engagement_id=engagement_id,
        ip_address=_client_ip(request),
    )
    await db.commit()
    await db.refresh(report)
    return ReportDetailOut.from_model(report)


@router.post("/{report_id}/export")
async def export_report(
    engagement_id: uuid.UUID,
    report_id: uuid.UUID,
    request: Request,
    fmt: ExportFormat = Query(..., alias="format"),
    principal: Principal = Depends(require(Capability.EXPORT_REPORTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> Response:
    """Render the report to POA&M CSV or a Markdown technical report and return it as
    a downloadable file. Rendering is a pure function of the stored body."""
    report = await get_org_report(db, engagement_id, report_id, principal.organization_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found")
    # The report title is authoritative on the row; surface it to the renderers
    # (which are pure functions of the body) without mutating the stored body.
    body = {**report.body, "title": report.title}
    if fmt is ExportFormat.CSV:
        content = render_poam_csv(body)
        media_type = "text/csv"
        filename = f"poam-{report.id}.csv"
    else:
        content = render_markdown_report(body)
        media_type = "text/markdown"
        filename = f"report-{report.id}.md"
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="report.exported",
        object_type="report",
        object_id=report.id,
        engagement_id=engagement_id,
        detail={"format": fmt.value},
        ip_address=_client_ip(request),
    )
    await db.commit()
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    engagement_id: uuid.UUID,
    report_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.EXPORT_REPORTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> None:
    report = await get_org_report(db, engagement_id, report_id, principal.organization_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found")
    await soft_delete_report(db, report, now=utcnow())
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="report.deleted",
        object_type="report",
        object_id=report.id,
        engagement_id=engagement_id,
        ip_address=_client_ip(request),
    )
    await db.commit()
