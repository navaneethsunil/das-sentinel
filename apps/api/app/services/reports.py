"""Report assembly + lifecycle (M3-B5) — DATABASE_SCHEMA §11, brief §15.

A report snapshots a set of findings into editable structured content (`reports.body`,
JSONB) at creation time: each finding's title, severity, current CVSS score (M3-B3),
affected asset, source of discovery, description/impact/remediation, validation
status, and compliance mappings (M3-B4), plus the POA&M-specific fields a human fills
in before export (responsible owner, planned completion date, milestones, risk-
acceptance notes). The body stays editable while status='draft'; finalizing locks it.
Rendering to POA&M CSV / Markdown happens in `app/reports/` from this body — the
export is a pure function of the snapshot, so what you edited is what you export.

The snapshot is deliberate: CVSS/compliance edits after creation don't retro-change an
existing report (regenerate for a fresh snapshot). report_findings records membership
+ ordering with an ON DELETE RESTRICT finding FK, so a cited finding can't be hard-
deleted out from under a report.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.engagement import Engagement
from app.models.finding import Finding
from app.models.report import Report, ReportFinding, ReportStatus, ReportType
from app.models.target import Target
from app.services.compliance import get_finding_mappings
from app.services.cvss import get_current_score
from app.services.findings_read import list_engagement_findings

# Body schema version — lets exporters and future migrations detect the shape.
BODY_SCHEMA = "das.report/v1"

# Fields a human fills in before export (start empty; §15 POA&M fields not derivable
# from a finding). Kept in one place so create + edit + export agree on the set.
EDITABLE_FINDING_FIELDS = (
    "responsible_owner",
    "planned_completion_date",
    "milestones",
    "risk_acceptance_notes",
)


class ReportError(Exception):
    """A report operation is invalid (e.g. editing a finalized report)."""


def _source_of_discovery(finding: Finding) -> str:
    pf = finding.partial_fingerprints if isinstance(finding.partial_fingerprints, dict) else {}
    source = pf.get("source")
    if isinstance(source, str) and source:
        return source
    return finding.provenance.value


def _affected_asset(target: Target | None) -> str:
    if target is None:
        return ""
    if target.primary_value:
        return f"{target.name} ({target.primary_value})"
    return target.name


async def _finding_entry(
    session: AsyncSession, finding: Finding, target: Target | None, index: int
) -> dict[str, Any]:
    score = await get_current_score(session, finding.id)
    mappings = await get_finding_mappings(session, finding.id)
    return {
        "finding_id": str(finding.id),
        "weakness_id": f"W-{index:03d}",
        "title": finding.title,
        "severity": finding.severity.value,
        "current_status": finding.status.value,
        "validation_status": finding.provenance.value,
        "is_false_positive": finding.is_false_positive,
        "affected_asset": _affected_asset(target),
        "source_of_discovery": _source_of_discovery(finding),
        "description": finding.description,
        "impact": finding.impact,
        "recommended_remediation": finding.recommendation,
        "cvss": (
            {
                "version": score.version.value,
                "base_score": float(score.base_score),
                "severity_band": score.severity_band.value,
                "vector": score.vector_string,
            }
            if score is not None
            else None
        ),
        "mappings": [
            {
                "framework_key": framework.key,
                "framework_name": framework.name,
                "code": control.code,
                "title": control.title,
            }
            for _mapping, control, framework in mappings
        ],
        # editable POA&M fields (§15) — human-owned, empty at generation
        **{field: "" for field in EDITABLE_FINDING_FIELDS},
    }


async def assemble_report_body(
    session: AsyncSession,
    engagement: Engagement,
    findings: list[Finding],
    *,
    report_type: ReportType,
    now: datetime,
) -> dict[str, Any]:
    """Snapshot findings (+ CVSS + compliance) into the editable report body."""
    target_ids = {f.target_id for f in findings}
    targets: dict[uuid.UUID, Target] = {}
    if target_ids:
        targets = {
            t.id: t
            for t in (
                await session.execute(select(Target).where(Target.id.in_(target_ids)))
            ).scalars()
        }
    entries = [
        await _finding_entry(session, f, targets.get(f.target_id), i)
        for i, f in enumerate(findings, start=1)
    ]
    return {
        "schema": BODY_SCHEMA,
        "report_type": report_type.value,
        "generated_at": now.isoformat(),
        "engagement": {
            "id": str(engagement.id),
            "name": engagement.name,
            "client_system_name": engagement.client_system_name,
        },
        "summary": "",  # editable executive/technical narrative
        "findings": entries,
    }


async def create_report(
    session: AsyncSession,
    engagement: Engagement,
    *,
    report_type: ReportType,
    title: str,
    finding_ids: list[uuid.UUID] | None,
    generated_by: uuid.UUID | None,
    now: datetime,
) -> Report:
    """Generate a report for an engagement. With `finding_ids=None`, snapshots every
    canonical finding; otherwise only the requested ones (preserving that order,
    ignoring ids not in the engagement). Returns the flushed report; caller commits."""
    canonical = await list_engagement_findings(session, engagement.id)
    if finding_ids is None:
        findings = canonical
    else:
        by_id = {f.id: f for f in canonical}
        findings = [by_id[fid] for fid in finding_ids if fid in by_id]

    body = await assemble_report_body(
        session, engagement, findings, report_type=report_type, now=now
    )
    report = Report(
        engagement_id=engagement.id,
        report_type=report_type,
        title=title,
        status=ReportStatus.DRAFT,
        body=body,
        generated_by=generated_by,
        created_at=now,
        updated_at=now,
    )
    session.add(report)
    await session.flush()
    for order, f in enumerate(findings):
        session.add(ReportFinding(report_id=report.id, finding_id=f.id, sort_order=order))
    await session.flush()
    return report


async def update_report(
    session: AsyncSession,
    report: Report,
    *,
    title: str | None,
    body: dict[str, Any] | None,
    now: datetime,
) -> Report:
    """Edit a draft report's title and/or body. A finalized report is immutable
    (fail-closed → ReportError). Caller commits."""
    if report.status is ReportStatus.FINAL:
        raise ReportError("a finalized report cannot be edited")
    if title is not None:
        report.title = title
    if body is not None:
        report.body = body
    report.updated_at = now
    await session.flush()
    return report


async def finalize_report(session: AsyncSession, report: Report, *, now: datetime) -> Report:
    """Lock a report against further edits (idempotent). Caller commits."""
    report.status = ReportStatus.FINAL
    report.updated_at = now
    await session.flush()
    return report


async def get_org_report(
    session: AsyncSession,
    engagement_id: uuid.UUID,
    report_id: uuid.UUID,
    org_id: uuid.UUID,
) -> Report | None:
    """A non-deleted report within an engagement owned by the caller's org, or None
    (router → 404 — no cross-org/cross-engagement leak)."""
    return (
        await session.execute(
            select(Report)
            .join(Engagement, Report.engagement_id == Engagement.id)
            .where(
                Report.id == report_id,
                Report.engagement_id == engagement_id,
                Report.deleted_at.is_(None),
                Engagement.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()


async def list_engagement_reports(session: AsyncSession, engagement_id: uuid.UUID) -> list[Report]:
    """Non-deleted reports for an engagement, newest first."""
    return list(
        (
            await session.execute(
                select(Report)
                .where(Report.engagement_id == engagement_id, Report.deleted_at.is_(None))
                .order_by(Report.created_at.desc())
            )
        ).scalars()
    )


async def soft_delete_report(session: AsyncSession, report: Report, *, now: datetime) -> None:
    """Soft-delete a report (deleted_at); its report_findings rows remain. Caller commits."""
    report.deleted_at = now
    await session.flush()
