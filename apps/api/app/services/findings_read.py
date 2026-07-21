"""Read seam for findings (M2-F3).

Every query is org- and engagement-scoped through the caller's principal — a
finding, its evidence, or its history from another org/engagement is never
returned (no IDOR/BOLA, TM-3). Soft-deleted findings are excluded. Evidence is
only served when it is actually linked to the finding being viewed, so a valid
`evidence_id` from a different finding cannot be read through another finding's
URL. Loading a blob goes through the storage abstraction, which re-verifies the
SHA-256 (`load_evidence`) — a tampered blob is a loud failure, never served.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.engagement import Engagement
from app.models.evidence import Evidence
from app.models.finding import (
    Finding,
    FindingEvidence,
    FindingStatusHistory,
    Severity,
)
from app.storage.evidence import BlobStore, EvidenceNotFoundError, load_evidence

# Severity-first ordering for the list (most urgent on top), newest within a tier.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


async def get_org_finding(
    db: AsyncSession, engagement_id: uuid.UUID, finding_id: uuid.UUID, org_id: uuid.UUID
) -> Finding | None:
    """A single non-deleted finding within an engagement owned by the caller's
    org, or None (router → 404 — no cross-org/cross-engagement leak)."""
    return (
        await db.execute(
            select(Finding)
            .join(Engagement, Finding.engagement_id == Engagement.id)
            .where(
                Finding.id == finding_id,
                Finding.engagement_id == engagement_id,
                Finding.deleted_at.is_(None),
                Engagement.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()


async def list_engagement_findings(
    db: AsyncSession,
    engagement_id: uuid.UUID,
    *,
    scan_id: uuid.UUID | None = None,
    limit: int = 500,
) -> list[Finding]:
    """Non-deleted findings for an engagement (the router has already proven the
    engagement belongs to the caller's org), optionally filtered to one scan.
    Ordered severity-first, newest within a severity."""
    stmt = select(Finding).where(
        Finding.engagement_id == engagement_id,
        Finding.deleted_at.is_(None),
    )
    if scan_id is not None:
        stmt = stmt.where(Finding.scan_id == scan_id)
    findings = list((await db.execute(stmt)).scalars())
    findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), -f.created_at.timestamp()))
    return findings[:limit]


async def get_finding_evidence_rows(
    db: AsyncSession, finding_id: uuid.UUID
) -> list[tuple[Evidence, str | None]]:
    """The evidence blobs cited by a finding, with each link's caption."""
    rows = (
        await db.execute(
            select(Evidence, FindingEvidence.caption)
            .join(FindingEvidence, FindingEvidence.evidence_id == Evidence.id)
            .where(FindingEvidence.finding_id == finding_id)
            .order_by(Evidence.created_at)
        )
    ).all()
    return [(evidence, caption) for evidence, caption in rows]


async def get_finding_status_history(
    db: AsyncSession, finding_id: uuid.UUID
) -> list[FindingStatusHistory]:
    """The append-only status transitions for a finding, oldest first."""
    return list(
        (
            await db.execute(
                select(FindingStatusHistory)
                .where(FindingStatusHistory.finding_id == finding_id)
                .order_by(FindingStatusHistory.changed_at)
            )
        ).scalars()
    )


async def load_linked_evidence(
    db: AsyncSession, store: BlobStore, finding_id: uuid.UUID, evidence_id: uuid.UUID
) -> tuple[Evidence, bytes] | None:
    """Return (evidence row, verified bytes) only when the evidence is linked to
    THIS finding; None otherwise (router → 404). The link check runs before the
    blob is fetched, so an unlinked evidence id never touches object storage."""
    link = (
        await db.execute(
            select(FindingEvidence).where(
                FindingEvidence.finding_id == finding_id,
                FindingEvidence.evidence_id == evidence_id,
            )
        )
    ).scalar_one_or_none()
    if link is None:
        return None
    data = await load_evidence(db, store, evidence_id)  # re-verifies SHA-256
    evidence = await db.get(Evidence, evidence_id)
    if evidence is None:  # load_evidence would have raised first; defensive
        raise EvidenceNotFoundError(str(evidence_id))
    return evidence, data
