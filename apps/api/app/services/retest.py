"""Reimport/retest reconciliation (M4-B3) — DefectDojo-modeled finding lifecycle.

After a CLEAN, COMPLETED rescan of a `(target, source)` population, findings the
rescan no longer surfaces auto-transition toward `mitigated`, and findings
believed resolved that reappear auto-reopen — every transition recorded in the
append-only `finding_status_history` with `changed_by=NULL` (automated,
evidence-backed, §2.9). Automation NEVER sets `fixed` (§2.9: human-only); the
strongest automated close is `mitigated`. Human risk decisions
(`accepted_risk`/`false_positive`/`out_of_scope`) are left untouched.

Only the caller of a clean, completed scan may invoke this: an errored/cancelled
scan proves nothing about a finding's absence, so reconciling on one would
wrongly mitigate live findings (fail-closed, CLAUDE.md §11.6).

`source` is the scanner name / suite name (the same value written to
`partial_fingerprints[PF_SOURCE]` and folded into `hash_code`) — reconciliation
is scoped to the population that this scan type actually re-tested. Per the
DefectDojo model, a rescan is assumed to fully re-test its source's population;
a partial rescan would mitigate untested findings — the documented ceiling.

For any reconciled finding that carries a remediation (a fix was drafted), a
`retests` row records the deterministic patch-validation outcome (resolved when
absent, still_present when present) with before/after evidence and the rescan —
the auditable before/after trail (schema §9).
"""

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.engagement import Engagement
from app.models.evidence import Evidence
from app.models.finding import (
    Finding,
    FindingEvidence,
    FindingStatus,
    FindingStatusHistory,
)
from app.models.remediation import Remediation, Retest, RetestResult
from app.models.target import Target
from app.services.finding_hash import PF_SOURCE

# Deterministic, rescan-presence-based lifecycle (schema §9).
_MITIGATE_FROM = {FindingStatus.OPEN, FindingStatus.IN_TRIAGE, FindingStatus.CONFIRMED}
_REOPEN_FROM = {FindingStatus.MITIGATED, FindingStatus.FIXED}
_MANAGED = _MITIGATE_FROM | _REOPEN_FROM


def next_status(prior: FindingStatus, present: bool) -> FindingStatus | None:
    """The rescan-driven transition for a finding, or None for no change. Present +
    believed-resolved → reopen (OPEN); absent + active → auto-mitigate (MITIGATED).
    Automation never reaches FIXED (§2.9: human-only) and never overrides a human
    risk decision (accepted_risk / false_positive / out_of_scope stay put)."""
    if present and prior in _REOPEN_FROM:
        return FindingStatus.OPEN
    if not present and prior in _MITIGATE_FROM:
        return FindingStatus.MITIGATED
    return None


async def _latest_remediation_id(session: AsyncSession, finding_id: uuid.UUID) -> uuid.UUID | None:
    return (
        await session.execute(
            select(Remediation.id)
            .where(Remediation.finding_id == finding_id)
            .order_by(Remediation.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def _detection_evidence_id(session: AsyncSession, finding_id: uuid.UUID) -> uuid.UUID | None:
    """The finding's earliest cited evidence — its original detection proof (the
    'before' side of a retest)."""
    return (
        await session.execute(
            select(FindingEvidence.evidence_id)
            .join(Evidence, Evidence.id == FindingEvidence.evidence_id)
            .where(FindingEvidence.finding_id == finding_id)
            .order_by(Evidence.created_at)
            .limit(1)
        )
    ).scalar_one_or_none()


async def reconcile_reimport(
    session: AsyncSession,
    *,
    engagement: Engagement,
    target: Target,
    source: str,
    observed_hashes: set[bytes],
    rescan_scan_id: uuid.UUID,
    now: datetime,
    after_evidence_id: uuid.UUID | None = None,
) -> list[Retest]:
    """Reconcile the `(target, source)` finding population against what this rescan
    observed. Flushed, not committed — commits with the caller's transaction (which
    must have already persisted this scan's findings, so `observed_hashes` is
    complete). Returns the retests recorded (findings that carried a remediation)."""
    population = (
        (
            await session.execute(
                select(Finding).where(
                    Finding.engagement_id == engagement.id,
                    Finding.target_id == target.id,
                    Finding.deleted_at.is_(None),
                    Finding.duplicate_of.is_(None),
                    Finding.partial_fingerprints[PF_SOURCE].astext == source,
                )
            )
        )
        .scalars()
        .all()
    )

    retests: list[Retest] = []
    for finding in population:
        prior = finding.status
        if prior not in _MANAGED:
            continue  # human risk decision — never overridden by automation
        present = finding.hash_code in observed_hashes

        new_status = next_status(prior, present)
        if new_status is not None:
            finding.status = new_status
            finding.updated_at = now
            verb = "reappeared in" if present else "absent from"
            session.add(
                FindingStatusHistory(
                    finding_id=finding.id,
                    from_status=prior,
                    to_status=new_status,
                    changed_by=None,
                    reason=f"{verb} rescan {rescan_scan_id} ({source})",
                    changed_at=now,
                )
            )

        remediation_id = await _latest_remediation_id(session, finding.id)
        if remediation_id is not None:
            retest = Retest(
                finding_id=finding.id,
                remediation_id=remediation_id,
                rescan_scan_id=rescan_scan_id,
                before_evidence_id=await _detection_evidence_id(session, finding.id),
                after_evidence_id=after_evidence_id,
                result=RetestResult.STILL_PRESENT if present else RetestResult.RESOLVED,
                performed_by=None,
                performed_at=now,
            )
            session.add(retest)
            retests.append(retest)

    await session.flush()
    return retests
