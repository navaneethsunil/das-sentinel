"""Create findings from a scanner run (M3-W1).

The scanner-side sibling of services/findings.py (which handles LLM suites): turns
a `ScannerResult`'s normalized findings into `findings` rows, each carrying its
scanner_run link, the shared severity/SARIF vocabulary, a stable dedup identity
(`hash_code` + `partial_fingerprints`), and a `finding_evidence` link to the raw
tool output stored immutably in the object store. Because a scanner's detector is
deterministic, these are `automated` findings (not `ai_generated`) and start
`open`; the append-only status history records the creation. Nothing here can set
a finding to confirmed/fixed (§2.9 holds by construction).

Idempotent: a re-run whose finding produces the same `hash_code` reuses the
existing row instead of duplicating it (content-addressed evidence dedups too).
"""

import hashlib
import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.engagement import Engagement
from app.models.evidence import Evidence
from app.models.finding import (
    Finding,
    FindingEvidence,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
    SarifLevel,
    Severity,
)
from app.models.scan import Scan
from app.models.scanner import ScannerRun
from app.models.target import Target
from app.scanners.base import NormalizedFinding, ScannerResult

_SEVERITY_TO_SARIF = {
    Severity.CRITICAL: SarifLevel.ERROR,
    Severity.HIGH: SarifLevel.ERROR,
    Severity.MEDIUM: SarifLevel.WARNING,
    Severity.LOW: SarifLevel.NOTE,
    Severity.INFORMATIONAL: SarifLevel.NONE,
}


def _hash_code(
    engagement_id: uuid.UUID, target_id: uuid.UUID, scanner: str, fingerprint: str
) -> bytes:
    """Stable dedup identity — the same fingerprinted finding from the same scanner
    against the same target in the same engagement is one finding across runs."""
    return hashlib.sha256(f"{engagement_id}|{target_id}|{scanner}|{fingerprint}".encode()).digest()


async def create_findings_from_scanner(
    session: AsyncSession,
    *,
    engagement: Engagement,
    target: Target,
    scan: Scan,
    scanner_run: ScannerRun,
    result: ScannerResult,
    raw_evidence: Evidence | None,
    now: datetime,
) -> list[Finding]:
    """Persist one finding per normalized finding (flushed, not committed — commits
    atomically with the caller's transaction). Returns findings (new or reused)."""
    findings: list[Finding] = []
    for nf in result.findings:
        hash_code = _hash_code(engagement.id, target.id, result.scanner_name, nf.fingerprint)
        existing = (
            await session.execute(
                select(Finding).where(
                    Finding.engagement_id == engagement.id,
                    Finding.hash_code == hash_code,
                    Finding.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            findings.append(existing)
            continue
        findings.append(
            await _create_one(
                session,
                engagement=engagement,
                target=target,
                scan=scan,
                scanner_run=scanner_run,
                result=result,
                nf=nf,
                raw_evidence=raw_evidence,
                hash_code=hash_code,
                now=now,
            )
        )
    return findings


async def _create_one(
    session: AsyncSession,
    *,
    engagement: Engagement,
    target: Target,
    scan: Scan,
    scanner_run: ScannerRun,
    result: ScannerResult,
    nf: NormalizedFinding,
    raw_evidence: Evidence | None,
    hash_code: bytes,
    now: datetime,
) -> Finding:
    finding = Finding(
        engagement_id=engagement.id,
        target_id=target.id,
        scan_id=scan.id,
        scanner_run_id=scanner_run.id,
        rule_id=nf.rule_id,
        title=nf.title,
        message=nf.message,
        sarif_level=_SEVERITY_TO_SARIF[nf.severity],
        location={
            **nf.location,
            "scanner": result.scanner_name,
            "scanner_version": result.scanner_version,
            "rules_digest": result.rules_digest,
        },
        severity=nf.severity,
        provenance=FindingProvenance.AUTOMATED,
        status=FindingStatus.OPEN,
        hash_code=hash_code,
        partial_fingerprints={
            "scanner": result.scanner_name,
            "fingerprint": nf.fingerprint,
            "rule_id": nf.rule_id,
        },
        description=nf.description,
        recommendation=nf.recommendation,
        created_at=now,
        updated_at=now,
    )
    session.add(finding)
    await session.flush()
    if raw_evidence is not None:
        session.add(
            FindingEvidence(
                finding_id=finding.id,
                evidence_id=raw_evidence.id,
                caption=f"raw {result.scanner_name} output",
            )
        )
    session.add(
        FindingStatusHistory(
            finding_id=finding.id,
            from_status=None,
            to_status=FindingStatus.OPEN,
            changed_by=None,
            reason=f"opened by {result.scanner_name} scanner",
            changed_at=now,
        )
    )
    await session.flush()
    return finding
