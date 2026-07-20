"""Create findings from an AI/LLM suite run (M2-B4).

Turns a `SuiteResult`'s successful probes into `findings` rows, each carrying:
concrete transcript evidence (stored once, content-addressed), a stable dedup
identity (`hash_code` + `partial_fingerprints`), and its OWASP-LLM mapping. Because
the suite's detector is deterministic, these are `automated` findings — not
`ai_generated` — and start `open`; the append-only status history records the
creation. The provenance/status rule (an unreviewed AI finding is never presented
as verified — §2.9) is upheld by construction: nothing here can set a finding to
confirmed/fixed.

Idempotent: a re-run whose probe produces the same `hash_code` reuses the existing
finding instead of duplicating it (content-addressed evidence dedups likewise).
"""

import hashlib
import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.engagement import Engagement
from app.models.evidence import EvidenceKind
from app.models.finding import (
    Finding,
    FindingEvidence,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
    SarifLevel,
    Severity,
)
from app.models.scan import Scan, TestRun
from app.models.target import Target
from app.storage.evidence import BlobStore, store_evidence
from app.suites.base import ProbeResult, SuiteResult, serialize_probe_transcript
from app.suites.owasp_llm import owasp_llm_ref

_SEVERITY_TO_SARIF = {
    Severity.CRITICAL: SarifLevel.ERROR,
    Severity.HIGH: SarifLevel.ERROR,
    Severity.MEDIUM: SarifLevel.WARNING,
    Severity.LOW: SarifLevel.NOTE,
    Severity.INFORMATIONAL: SarifLevel.NONE,
}


def _hash_code(engagement_id: uuid.UUID, target_id: uuid.UUID, suite: str, probe_id: str) -> bytes:
    """Stable dedup identity — same probe against the same target in the same
    engagement is the same finding across runs."""
    return hashlib.sha256(f"{engagement_id}|{target_id}|{suite}|{probe_id}".encode()).digest()


async def create_findings_from_suite(
    session: AsyncSession,
    store: BlobStore,
    *,
    engagement: Engagement,
    target: Target,
    scan: Scan,
    test_run: TestRun,
    suite_result: SuiteResult,
    now: datetime,
) -> list[Finding]:
    """Persist one finding per successful probe (flushed, not committed — commits
    atomically with the caller's transaction, like store_evidence). Returns the
    findings (new or pre-existing)."""
    findings: list[Finding] = []
    for probe_result in suite_result.succeeded:
        probe = probe_result.probe
        hash_code = _hash_code(engagement.id, target.id, suite_result.suite, probe.probe_id)
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
                store,
                engagement=engagement,
                target=target,
                scan=scan,
                test_run=test_run,
                suite_result=suite_result,
                probe_result=probe_result,
                hash_code=hash_code,
                now=now,
            )
        )
    return findings


async def _create_one(
    session: AsyncSession,
    store: BlobStore,
    *,
    engagement: Engagement,
    target: Target,
    scan: Scan,
    test_run: TestRun,
    suite_result: SuiteResult,
    probe_result: ProbeResult,
    hash_code: bytes,
    now: datetime,
) -> Finding:
    probe = probe_result.probe
    owasp = owasp_llm_ref(probe.owasp)
    evidence = await store_evidence(
        session,
        store,
        organization_id=engagement.organization_id,
        content=serialize_probe_transcript(probe_result),
        kind=EvidenceKind.LLM_TRANSCRIPT,
        content_type="application/json",
    )
    finding = Finding(
        engagement_id=engagement.id,
        target_id=target.id,
        scan_id=scan.id,
        test_run_id=test_run.id,
        rule_id=probe.probe_id,
        title=probe.title,
        message=f"{probe.title} — {owasp['title']} ({owasp['code']}) via {probe.technique.value}",
        sarif_level=_SEVERITY_TO_SARIF[probe.severity],
        location={
            "owasp": owasp,
            "technique": probe.technique.value,
            "suite": suite_result.suite,
            "engine": suite_result.engine,
            "engine_version": suite_result.engine_version,
            "probe_bundle_sha256": suite_result.bundle_sha256,
            "detector_evidence": probe_result.evidence,
        },
        severity=probe.severity,
        provenance=FindingProvenance.AUTOMATED,
        status=FindingStatus.OPEN,
        hash_code=hash_code,
        partial_fingerprints={
            "suite": suite_result.suite,
            "probe": probe.probe_id,
            "bundle": suite_result.bundle_id,
        },
        description=probe.description,
        recommendation=probe.recommendation,
        created_at=now,
        updated_at=now,
    )
    session.add(finding)
    await session.flush()
    session.add(
        FindingEvidence(
            finding_id=finding.id,
            evidence_id=evidence.id,
            caption=f"{suite_result.suite} transcript",
        )
    )
    session.add(
        FindingStatusHistory(
            finding_id=finding.id,
            from_status=None,
            to_status=FindingStatus.OPEN,
            changed_by=None,
            reason=f"opened by {suite_result.suite} suite ({suite_result.engine})",
            changed_at=now,
        )
    )
    await session.flush()
    return finding
