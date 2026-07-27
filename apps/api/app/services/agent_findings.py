"""Persist agent-permission suite results as findings (M5, slice 4).

The agent-target sibling of services/findings.py (LLM suites) and
services/scanner_findings.py (scanners): turns each SUCCEEDED probe (the agent
crossed a permission boundary) into a `findings` row carrying the concrete
monitored transcript as immutable evidence, a stable dedup identity, and its
OWASP LLM06 (Excessive Agency) + OWASP-Agentic-2026 ASI02 (Tool Misuse) mapping.

Because the verdict is a deterministic read of the monitored transcript (not a
model judgement, §2.6), these are `automated` findings that start `open`; the
append-only status history records the creation, and nothing here can mark a
finding confirmed/fixed (§2.9 holds by construction). Idempotent: a re-run whose
probe produces the same `hash_code` reuses the existing finding.
"""

import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent.corpus import agentic_ref
from app.agent.suite import AgentPermissionSuiteResult, AgentProbeResult
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
from app.services.finding_hash import PF_FINGERPRINT, PF_SOURCE, compute_hash_code
from app.storage.evidence import BlobStore, store_evidence
from app.suites.owasp_llm import owasp_llm_ref

_SUITE = "agent_permission"

_SEVERITY_TO_SARIF = {
    Severity.CRITICAL: SarifLevel.ERROR,
    Severity.HIGH: SarifLevel.ERROR,
    Severity.MEDIUM: SarifLevel.WARNING,
    Severity.LOW: SarifLevel.NOTE,
    Severity.INFORMATIONAL: SarifLevel.NONE,
}


def serialize_probe_result(probe_result: AgentProbeResult) -> bytes:
    """Canonical JSON of ONE probe result (verdict + full monitored transcript) —
    the evidence blob a finding cites. Deterministic (sorted keys) so identical
    results content-address to one object."""
    return json.dumps(
        probe_result.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


async def create_findings_from_agent_suite(
    session: AsyncSession,
    store: BlobStore,
    *,
    engagement: Engagement,
    target: Target,
    scan: Scan,
    test_run: TestRun,
    suite_result: AgentPermissionSuiteResult,
    now: datetime,
) -> list[Finding]:
    """Persist one finding per succeeded probe (flushed, not committed — commits
    with the caller's transaction). Returns the findings (new or pre-existing)."""
    findings: list[Finding] = []
    for probe_result in suite_result.succeeded:
        probe = probe_result.probe
        hash_code = compute_hash_code(engagement.id, target.id, _SUITE, probe.probe_id)
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
    probe_result: AgentProbeResult,
    hash_code: bytes,
    now: datetime,
) -> Finding:
    probe = probe_result.probe
    owasp = owasp_llm_ref(probe.owasp)
    asi = agentic_ref(probe.asi)
    evidence = await store_evidence(
        session,
        store,
        organization_id=engagement.organization_id,
        content=serialize_probe_result(probe_result),
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
        message=f"{probe.title} — {owasp['code']} {owasp['title']} / {asi['code']} {asi['title']}",
        sarif_level=_SEVERITY_TO_SARIF[probe.severity],
        location={
            "owasp": owasp,
            "asi": asi,
            "category": probe.category.value,
            "watch_tool": probe.watch_tool,
            "suite": _SUITE,
            "violation_evidence": probe_result.evidence,
        },
        severity=probe.severity,
        provenance=FindingProvenance.AUTOMATED,
        status=FindingStatus.OPEN,
        hash_code=hash_code,
        partial_fingerprints={
            PF_SOURCE: _SUITE,
            PF_FINGERPRINT: probe.probe_id,
            "category": probe.category.value,
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
            caption=f"agent permission transcript ({probe.category.value})",
        )
    )
    session.add(
        FindingStatusHistory(
            finding_id=finding.id,
            from_status=None,
            to_status=FindingStatus.OPEN,
            changed_by=None,
            reason=f"opened by agent_permission suite ({probe.category.value})",
            changed_at=now,
        )
    )
    await session.flush()
    return finding
