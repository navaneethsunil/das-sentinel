"""M2-F3: the findings read projection (pure — no DB, no pyrit).

Proves `FindingOut`/`FindingDetailOut` lift the OWASP-LLM tag, technique, and
suite out of `finding.location` for display, degrade to null when those keys are
absent (a non-suite finding), and that the detail projection carries evidence +
status history. The org-scoped queries and the evidence-link guard are proven
live in scripts/verify_findings.py.
"""

import uuid
from datetime import UTC, datetime

from app.models.evidence import Evidence, EvidenceKind
from app.models.finding import (
    Finding,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
    SarifLevel,
    Severity,
)
from app.schemas.findings import FindingDetailOut, FindingOut

_NOW = datetime(2026, 7, 21, tzinfo=UTC)


def _suite_finding() -> Finding:
    return Finding(
        id=uuid.uuid4(),
        engagement_id=uuid.uuid4(),
        target_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        test_run_id=uuid.uuid4(),
        rule_id="pi.direct.system-override",
        title="Direct system-prompt override",
        message="Direct system-prompt override — Prompt Injection (LLM01) via direct",
        sarif_level=SarifLevel.ERROR,
        location={
            "owasp": {"framework": "OWASP-LLM-2025", "code": "LLM01", "title": "Prompt Injection"},
            "technique": "direct",
            "suite": "prompt_injection",
            "engine": "pyrit",
            "detector_evidence": "PWNED",
        },
        severity=Severity.HIGH,
        provenance=FindingProvenance.AUTOMATED,
        status=FindingStatus.OPEN,
        is_false_positive=False,
        description="The model followed an injected instruction.",
        recommendation="Enforce instruction hierarchy.",
        partial_fingerprints={"suite": "prompt_injection", "probe": "pi.direct.system-override"},
        created_at=_NOW,
        updated_at=_NOW,
    )


def test_finding_out_lifts_owasp_tag_and_technique() -> None:
    out = FindingOut.from_model(_suite_finding())
    assert out.owasp is not None
    assert out.owasp.code == "LLM01"
    assert out.owasp.title == "Prompt Injection"
    assert out.technique == "direct"
    assert out.suite == "prompt_injection"
    assert out.provenance is FindingProvenance.AUTOMATED
    assert out.status is FindingStatus.OPEN


def test_finding_out_degrades_when_location_has_no_owasp() -> None:
    f = _suite_finding()
    f.location = {"file": "app/x.py", "line": 12}  # a future scanner-style location
    out = FindingOut.from_model(f)
    assert out.owasp is None
    assert out.technique is None
    assert out.suite is None


def test_finding_out_handles_null_location() -> None:
    f = _suite_finding()
    f.location = None
    out = FindingOut.from_model(f)
    assert out.owasp is None
    assert out.technique is None


def test_finding_detail_carries_evidence_and_history() -> None:
    f = _suite_finding()
    evidence = Evidence(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        object_key="sha256/abc",
        content_sha256=b"\x01\x02\x03",
        size_bytes=42,
        content_type="application/json",
        kind=EvidenceKind.LLM_TRANSCRIPT,
        created_at=_NOW,
    )
    history = [
        FindingStatusHistory(
            id=uuid.uuid4(),
            finding_id=f.id,
            from_status=None,
            to_status=FindingStatus.OPEN,
            changed_by=None,
            reason="opened by prompt_injection suite (pyrit)",
            changed_at=_NOW,
        )
    ]
    detail = FindingDetailOut.from_model(f, [(evidence, "prompt_injection transcript")], history)

    assert detail.owasp is not None and detail.owasp.code == "LLM01"
    assert detail.description == "The model followed an injected instruction."
    assert len(detail.evidence) == 1
    assert detail.evidence[0].content_sha256 == "010203"  # bytes → hex
    assert detail.evidence[0].caption == "prompt_injection transcript"
    assert detail.evidence[0].kind is EvidenceKind.LLM_TRANSCRIPT
    assert len(detail.status_history) == 1
    assert detail.status_history[0].to_status is FindingStatus.OPEN
    assert detail.status_history[0].from_status is None
