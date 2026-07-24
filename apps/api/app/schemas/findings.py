"""Finding read schemas (M2-F3) — the read-only projection the findings UI renders.

Findings are created by the suite path (services/findings.py); this module only
*reads* them. `FindingOut` is the list projection; `FindingDetailOut` adds the
full text, the linked evidence rows, and the append-only status history.
`EvidenceContentOut` carries a single transcript's bytes decoded to text — served
through the API (which re-verifies the SHA-256 via the storage abstraction) so the
browser never talks to object storage directly.

The OWASP-LLM tag, technique, and suite are lifted out of `finding.location` for
convenience; a finding without those keys (e.g. a future scanner finding) simply
reports them as null rather than failing.
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.evidence import Evidence, EvidenceKind
from app.models.finding import (
    Finding,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
    SarifLevel,
    Severity,
)


class OwaspRef(BaseModel):
    framework: str
    code: str
    title: str


def _owasp_from_location(location: dict[str, Any] | None) -> OwaspRef | None:
    if not isinstance(location, dict):
        return None
    owasp = location.get("owasp")
    if isinstance(owasp, dict) and all(k in owasp for k in ("framework", "code", "title")):
        return OwaspRef(framework=owasp["framework"], code=owasp["code"], title=owasp["title"])
    return None


def _location_str(location: dict[str, Any] | None, key: str) -> str | None:
    if not isinstance(location, dict):
        return None
    value = location.get(key)
    return value if isinstance(value, str) else None


class FindingOut(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    target_id: uuid.UUID
    scan_id: uuid.UUID | None
    test_run_id: uuid.UUID | None
    rule_id: str | None
    title: str
    message: str
    severity: Severity
    sarif_level: SarifLevel | None
    provenance: FindingProvenance
    status: FindingStatus
    is_false_positive: bool
    owasp: OwaspRef | None
    technique: str | None
    suite: str | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, f: Finding) -> "FindingOut":
        return cls(**_base_fields(f))


def _base_fields(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "engagement_id": f.engagement_id,
        "target_id": f.target_id,
        "scan_id": f.scan_id,
        "test_run_id": f.test_run_id,
        "rule_id": f.rule_id,
        "title": f.title,
        "message": f.message,
        "severity": f.severity,
        "sarif_level": f.sarif_level,
        "provenance": f.provenance,
        "status": f.status,
        "is_false_positive": f.is_false_positive,
        "owasp": _owasp_from_location(f.location),
        "technique": _location_str(f.location, "technique"),
        "suite": _location_str(f.location, "suite"),
        "created_at": f.created_at,
        "updated_at": f.updated_at,
    }


class FindingEvidenceOut(BaseModel):
    evidence_id: uuid.UUID
    kind: EvidenceKind
    content_type: str
    size_bytes: int
    content_sha256: str  # hex
    caption: str | None
    created_at: datetime

    @classmethod
    def from_row(cls, evidence: Evidence, caption: str | None) -> "FindingEvidenceOut":
        return cls(
            evidence_id=evidence.id,
            kind=evidence.kind,
            content_type=evidence.content_type,
            size_bytes=evidence.size_bytes,
            content_sha256=evidence.content_sha256.hex(),
            caption=caption,
            created_at=evidence.created_at,
        )


class FindingStatusEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    from_status: FindingStatus | None
    to_status: FindingStatus
    changed_by: uuid.UUID | None
    reason: str | None
    changed_at: datetime


class FindingDetailOut(FindingOut):
    description: str | None
    impact: str | None
    recommendation: str | None
    location: dict[str, Any] | None
    partial_fingerprints: dict[str, Any] | None
    duplicate_of: uuid.UUID | None
    evidence: list[FindingEvidenceOut]
    status_history: list[FindingStatusEntryOut]

    @classmethod
    def from_model(  # type: ignore[override]
        cls,
        f: Finding,
        evidence: list[tuple[Evidence, str | None]],
        history: list[FindingStatusHistory],
    ) -> "FindingDetailOut":
        return cls(
            **_base_fields(f),
            description=f.description,
            impact=f.impact,
            recommendation=f.recommendation,
            location=f.location,
            partial_fingerprints=f.partial_fingerprints,
            duplicate_of=f.duplicate_of,
            evidence=[FindingEvidenceOut.from_row(e, cap) for e, cap in evidence],
            status_history=[FindingStatusEntryOut.model_validate(h) for h in history],
        )


class SarifImportOut(BaseModel):
    """Result of importing a SARIF 2.1.0 log for a target (M3-B2). `created` are
    novel findings; `duplicates` matched an existing finding by hash_code and were
    linked `duplicate_of`. The raw SARIF is stored once as cited evidence."""

    target_id: uuid.UUID
    evidence_id: uuid.UUID
    created: int
    duplicates: int
    finding_ids: list[uuid.UUID]


class EvidenceContentOut(BaseModel):
    """A single evidence blob's content, fetched and integrity-verified server-side.
    Transcripts are UTF-8 JSON; `content` is the decoded text for the viewer."""

    evidence_id: uuid.UUID
    kind: EvidenceKind
    content_type: str
    size_bytes: int
    content_sha256: str  # hex
    content: str
