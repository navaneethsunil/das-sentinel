"""SARIF 2.1.0 import/export + reimport dedup (M3-B2).

Findings are a superset of SARIF 2.1.0 (DATABASE_SCHEMA §7), so we can hand a
SARIF log to any consumer and ingest one from any producer.

Export: `build_sarif_log(findings)` emits a single-run SARIF log. Each result
carries its source + fingerprint + the exact `hash_code` (hex) in
`partialFingerprints`, so a DAS-exported log re-imports to the SAME identity.

Import: `import_sarif_findings(...)` parses a SARIF log for one target and, per
result, computes the canonical `hash_code` (TR-20 / finding_hash) — preferring the
exported hash when present, else deriving it from source + fingerprint. If a live
finding with that hash already exists for the target, the imported row is linked
`duplicate_of` the original instead of standing alone as a new open finding; a
novel result is created fresh. The raw SARIF is stored once as immutable evidence
and every imported finding cites it (chain of custody, §2.6).

Parsing is bounded and fail-closed (TM-8): oversized/malformed/over-count input
raises `SarifError` and nothing is imported. (The hostile-input fuzz matrix is
M3-SEC2; this module already refuses the obvious bad shapes.)
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

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
from app.models.scan import Scan
from app.models.target import Target
from app.services.finding_hash import (
    PF_FINGERPRINT,
    PF_SOURCE,
    compute_hash_code,
    location_fingerprint,
)
from app.storage.evidence import BlobStore, store_evidence

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_TOOL_NAME = "DAS Sentinel"
_HASH_KEY = "dasHash/v1"  # exact round-trip identity carried in partialFingerprints

# Bounds — refuse a hostile/oversized log before doing any work (TM-8).
MAX_SARIF_BYTES = 16 * 1024 * 1024
MAX_SARIF_RESULTS = 5000

_SARIF_LEVEL_STR = {
    SarifLevel.NONE: "none",
    SarifLevel.NOTE: "note",
    SarifLevel.WARNING: "warning",
    SarifLevel.ERROR: "error",
}
_STR_TO_LEVEL = {v: k for k, v in _SARIF_LEVEL_STR.items()}
_LEVEL_TO_SEVERITY = {
    SarifLevel.ERROR: Severity.HIGH,
    SarifLevel.WARNING: Severity.MEDIUM,
    SarifLevel.NOTE: Severity.LOW,
    SarifLevel.NONE: Severity.INFORMATIONAL,
}


class SarifError(Exception):
    """The SARIF document is oversized, malformed, or unsupported. Fail closed —
    nothing is imported."""


# ── Export ───────────────────────────────────────────────────────────────────
def _physical_location(location: dict[str, Any] | None) -> dict[str, Any] | None:
    loc = location if isinstance(location, dict) else {}
    uri = loc.get("file") or loc.get("url") or loc.get("endpoint")
    if not uri:
        return None
    physical: dict[str, Any] = {"artifactLocation": {"uri": str(uri)}}
    region: dict[str, Any] = {}
    if isinstance(loc.get("start_line"), int):
        region["startLine"] = loc["start_line"]
    if isinstance(loc.get("end_line"), int):
        region["endLine"] = loc["end_line"]
    if region:
        physical["region"] = region
    return {"physicalLocation": physical}


def _result_for(finding: Finding) -> dict[str, Any]:
    pf: dict[str, Any] = dict(finding.partial_fingerprints or {})
    pf[_HASH_KEY] = finding.hash_code.hex()
    result: dict[str, Any] = {
        "ruleId": finding.rule_id or str(pf.get(PF_SOURCE) or "das"),
        "level": _SARIF_LEVEL_STR.get(finding.sarif_level or SarifLevel.WARNING, "warning"),
        "message": {"text": finding.message},
        "partialFingerprints": pf,
        "properties": {
            "severity": finding.severity.value,
            "provenance": finding.provenance.value,
            "status": finding.status.value,
            "dasFindingId": str(finding.id),
        },
    }
    physical = _physical_location(finding.location)
    if physical is not None:
        result["locations"] = [physical]
    return result


def build_sarif_log(findings: list[Finding], *, tool_name: str = _TOOL_NAME) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log (single run) from findings. Each result embeds the
    exact hash_code so the log re-imports to the same identity (round-trip)."""
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": {"name": tool_name, "informationUri": "https://das.local"}},
                "results": [_result_for(f) for f in findings],
            }
        ],
    }


# ── Import ───────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ParsedResult:
    rule_id: str | None
    sarif_level: SarifLevel
    message: str
    location: dict[str, Any]
    source: str
    fingerprint: str
    exported_hash: bytes | None


@dataclass
class SarifImportSummary:
    evidence_id: uuid.UUID
    created: list[Finding] = field(default_factory=list)
    duplicates: list[Finding] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return self.created + self.duplicates


def parse_sarif(raw: bytes) -> dict[str, Any]:
    """Bounded, fail-closed parse of a SARIF log's bytes → dict. No unsafe
    deserialization; malformed/oversized/wrong-version raises SarifError."""
    if len(raw) > MAX_SARIF_BYTES:
        raise SarifError(f"SARIF exceeds {MAX_SARIF_BYTES}-byte cap")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise SarifError(f"SARIF is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise SarifError("SARIF root is not an object")
    if str(doc.get("version")) != SARIF_VERSION:
        raise SarifError(f"unsupported SARIF version {doc.get('version')!r} (need {SARIF_VERSION})")
    if not isinstance(doc.get("runs"), list):
        raise SarifError("SARIF 'runs' is missing or not a list")
    return doc


def _parse_location(result: dict[str, Any]) -> dict[str, Any]:
    loc: dict[str, Any] = {}
    locs = result.get("locations")
    if isinstance(locs, list) and locs and isinstance(locs[0], dict):
        physical = locs[0].get("physicalLocation")
        if isinstance(physical, dict):
            art = physical.get("artifactLocation")
            if isinstance(art, dict) and art.get("uri"):
                loc["file"] = str(art["uri"])
            region = physical.get("region")
            if isinstance(region, dict):
                if isinstance(region.get("startLine"), int):
                    loc["start_line"] = region["startLine"]
                if isinstance(region.get("endLine"), int):
                    loc["end_line"] = region["endLine"]
    return loc


def _exported_hash(pf: dict[str, Any]) -> bytes | None:
    raw = pf.get(_HASH_KEY)
    if not isinstance(raw, str):
        return None
    try:
        digest = bytes.fromhex(raw)
    except ValueError:
        return None
    return digest if len(digest) == 32 else None


def iter_results(doc: dict[str, Any]) -> list[ParsedResult]:
    """Flatten a parsed SARIF log's runs → results into ParsedResults. Skips
    non-dict runs/results defensively; refuses a log over the result cap (TM-8)."""
    parsed: list[ParsedResult] = []
    for run in doc.get("runs", []):
        if not isinstance(run, dict):
            continue
        tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
        driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
        driver_name = str(driver.get("name") or "imported")
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            if len(parsed) >= MAX_SARIF_RESULTS:
                raise SarifError(f"SARIF exceeds {MAX_SARIF_RESULTS}-result cap")
            rule_id = str(result["ruleId"]) if result.get("ruleId") is not None else None
            level_str = result.get("level")
            sarif_level = _STR_TO_LEVEL.get(str(level_str), SarifLevel.WARNING)
            message = ""
            msg = result.get("message")
            if isinstance(msg, dict) and isinstance(msg.get("text"), str):
                message = msg["text"]
            pf = result.get("partialFingerprints")
            pf = pf if isinstance(pf, dict) else {}
            location = _parse_location(result)
            source = str(pf.get(PF_SOURCE) or driver_name)
            fingerprint = str(pf.get(PF_FINGERPRINT) or location_fingerprint(rule_id, location))
            parsed.append(
                ParsedResult(
                    rule_id=rule_id,
                    sarif_level=sarif_level,
                    message=message or (rule_id or "imported finding"),
                    location=location,
                    source=source,
                    fingerprint=fingerprint,
                    exported_hash=_exported_hash(pf),
                )
            )
    return parsed


async def _existing_canonical(
    session: AsyncSession, target_id: uuid.UUID, hash_code: bytes
) -> Finding | None:
    """The oldest live, non-duplicate finding for this target with this hash — the
    canonical original a reimport links to."""
    return (
        await session.execute(
            select(Finding)
            .where(
                Finding.target_id == target_id,
                Finding.hash_code == hash_code,
                Finding.deleted_at.is_(None),
                Finding.duplicate_of.is_(None),
            )
            .order_by(Finding.created_at)
            .limit(1)
        )
    ).scalar_one_or_none()


async def import_sarif_findings(
    session: AsyncSession,
    store: BlobStore,
    *,
    engagement: Engagement,
    target: Target,
    raw: bytes,
    now: datetime,
    scan: Scan | None = None,
) -> SarifImportSummary:
    """Import a SARIF log's results as findings for `target`. On a hash_code
    collision with a live finding for the target, the imported row is linked
    `duplicate_of` the original (TR-20). Flushed, not committed — commits with the
    caller's transaction. The raw SARIF is stored once as immutable evidence and
    every imported finding cites it."""
    results = iter_results(parse_sarif(raw))
    evidence = await store_evidence(
        session,
        store,
        organization_id=engagement.organization_id,
        content=raw,
        kind=EvidenceKind.RAW_SCANNER_OUTPUT,
        content_type="application/sarif+json",
    )
    summary = SarifImportSummary(evidence_id=evidence.id)
    for pr in results:
        hash_code = pr.exported_hash or compute_hash_code(
            engagement.id, target.id, pr.source, pr.fingerprint
        )
        original = await _existing_canonical(session, target.id, hash_code)
        finding = Finding(
            engagement_id=engagement.id,
            target_id=target.id,
            scan_id=scan.id if scan is not None else None,
            rule_id=pr.rule_id,
            title=pr.rule_id or pr.source,
            message=pr.message,
            sarif_level=pr.sarif_level,
            location={**pr.location, PF_SOURCE: pr.source, "imported_from": "sarif"},
            severity=_LEVEL_TO_SEVERITY[pr.sarif_level],
            provenance=FindingProvenance.AUTOMATED,
            status=FindingStatus.OPEN,
            hash_code=hash_code,
            partial_fingerprints={
                PF_SOURCE: pr.source,
                PF_FINGERPRINT: pr.fingerprint,
                "imported": True,
            },
            duplicate_of=original.id if original is not None else None,
            created_at=now,
            updated_at=now,
        )
        session.add(finding)
        await session.flush()
        session.add(
            FindingEvidence(
                finding_id=finding.id,
                evidence_id=evidence.id,
                caption=f"imported SARIF ({pr.source})",
            )
        )
        session.add(
            FindingStatusHistory(
                finding_id=finding.id,
                from_status=None,
                to_status=FindingStatus.OPEN,
                changed_by=None,
                reason=f"imported from SARIF ({pr.source})",
                changed_at=now,
            )
        )
        await session.flush()
        (summary.duplicates if original is not None else summary.created).append(finding)
    return summary
