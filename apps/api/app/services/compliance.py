"""Compliance KB loader + finding↔control mapping (M3-B4) — DATABASE_SCHEMA §10.

Two responsibilities, deliberately separated:

  1. **Seed** the versioned knowledge base in `packages/compliance/*.json` (OWASP LLM
     2025, WSTG v4.2, NIST AI RMF, NIST AI 600-1, NIST 800-53 Rev 5.2.0, NIST 800-115)
     into `compliance_frameworks` + `compliance_controls`. Idempotent upsert — a
     re-seed updates names/titles and adds new controls, never deleting. Reading the
     KB is a deploy/operational step (a mounted or baked KB dir), not a per-request
     path, so the API never needs the files.

  2. **Map** findings to controls. Auto-mapping is *exact/identity*: a finding that
     already carries a structured OWASP-LLM reference (stamped deterministically by
     the M2 suites, app/suites/owasp_llm.py) is linked to the `owasp_llm_2025`
     control of that code. The tool never *invents* a cross-framework mapping
     (CLAUDE.md §2.6) — cross-walks to WSTG/NIST are added by a human via the manual
     edit path, recorded with mapped_by=VALIDATED. Auto mappings are mapped_by
     AUTOMATED. Everything is idempotent.
"""

import json
import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    FindingComplianceMapping,
)
from app.models.finding import Finding, FindingProvenance

# The framework strings our LLM suites stamp on findings' location.owasp block map to
# this KB framework key. Auto-mapping is identity (LLMnn code → that control).
_OWASP_LLM_ALIASES = frozenset({"owasp-llm-2025", "owasp llm 2025", "owasp_llm_2025"})
_OWASP_LLM_KEY = "owasp_llm_2025"


class ComplianceKBError(Exception):
    """The KB directory or one of its files is missing, malformed, or duplicative.
    Fail loud — a bad KB must not silently seed a partial/wrong catalog."""


class ComplianceMappingError(Exception):
    """A mapping request references an unknown control (fail-closed)."""


@dataclass(frozen=True)
class ControlKB:
    code: str
    title: str
    description: str | None


@dataclass(frozen=True)
class FrameworkKB:
    key: str
    name: str
    version: str
    source_url: str | None
    controls: tuple[ControlKB, ...]


def _require_str(doc: dict, field: str, where: str) -> str:
    value = doc.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ComplianceKBError(f"{where}: '{field}' must be a non-empty string")
    return value


def load_kb(kb_dir: Path) -> list[FrameworkKB]:
    """Parse every framework JSON in `kb_dir`. Fails loud on a missing dir, malformed
    JSON, a bad shape, or a duplicate framework key / control code."""
    if not kb_dir.is_dir():
        raise ComplianceKBError(f"compliance KB directory not found: {kb_dir}")
    files = sorted(kb_dir.glob("*.json"))
    if not files:
        raise ComplianceKBError(f"no framework JSON files in {kb_dir}")

    frameworks: list[FrameworkKB] = []
    seen_keys: set[str] = set()
    for path in files:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ComplianceKBError(f"{path.name}: invalid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise ComplianceKBError(f"{path.name}: root must be an object")

        key = _require_str(doc, "key", path.name)
        if key in seen_keys:
            raise ComplianceKBError(f"{path.name}: duplicate framework key {key!r}")
        seen_keys.add(key)
        raw_controls = doc.get("controls")
        if not isinstance(raw_controls, list) or not raw_controls:
            raise ComplianceKBError(f"{path.name}: 'controls' must be a non-empty list")

        controls: list[ControlKB] = []
        seen_codes: set[str] = set()
        for entry in raw_controls:
            if not isinstance(entry, dict):
                raise ComplianceKBError(f"{path.name}: each control must be an object")
            code = _require_str(entry, "code", f"{path.name} control")
            if code in seen_codes:
                raise ComplianceKBError(f"{path.name}: duplicate control code {code!r}")
            seen_codes.add(code)
            title = _require_str(entry, "title", f"{path.name} control {code}")
            desc = entry.get("description")
            controls.append(
                ControlKB(
                    code=code,
                    title=title,
                    description=desc if isinstance(desc, str) and desc.strip() else None,
                )
            )
        source_url = doc.get("source_url")
        frameworks.append(
            FrameworkKB(
                key=key,
                name=_require_str(doc, "name", path.name),
                version=_require_str(doc, "version", path.name),
                source_url=source_url if isinstance(source_url, str) else None,
                controls=tuple(controls),
            )
        )
    return frameworks


async def seed_frameworks(session: AsyncSession, kb_dir: Path) -> dict[str, int]:
    """Idempotent upsert of the KB into the DB. Updates framework metadata + control
    titles/descriptions in place and inserts missing controls; never deletes (a
    control could be cited by a finding, and the FK is RESTRICT). Returns counts of
    frameworks and controls processed. Caller commits."""
    kb = load_kb(kb_dir)
    frameworks = controls = 0
    for fw in kb:
        existing_fw = (
            await session.execute(
                select(ComplianceFramework).where(ComplianceFramework.key == fw.key)
            )
        ).scalar_one_or_none()
        if existing_fw is None:
            existing_fw = ComplianceFramework(
                key=fw.key, name=fw.name, version=fw.version, source_url=fw.source_url
            )
            session.add(existing_fw)
            await session.flush()
        else:
            existing_fw.name = fw.name
            existing_fw.version = fw.version
            existing_fw.source_url = fw.source_url
        frameworks += 1

        existing_controls = {
            c.code: c
            for c in (
                await session.execute(
                    select(ComplianceControl).where(
                        ComplianceControl.framework_id == existing_fw.id
                    )
                )
            ).scalars()
        }
        for c in fw.controls:
            row = existing_controls.get(c.code)
            if row is None:
                session.add(
                    ComplianceControl(
                        framework_id=existing_fw.id,
                        code=c.code,
                        title=c.title,
                        description=c.description,
                    )
                )
            else:
                row.title = c.title
                row.description = c.description
            controls += 1
    await session.flush()
    return {"frameworks": frameworks, "controls": controls}


async def _control_by_framework_code(
    session: AsyncSession, framework_key: str, code: str
) -> ComplianceControl | None:
    return (
        await session.execute(
            select(ComplianceControl)
            .join(ComplianceFramework, ComplianceControl.framework_id == ComplianceFramework.id)
            .where(ComplianceFramework.key == framework_key, ComplianceControl.code == code)
        )
    ).scalar_one_or_none()


async def _mapping_exists(
    session: AsyncSession, finding_id: uuid.UUID, control_id: uuid.UUID
) -> bool:
    return (
        await session.get(
            FindingComplianceMapping, {"finding_id": finding_id, "control_id": control_id}
        )
    ) is not None


async def auto_map_finding(session: AsyncSession, finding: Finding) -> list[uuid.UUID]:
    """Create AUTOMATED mappings from the structured references a finding already
    carries. Currently: an OWASP-LLM-coded finding → the owasp_llm_2025 control of
    that exact code. Idempotent — returns only the control_ids newly linked. Caller
    commits."""
    location = finding.location if isinstance(finding.location, dict) else {}
    owasp = location.get("owasp")
    if not isinstance(owasp, dict):
        return []
    framework = str(owasp.get("framework", "")).strip().lower()
    code = owasp.get("code")
    if framework not in _OWASP_LLM_ALIASES or not isinstance(code, str):
        return []
    control = await _control_by_framework_code(session, _OWASP_LLM_KEY, code)
    if control is None:  # KB not seeded, or a stale/unknown code — map nothing
        return []
    if await _mapping_exists(session, finding.id, control.id):
        return []
    session.add(
        FindingComplianceMapping(
            finding_id=finding.id,
            control_id=control.id,
            mapped_by=FindingProvenance.AUTOMATED,
        )
    )
    await session.flush()
    return [control.id]


async def add_mapping(
    session: AsyncSession,
    finding: Finding,
    control_id: uuid.UUID,
    *,
    mapped_by: FindingProvenance = FindingProvenance.VALIDATED,
    confidence: float | None = None,
) -> FindingComplianceMapping:
    """Add (or return the existing) mapping of a finding to a control. A human-added
    mapping is VALIDATED by default. Unknown control → fail-closed. Caller commits."""
    control = await session.get(ComplianceControl, control_id)
    if control is None:
        raise ComplianceMappingError("unknown control")
    existing = await session.get(
        FindingComplianceMapping, {"finding_id": finding.id, "control_id": control_id}
    )
    if existing is not None:
        return existing
    row = FindingComplianceMapping(
        finding_id=finding.id,
        control_id=control_id,
        mapped_by=mapped_by,
        confidence=confidence,
    )
    session.add(row)
    await session.flush()
    return row


async def remove_mapping(
    session: AsyncSession, finding_id: uuid.UUID, control_id: uuid.UUID
) -> bool:
    """Remove a finding↔control mapping. Returns True if a row was deleted."""
    result = await session.execute(
        delete(FindingComplianceMapping).where(
            FindingComplianceMapping.finding_id == finding_id,
            FindingComplianceMapping.control_id == control_id,
        )
    )
    return bool(result.rowcount)


async def list_frameworks(
    session: AsyncSession,
) -> list[tuple[ComplianceFramework, list[ComplianceControl]]]:
    """All frameworks with their controls (controls sorted by code) — the reference
    catalog the manual-mapping UI picks from."""
    frameworks = list(
        (
            await session.execute(select(ComplianceFramework).order_by(ComplianceFramework.key))
        ).scalars()
    )
    out: list[tuple[ComplianceFramework, list[ComplianceControl]]] = []
    for fw in frameworks:
        controls = list(
            (
                await session.execute(
                    select(ComplianceControl)
                    .where(ComplianceControl.framework_id == fw.id)
                    .order_by(ComplianceControl.code)
                )
            ).scalars()
        )
        out.append((fw, controls))
    return out


async def get_finding_mappings(
    session: AsyncSession, finding_id: uuid.UUID
) -> list[tuple[FindingComplianceMapping, ComplianceControl, ComplianceFramework]]:
    """A finding's control mappings joined to control + framework, for display."""
    rows = (
        await session.execute(
            select(FindingComplianceMapping, ComplianceControl, ComplianceFramework)
            .join(
                ComplianceControl,
                FindingComplianceMapping.control_id == ComplianceControl.id,
            )
            .join(
                ComplianceFramework,
                ComplianceControl.framework_id == ComplianceFramework.id,
            )
            .where(FindingComplianceMapping.finding_id == finding_id)
            .order_by(ComplianceFramework.key, ComplianceControl.code)
        )
    ).all()
    return [(m, c, f) for m, c, f in rows]
