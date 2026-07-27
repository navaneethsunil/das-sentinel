"""Deterministic scan-plan generation (M4) — recommend next scans from recon.

ROADMAP §M4: "recommend next scans from recon + target type." This module is
entirely deterministic (no LLM, no mutation): it maps a target's type to the
scanners that apply, then refines the rationale/ordering using the INFORMATIONAL
recon facts already gathered for that target (httpx technologies, katana
endpoints). It is READ-ONLY analysis — it recommends, it never launches a scan
(that still goes through the authorized launch_scan path). A recommendation is
flagged `already_run` when a completed scan of that kind exists for the target, so
the plan shows what is left to do.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus, TestRun
from app.models.scanner import ScannerRun
from app.models.target import Target, TargetType


@dataclass(frozen=True)
class ScanRecommendation:
    scanner: str  # scanner adapter name or LLM suite name
    category: str  # recon | sast | sca | secrets | dast | llm
    reason: str
    already_run: bool


@dataclass(frozen=True)
class ScanPlan:
    target_id: uuid.UUID
    target_type: str
    detected_technologies: list[str]
    endpoints_discovered: int
    recommendations: list[ScanRecommendation]


# (scanner, category, base reason) per target type. Ordered recon → deep.
_WEB = [
    ("httpx", "recon", "Fingerprint the web endpoint (tech, headers, TLS)."),
    ("katana", "recon", "Crawl in-scope to map the endpoint/URL surface."),
    ("testssl", "recon", "Assess the endpoint's TLS protocol/cipher/certificate posture."),
    ("nuclei", "dast", "Run safe-active template checks against the web target."),
    ("zap", "dast", "Run a DAST baseline against the web target."),
]
_API = [
    ("httpx", "recon", "Fingerprint the API endpoint (tech, headers, TLS)."),
    ("testssl", "recon", "Assess the endpoint's TLS protocol/cipher/certificate posture."),
    ("nuclei", "dast", "Run safe-active template checks against the API."),
    ("zap", "dast", "Run a DAST baseline against the API."),
]
_SOURCE = [
    ("semgrep", "sast", "Static analysis over the source tree."),
    ("gitleaks", "secrets", "Scan the source for hardcoded secrets."),
    ("osv-scanner", "sca", "Check dependencies for known vulnerabilities."),
]
_LLM = [
    ("prompt_injection", "llm", "Run the prompt-injection suite against the model."),
    ("data_leakage", "llm", "Run the data-leakage suite against the model."),
]

_PLAN_BY_TYPE: dict[TargetType, list[tuple[str, str, str]]] = {
    TargetType.WEB_APP: _WEB,
    TargetType.REST_API: _API,
    TargetType.GRAPHQL_API: _API,
    TargetType.SOURCE_REPO: _SOURCE,
    TargetType.SOURCE_ARCHIVE: _SOURCE,
    TargetType.AI_CHATBOT: _LLM,
    TargetType.LLM_API_WRAPPER: _LLM,
    TargetType.AI_AGENT: _LLM,
}


def recon_signals(findings: list[Finding]) -> tuple[list[str], int]:
    """Extract recon signals from a target's findings: the distinct detected
    technologies (httpx-tech facts) and the count of discovered endpoints
    (katana-endpoint facts). Pure."""
    techs: set[str] = set()
    endpoints = 0
    for f in findings:
        loc = f.location if isinstance(f.location, dict) else {}
        if f.rule_id == "httpx-tech":
            tech = loc.get("technology")
            if isinstance(tech, str) and tech:
                techs.add(tech)
        elif f.rule_id == "katana-endpoint":
            endpoints += 1
    return sorted(techs), endpoints


def build_recommendations(
    target_type: TargetType,
    *,
    detected_techs: list[str],
    endpoint_count: int,
    ran_sources: set[str],
) -> list[ScanRecommendation]:
    """Deterministic recommendations for a target type, with reasons refined by the
    recon signals and each flagged `already_run`. Pure — no DB, no LLM."""
    recs: list[ScanRecommendation] = []
    for scanner, category, reason in _PLAN_BY_TYPE.get(target_type, []):
        refined = reason
        if scanner in ("nuclei", "zap") and endpoint_count:
            refined = f"{reason} ({endpoint_count} endpoint(s) mapped by recon)."
        if scanner == "nuclei" and detected_techs:
            refined = f"{refined} Recon detected: {', '.join(detected_techs[:5])}."
        recs.append(
            ScanRecommendation(
                scanner=scanner,
                category=category,
                reason=refined,
                already_run=scanner in ran_sources,
            )
        )
    return recs


async def _target_findings(db: AsyncSession, engagement_id: uuid.UUID, target_id: uuid.UUID):  # noqa: ANN202
    stmt = select(Finding).where(
        Finding.engagement_id == engagement_id,
        Finding.target_id == target_id,
        Finding.deleted_at.is_(None),
        Finding.duplicate_of.is_(None),
    )
    return list((await db.execute(stmt)).scalars())


async def _ran_sources(db: AsyncSession, target_id: uuid.UUID) -> set[str]:
    """Scan kinds already COMPLETED for this target — scanner names from
    scanner_runs and LLM suite names from test_runs — so the plan can mark
    recommendations `already_run`."""
    scanner_names = (
        await db.execute(
            select(ScannerRun.scanner_name)
            .join(Scan, ScannerRun.scan_id == Scan.id)
            .where(Scan.target_id == target_id, ScannerRun.status == ScanStatus.COMPLETED)
        )
    ).scalars()
    suites = (
        await db.execute(
            select(TestRun.suite)
            .join(Scan, TestRun.scan_id == Scan.id)
            .where(Scan.target_id == target_id, TestRun.status == ScanStatus.COMPLETED)
        )
    ).scalars()
    ran: set[str] = {str(n) for n in scanner_names}
    ran |= {s.value for s in suites}
    return ran


async def scan_plan_for_target(
    db: AsyncSession, engagement_id: uuid.UUID, target: Target
) -> ScanPlan:
    """Build the deterministic scan plan for one target from its type + recon."""
    findings = await _target_findings(db, engagement_id, target.id)
    techs, endpoints = recon_signals(findings)
    ran = await _ran_sources(db, target.id)
    return ScanPlan(
        target_id=target.id,
        target_type=target.target_type.value,
        detected_technologies=techs,
        endpoints_discovered=endpoints,
        recommendations=build_recommendations(
            target.target_type,
            detected_techs=techs,
            endpoint_count=endpoints,
            ran_sources=ran,
        ),
    )
