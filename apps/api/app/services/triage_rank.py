"""Deterministic triage: group + rank an engagement's findings (M4-B2).

ROADMAP §M4 triage guardrail — "compute severity DETERMINISTICALLY (CVSS/SSVC);
the LLM explains, it does not decide" (CLAUDE.md §2.6). This module is entirely
deterministic: no LLM, no mutation, no status change. It reads the canonical
(non-duplicate) findings and orders them by a fixed key — severity band, then the
current CVSS base score, then recency — and groups findings that share a weakness
class (rule_id, else discovery source) so related alerts are triaged together.

The per-finding "explain-why" narrative is the separately-guardrailed
`triage_finding` (M2-SEC2); flagging false positives / de-prioritizing remain
human-in-the-loop actions and are not done here.
"""

import uuid
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, Severity
from app.services.cvss import get_current_score
from app.services.finding_hash import PF_SOURCE
from app.services.findings_read import list_engagement_findings

# Ascending = most severe first (stable, deterministic tie-break base).
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


@dataclass(frozen=True)
class RankedFinding:
    finding_id: uuid.UUID
    rank: int  # 1 = highest priority
    severity: Severity
    cvss_base_score: float | None
    group_key: str
    title: str
    rule_id: str | None


@dataclass
class FindingGroup:
    group_key: str
    title: str
    severity: Severity  # the most severe member
    count: int = 0
    top_rank: int = 0  # best (lowest) rank among members
    finding_ids: list[uuid.UUID] = field(default_factory=list)


def group_key_for(finding: Finding) -> str:
    """A finding's weakness-class key: its rule_id, else its discovery source,
    else 'ungrouped' — so the same rule across many locations triages as one group."""
    if finding.rule_id:
        return finding.rule_id
    pf = finding.partial_fingerprints or {}
    source = pf.get(PF_SOURCE) if isinstance(pf, dict) else None
    return str(source) if source else "ungrouped"


def rank_findings(
    findings: list[Finding], cvss_scores: dict[uuid.UUID, float | None]
) -> list[RankedFinding]:
    """Deterministic ranking: severity band, then current CVSS base score
    (unscored sorts last within a band), then recency. Pure — no DB, no LLM."""

    def sort_key(f: Finding) -> tuple:
        score = cvss_scores.get(f.id)
        return (
            _SEVERITY_ORDER.get(f.severity, 99),
            -(score if score is not None else -1.0),  # higher score first; unscored last
            -f.created_at.timestamp(),
        )

    ordered = sorted(findings, key=sort_key)
    return [
        RankedFinding(
            finding_id=f.id,
            rank=i,
            severity=f.severity,
            cvss_base_score=cvss_scores.get(f.id),
            group_key=group_key_for(f),
            title=f.title,
            rule_id=f.rule_id,
        )
        for i, f in enumerate(ordered, start=1)
    ]


def group_ranked(ranked: list[RankedFinding]) -> list[FindingGroup]:
    """Aggregate ranked findings into weakness-class groups, ordered by their best
    member rank. Pure."""
    groups: dict[str, FindingGroup] = {}
    order: list[str] = []
    for rf in ranked:
        group = groups.get(rf.group_key)
        if group is None:
            group = FindingGroup(
                group_key=rf.group_key, title=rf.title, severity=rf.severity, top_rank=rf.rank
            )
            groups[rf.group_key] = group
            order.append(rf.group_key)
        group.count += 1
        group.finding_ids.append(rf.finding_id)
        if _SEVERITY_ORDER.get(rf.severity, 99) < _SEVERITY_ORDER.get(group.severity, 99):
            group.severity = rf.severity  # most severe member represents the group
        group.top_rank = min(group.top_rank, rf.rank)
    return sorted((groups[k] for k in order), key=lambda g: g.top_rank)


async def triage_overview(
    db: AsyncSession, engagement_id: uuid.UUID
) -> tuple[list[RankedFinding], list[FindingGroup]]:
    """Load canonical findings for an engagement, attach each one's current CVSS
    base score, and return the deterministic ranking + grouping."""
    findings = await list_engagement_findings(db, engagement_id)
    cvss_scores: dict[uuid.UUID, float | None] = {}
    for f in findings:
        current = await get_current_score(db, f.id)
        cvss_scores[f.id] = float(current.base_score) if current is not None else None
    ranked = rank_findings(findings, cvss_scores)
    return ranked, group_ranked(ranked)
