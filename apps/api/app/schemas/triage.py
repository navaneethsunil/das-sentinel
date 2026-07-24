"""Triage overview API schemas (M4-B2) — deterministic ranking + grouping."""

import uuid

from pydantic import BaseModel

from app.services.triage_rank import FindingGroup, RankedFinding


class RankedFindingOut(BaseModel):
    finding_id: uuid.UUID
    rank: int
    severity: str
    cvss_base_score: float | None
    group_key: str
    title: str
    rule_id: str | None

    @classmethod
    def from_obj(cls, r: RankedFinding) -> "RankedFindingOut":
        return cls(
            finding_id=r.finding_id,
            rank=r.rank,
            severity=r.severity.value,
            cvss_base_score=r.cvss_base_score,
            group_key=r.group_key,
            title=r.title,
            rule_id=r.rule_id,
        )


class FindingGroupOut(BaseModel):
    group_key: str
    title: str
    severity: str
    count: int
    top_rank: int
    finding_ids: list[uuid.UUID]

    @classmethod
    def from_obj(cls, g: FindingGroup) -> "FindingGroupOut":
        return cls(
            group_key=g.group_key,
            title=g.title,
            severity=g.severity.value,
            count=g.count,
            top_rank=g.top_rank,
            finding_ids=g.finding_ids,
        )


class TriageOverviewOut(BaseModel):
    ranked: list[RankedFindingOut]
    groups: list[FindingGroupOut]
