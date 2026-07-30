"""LLM log-analysis API schemas."""

import uuid

from pydantic import BaseModel

from app.models.finding import Finding


class LogAnalysisRequest(BaseModel):
    """Which raw-log evidence blob to analyze (must belong to the engagement's org)."""

    evidence_id: uuid.UUID


class LogAnalysisCandidateOut(BaseModel):
    finding_id: uuid.UUID
    title: str
    line_start: int
    line_end: int


class LogAnalysisResultOut(BaseModel):
    """Created ai_generated candidate findings. All INFORMATIONAL/OPEN, unreviewed —
    the UI must label them ai_generated until a human validates them."""

    candidate_count: int
    findings: list[LogAnalysisCandidateOut]

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "LogAnalysisResultOut":
        items = [
            LogAnalysisCandidateOut(
                finding_id=f.id,
                title=f.title,
                line_start=(f.location or {}).get("log_analysis", {}).get("line_start", 0),
                line_end=(f.location or {}).get("log_analysis", {}).get("line_end", 0),
            )
            for f in findings
        ]
        return cls(candidate_count=len(items), findings=items)
