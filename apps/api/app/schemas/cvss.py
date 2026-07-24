"""CVSS scoring schemas (M3-B3).

The input carries only the vector string plus the override intent — the base
score and severity band are derived server-side from the vector by the `cvss`
package (services/cvss.py), never accepted from the client. A manual override
must carry a justification (mirrored by the service's fail-closed check and the
DB's intent for `override_justification`).
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, model_validator

from app.models.cvss import CvssScore, CvssVersion
from app.models.finding import Severity


class CvssScoreIn(BaseModel):
    vector_string: str
    is_manual_override: bool = False
    override_justification: str | None = None

    @model_validator(mode="after")
    def _require_justification(self) -> "CvssScoreIn":
        if self.is_manual_override and not (
            self.override_justification and self.override_justification.strip()
        ):
            raise ValueError("override_justification is required when is_manual_override is true")
        return self


class CvssScoreOut(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    version: CvssVersion
    vector_string: str
    base_score: float
    severity_band: Severity
    is_current: bool
    is_manual_override: bool
    override_justification: str | None
    scored_by: uuid.UUID | None
    created_at: datetime

    @classmethod
    def from_model(cls, s: CvssScore) -> "CvssScoreOut":
        return cls(
            id=s.id,
            finding_id=s.finding_id,
            version=s.version,
            vector_string=s.vector_string,
            base_score=float(s.base_score),
            severity_band=s.severity_band,
            is_current=s.is_current,
            is_manual_override=s.is_manual_override,
            override_justification=s.override_justification,
            scored_by=s.scored_by,
            created_at=s.created_at,
        )


class CvssHistoryOut(BaseModel):
    """The current score (if any) plus the full insert-only history, newest first."""

    current: CvssScoreOut | None
    history: list[CvssScoreOut]
