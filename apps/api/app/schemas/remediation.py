"""Remediation guidance API schemas (M4-B1)."""

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.remediation import Remediation
from app.services.remediation import PATCH_REVIEW_NOTICE


class RemediationOut(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    guidance_text: str
    secure_code_example: str | None
    patch_suggestion: str | None
    # Non-null only when a patch is suggested — a patch is never auto-applied.
    patch_review_notice: str | None
    is_ai_generated: bool
    created_by: uuid.UUID | None
    created_at: datetime

    @classmethod
    def from_model(cls, r: Remediation) -> "RemediationOut":
        return cls(
            id=r.id,
            finding_id=r.finding_id,
            guidance_text=r.guidance_text,
            secure_code_example=r.secure_code_example,
            patch_suggestion=r.patch_suggestion,
            patch_review_notice=PATCH_REVIEW_NOTICE if r.patch_suggestion else None,
            is_ai_generated=r.is_ai_generated,
            created_by=r.created_by,
            created_at=r.created_at,
        )
