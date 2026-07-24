"""Remediation guidance (M4-B1) — DATABASE_SCHEMA §9.

Per-finding DRAFT remediation produced by our own LLM under the M2-SEC2 triage
guardrails (data-not-instructions, structured output, validated evidence
pointers). It is `is_ai_generated` and for human review — generating it never
marks the finding fixed (CLAUDE.md §2.9/§7). A `patch_suggestion` is always
surfaced with a "requires developer review" notice. Multiple rows per finding
are allowed (regeneration appends); the newest is the current guidance.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.identity import GEN_UUID, NOW, UUID_PK


class Remediation(Base):
    __tablename__ = "remediations"

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    # Plain-English guidance: root cause + fix + verification (schema §9).
    guidance_text: Mapped[str] = mapped_column(Text, nullable=False)
    secure_code_example: Mapped[str | None] = mapped_column(Text)
    # ALWAYS presented with a "requires developer review" notice (never auto-applied).
    patch_suggestion: Mapped[str | None] = mapped_column(Text)
    is_ai_generated: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)

    __table_args__ = (Index("ix_remediations_finding", "finding_id"),)
