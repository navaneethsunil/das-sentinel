"""Remediation guidance + patch-validation retests (M4-B1/M4-B3) — DATABASE_SCHEMA §9.

Per-finding DRAFT remediation produced by our own LLM under the M2-SEC2 triage
guardrails (data-not-instructions, structured output, validated evidence
pointers). It is `is_ai_generated` and for human review — generating it never
marks the finding fixed (CLAUDE.md §2.9/§7). A `patch_suggestion` is always
surfaced with a "requires developer review" notice. Multiple rows per finding
are allowed (regeneration appends); the newest is the current guidance.

A `Retest` is the patch-validation record: when a rescan re-evaluates a finding
that carried a remediation, it captures the deterministic outcome (still_present
| resolved | inconclusive) with the before/after evidence and the rescan that
produced it. Retests are insert-only (schema §631) — the row IS the audit trail.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.identity import GEN_UUID, NOW, UUID_PK


class RetestResult(enum.Enum):
    STILL_PRESENT = "still_present"
    RESOLVED = "resolved"
    INCONCLUSIVE = "inconclusive"


RETEST_RESULT_ENUM = Enum(
    RetestResult, name="retest_result", values_callable=lambda e: [m.value for m in e]
)


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


class Retest(Base):
    """Patch-validation record for one rescan of one finding (schema §9). Insert-only
    (§631) — `performed_by` is NULL when produced by automated rescan reconciliation
    (M4-B3), set when a human records a retest."""

    __tablename__ = "retests"

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    remediation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("remediations.id"))
    rescan_scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id"))
    before_evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"))
    after_evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"))
    result: Mapped[RetestResult] = mapped_column(RETEST_RESULT_ENUM, nullable=False)
    performed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    performed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)

    __table_args__ = (Index("ix_retests_finding", "finding_id"),)
