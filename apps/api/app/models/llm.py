"""LLM interaction model (M2-D2) — DATABASE_SCHEMA §12.

Every LLM call is recorded for cost tracking and, critically, for proving the
safety controls held: was_redacted (redaction ran before egress) and hosted
(whether the call left the box) are the audit evidence that the engagement's
hosted_models_allowed gate and redaction-before-egress were enforced
(CLAUDE.md §2.7). Insert-only, like audit_events — a raising trigger enforces it
in the DB.
"""

import enum
import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Integer, Numeric, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.identity import GEN_UUID, NOW, UUID_PK


class LLMPurpose(enum.Enum):
    TEST_GEN = "test_gen"
    TRIAGE = "triage"
    REMEDIATION = "remediation"
    MAPPING = "mapping"
    REPORT = "report"
    SUMMARIZATION = "summarization"


LLM_PURPOSE_ENUM = Enum(
    LLMPurpose, name="llm_purpose", values_callable=lambda e: [m.value for m in e]
)


class LLMInteraction(Base):
    __tablename__ = "llm_interactions"
    __table_args__ = (Index("ix_llm_engagement_time", "engagement_id", text("created_at DESC")),)

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT")
    )
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("engagements.id"))
    purpose: Mapped[LLMPurpose] = mapped_column(LLM_PURPOSE_ENUM)
    provider: Mapped[str] = mapped_column(Text)  # 'anthropic','ollama','vllm'
    model: Mapped[str] = mapped_column(Text)  # 'claude-opus-4-8', ...
    prompt_template: Mapped[str | None] = mapped_column(Text)  # template id + version
    # Proof-of-control fields (see module docstring).
    was_redacted: Mapped[bool] = mapped_column(Boolean, server_default="false")
    hosted: Mapped[bool] = mapped_column(Boolean)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    # Polymorphic reference to what the call was about (no FK — spans tables).
    ref_object_type: Mapped[str | None] = mapped_column(
        Text
    )  # 'scan','test_run','finding','report'
    ref_object_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
