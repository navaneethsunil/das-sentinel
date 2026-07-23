"""CVSS scoring model (M3-D2) — DATABASE_SCHEMA §8.

Score history, never updated in place: a new row is inserted and the prior
is_current is cleared, so the table itself is the audit trail (CVSS history is
never soft-deleted or mutated — §general-conventions). The ux_cvss_current
partial unique index guarantees at most one current row per finding; the service
layer (M3-B3) guarantees at least one. v4.0 is the default; v3.1 is retained for
historical CVEs (dual-scoring, CLAUDE.md §1). Scores are computed with the
maintained `cvss` PyPI package — v4.0's MacroVector scoring is never hand-rolled.

severity is reused (from the M2-D1 finding migration); cvss_version is new.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Numeric,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.finding import SEVERITY_ENUM, Severity
from app.models.identity import GEN_UUID, NOW, UUID_PK


class CvssVersion(enum.Enum):
    V4_0 = "v4_0"
    V3_1 = "v3_1"


CVSS_VERSION_ENUM = Enum(
    CvssVersion, name="cvss_version", values_callable=lambda e: [m.value for m in e]
)


class CvssScore(Base):
    __tablename__ = "cvss_scores"
    __table_args__ = (
        CheckConstraint(
            "base_score >= 0.0 AND base_score <= 10.0", name="ck_cvss_scores_base_score_range"
        ),
        # Exactly one current score per finding (partial unique).
        Index("ux_cvss_current", "finding_id", unique=True, postgresql_where=text("is_current")),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    version: Mapped[CvssVersion] = mapped_column(CVSS_VERSION_ENUM)
    vector_string: Mapped[str] = mapped_column(Text)
    base_score: Mapped[float] = mapped_column(Numeric(3, 1))
    severity_band: Mapped[Severity] = mapped_column(SEVERITY_ENUM)
    is_current: Mapped[bool] = mapped_column(Boolean, server_default="true")
    is_manual_override: Mapped[bool] = mapped_column(Boolean, server_default="false")
    # Required (app-enforced) when is_manual_override.
    override_justification: Mapped[str | None] = mapped_column(Text)
    # NULL when the score was computed automatically.
    scored_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
