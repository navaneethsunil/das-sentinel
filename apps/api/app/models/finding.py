"""Finding models (M2-D1) — DATABASE_SCHEMA §7.

The core artifact, modeled as a superset of SARIF 2.1.0 so we can import/export
SARIF while carrying DAST/recon/LLM fields SARIF under-serves. Every finding
carries a provenance label (automated / ai_generated / validated /
manually_overridden) and a dedup identity (hash_code + partial_fingerprints).

Provenance rule (enforced in the service layer, M2+): an LLM-produced finding
is written provenance='ai_generated' and cannot move to confirmed/fixed without
a human transition recorded in finding_status_history — that is how the UI's
"automated vs. validated" distinction stays truthful (CLAUDE.md §2.9).

scanner_run_id's FK to scanner_runs is added in M3-D1 (once that table lands).
finding_status_history is append-only (DB trigger).
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, LargeBinary, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.identity import GEN_UUID, NOW, UUID_PK


class SarifLevel(enum.Enum):
    NONE = "none"
    NOTE = "note"
    WARNING = "warning"
    ERROR = "error"


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingProvenance(enum.Enum):
    AUTOMATED = "automated"
    AI_GENERATED = "ai_generated"
    VALIDATED = "validated"
    MANUALLY_OVERRIDDEN = "manually_overridden"


class FindingStatus(enum.Enum):
    OPEN = "open"
    IN_TRIAGE = "in_triage"
    CONFIRMED = "confirmed"
    MITIGATED = "mitigated"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    OUT_OF_SCOPE = "out_of_scope"


def _pg_enum(py_enum: type[enum.Enum], name: str) -> Enum:
    return Enum(py_enum, name=name, values_callable=lambda e: [m.value for m in e])


SARIF_LEVEL_ENUM = _pg_enum(SarifLevel, "sarif_level")
SEVERITY_ENUM = _pg_enum(Severity, "severity")
FINDING_PROVENANCE_ENUM = _pg_enum(FindingProvenance, "finding_provenance")
FINDING_STATUS_ENUM = _pg_enum(FindingStatus, "finding_status")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_engagement", "engagement_id"),
        Index("ix_findings_target_status", "target_id", "status"),
        Index("ix_findings_hash", "hash_code"),
        Index("ix_findings_fp_gin", "partial_fingerprints", postgresql_using="gin"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id", ondelete="RESTRICT")
    )
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("targets.id", ondelete="RESTRICT"))
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id"))
    scanner_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scanner_runs.id"))
    test_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("test_runs.id"))

    # SARIF-aligned core
    rule_id: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text)
    sarif_level: Mapped[SarifLevel | None] = mapped_column(SARIF_LEVEL_ENUM)
    # file/line/region (SAST) OR endpoint/method (DAST) OR prompt ref (LLM).
    location: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    # Triage & risk
    severity: Mapped[Severity] = mapped_column(
        SEVERITY_ENUM, server_default=Severity.INFORMATIONAL.value
    )
    provenance: Mapped[FindingProvenance] = mapped_column(FINDING_PROVENANCE_ENUM)
    status: Mapped[FindingStatus] = mapped_column(
        FINDING_STATUS_ENUM, server_default=FindingStatus.OPEN.value
    )
    is_false_positive: Mapped[bool] = mapped_column(Boolean, server_default="false")

    # Dedup identity (DefectDojo-style + SARIF fingerprints)
    hash_code: Mapped[bytes] = mapped_column(LargeBinary)
    partial_fingerprints: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    duplicate_of: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id"))

    description: Mapped[str | None] = mapped_column(Text)
    impact: Mapped[str | None] = mapped_column(Text)
    recommendation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FindingEvidence(Base):
    """Many-to-many: a finding can cite multiple evidence blobs."""

    __tablename__ = "finding_evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="RESTRICT"), primary_key=True
    )
    caption: Mapped[str | None] = mapped_column(Text)


class FindingStatusHistory(Base):
    """Append-only status-transition log (who moved it, when, why). DB trigger
    enforces insert-only."""

    __tablename__ = "finding_status_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    from_status: Mapped[FindingStatus | None] = mapped_column(FINDING_STATUS_ENUM)
    to_status: Mapped[FindingStatus] = mapped_column(FINDING_STATUS_ENUM)
    changed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    reason: Mapped[str | None] = mapped_column(Text)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
