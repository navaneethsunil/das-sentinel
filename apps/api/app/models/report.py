"""Report models (M3-D3) — DATABASE_SCHEMA §11.

A report is editable structured content (body JSONB) rendered to exports
(POA&M CSV + Markdown at MVP; PDF/DOCX/JSON at M6). The row stays editable
until status='final'. reports is a user-facing domain row, so it carries
deleted_at (soft delete); report_findings is a pure join and is not.

report_findings snapshots which findings a report includes and their ordering;
its finding FK is ON DELETE RESTRICT so a finding cited by a report cannot be
hard-deleted out from under it.

Both enums (report_type, report_status) are new.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.identity import GEN_UUID, NOW, UUID_PK


class ReportType(enum.Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    POAM = "poam"


class ReportStatus(enum.Enum):
    DRAFT = "draft"
    FINAL = "final"


def _pg_enum(py_enum: type[enum.Enum], name: str) -> Enum:
    return Enum(py_enum, name=name, values_callable=lambda e: [m.value for m in e])


REPORT_TYPE_ENUM = _pg_enum(ReportType, "report_type")
REPORT_STATUS_ENUM = _pg_enum(ReportStatus, "report_status")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id", ondelete="RESTRICT")
    )
    report_type: Mapped[ReportType] = mapped_column(REPORT_TYPE_ENUM)
    title: Mapped[str] = mapped_column(Text)
    status: Mapped[ReportStatus] = mapped_column(
        REPORT_STATUS_ENUM, server_default=ReportStatus.DRAFT.value
    )
    # Editable structured content before export.
    body: Mapped[dict[str, Any]] = mapped_column(JSONB)
    generated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReportFinding(Base):
    """Which findings a report includes, and the snapshot ordering."""

    __tablename__ = "report_findings"

    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), primary_key=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="RESTRICT"), primary_key=True
    )
    sort_order: Mapped[int] = mapped_column(Integer, server_default="0")
