"""Report schemas (M3-B5)."""

import enum
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.report import Report, ReportStatus, ReportType


class ReportCreateIn(BaseModel):
    report_type: ReportType
    title: str
    # None → snapshot every canonical finding; else only these (in order).
    finding_ids: list[uuid.UUID] | None = None


class ReportUpdateIn(BaseModel):
    title: str | None = None
    body: dict[str, Any] | None = None


class ExportFormat(enum.Enum):
    CSV = "csv"
    MARKDOWN = "markdown"


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    report_type: ReportType
    title: str
    status: ReportStatus
    generated_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class ReportDetailOut(ReportOut):
    body: dict[str, Any]

    @classmethod
    def from_model(cls, r: Report) -> "ReportDetailOut":
        return cls(
            id=r.id,
            engagement_id=r.engagement_id,
            report_type=r.report_type,
            title=r.title,
            status=r.status,
            generated_by=r.generated_by,
            created_at=r.created_at,
            updated_at=r.updated_at,
            body=r.body,
        )
