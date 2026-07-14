"""Audit event model (M1-D4) — DATABASE_SCHEMA.md §12.

Append-only: no updated_at, no deletes, ever. The migration installs a
DB-level trigger that raises on UPDATE/DELETE (TM-9) — defense in depth under
the app-level audit writer (M1-B5); full role separation lands at hardening.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Text, text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.identity import GEN_UUID, NOW, UUID_PK


class AuditOutcome(enum.Enum):
    SUCCESS = "success"
    BLOCKED = "blocked"
    FAILURE = "failure"


AUDIT_OUTCOME_ENUM = Enum(
    AuditOutcome, name="audit_outcome", values_callable=lambda e: [m.value for m in e]
)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_engagement_time", "engagement_id", text("created_at DESC")),
        Index("ix_audit_actor_time", "actor_user_id", text("created_at DESC")),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT")
    )
    # NULL for system/automated actions.
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    # 'scan.queued', 'scope.blocked', 'roe.accepted', 'finding.validated', ...
    action: Mapped[str] = mapped_column(Text)
    object_type: Mapped[str] = mapped_column(Text)  # 'scan', 'engagement', 'finding', ...
    object_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("engagements.id"))
    outcome: Mapped[AuditOutcome] = mapped_column(
        AUDIT_OUTCOME_ENUM, server_default=AuditOutcome.SUCCESS.value
    )
    # Structured context (e.g. why a scope check blocked).
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    ip_address: Mapped[str | None] = mapped_column(INET)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
