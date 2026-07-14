"""Target inventory models (M1-D3) — DATABASE_SCHEMA.md §5.

Targets carry UNIQUE (id, engagement_id) so approval_gates (and later scans)
can enforce same-engagement binding with a composite FK — an approval for a
target in one engagement can never be attached to another engagement's scan.
auth_config holds secret-manager references only, never plaintext credentials
(TR-23).
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.identity import GEN_UUID, NOW, UUID_PK


class TargetType(enum.Enum):
    WEB_APP = "web_app"
    REST_API = "rest_api"
    GRAPHQL_API = "graphql_api"
    SOURCE_REPO = "source_repo"
    SOURCE_ARCHIVE = "source_archive"
    AI_CHATBOT = "ai_chatbot"
    LLM_API_WRAPPER = "llm_api_wrapper"
    AI_AGENT = "ai_agent"


class EnvironmentLabel(enum.Enum):
    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"


class AuthStatus(enum.Enum):
    NONE = "none"
    CONFIGURED = "configured"
    VERIFIED = "verified"


TARGET_TYPE_ENUM = Enum(
    TargetType, name="target_type", values_callable=lambda e: [m.value for m in e]
)
ENVIRONMENT_LABEL_ENUM = Enum(
    EnvironmentLabel, name="environment_label", values_callable=lambda e: [m.value for m in e]
)
AUTH_STATUS_ENUM = Enum(
    AuthStatus, name="auth_status", values_callable=lambda e: [m.value for m in e]
)


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (
        # Composite key so dependents can enforce same-engagement FKs.
        UniqueConstraint("id", "engagement_id"),
        Index("ix_targets_engagement", "engagement_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(Text)
    target_type: Mapped[TargetType] = mapped_column(TARGET_TYPE_ENUM)
    environment: Mapped[EnvironmentLabel] = mapped_column(
        ENVIRONMENT_LABEL_ENUM, server_default=EnvironmentLabel.DEV.value
    )
    # URL / base URL / repo URL / object key of an uploaded archive.
    primary_value: Mapped[str] = mapped_column(Text)
    auth_status: Mapped[AuthStatus] = mapped_column(
        AUTH_STATUS_ENUM, server_default=AuthStatus.NONE.value
    )
    # References/handles (e.g. secrets-manager key id) — never raw credentials.
    auth_config: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Denormalized rollup for the inventory view; severity counts come from findings.
    risk_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    engagement: Mapped["Engagement"] = relationship(back_populates="targets")  # noqa: F821
