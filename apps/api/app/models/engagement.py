"""Engagement, scope, ROE, approval-gate models (M1-D2) — DATABASE_SCHEMA.md §4.

This is the authorization core the scope-enforcement service (M1-B9) reads:
no scan runs without an active engagement, an accepted (immutable) ROE, and —
for high-risk actions — a single-use approval gate bound to the exact operation
digest. Blocklist scope items always win over allowlist in the service.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.identity import GEN_UUID, NOW, UUID_PK


class EngagementStatus(enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    CLOSED = "closed"


class ScanIntensity(enum.Enum):
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe_active"
    AUTHENTICATED_ACTIVE = "authenticated_active"
    HIGH_RISK = "high_risk"


class ScopeKind(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"


class ScopeMatcher(enum.Enum):
    URL = "url"
    DOMAIN = "domain"
    IP_CIDR = "ip_cidr"
    API_BASE = "api_base"
    REPO = "repo"


class ApprovalStatus(enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSUMED = "consumed"


def _pg_enum(py_enum: type[enum.Enum], name: str) -> Enum:
    return Enum(py_enum, name=name, values_callable=lambda e: [m.value for m in e])


ENGAGEMENT_STATUS_ENUM = _pg_enum(EngagementStatus, "engagement_status")
SCAN_INTENSITY_ENUM = _pg_enum(ScanIntensity, "scan_intensity")
SCOPE_KIND_ENUM = _pg_enum(ScopeKind, "scope_kind")
SCOPE_MATCHER_ENUM = _pg_enum(ScopeMatcher, "scope_matcher")
APPROVAL_STATUS_ENUM = _pg_enum(ApprovalStatus, "approval_status")


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(Text)
    client_system_name: Mapped[str] = mapped_column(Text)
    status: Mapped[EngagementStatus] = mapped_column(
        ENGAGEMENT_STATUS_ENUM, server_default=EngagementStatus.DRAFT.value
    )
    test_window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    test_window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Authoritative outbound ceiling — the worker/egress shaper enforces it.
    rate_limit_rps: Mapped[int] = mapped_column(Integer, server_default=text("5"))
    max_intensity: Mapped[ScanIntensity] = mapped_column(
        SCAN_INTENSITY_ENUM, server_default=ScanIntensity.SAFE_ACTIVE.value
    )
    # Gates hosted LLM egress (CLAUDE.md §2.7) — default deny.
    hosted_models_allowed: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    coordination_contact: Mapped[str | None] = mapped_column(Text)
    emergency_stop_contact: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scope_items: Mapped[list["ScopeItem"]] = relationship(back_populates="engagement")
    roe_acknowledgements: Mapped[list["ROEAcknowledgement"]] = relationship(
        back_populates="engagement"
    )
    approval_gates: Mapped[list["ApprovalGate"]] = relationship(back_populates="engagement")
    targets: Mapped[list["Target"]] = relationship(back_populates="engagement")  # noqa: F821


class ScopeItem(Base):
    __tablename__ = "scope_items"
    __table_args__ = (Index("ix_scope_items_engagement", "engagement_id", "kind"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE")
    )
    kind: Mapped[ScopeKind] = mapped_column(SCOPE_KIND_ENUM)
    matcher_type: Mapped[ScopeMatcher] = mapped_column(SCOPE_MATCHER_ENUM)
    value: Mapped[str] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)

    engagement: Mapped[Engagement] = relationship(back_populates="scope_items")


class ROEAcknowledgement(Base):
    """Immutable signed ROE artifact — never updated or soft-deleted."""

    __tablename__ = "roe_acknowledgements"

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id", ondelete="RESTRICT")
    )
    accepted_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    roe_text: Mapped[str] = mapped_column(Text)
    scope_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    # {test_window_start, test_window_end, rate_limit_rps, max_intensity}
    terms_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    # SHA-256 over (roe_text || scope_snapshot || terms_snapshot)
    content_hash: Mapped[bytes] = mapped_column(LargeBinary)
    ip_address: Mapped[str | None] = mapped_column(INET)

    engagement: Mapped[Engagement] = relationship(back_populates="roe_acknowledgements")


class ApprovalGate(Base):
    """High-risk action approval — a state machine bound to ONE exact operation.

    pending → approved → consumed (or → denied / expired / revoked). Approval is
    per-target and single-use: consumption is an atomic conditional UPDATE whose
    affected-row count is checked (0 rows ⇒ already used/expired/revoked ⇒ refuse).
    """

    __tablename__ = "approval_gates"
    __table_args__ = (
        # Composite key so scans can enforce a same-engagement FK later.
        UniqueConstraint("id", "engagement_id"),
        # Same-engagement binding (added in M1-D3, after targets exists): an
        # approval can only reference a target inside its own engagement.
        ForeignKeyConstraint(
            ["target_id", "engagement_id"],
            ["targets.id", "targets.engagement_id"],
            ondelete="RESTRICT",
        ),
        # State-machine integrity in the DDL, not just app code.
        CheckConstraint(
            "(status = 'pending' AND decided_at IS NULL AND decided_by IS NULL) OR "
            "(status IN ('approved', 'denied') AND decided_at IS NOT NULL "
            "AND decided_by IS NOT NULL) OR "
            "(status = 'expired') OR "
            "(status = 'revoked' AND revoked_at IS NOT NULL) OR "
            "(status = 'consumed' AND consumed_at IS NOT NULL "
            "AND consumed_by_scan_id IS NOT NULL)",
            name="approval_decided_fields",
        ),
        Index("ix_approval_gates_engagement", "engagement_id", "target_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id", ondelete="RESTRICT")
    )
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    action_type: Mapped[str] = mapped_column(Text)
    justification: Mapped[str] = mapped_column(Text)
    # SHA-256 over the canonical operation subject; API and worker both recompute
    # and require equality, so an approval can't be paired with swapped exec fields.
    operation_digest: Mapped[bytes] = mapped_column(LargeBinary)
    roe_ack_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roe_acknowledgements.id"))
    policy_version: Mapped[str] = mapped_column(Text)

    status: Mapped[ApprovalStatus] = mapped_column(
        APPROVAL_STATUS_ENUM, server_default=ApprovalStatus.PENDING.value
    )
    decided_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_reason: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))  # MANDATORY expiry
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    revocation_reason: Mapped[str | None] = mapped_column(Text)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Single-use claim (M2-D1): FK to scans, added via ALTER after scans exists.
    # use_alter breaks the scans↔approval_gates metadata cycle (scans has a
    # composite FK back to approval_gates).
    consumed_by_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey(
            "scans.id",
            use_alter=True,
            name="fk_approval_gates_consumed_by_scan_id_scans",
        )
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)

    engagement: Mapped[Engagement] = relationship(back_populates="approval_gates")
    roe_acknowledgement: Mapped[ROEAcknowledgement] = relationship()
