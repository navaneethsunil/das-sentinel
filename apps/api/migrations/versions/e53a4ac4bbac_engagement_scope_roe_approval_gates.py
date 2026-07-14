"""engagement, scope, ROE, approval gates (M1-D2).

DATABASE_SCHEMA.md §4: the authorization core. Engagements carry the frozen
authorization terms (window, rate limit, max intensity, hosted-model gate);
scope_items hold allow AND deny matchers (deny wins in the service); ROE
acceptances are immutable snapshots with a content hash; approval_gates is a
full single-use state machine (pending → approved → consumed | denied |
expired | revoked) bound to one target and one exact operation digest, with
the state-machine CHECK enforced in the DDL.

approval_gates.target_id gets its composite FK to targets in M1-D3 (targets
is created after this table); consumed_by_scan_id gets its FK with scans.

Revision ID: e53a4ac4bbac
Revises: 3a9e97b159b1
Create Date: 2026-07-14 15:05:23.587212
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e53a4ac4bbac"
down_revision: str | Sequence[str] | None = "3a9e97b159b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# create_type=False everywhere: enums are created/dropped explicitly below.
engagement_status = postgresql.ENUM(
    "draft", "active", "paused", "closed", name="engagement_status", create_type=False
)
scan_intensity = postgresql.ENUM(
    "passive",
    "safe_active",
    "authenticated_active",
    "high_risk",
    name="scan_intensity",
    create_type=False,
)
scope_kind = postgresql.ENUM("allow", "deny", name="scope_kind", create_type=False)
scope_matcher = postgresql.ENUM(
    "url", "domain", "ip_cidr", "api_base", "repo", name="scope_matcher", create_type=False
)
approval_status = postgresql.ENUM(
    "pending",
    "approved",
    "denied",
    "expired",
    "revoked",
    "consumed",
    name="approval_status",
    create_type=False,
)

ENUMS = (engagement_status, scan_intensity, scope_kind, scope_matcher, approval_status)

TIMESTAMPTZ_NOW = {"server_default": sa.text("now()"), "nullable": False}


def upgrade() -> None:
    bind = op.get_bind()
    for enum in ENUMS:
        enum.create(bind, checkfirst=True)

    op.create_table(
        "engagements",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("client_system_name", sa.Text(), nullable=False),
        sa.Column("status", engagement_status, server_default="draft", nullable=False),
        sa.Column("test_window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("test_window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rate_limit_rps", sa.Integer(), server_default=sa.text("5"), nullable=False),
        sa.Column("max_intensity", scan_intensity, server_default="safe_active", nullable=False),
        sa.Column(
            "hosted_models_allowed", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("coordination_contact", sa.Text(), nullable=True),
        sa.Column("emergency_stop_contact", sa.Text(), nullable=True),
        sa.Column(
            "created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
        sa.Column("updated_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "scope_items",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column(
            "engagement_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("engagements.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", scope_kind, nullable=False),
        sa.Column("matcher_type", scope_matcher, nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
    )
    op.create_index("ix_scope_items_engagement", "scope_items", ["engagement_id", "kind"])

    op.create_table(
        "roe_acknowledgements",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column(
            "engagement_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("engagements.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "accepted_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column("accepted_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
        sa.Column("roe_text", sa.Text(), nullable=False),
        sa.Column("scope_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("terms_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("content_hash", sa.LargeBinary(), nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
    )

    op.create_table(
        "approval_gates",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column(
            "engagement_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("engagements.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "requested_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("operation_digest", sa.LargeBinary(), nullable=False),
        sa.Column(
            "roe_ack_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("roe_acknowledgements.id"),
            nullable=False,
        ),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("status", approval_status, server_default="pending", nullable=False),
        sa.Column(
            "decided_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "revoked_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True
        ),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_by_scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
        sa.UniqueConstraint("id", "engagement_id"),
        sa.CheckConstraint(
            "(status = 'pending' AND decided_at IS NULL AND decided_by IS NULL) OR "
            "(status IN ('approved', 'denied') AND decided_at IS NOT NULL "
            "AND decided_by IS NOT NULL) OR "
            "(status = 'expired') OR "
            "(status = 'revoked' AND revoked_at IS NOT NULL) OR "
            "(status = 'consumed' AND consumed_at IS NOT NULL "
            "AND consumed_by_scan_id IS NOT NULL)",
            name="approval_decided_fields",
        ),
    )
    op.create_index(
        "ix_approval_gates_engagement", "approval_gates", ["engagement_id", "target_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_approval_gates_engagement", table_name="approval_gates")
    op.drop_table("approval_gates")
    op.drop_table("roe_acknowledgements")
    op.drop_index("ix_scope_items_engagement", table_name="scope_items")
    op.drop_table("scope_items")
    op.drop_table("engagements")
    bind = op.get_bind()
    for enum in reversed(ENUMS):
        enum.drop(bind, checkfirst=True)
