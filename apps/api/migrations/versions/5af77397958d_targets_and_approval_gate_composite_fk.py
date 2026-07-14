"""targets + approval-gate composite FK (M1-D3).

DATABASE_SCHEMA.md §5: target inventory with UNIQUE (id, engagement_id), plus
the deferred ALTER on approval_gates — (target_id, engagement_id) →
targets (id, engagement_id) — so an approval can only ever bind to a target in
its own engagement (approval_gates was created before targets in M1-D2).
auth_config holds secret-manager references only, never plaintext (TR-23).

Revision ID: 5af77397958d
Revises: e53a4ac4bbac
Create Date: 2026-07-14 15:12:14.026379
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "5af77397958d"
down_revision: str | Sequence[str] | None = "e53a4ac4bbac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

target_type = postgresql.ENUM(
    "web_app",
    "rest_api",
    "graphql_api",
    "source_repo",
    "source_archive",
    "ai_chatbot",
    "llm_api_wrapper",
    "ai_agent",
    name="target_type",
    create_type=False,
)
environment_label = postgresql.ENUM(
    "dev", "staging", "production", name="environment_label", create_type=False
)
auth_status = postgresql.ENUM(
    "none", "configured", "verified", name="auth_status", create_type=False
)

ENUMS = (target_type, environment_label, auth_status)

APPROVAL_TARGET_FK = "fk_approval_gates_target_id_engagement_id_targets"

TIMESTAMPTZ_NOW = {"server_default": sa.text("now()"), "nullable": False}


def upgrade() -> None:
    bind = op.get_bind()
    for enum in ENUMS:
        enum.create(bind, checkfirst=True)

    op.create_table(
        "targets",
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
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("target_type", target_type, nullable=False),
        sa.Column("environment", environment_label, server_default="dev", nullable=False),
        sa.Column("primary_value", sa.Text(), nullable=False),
        sa.Column("auth_status", auth_status, server_default="none", nullable=False),
        sa.Column("auth_config", postgresql.JSONB(), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("risk_summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
        sa.Column("updated_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("id", "engagement_id"),
    )
    op.create_index("ix_targets_engagement", "targets", ["engagement_id"])

    op.create_foreign_key(
        APPROVAL_TARGET_FK,
        "approval_gates",
        "targets",
        ["target_id", "engagement_id"],
        ["id", "engagement_id"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.drop_constraint(APPROVAL_TARGET_FK, "approval_gates", type_="foreignkey")
    op.drop_index("ix_targets_engagement", table_name="targets")
    op.drop_table("targets")
    bind = op.get_bind()
    for enum in reversed(ENUMS):
        enum.drop(bind, checkfirst=True)
