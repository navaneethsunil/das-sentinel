"""audit_events, append-only (M1-D4).

DATABASE_SCHEMA.md §12: the audit log. Append-only is enforced in the DB
itself — a trigger raises on any UPDATE or DELETE (TM-9). A loud trigger is
deliberate over a silent `DO INSTEAD NOTHING` rule: tampering must fail, not
no-op (fail closed, SECURITY_DEVELOPMENT_PLAN §6). Role separation comes at
hardening; this is the in-schema floor.

Revision ID: 066019c35fe5
Revises: 5af77397958d
Create Date: 2026-07-14 15:15:04.558363
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "066019c35fe5"
down_revision: str | Sequence[str] | None = "5af77397958d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

audit_outcome = postgresql.ENUM(
    "success", "blocked", "failure", name="audit_outcome", create_type=False
)

TIMESTAMPTZ_NOW = {"server_default": sa.text("now()"), "nullable": False}


def upgrade() -> None:
    audit_outcome.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "audit_events",
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
        sa.Column(
            "actor_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True
        ),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("object_type", sa.Text(), nullable=False),
        sa.Column("object_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "engagement_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("engagements.id"),
            nullable=True,
        ),
        sa.Column("outcome", audit_outcome, server_default="success", nullable=False),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
    )
    op.create_index(
        "ix_audit_engagement_time",
        "audit_events",
        ["engagement_id", sa.text("created_at DESC")],
    )
    op.create_index(
        "ix_audit_actor_time",
        "audit_events",
        ["actor_user_id", sa.text("created_at DESC")],
    )

    op.execute(
        """
        CREATE FUNCTION audit_events_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events is append-only (TM-9): % denied', TG_OP;
        END
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_no_update_delete
            BEFORE UPDATE OR DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER audit_events_no_update_delete ON audit_events")
    op.execute("DROP FUNCTION audit_events_immutable()")
    op.drop_index("ix_audit_actor_time", table_name="audit_events")
    op.drop_index("ix_audit_engagement_time", table_name="audit_events")
    op.drop_table("audit_events")
    audit_outcome.drop(op.get_bind(), checkfirst=True)
