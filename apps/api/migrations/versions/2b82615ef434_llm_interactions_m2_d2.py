"""llm_interactions (M2-D2).

DATABASE_SCHEMA §12: every LLM call recorded for cost tracking and control
proof (was_redacted / hosted). Insert-only, like audit_events — a raising
trigger enforces it in the DB (static-literal DDL, no dynamic SQL).

Revision ID: 2b82615ef434
Revises: 3d73f9cffd47
Create Date: 2026-07-16 10:38:11.076381
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "2b82615ef434"
down_revision: str | Sequence[str] | None = "3d73f9cffd47"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

llm_purpose = postgresql.ENUM(
    "test_gen",
    "triage",
    "remediation",
    "mapping",
    "report",
    "summarization",
    name="llm_purpose",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    llm_purpose.create(bind, checkfirst=True)

    op.create_table(
        "llm_interactions",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("engagement_id", sa.UUID(), nullable=True),
        sa.Column("purpose", llm_purpose, nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("model", sa.Text(), nullable=False),
        sa.Column("prompt_template", sa.Text(), nullable=True),
        sa.Column("was_redacted", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("hosted", sa.Boolean(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("cost_usd", sa.Numeric(precision=12, scale=6), nullable=True),
        sa.Column("ref_object_type", sa.Text(), nullable=True),
        sa.Column("ref_object_id", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name=op.f("fk_llm_interactions_engagement_id_engagements"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_llm_interactions_organization_id_organizations"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_llm_interactions")),
    )
    op.create_index(
        "ix_llm_engagement_time",
        "llm_interactions",
        ["engagement_id", sa.literal_column("created_at DESC")],
        unique=False,
    )

    # Insert-only enforcement (TM-9), static-literal DDL as in audit_events.
    op.execute(
        """
        CREATE FUNCTION llm_interactions_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'llm_interactions is append-only (TM-9): % denied', TG_OP;
        END
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER llm_interactions_no_update_delete
            BEFORE UPDATE OR DELETE ON llm_interactions
            FOR EACH ROW EXECUTE FUNCTION llm_interactions_immutable();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER llm_interactions_no_update_delete ON llm_interactions")
    op.execute("DROP FUNCTION llm_interactions_immutable()")
    op.drop_index("ix_llm_engagement_time", table_name="llm_interactions")
    op.drop_table("llm_interactions")
    llm_purpose.drop(op.get_bind(), checkfirst=True)
