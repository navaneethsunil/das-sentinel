"""remediations (M4-B1) — DATABASE_SCHEMA §9.

Per-finding DRAFT remediation guidance produced by our own LLM (is_ai_generated),
for human review. finding_id CASCADEs (guidance dies with its finding);
created_by is a nullable user ref (NULL for a purely AI-generated draft). No new
enum. The companion `retests` table (patch-validation) is a later M4 slice.

Revision ID: d4f1a2b3c5e6
Revises: c7f2a9d4e130
Create Date: 2026-07-24
"""

import sqlalchemy as sa
from alembic import op

revision = "d4f1a2b3c5e6"
down_revision = "c7f2a9d4e130"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "remediations",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("guidance_text", sa.Text(), nullable=False),
        sa.Column("secure_code_example", sa.Text(), nullable=True),
        sa.Column("patch_suggestion", sa.Text(), nullable=True),
        sa.Column("is_ai_generated", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_remediations_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name=op.f("fk_remediations_created_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_remediations")),
    )
    op.create_index("ix_remediations_finding", "remediations", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_remediations_finding", table_name="remediations")
    op.drop_table("remediations")
