"""reports + report_findings (M3-D3) — DATABASE_SCHEMA §11.

The report layer for the MVP export slice: a report holds editable structured
content (body JSONB) rendered to POA&M CSV + Markdown; it stays editable until
status='final'. reports is a user-facing domain row (soft-deletable via
deleted_at); report_findings is the join capturing inclusion + snapshot order,
with a RESTRICT FK so a cited finding cannot be hard-deleted out from under a
report.

Both enums (report_type, report_status) are new and created here.

Revision ID: c7f2a9d4e130
Revises: b3e8d1c60f24
Create Date: 2026-07-23
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c7f2a9d4e130"
down_revision = "b3e8d1c60f24"
branch_labels = None
depends_on = None

report_type = postgresql.ENUM(
    "executive", "technical", "poam", name="report_type", create_type=False
)
report_status = postgresql.ENUM("draft", "final", name="report_status", create_type=False)
NEW_ENUMS = (report_type, report_status)

TSNOW = {"server_default": sa.text("now()"), "nullable": False}


def upgrade() -> None:
    bind = op.get_bind()
    for enum in NEW_ENUMS:
        enum.create(bind, checkfirst=True)

    op.create_table(
        "reports",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("engagement_id", sa.UUID(), nullable=False),
        sa.Column("report_type", report_type, nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("status", report_status, server_default="draft", nullable=False),
        sa.Column("body", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("generated_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **TSNOW),
        sa.Column("updated_at", sa.DateTime(timezone=True), **TSNOW),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name=op.f("fk_reports_engagement_id_engagements"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["generated_by"], ["users.id"], name=op.f("fk_reports_generated_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reports")),
    )

    op.create_table(
        "report_findings",
        sa.Column("report_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("sort_order", sa.Integer(), server_default="0", nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_report_findings_finding_id_findings"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["reports.id"],
            name=op.f("fk_report_findings_report_id_reports"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("report_id", "finding_id", name=op.f("pk_report_findings")),
    )


def downgrade() -> None:
    op.drop_table("report_findings")
    op.drop_table("reports")

    bind = op.get_bind()
    for enum in reversed(NEW_ENUMS):
        enum.drop(bind, checkfirst=True)
