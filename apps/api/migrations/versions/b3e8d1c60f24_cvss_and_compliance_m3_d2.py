"""cvss_scores + compliance mapping (M3-D2) — DATABASE_SCHEMA §8, §10.

Adds the reporting-slice scoring/mapping layer:
- cvss_scores: score history (insert-only in practice; a new row supersedes the
  prior current via ux_cvss_current), base_score range CHECK, v4.0/v3.1.
- compliance_frameworks / compliance_controls: lookup tables (extend often, so
  not enums), seeded from packages/compliance/ at M3-B4.
- finding_compliance_mappings: finding↔control M2M with the mapping's own
  provenance + optional LLM confidence.

Only cvss_version is a new enum (created here). severity (cvss_scores.severity_band)
and finding_provenance (finding_compliance_mappings.mapped_by) already exist from
the M2-D1 finding migration — referenced with create_type=False so no CREATE TYPE
is re-emitted.

Revision ID: b3e8d1c60f24
Revises: 9a1f4c7b2e60
Create Date: 2026-07-23
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b3e8d1c60f24"
down_revision = "9a1f4c7b2e60"
branch_labels = None
depends_on = None

# New enum — created here.
cvss_version = postgresql.ENUM("v4_0", "v3_1", name="cvss_version", create_type=False)

# Existing types (M2-D1 finding migration) — referenced, never (re)created.
severity = postgresql.ENUM(
    "critical", "high", "medium", "low", "informational", name="severity", create_type=False
)
finding_provenance = postgresql.ENUM(
    "automated",
    "ai_generated",
    "validated",
    "manually_overridden",
    name="finding_provenance",
    create_type=False,
)

TSNOW = {"server_default": sa.text("now()"), "nullable": False}


def upgrade() -> None:
    bind = op.get_bind()
    cvss_version.create(bind, checkfirst=True)

    op.create_table(
        "cvss_scores",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("version", cvss_version, nullable=False),
        sa.Column("vector_string", sa.Text(), nullable=False),
        sa.Column("base_score", sa.Numeric(precision=3, scale=1), nullable=False),
        sa.Column("severity_band", severity, nullable=False),
        sa.Column("is_current", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("is_manual_override", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("override_justification", sa.Text(), nullable=True),
        sa.Column("scored_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **TSNOW),
        sa.CheckConstraint(
            "base_score >= 0.0 AND base_score <= 10.0",
            name=op.f("ck_cvss_scores_base_score_range"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_cvss_scores_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scored_by"], ["users.id"], name=op.f("fk_cvss_scores_scored_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cvss_scores")),
    )
    op.create_index(
        "ux_cvss_current",
        "cvss_scores",
        ["finding_id"],
        unique=True,
        postgresql_where=sa.text("is_current"),
    )

    op.create_table(
        "compliance_frameworks",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compliance_frameworks")),
        sa.UniqueConstraint("key", name=op.f("uq_compliance_frameworks_key")),
    )

    op.create_table(
        "compliance_controls",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("framework_id", sa.UUID(), nullable=False),
        sa.Column("code", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["framework_id"],
            ["compliance_frameworks.id"],
            name=op.f("fk_compliance_controls_framework_id_compliance_frameworks"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compliance_controls")),
        sa.UniqueConstraint(
            "framework_id", "code", name=op.f("uq_compliance_controls_framework_id_code")
        ),
    )

    op.create_table(
        "finding_compliance_mappings",
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("control_id", sa.UUID(), nullable=False),
        sa.Column("mapped_by", finding_provenance, server_default="automated", nullable=False),
        sa.Column("confidence", sa.Numeric(precision=3, scale=2), nullable=True),
        sa.ForeignKeyConstraint(
            ["control_id"],
            ["compliance_controls.id"],
            name=op.f("fk_finding_compliance_mappings_control_id_compliance_controls"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_finding_compliance_mappings_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "finding_id", "control_id", name=op.f("pk_finding_compliance_mappings")
        ),
    )


def downgrade() -> None:
    op.drop_table("finding_compliance_mappings")
    op.drop_table("compliance_controls")
    op.drop_table("compliance_frameworks")
    op.drop_index(
        "ux_cvss_current", table_name="cvss_scores", postgresql_where=sa.text("is_current")
    )
    op.drop_table("cvss_scores")

    bind = op.get_bind()
    cvss_version.drop(bind, checkfirst=True)
