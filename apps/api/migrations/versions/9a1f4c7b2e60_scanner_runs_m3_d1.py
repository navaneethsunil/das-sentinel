"""scanner_runs (M3-D1) — DATABASE_SCHEMA §6.

The external-tool sibling of test_runs: one row per Semgrep/ZAP/… invocation
within a scan. Reuses the existing scan_status enum (create_type=False — it was
created by the M2-D1 scan migration), so no CREATE TYPE is emitted here.

Also closes the deferred FK from findings.scanner_run_id → scanner_runs(id):
that column landed in M2-D1 as a plain UUID because scanner_runs did not exist
yet; the FK is added now that it does.

Revision ID: 9a1f4c7b2e60
Revises: 8c4e1f7a9b23
Create Date: 2026-07-23
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "9a1f4c7b2e60"
down_revision = "8c4e1f7a9b23"
branch_labels = None
depends_on = None

# Existing type (M2-D1 scan migration) — referenced, never (re)created.
scan_status = postgresql.ENUM(
    "queued",
    "running",
    "completed",
    "failed",
    "cancelled",
    name="scan_status",
    create_type=False,
)


def upgrade() -> None:
    op.create_table(
        "scanner_runs",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("scanner_name", sa.Text(), nullable=False),
        sa.Column("scanner_version", sa.Text(), nullable=False),
        sa.Column("image_digest", sa.Text(), nullable=True),
        sa.Column("rules_digest", sa.Text(), nullable=True),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", scan_status, server_default="queued", nullable=False),
        sa.Column("os_process_group", sa.Integer(), nullable=True),
        sa.Column("raw_evidence_id", sa.UUID(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["raw_evidence_id"],
            ["evidence.id"],
            name=op.f("fk_scanner_runs_raw_evidence_id_evidence"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_scanner_runs_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scanner_runs")),
    )
    op.create_index("ix_scanner_runs_scan", "scanner_runs", ["scan_id"], unique=False)

    # Deferred FK from M2-D1 (findings.scanner_run_id was a plain UUID column).
    op.create_foreign_key(
        op.f("fk_findings_scanner_run_id_scanner_runs"),
        "findings",
        "scanner_runs",
        ["scanner_run_id"],
        ["id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_findings_scanner_run_id_scanner_runs"), "findings", type_="foreignkey"
    )
    op.drop_index("ix_scanner_runs_scan", table_name="scanner_runs")
    op.drop_table("scanner_runs")
