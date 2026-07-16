"""scans, execution_authorizations, test_runs, evidence, findings (M2-D1).

DATABASE_SCHEMA §6–7: the scan/run/evidence/finding data layer.

Enums are created once with create_type=False (the M1 pattern) because several
are reused across tables (scan_status in scans+test_runs, finding_status in
findings+finding_status_history) and scan_intensity already exists from the
engagement migration — letting create_table emit CREATE TYPE would double-create
or collide.

Three tables are chain-of-custody records and get the same raising insert-only
trigger as audit_events / roe_acknowledgements (M1-D4/SEC4, TM-9): evidence
(immutable blob pointers), execution_authorizations (the frozen authorization
envelope), and finding_status_history (append-only transition log). A dedicated
least-privilege DB role is the production complement; the trigger is the
role-independent floor.

The deferred approval_gates.consumed_by_scan_id → scans(id) FK is added here
(single-use approval claim) now that scans exists.

Revision ID: 3d73f9cffd47
Revises: 4ba81961ace3
Create Date: 2026-07-16 09:22:00.444864
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "3d73f9cffd47"
down_revision: str | Sequence[str] | None = "4ba81961ace3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# New enum types — created explicitly (create_type=False) so multi-table reuse
# doesn't emit CREATE TYPE more than once.
scan_status = postgresql.ENUM(
    "queued",
    "running",
    "completed",
    "failed",
    "cancelled",
    name="scan_status",
    create_type=False,
)
test_suite = postgresql.ENUM(
    "prompt_injection",
    "data_leakage",
    "agent_permission",
    name="test_suite",
    create_type=False,
)
evidence_kind = postgresql.ENUM(
    "raw_scanner_output",
    "http_transcript",
    "llm_transcript",
    "source_archive",
    name="evidence_kind",
    create_type=False,
)
sarif_level = postgresql.ENUM(
    "none",
    "note",
    "warning",
    "error",
    name="sarif_level",
    create_type=False,
)
severity = postgresql.ENUM(
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    name="severity",
    create_type=False,
)
finding_provenance = postgresql.ENUM(
    "automated",
    "ai_generated",
    "validated",
    "manually_overridden",
    name="finding_provenance",
    create_type=False,
)
finding_status = postgresql.ENUM(
    "open",
    "in_triage",
    "confirmed",
    "mitigated",
    "fixed",
    "accepted_risk",
    "false_positive",
    "out_of_scope",
    name="finding_status",
    create_type=False,
)
NEW_ENUMS = (
    scan_status,
    test_suite,
    evidence_kind,
    sarif_level,
    severity,
    finding_provenance,
    finding_status,
)

# Existing type (engagement migration) — referenced, never (re)created.
scan_intensity = postgresql.ENUM(
    "passive",
    "safe_active",
    "authenticated_active",
    "high_risk",
    name="scan_intensity",
    create_type=False,
)

TSNOW = {"server_default": sa.text("now()"), "nullable": False}


def upgrade() -> None:
    bind = op.get_bind()
    for enum in NEW_ENUMS:
        enum.create(bind, checkfirst=True)

    op.create_table(
        "evidence",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("content_type", sa.Text(), nullable=False),
        sa.Column("kind", evidence_kind, nullable=False),
        sa.Column("retain_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **TSNOW),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_evidence_organization_id_organizations"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence")),
        sa.UniqueConstraint("object_key", name=op.f("uq_evidence_object_key")),
    )
    op.create_index("ux_evidence_hash", "evidence", ["content_sha256"], unique=True)

    op.create_table(
        "scans",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("engagement_id", sa.UUID(), nullable=False),
        sa.Column("target_id", sa.UUID(), nullable=False),
        sa.Column("intensity", scan_intensity, nullable=False),
        sa.Column("status", scan_status, server_default="queued", nullable=False),
        sa.Column("approval_gate_id", sa.UUID(), nullable=True),
        sa.Column("initiated_by", sa.UUID(), nullable=False),
        sa.Column("queued_at", sa.DateTime(timezone=True), **TSNOW),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["approval_gate_id", "engagement_id"],
            ["approval_gates.id", "approval_gates.engagement_id"],
            name=op.f("fk_scans_approval_gate_id_engagement_id_approval_gates"),
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name=op.f("fk_scans_engagement_id_engagements"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["initiated_by"], ["users.id"], name=op.f("fk_scans_initiated_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["target_id", "engagement_id"],
            ["targets.id", "targets.engagement_id"],
            name=op.f("fk_scans_target_id_engagement_id_targets"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scans")),
    )
    op.create_index("ix_scans_engagement", "scans", ["engagement_id"], unique=False)
    op.create_index(
        "ix_scans_status",
        "scans",
        ["status"],
        unique=False,
        postgresql_where=sa.text("status IN ('queued','running')"),
    )

    op.create_table(
        "execution_authorizations",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("engagement_id", sa.UUID(), nullable=False),
        sa.Column("target_id", sa.UUID(), nullable=False),
        sa.Column("requested_by", sa.UUID(), nullable=False),
        sa.Column("effective_intensity", scan_intensity, nullable=False),
        sa.Column("normalized_config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("server_capabilities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("roe_ack_id", sa.UUID(), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("approval_gate_id", sa.UUID(), nullable=True),
        sa.Column("operation_digest", sa.LargeBinary(), nullable=False),
        sa.Column("test_window", postgresql.TSTZRANGE(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **TSNOW),
        sa.ForeignKeyConstraint(
            ["approval_gate_id", "engagement_id"],
            ["approval_gates.id", "approval_gates.engagement_id"],
            name=op.f("fk_execution_authorizations_approval_gate_id_engagement_id_approval_gates"),
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"],
            ["users.id"],
            name=op.f("fk_execution_authorizations_requested_by_users"),
        ),
        sa.ForeignKeyConstraint(
            ["roe_ack_id"],
            ["roe_acknowledgements.id"],
            name=op.f("fk_execution_authorizations_roe_ack_id_roe_acknowledgements"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_execution_authorizations_scan_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["target_id", "engagement_id"],
            ["targets.id", "targets.engagement_id"],
            name=op.f("fk_execution_authorizations_target_id_engagement_id_targets"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_execution_authorizations")),
        sa.UniqueConstraint("scan_id", name=op.f("uq_execution_authorizations_scan_id")),
    )
    op.create_index(
        "ix_exec_auth_engagement", "execution_authorizations", ["engagement_id"], unique=False
    )

    op.create_table(
        "test_runs",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("suite", test_suite, nullable=False),
        sa.Column("engine", sa.Text(), nullable=True),
        sa.Column("engine_version", sa.Text(), nullable=True),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", scan_status, server_default="queued", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_test_runs_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_test_runs")),
    )
    op.create_index("ix_test_runs_scan", "test_runs", ["scan_id"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("engagement_id", sa.UUID(), nullable=False),
        sa.Column("target_id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=True),
        sa.Column("scanner_run_id", sa.UUID(), nullable=True),
        sa.Column("test_run_id", sa.UUID(), nullable=True),
        sa.Column("rule_id", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("sarif_level", sarif_level, nullable=True),
        sa.Column("location", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("severity", severity, server_default="informational", nullable=False),
        sa.Column("provenance", finding_provenance, nullable=False),
        sa.Column("status", finding_status, server_default="open", nullable=False),
        sa.Column("is_false_positive", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("hash_code", sa.LargeBinary(), nullable=False),
        sa.Column("partial_fingerprints", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("duplicate_of", sa.UUID(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("impact", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **TSNOW),
        sa.Column("updated_at", sa.DateTime(timezone=True), **TSNOW),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["duplicate_of"], ["findings.id"], name=op.f("fk_findings_duplicate_of_findings")
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name=op.f("fk_findings_engagement_id_engagements"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], name=op.f("fk_findings_scan_id_scans")),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name=op.f("fk_findings_target_id_targets"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["test_run_id"], ["test_runs.id"], name=op.f("fk_findings_test_run_id_test_runs")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
    )
    op.create_index("ix_findings_engagement", "findings", ["engagement_id"], unique=False)
    op.create_index(
        "ix_findings_fp_gin",
        "findings",
        ["partial_fingerprints"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index("ix_findings_hash", "findings", ["hash_code"], unique=False)
    op.create_index("ix_findings_target_status", "findings", ["target_id", "status"], unique=False)

    op.create_table(
        "finding_evidence",
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("evidence_id", sa.UUID(), nullable=False),
        sa.Column("caption", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name=op.f("fk_finding_evidence_evidence_id_evidence"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_finding_evidence_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("finding_id", "evidence_id", name=op.f("pk_finding_evidence")),
    )

    op.create_table(
        "finding_status_history",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("from_status", finding_status, nullable=True),
        sa.Column("to_status", finding_status, nullable=False),
        sa.Column("changed_by", sa.UUID(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), **TSNOW),
        sa.ForeignKeyConstraint(
            ["changed_by"],
            ["users.id"],
            name=op.f("fk_finding_status_history_changed_by_users"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_finding_status_history_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_status_history")),
    )

    # Deferred single-use-claim FK, now that scans exists.
    op.create_foreign_key(
        "fk_approval_gates_consumed_by_scan_id_scans",
        "approval_gates",
        "scans",
        ["consumed_by_scan_id"],
        ["id"],
    )

    # Insert-only enforcement (TM-9) for the chain-of-custody tables. Static
    # DDL literals (no dynamic SQL) matching audit_events/roe_acknowledgements —
    # the table names are fixed, so there is no injection surface to build.
    op.execute(
        """
        CREATE FUNCTION evidence_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'evidence is append-only (TM-9): % denied', TG_OP;
        END
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER evidence_no_update_delete
            BEFORE UPDATE OR DELETE ON evidence
            FOR EACH ROW EXECUTE FUNCTION evidence_immutable();
        """
    )
    op.execute(
        """
        CREATE FUNCTION execution_authorizations_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'execution_authorizations is append-only (TM-9): % denied', TG_OP;
        END
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER execution_authorizations_no_update_delete
            BEFORE UPDATE OR DELETE ON execution_authorizations
            FOR EACH ROW EXECUTE FUNCTION execution_authorizations_immutable();
        """
    )
    op.execute(
        """
        CREATE FUNCTION finding_status_history_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'finding_status_history is append-only (TM-9): % denied', TG_OP;
        END
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER finding_status_history_no_update_delete
            BEFORE UPDATE OR DELETE ON finding_status_history
            FOR EACH ROW EXECUTE FUNCTION finding_status_history_immutable();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER finding_status_history_no_update_delete ON finding_status_history")
    op.execute("DROP FUNCTION finding_status_history_immutable()")
    op.execute("DROP TRIGGER execution_authorizations_no_update_delete ON execution_authorizations")
    op.execute("DROP FUNCTION execution_authorizations_immutable()")
    op.execute("DROP TRIGGER evidence_no_update_delete ON evidence")
    op.execute("DROP FUNCTION evidence_immutable()")

    op.drop_constraint(
        "fk_approval_gates_consumed_by_scan_id_scans", "approval_gates", type_="foreignkey"
    )
    op.drop_table("finding_status_history")
    op.drop_table("finding_evidence")
    op.drop_index("ix_findings_target_status", table_name="findings")
    op.drop_index("ix_findings_hash", table_name="findings")
    op.drop_index("ix_findings_fp_gin", table_name="findings", postgresql_using="gin")
    op.drop_index("ix_findings_engagement", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_test_runs_scan", table_name="test_runs")
    op.drop_table("test_runs")
    op.drop_index("ix_exec_auth_engagement", table_name="execution_authorizations")
    op.drop_table("execution_authorizations")
    op.drop_index(
        "ix_scans_status",
        table_name="scans",
        postgresql_where=sa.text("status IN ('queued','running')"),
    )
    op.drop_index("ix_scans_engagement", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ux_evidence_hash", table_name="evidence")
    op.drop_table("evidence")

    bind = op.get_bind()
    for enum in reversed(NEW_ENUMS):
        enum.drop(bind, checkfirst=True)
