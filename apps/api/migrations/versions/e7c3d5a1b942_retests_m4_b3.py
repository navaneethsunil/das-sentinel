"""retests (M4-B3) — DATABASE_SCHEMA §9, patch validation.

The companion to `remediations`: one row per rescan re-evaluation of a finding,
capturing the deterministic outcome (still_present | resolved | inconclusive)
with before/after evidence and the rescan that produced it. finding_id CASCADEs;
every other ref is nullable (a retest may predate a remediation, or an automated
rescan reconciliation has no performing user). Insert-only (schema §631) — the
row IS the audit trail, so an append-only trigger denies UPDATE/DELETE (TM-9),
mirroring finding_status_history / audit_events.

Revision ID: e7c3d5a1b942
Revises: d4f1a2b3c5e6
Create Date: 2026-07-27
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e7c3d5a1b942"
down_revision = "d4f1a2b3c5e6"
branch_labels = None
depends_on = None

retest_result = postgresql.ENUM(
    "still_present", "resolved", "inconclusive", name="retest_result", create_type=False
)


def upgrade() -> None:
    bind = op.get_bind()
    retest_result.create(bind, checkfirst=True)
    op.create_table(
        "retests",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("remediation_id", sa.UUID(), nullable=True),
        sa.Column("rescan_scan_id", sa.UUID(), nullable=True),
        sa.Column("before_evidence_id", sa.UUID(), nullable=True),
        sa.Column("after_evidence_id", sa.UUID(), nullable=True),
        sa.Column("result", retest_result, nullable=False),
        sa.Column("performed_by", sa.UUID(), nullable=True),
        sa.Column(
            "performed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_retests_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["remediation_id"],
            ["remediations.id"],
            name=op.f("fk_retests_remediation_id_remediations"),
        ),
        sa.ForeignKeyConstraint(
            ["rescan_scan_id"], ["scans.id"], name=op.f("fk_retests_rescan_scan_id_scans")
        ),
        sa.ForeignKeyConstraint(
            ["before_evidence_id"],
            ["evidence.id"],
            name=op.f("fk_retests_before_evidence_id_evidence"),
        ),
        sa.ForeignKeyConstraint(
            ["after_evidence_id"],
            ["evidence.id"],
            name=op.f("fk_retests_after_evidence_id_evidence"),
        ),
        sa.ForeignKeyConstraint(
            ["performed_by"], ["users.id"], name=op.f("fk_retests_performed_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_retests")),
    )
    op.create_index("ix_retests_finding", "retests", ["finding_id"])

    # Insert-only enforcement (TM-9), static-literal DDL as in audit_events.
    op.execute(
        """
        CREATE FUNCTION retests_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'retests is append-only (TM-9): % denied', TG_OP;
        END
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER retests_no_update_delete
            BEFORE UPDATE OR DELETE ON retests
            FOR EACH ROW EXECUTE FUNCTION retests_immutable();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER retests_no_update_delete ON retests")
    op.execute("DROP FUNCTION retests_immutable()")
    op.drop_index("ix_retests_finding", table_name="retests")
    op.drop_table("retests")
    retest_result.drop(op.get_bind(), checkfirst=True)
