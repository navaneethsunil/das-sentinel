"""roe_acknowledgements immutable trigger (M1-SEC4).

ROE acknowledgements are permanent authorization records (DATABASE_SCHEMA §4:
"No updated_at / deleted_at"). Enforce insert-only in the DB itself with a
raising trigger, exactly as audit_events does (M1-D4, TM-9) — a loud failure on
UPDATE/DELETE, not a silent no-op, so tampering with a signed ROE cannot
succeed even by a direct DB write. (A dedicated least-privilege app role with
UPDATE/DELETE revoked is the production-hardening complement; the trigger is the
role-independent floor.)

Revision ID: 4ba81961ace3
Revises: 066019c35fe5
Create Date: 2026-07-15 16:30:31.036900
"""

from collections.abc import Sequence

from alembic import op

revision: str = "4ba81961ace3"
down_revision: str | Sequence[str] | None = "066019c35fe5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION roe_acknowledgements_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'roe_acknowledgements is append-only (TM-9): % denied', TG_OP;
        END
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER roe_acknowledgements_no_update_delete
            BEFORE UPDATE OR DELETE ON roe_acknowledgements
            FOR EACH ROW EXECUTE FUNCTION roe_acknowledgements_immutable();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER roe_acknowledgements_no_update_delete ON roe_acknowledgements")
    op.execute("DROP FUNCTION roe_acknowledgements_immutable()")
