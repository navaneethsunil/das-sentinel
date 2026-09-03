"""LLM interaction status + error_category (sec-4).

Adds an append-only outcome trail to llm_interactions: `status`
('attempt'|'success'|'failure') and `error_category` (sanitized error class on
failure). Existing rows were all successful completions → backfilled 'success'.

Revision ID: c4e7f1a9b820
Revises: b6d9e2f47a13
Create Date: 2026-09-03
"""

import sqlalchemy as sa
from alembic import op

revision = "c4e7f1a9b820"
down_revision = "b6d9e2f47a13"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "llm_interactions",
        sa.Column("status", sa.Text(), server_default="success", nullable=False),
    )
    op.add_column("llm_interactions", sa.Column("error_category", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("llm_interactions", "error_category")
    op.drop_column("llm_interactions", "status")
