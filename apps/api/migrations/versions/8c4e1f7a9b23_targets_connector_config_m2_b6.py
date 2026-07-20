"""targets.connector_config (LLM target connector transport shape) — M2-B6

An LLM/chatbot target needs a description of how to reach it: how to place a
prompt into the request body, where to read the reply from the response, which
header carries auth, etc. That transport shape is NON-secret (the credential
stays a reference in auth_config, TR-23), so it lives in its own nullable JSONB
column consumed by app/connectors. Nullable: only chatbot/LLM-wrapper targets
carry it.

Revision ID: 8c4e1f7a9b23
Revises: 7f3a1b9c2d05
Create Date: 2026-07-20
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "8c4e1f7a9b23"
down_revision = "7f3a1b9c2d05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column("connector_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("targets", "connector_config")
