"""LLM interaction effective destination (sec-16).

Adds `destination` to llm_interactions: the pinned `ip[:port]` a self-hosted
provider call (Ollama) actually connected to, recorded on the 'success' outcome
row so the audit trail shows where each prompt went — the registration-time
address alone cannot prove that once a hostname can rebind. Nullable: SDK-owned
connections (Anthropic) and pre-egress 'attempt' rows carry none.

Revision ID: d8f2a6c41e07
Revises: c4e7f1a9b820
Create Date: 2026-09-08
"""

import sqlalchemy as sa
from alembic import op

revision = "d8f2a6c41e07"
down_revision = "c4e7f1a9b820"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("llm_interactions", sa.Column("destination", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("llm_interactions", "destination")
