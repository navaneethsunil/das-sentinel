"""Add the 'log_analysis' value to the llm_purpose enum (LOG_ANALYSIS feature).

LLM log analysis is a new discovery source: it reads a raw-log evidence blob and
proposes ai_generated candidate findings, so its interactions are audited under a
new purpose. PG 17 permits ALTER TYPE ... ADD VALUE inside a transaction; the new
value is only *used* by later transactions, so this is safe. Removing an enum value
is not supported by Postgres without recreating the type, so downgrade is a no-op.

Revision ID: b7d2e9f14c38
Revises: a2b4c6d8e0f2
Create Date: 2026-07-30
"""

from alembic import op

revision = "b7d2e9f14c38"
down_revision = "a2b4c6d8e0f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE llm_purpose ADD VALUE IF NOT EXISTS 'log_analysis'")


def downgrade() -> None:
    # Postgres cannot drop a single enum value without recreating the type; the
    # unused value is left in place (harmless).
    pass
