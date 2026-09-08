"""Engagement closed_at — stamped on the terminal transition to CLOSED.

Nullable timestamptz; NULL means the engagement has never been closed. Backfills
already-closed rows from updated_at (the close was the last status write).

Revision ID: b6d9e2f47a13
Revises: e1c8b5a37d94
Create Date: 2026-09-01
"""

import sqlalchemy as sa
from alembic import op

revision = "b6d9e2f47a13"
down_revision = "e1c8b5a37d94"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("engagements", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE engagements SET closed_at = updated_at WHERE status = 'closed'")


def downgrade() -> None:
    op.drop_column("engagements", "closed_at")
