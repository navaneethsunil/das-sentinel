"""scans runner handle (runner_ref + last_heartbeat_at) — M2-W1

The orchestration worker records the child process/container id of the run it
spawns (runner_ref) so emergency stop (M2-W2) can terminate that exact process
tree, and heartbeats (last_heartbeat_at) so a watchdog can tell a live run from
a wedged one. Both nullable: a queued scan has neither yet.

Revision ID: 7f3a1b9c2d05
Revises: 2b82615ef434
Create Date: 2026-07-17
"""

import sqlalchemy as sa
from alembic import op

revision = "7f3a1b9c2d05"
down_revision = "2b82615ef434"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("runner_ref", sa.Text(), nullable=True))
    op.add_column(
        "scans",
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "last_heartbeat_at")
    op.drop_column("scans", "runner_ref")
