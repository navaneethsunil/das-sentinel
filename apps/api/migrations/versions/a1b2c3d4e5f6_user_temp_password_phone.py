"""User temp-password force-change flag + self-service phone field.

Adds `must_change_password` (set when an admin creates a user or resets their
password to an auto-generated temporary one; cleared when the user sets their
own) and `phone` (self-service profile field, nullable).

Revision ID: a1b2c3d4e5f6
Revises: c9f3a1e4d287
Create Date: 2026-07-31
"""

import sqlalchemy as sa
from alembic import op

revision = "a1b2c3d4e5f6"
down_revision = "c9f3a1e4d287"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    op.add_column("users", sa.Column("phone", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "phone")
    op.drop_column("users", "must_change_password")
