"""baseline — empty root revision (M0-D1).

Proves the migration pipeline end-to-end (one-shot `migrate` service → alembic_version
table) before any real schema lands. First real tables arrive in M1-D1.

Revision ID: caab8ec4571a
Revises:
Create Date: 2026-07-14 09:10:33.344498
"""

from collections.abc import Sequence

revision: str = "caab8ec4571a"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
