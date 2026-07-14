"""identity: organizations, users, sessions (M1-D1).

DATABASE_SCHEMA.md §3: multi-tenant identity root. Enables citext (DB-side
case-insensitive email uniqueness), creates the user_role enum, and the
organizations → users → sessions chain. Sessions store only the SHA-256 of the
opaque cookie token — the raw token never touches the DB.

Revision ID: 3a9e97b159b1
Revises: caab8ec4571a
Create Date: 2026-07-14 14:55:32.418321
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "3a9e97b159b1"
down_revision: str | Sequence[str] | None = "caab8ec4571a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# create_type=False: the enum is created/dropped explicitly below so create_table
# can't try to re-create it (checkfirst semantics stay in one place).
user_role = postgresql.ENUM(
    "admin", "tester", "reviewer", "read_only", name="user_role", create_type=False
)

TIMESTAMPTZ_NOW = {"server_default": sa.text("now()"), "nullable": False}


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")
    user_role.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "organizations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
        sa.Column("updated_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
    )

    op.create_table(
        "users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("email", postgresql.CITEXT(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("role", user_role, server_default="read_only", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
        sa.Column("updated_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("organization_id", "email"),
    )

    op.create_table(
        "sessions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), **TIMESTAMPTZ_NOW),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_sessions_user_active",
        "sessions",
        ["user_id"],
        postgresql_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_sessions_user_active", table_name="sessions")
    op.drop_table("sessions")
    op.drop_table("users")
    op.drop_table("organizations")
    user_role.drop(op.get_bind(), checkfirst=True)
    op.execute("DROP EXTENSION IF EXISTS citext")
