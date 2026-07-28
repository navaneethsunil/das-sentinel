"""MFA / TOTP (SEC-DEBT-2) — DATABASE_SCHEMA §3, auth second factor.

Adds the per-user TOTP fields (encrypted secret + confirmed flag) and the
single-use recovery-code table. mfa_secret holds the Fernet-encrypted base32
secret — pending during enrollment, active once mfa_enabled flips true. Recovery
codes are stored SHA-256-hashed (high-entropy → fast hash is correct) and
consumed atomically by an UPDATE … WHERE used_at IS NULL.

Revision ID: f1a2c3d4e5f6
Revises: e7c3d5a1b942
Create Date: 2026-07-28
"""

import sqlalchemy as sa
from alembic import op

revision = "f1a2c3d4e5f6"
down_revision = "e7c3d5a1b942"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("mfa_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.add_column("users", sa.Column("mfa_secret", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("mfa_confirmed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("code_hash", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code_hash"),
    )
    op.create_index("ix_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_mfa_recovery_codes_user_id", table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")
    op.drop_column("users", "mfa_confirmed_at")
    op.drop_column("users", "mfa_secret")
    op.drop_column("users", "mfa_enabled")
