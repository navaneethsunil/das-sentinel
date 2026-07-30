"""Managed credential store — encrypted, org-scoped secret vault.

Adds `credentials`: a named secret referenced elsewhere as `cred:<id>`. The secret
is Fernet-encrypted at rest (secret_encrypted); the key lives outside this DB
(Settings.credential_encryption_key). Soft-deleted (deleted_at) with a partial
unique index so a name is unique among LIVE credentials per org and reusable after
deletion.

Revision ID: c9f3a1e4d287
Revises: b7d2e9f14c38
Create Date: 2026-07-30
"""

import sqlalchemy as sa
from alembic import op

revision = "c9f3a1e4d287"
down_revision = "b7d2e9f14c38"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "credentials",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("secret_encrypted", sa.Text(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_credentials_org", "credentials", ["organization_id"])
    op.create_index(
        "ux_credentials_org_name",
        "credentials",
        ["organization_id", "name"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ux_credentials_org_name", table_name="credentials")
    op.drop_index("ix_credentials_org", table_name="credentials")
    op.drop_table("credentials")
