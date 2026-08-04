"""AI model registry — operator-registered providers, referenced per engagement.

Adds `ai_models` (an Anthropic key + model id, or an Ollama endpoint + model name,
registered once in the UI) and `engagements.ai_model_id` selecting which registered
model an engagement's analysis runs on (NULL = the org default). The API key is
Fernet-encrypted (api_key_encrypted), key held outside this DB.

Revision ID: e1c8b5a37d94
Revises: a1b2c3d4e5f6
Create Date: 2026-08-03
"""

import sqlalchemy as sa
from alembic import op

revision = "e1c8b5a37d94"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_models",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("model_id", sa.Text(), nullable=False),
        sa.Column("base_url", sa.Text(), nullable=True),
        sa.Column("api_key_encrypted", sa.Text(), nullable=True),
        sa.Column("is_default", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(provider = 'anthropic' AND api_key_encrypted IS NOT NULL) OR "
            "(provider = 'ollama' AND base_url IS NOT NULL)",
            name="ai_models_provider_config",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ux_ai_models_org_name",
        "ai_models",
        ["organization_id", "name"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index(
        "ux_ai_models_org_default",
        "ai_models",
        ["organization_id"],
        unique=True,
        postgresql_where=sa.text("is_default AND deleted_at IS NULL"),
    )
    op.add_column("engagements", sa.Column("ai_model_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_engagements_ai_model_id_ai_models",
        "engagements",
        "ai_models",
        ["ai_model_id"],
        ["id"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.drop_constraint("fk_engagements_ai_model_id_ai_models", "engagements", type_="foreignkey")
    op.drop_column("engagements", "ai_model_id")
    op.drop_index("ux_ai_models_org_default", table_name="ai_models")
    op.drop_index("ux_ai_models_org_name", table_name="ai_models")
    op.drop_table("ai_models")
