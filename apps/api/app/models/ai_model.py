"""Registered AI models — the operator-managed provider registry.

An admin registers a model ONCE under System → AI models (an Anthropic API key +
model id, or a local Ollama endpoint + model name) and every engagement then uses
a registered model instead of the process's environment variables. The API key is
Fernet-encrypted at rest with the same cipher as the credential store and is
WRITE-ONLY: no endpoint ever returns it; it is decrypted in-memory to build the
provider adapter.

Soft-deleted (deleted_at) so audit history and `llm_interactions` references stay
intact; an engagement pinned to a deleted model fails loud rather than silently
falling back to a different provider (CLAUDE.md §11.6).
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.identity import GEN_UUID, NOW, UUID_PK

PROVIDERS = ("anthropic", "ollama")


class AIModel(Base):
    __tablename__ = "ai_models"
    __table_args__ = (
        # A registered model must carry what its provider needs to run: a hosted
        # provider needs a key, a local one needs an endpoint. Enforced in the DDL
        # so no code path can register a model that cannot be built.
        CheckConstraint(
            "(provider = 'anthropic' AND api_key_encrypted IS NOT NULL) OR "
            "(provider = 'ollama' AND base_url IS NOT NULL)",
            name="ai_models_provider_config",
        ),
        Index(
            "ux_ai_models_org_name",
            "organization_id",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        # At most one default per org — a DB guarantee, not an app convention.
        Index(
            "ux_ai_models_org_default",
            "organization_id",
            unique=True,
            postgresql_where=text("is_default AND deleted_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(Text)
    provider: Mapped[str] = mapped_column(Text)  # anthropic | ollama
    # The provider's own model identifier, e.g. claude-opus-4-8 / llama3.1:8b.
    model_id: Mapped[str] = mapped_column(Text)
    # Local providers only (Ollama base URL). Hosted providers use the SDK default.
    base_url: Mapped[str | None] = mapped_column(Text)
    # Fernet token of the provider API key — never returned by any endpoint.
    api_key_encrypted: Mapped[str | None] = mapped_column(Text)
    is_default: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
