"""Managed credential store (secret-manager-lite).

A named, organization-scoped secret the analyst creates once and then *references*
from targets (and any future secret-bearing field) as `cred:<id>` instead of
pasting the value as plaintext (TR-23: auth_config holds references, never raw
credentials). The secret value is Fernet-encrypted at rest and is WRITE-ONLY: no
API path ever returns it — it is decrypted only in-memory at scan time to build a
request header, exactly like the connector already treated `env:` references.

Soft-deleted (deleted_at) rather than hard-deleted so an audit trail and any
in-flight reference survive; a deleted credential fails resolution loud.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.identity import GEN_UUID, NOW, UUID_PK


class Credential(Base):
    __tablename__ = "credentials"
    __table_args__ = (
        # One live name per org (case-sensitive); soft-deleted rows are excluded so
        # a name can be reused after deletion.
        Index(
            "ux_credentials_org_name",
            "organization_id",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_credentials_org", "organization_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    # Fernet token of the secret — never returned by any endpoint.
    secret_encrypted: Mapped[str] = mapped_column(Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
