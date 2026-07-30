"""Managed credential schemas. The secret is WRITE-ONLY — it appears only on the
create request (as a SecretStr, never echoed) and is absent from every response."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, SecretStr

from app.models.credential import Credential
from app.services.credentials import CRED_REF_PREFIX


class CredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    # SecretStr so it is not accidentally logged/serialized; unwrapped only to encrypt.
    secret: SecretStr = Field(min_length=1)


class CredentialOut(BaseModel):
    """Credential metadata. Carries NO secret — only the reference token callers
    paste into a target's auth config."""

    id: uuid.UUID
    name: str
    description: str | None
    reference: str  # the cred:<id> token to use in auth_config
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, c: Credential) -> "CredentialOut":
        return cls(
            id=c.id,
            name=c.name,
            description=c.description,
            reference=f"{CRED_REF_PREFIX}{c.id}",
            created_by=c.created_by,
            created_at=c.created_at,
            updated_at=c.updated_at,
        )
