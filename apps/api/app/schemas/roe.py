"""ROE schemas (M1-B8). content_hash is exposed as hex (bytea in the DB)."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.engagement import ROEAcknowledgement


class ROEView(BaseModel):
    """The ROE for the engagement's current state, plus acceptance status."""

    roe_text: str
    scope_snapshot: list[dict[str, str]]
    terms_snapshot: dict[str, object]
    content_hash: str  # hex of the current render
    is_accepted: bool
    requires_reacceptance: bool
    latest_acknowledgement_id: uuid.UUID | None
    accepted_at: datetime | None


class ROEAccept(BaseModel):
    # The hash the user was shown; the server refuses (409) if the ROE changed
    # since it was rendered — you can only accept what you actually saw.
    acknowledged_content_hash: str = Field(min_length=64, max_length=64)


class ROEAcknowledgementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    accepted_by: uuid.UUID
    accepted_at: datetime
    roe_text: str
    scope_snapshot: list[dict[str, str]]
    terms_snapshot: dict[str, object]
    content_hash: str

    @classmethod
    def from_model(cls, ack: ROEAcknowledgement) -> "ROEAcknowledgementOut":
        return cls(
            id=ack.id,
            engagement_id=ack.engagement_id,
            accepted_by=ack.accepted_by,
            accepted_at=ack.accepted_at,
            roe_text=ack.roe_text,
            scope_snapshot=ack.scope_snapshot,
            terms_snapshot=ack.terms_snapshot,
            content_hash=ack.content_hash.hex(),
        )
