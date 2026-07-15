"""Scope-item schemas (M1-B7). Values are validated + normalized against their
matcher_type at the API boundary via the shared matcher validator."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.engagement import ScopeKind, ScopeMatcher
from app.services.scope_matchers import validate_matcher


class ScopeItemCreate(BaseModel):
    kind: ScopeKind
    matcher_type: ScopeMatcher
    value: str = Field(min_length=1, max_length=2000)
    notes: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def _normalize_value(self) -> "ScopeItemCreate":
        # ValueError here surfaces as a 422 with the matcher-specific message.
        self.value = validate_matcher(self.matcher_type, self.value)
        return self


class ScopeItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    kind: ScopeKind
    matcher_type: ScopeMatcher
    value: str
    notes: str | None
    created_at: datetime
