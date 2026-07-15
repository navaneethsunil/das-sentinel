"""Target schemas (M1-B10). auth_config is validated to hold references only;
findings_by_severity is a computed rollup (empty until findings land)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.engagement import ScopeMatcher
from app.models.target import AuthStatus, EnvironmentLabel, Target, TargetType
from app.services.scope_matchers import validate_matcher
from app.services.targets import validate_auth_config_references

# Which target types carry a URL vs a repo vs a free-form value.
_URL_TYPES = {
    TargetType.WEB_APP,
    TargetType.REST_API,
    TargetType.GRAPHQL_API,
    TargetType.AI_CHATBOT,
    TargetType.LLM_API_WRAPPER,
    TargetType.AI_AGENT,
}


def _validate_primary_value(target_type: TargetType, value: str) -> str:
    if target_type in _URL_TYPES:
        return validate_matcher(ScopeMatcher.URL, value)
    if target_type == TargetType.SOURCE_REPO:
        return validate_matcher(ScopeMatcher.REPO, value)
    return value  # source_archive: object key / free-form


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target_type: TargetType
    environment: EnvironmentLabel = EnvironmentLabel.DEV
    primary_value: str = Field(min_length=1, max_length=2000)
    auth_status: AuthStatus = AuthStatus.NONE
    auth_config: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _validate(self) -> "TargetCreate":
        self.primary_value = _validate_primary_value(self.target_type, self.primary_value)
        validate_auth_config_references(self.auth_config)
        return self


class TargetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    environment: EnvironmentLabel | None = None
    primary_value: str | None = Field(default=None, min_length=1, max_length=2000)
    auth_status: AuthStatus | None = None
    auth_config: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _validate_auth(self) -> "TargetUpdate":
        # primary_value depends on target_type (immutable post-create), so it is
        # re-validated in the handler where the type is known.
        validate_auth_config_references(self.auth_config)
        return self


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    name: str
    target_type: TargetType
    environment: EnvironmentLabel
    primary_value: str
    auth_status: AuthStatus
    auth_config: dict[str, Any] | None
    last_scan_at: datetime | None
    risk_summary: str | None
    findings_by_severity: dict[str, int]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, target: Target) -> "TargetOut":
        return cls(
            id=target.id,
            engagement_id=target.engagement_id,
            name=target.name,
            target_type=target.target_type,
            environment=target.environment,
            primary_value=target.primary_value,
            auth_status=target.auth_status,
            auth_config=target.auth_config,
            last_scan_at=target.last_scan_at,
            risk_summary=target.risk_summary,
            # Computed from findings later; empty at M1 (no findings yet).
            findings_by_severity={},
            created_at=target.created_at,
            updated_at=target.updated_at,
        )
