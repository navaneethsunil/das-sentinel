"""Engagement schemas (M1-B6)."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.engagement import EngagementStatus, ScanIntensity

MAX_RATE_LIMIT_RPS = 1000


def _check_window(start: datetime | None, end: datetime | None) -> None:
    if start is not None and end is not None and end <= start:
        raise ValueError("test_window_end must be after test_window_start")


class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    client_system_name: str = Field(min_length=1, max_length=200)
    test_window_start: datetime | None = None
    test_window_end: datetime | None = None
    rate_limit_rps: int = Field(default=5, ge=1, le=MAX_RATE_LIMIT_RPS)
    max_intensity: ScanIntensity = ScanIntensity.SAFE_ACTIVE
    hosted_models_allowed: bool = False
    coordination_contact: str | None = Field(default=None, max_length=500)
    emergency_stop_contact: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _validate_window(self) -> "EngagementCreate":
        _check_window(self.test_window_start, self.test_window_end)
        return self


class EngagementUpdate(BaseModel):
    """Partial edit — only supplied fields change. Status is NOT editable here;
    use the status-transition endpoint so the state machine is enforced."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    client_system_name: str | None = Field(default=None, min_length=1, max_length=200)
    test_window_start: datetime | None = None
    test_window_end: datetime | None = None
    rate_limit_rps: int | None = Field(default=None, ge=1, le=MAX_RATE_LIMIT_RPS)
    max_intensity: ScanIntensity | None = None
    hosted_models_allowed: bool | None = None
    coordination_contact: str | None = Field(default=None, max_length=500)
    emergency_stop_contact: str | None = Field(default=None, max_length=500)


class StatusChange(BaseModel):
    status: EngagementStatus


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    client_system_name: str
    status: EngagementStatus
    test_window_start: datetime | None
    test_window_end: datetime | None
    rate_limit_rps: int
    max_intensity: ScanIntensity
    hosted_models_allowed: bool
    coordination_contact: str | None
    emergency_stop_contact: str | None
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
