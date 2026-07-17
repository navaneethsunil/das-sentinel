"""Scan schemas (M2-W2).

Read-only projection for status/cancel responses. There is no launch schema yet
— scan creation arrives with the suite launcher (M2-B6/F1); this file exists so
the emergency-stop endpoint can return the scan's live state.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanIntensity, ScanStatus


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    target_id: uuid.UUID
    intensity: ScanIntensity
    status: ScanStatus
    cancel_requested: bool
    runner_ref: str | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    last_heartbeat_at: datetime | None
    error_summary: str | None
