"""Audit read schemas (M1-F5). actor_email/engagement_name are joined in for
display — the stored row keeps only ids (the actor may be deactivated, the
engagement soft-deleted; the event is immutable either way)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.models.audit import AuditEvent, AuditOutcome


class AuditEventOut(BaseModel):
    id: uuid.UUID
    actor_user_id: uuid.UUID | None
    actor_email: str | None
    action: str
    object_type: str
    object_id: uuid.UUID | None
    engagement_id: uuid.UUID | None
    engagement_name: str | None
    outcome: AuditOutcome
    detail: dict[str, Any] | None
    ip_address: str | None
    created_at: datetime

    @classmethod
    def from_row(
        cls, event: AuditEvent, actor_email: str | None, engagement_name: str | None
    ) -> "AuditEventOut":
        return cls(
            id=event.id,
            actor_user_id=event.actor_user_id,
            actor_email=actor_email,
            action=event.action,
            object_type=event.object_type,
            object_id=event.object_id,
            engagement_id=event.engagement_id,
            engagement_name=engagement_name,
            outcome=event.outcome,
            detail=event.detail,
            # asyncpg returns INET as an ipaddress object, not a str.
            ip_address=str(event.ip_address) if event.ip_address is not None else None,
            created_at=event.created_at,
        )
