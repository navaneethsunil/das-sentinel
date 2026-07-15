"""M1-B5: audit writer + status→outcome mapping. The middleware coverage net
and the DB append-only trigger are exercised live (scripts/verify_audit.py);
here we pin the pure mapping and that AuditService.log builds the right row."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.audit import AuditService, outcome_for_status
from app.models.audit import AuditOutcome


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (200, AuditOutcome.SUCCESS),
        (201, AuditOutcome.SUCCESS),
        (302, AuditOutcome.SUCCESS),
        (400, AuditOutcome.FAILURE),
        (401, AuditOutcome.FAILURE),
        (403, AuditOutcome.BLOCKED),
        (404, AuditOutcome.FAILURE),
        (409, AuditOutcome.FAILURE),
        (422, AuditOutcome.FAILURE),
        (500, AuditOutcome.FAILURE),
    ],
)
def test_outcome_for_status(status_code: int, expected: AuditOutcome) -> None:
    assert outcome_for_status(status_code) == expected


async def test_log_builds_and_persists_event() -> None:
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    org_id, actor_id, obj_id, eng_id = (uuid.uuid4() for _ in range(4))

    event = await AuditService(db).log(
        organization_id=org_id,
        action="roe.accepted",
        object_type="engagement",
        actor_user_id=actor_id,
        object_id=obj_id,
        engagement_id=eng_id,
        outcome=AuditOutcome.SUCCESS,
        detail={"content_hash": "abc"},
        ip_address="10.0.0.9",
    )

    db.add.assert_called_once_with(event)
    db.flush.assert_awaited_once()
    assert event.organization_id == org_id
    assert event.actor_user_id == actor_id
    assert event.action == "roe.accepted"
    assert event.object_type == "engagement"
    assert event.object_id == obj_id
    assert event.engagement_id == eng_id
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.detail == {"content_hash": "abc"}
    assert event.ip_address == "10.0.0.9"


async def test_log_defaults_system_actor_and_success() -> None:
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()

    event = await AuditService(db).log(
        organization_id=uuid.uuid4(),
        action="scan.autotriage",
        object_type="scan",
    )

    assert event.actor_user_id is None  # system/automated action
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.detail is None
