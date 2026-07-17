"""Scan launch + orchestration unit tests (M2-W1) — CI-safe: no DB, no worker.

Covers the pure divergence check and launch_scan's authorize→create→freeze path
with a fake session. The DB-coupled orchestration (re-derive/refuse/consume/run
across transactions) is exercised live in scripts/verify_scans.py.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.core.scope import (
    EngagementInactive,
    Operation,
    OperationKind,
    compute_operation_digest,
)
from app.core.scope import (
    ExecutionAuthorization as ScopeAuthorization,
)
from app.models.engagement import (
    Engagement,
    EngagementStatus,
    ROEAcknowledgement,
    ScanIntensity,
    ScopeItem,
    ScopeKind,
    ScopeMatcher,
)
from app.models.scan import ExecutionAuthorization, ScanStatus
from app.models.target import Target, TargetType
from app.services.roe import render_current_roe
from app.services.scans import launch_scan
from app.workers.orchestration import divergence_reason

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
ENG_ID = uuid.uuid4()
TARGET_ID = uuid.uuid4()
ORG_ID = uuid.uuid4()
ROE_ACK_ID = uuid.uuid4()
ACTOR = uuid.uuid4()

ALLOW = [ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.DOMAIN, value="app.example.com")]
SAFE_OP = Operation(target_id=TARGET_ID, kind=OperationKind.SAFE_ACTIVE_SCAN)


def _engagement(**overrides: object) -> Engagement:
    base: dict[str, object] = {
        "id": ENG_ID,
        "organization_id": ORG_ID,
        "name": "Acme",
        "client_system_name": "acme-web",
        "status": EngagementStatus.ACTIVE,
        "test_window_start": NOW - timedelta(days=1),
        "test_window_end": NOW + timedelta(days=1),
        "rate_limit_rps": 5,
        "max_intensity": ScanIntensity.SAFE_ACTIVE,
        "hosted_models_allowed": False,
    }
    base.update(overrides)
    return Engagement(**base)


def _target() -> Target:
    return Target(
        id=TARGET_ID,
        engagement_id=ENG_ID,
        name="web",
        target_type=TargetType.WEB_APP,
        primary_value="https://app.example.com/",
    )


def _accepted_roe(engagement: Engagement, scope_items: list[ScopeItem]) -> ROEAcknowledgement:
    _, _, terms, content_hash = render_current_roe(engagement, scope_items)
    return ROEAcknowledgement(
        id=ROE_ACK_ID,
        engagement_id=engagement.id,
        accepted_by=uuid.uuid4(),
        accepted_at=NOW - timedelta(hours=1),
        roe_text="frozen",
        scope_snapshot=[],
        terms_snapshot=terms,
        content_hash=content_hash,
    )


class _FakeSession:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        pass


# ── divergence_reason (pure) ───────────────────────────────────────────────────


def _auth(**overrides) -> ScopeAuthorization:
    base = {
        "engagement_id": ENG_ID,
        "target_id": TARGET_ID,
        "effective_intensity": ScanIntensity.SAFE_ACTIVE,
        "operation_digest": b"digest-A",
        "roe_ack_id": ROE_ACK_ID,
        "approval_id": None,
        "authorized_at": NOW,
    }
    base.update(overrides)
    return ScopeAuthorization(**base)


def _envelope(**overrides) -> ExecutionAuthorization:
    base = {
        "target_id": TARGET_ID,
        "effective_intensity": ScanIntensity.SAFE_ACTIVE,
        "operation_digest": b"digest-A",
        "roe_ack_id": ROE_ACK_ID,
        "approval_gate_id": None,
    }
    base.update(overrides)
    return ExecutionAuthorization(**base)


def test_divergence_none_when_matching() -> None:
    assert divergence_reason(_auth(), _envelope()) is None


def test_divergence_digest_mismatch() -> None:
    assert divergence_reason(_auth(operation_digest=b"other"), _envelope()) == (
        "operation_digest_mismatch"
    )


def test_divergence_intensity_mismatch() -> None:
    auth = _auth(effective_intensity=ScanIntensity.PASSIVE)
    assert divergence_reason(auth, _envelope()) == "intensity_mismatch"


def test_divergence_approval_mismatch() -> None:
    approval_id = uuid.uuid4()
    assert divergence_reason(_auth(approval_id=approval_id), _envelope()) == "approval_mismatch"


def test_divergence_roe_ack_mismatch() -> None:
    assert divergence_reason(_auth(roe_ack_id=uuid.uuid4()), _envelope()) == "roe_ack_mismatch"


# ── launch_scan ────────────────────────────────────────────────────────────────


async def test_launch_creates_scan_and_frozen_envelope() -> None:
    eng = _engagement()
    session = _FakeSession()
    scan = await launch_scan(
        session,
        engagement=eng,
        target=_target(),
        scope_items=ALLOW,
        op=SAFE_OP,
        roe_ack=_accepted_roe(eng, ALLOW),
        initiated_by=ACTOR,
        now=NOW,
        config={"suites": ["prompt_injection"]},
    )
    assert scan.status is ScanStatus.QUEUED
    assert scan.intensity is ScanIntensity.SAFE_ACTIVE
    assert scan.approval_gate_id is None

    envelopes = [o for o in session.added if isinstance(o, ExecutionAuthorization)]
    assert len(envelopes) == 1
    env = envelopes[0]
    assert env.operation_digest == compute_operation_digest(
        eng.id, SAFE_OP, ScanIntensity.SAFE_ACTIVE
    )
    assert env.effective_intensity is ScanIntensity.SAFE_ACTIVE
    assert env.roe_ack_id == ROE_ACK_ID
    assert env.normalized_config["kind"] == OperationKind.SAFE_ACTIVE_SCAN.value
    assert env.normalized_config["suites"] == ["prompt_injection"]


async def test_launch_refuses_unauthorized_operation() -> None:
    eng = _engagement(status=EngagementStatus.DRAFT)  # inactive → keystone raises
    session = _FakeSession()
    with pytest.raises(EngagementInactive):
        await launch_scan(
            session,
            engagement=eng,
            target=_target(),
            scope_items=ALLOW,
            op=SAFE_OP,
            roe_ack=_accepted_roe(eng, ALLOW),
            initiated_by=ACTOR,
            now=NOW,
        )
