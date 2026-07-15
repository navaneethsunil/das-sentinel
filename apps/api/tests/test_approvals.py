"""M1-B11: approval-gate state-machine transitions. The atomic single-use
consume (DB conditional UPDATE) and endpoint RBAC are verified live
(scripts/verify_approvals.py); here we pin the pure transition guards."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.models.engagement import ApprovalGate, ApprovalStatus
from app.services.approvals import (
    ApprovalStateError,
    decide_approval,
    expire_if_due,
    revoke_approval,
)

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)


def _pending_gate(**overrides: object) -> ApprovalGate:
    gate = ApprovalGate(
        id=uuid.uuid4(),
        engagement_id=uuid.uuid4(),
        target_id=uuid.uuid4(),
        requested_by=uuid.uuid4(),
        action_type="exploit_validation",
        justification="j",
        operation_digest=b"\x00" * 32,
        roe_ack_id=uuid.uuid4(),
        policy_version="1",
        status=ApprovalStatus.PENDING,
        expires_at=NOW + timedelta(hours=1),
    )
    for k, v in overrides.items():
        setattr(gate, k, v)
    return gate


def test_decide_approves_pending() -> None:
    gate = _pending_gate()
    decide_approval(gate, decided_by=uuid.uuid4(), approve=True, reason="ok", now=NOW)
    assert gate.status is ApprovalStatus.APPROVED
    assert gate.decided_at == NOW and gate.decided_by is not None


def test_decide_denies_pending() -> None:
    gate = _pending_gate()
    decide_approval(gate, decided_by=uuid.uuid4(), approve=False, reason="no", now=NOW)
    assert gate.status is ApprovalStatus.DENIED
    assert gate.decided_at is not None


def test_cannot_decide_twice() -> None:
    gate = _pending_gate()
    decide_approval(gate, decided_by=uuid.uuid4(), approve=True, reason=None, now=NOW)
    with pytest.raises(ApprovalStateError):
        decide_approval(gate, decided_by=uuid.uuid4(), approve=True, reason=None, now=NOW)


def test_cannot_decide_expired_request() -> None:
    gate = _pending_gate(expires_at=NOW - timedelta(seconds=1))
    with pytest.raises(ApprovalStateError, match="expired"):
        decide_approval(gate, decided_by=uuid.uuid4(), approve=True, reason=None, now=NOW)
    assert gate.status is ApprovalStatus.EXPIRED  # auto-transitioned


def test_revoke_only_from_approved() -> None:
    gate = _pending_gate()
    with pytest.raises(ApprovalStateError):
        revoke_approval(gate, revoked_by=uuid.uuid4(), reason=None, now=NOW)
    decide_approval(gate, decided_by=uuid.uuid4(), approve=True, reason=None, now=NOW)
    revoke_approval(gate, revoked_by=uuid.uuid4(), reason="compromised", now=NOW)
    assert gate.status is ApprovalStatus.REVOKED
    assert gate.revoked_at is not None


def test_cannot_revoke_twice() -> None:
    gate = _pending_gate()
    decide_approval(gate, decided_by=uuid.uuid4(), approve=True, reason=None, now=NOW)
    revoke_approval(gate, revoked_by=uuid.uuid4(), reason=None, now=NOW)
    with pytest.raises(ApprovalStateError):
        revoke_approval(gate, revoked_by=uuid.uuid4(), reason=None, now=NOW)


def test_expire_if_due_flips_pending_and_approved() -> None:
    past = NOW - timedelta(seconds=1)
    assert expire_if_due(_pending_gate(expires_at=past), NOW) is True
    approved = _pending_gate(
        status=ApprovalStatus.APPROVED,
        decided_by=uuid.uuid4(),
        decided_at=NOW - timedelta(hours=2),
        expires_at=past,
    )
    assert expire_if_due(approved, NOW) is True
    assert approved.status is ApprovalStatus.EXPIRED


def test_expire_if_due_noop_when_live() -> None:
    assert expire_if_due(_pending_gate(), NOW) is False
