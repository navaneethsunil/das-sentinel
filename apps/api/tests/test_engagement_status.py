"""M1-B6: engagement status machine. Full endpoint behavior (RBAC, org
scoping, audit) is verified live (scripts/verify_engagements.py); here we pin
every transition, allowed and forbidden."""

import pytest

from app.models.engagement import EngagementStatus
from app.services.engagements import can_transition

S = EngagementStatus

ALLOWED = {
    (S.DRAFT, S.ACTIVE),
    (S.DRAFT, S.CLOSED),
    (S.ACTIVE, S.PAUSED),
    (S.ACTIVE, S.CLOSED),
    (S.PAUSED, S.ACTIVE),
    (S.PAUSED, S.CLOSED),
}


@pytest.mark.parametrize("current", list(S))
@pytest.mark.parametrize("target", list(S))
def test_transition_matrix(current: EngagementStatus, target: EngagementStatus) -> None:
    assert can_transition(current, target) is ((current, target) in ALLOWED)


def test_closed_is_terminal() -> None:
    assert not any(can_transition(S.CLOSED, t) for t in S)


def test_no_self_transition_is_allowed() -> None:
    # Same-status is a no-op the router special-cases; the machine itself
    # never lists a status as a valid target of itself.
    assert not any(can_transition(s, s) for s in S)
