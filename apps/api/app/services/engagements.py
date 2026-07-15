"""Engagement lifecycle rules (M1-B6).

The status machine is draft → active → paused → closed. Pausing an active
engagement and resuming it are both allowed; closed is terminal. Enforced here
(pure, deterministic) so the router and any future caller share one definition.
"""

from app.models.engagement import EngagementStatus

_S = EngagementStatus

ALLOWED_TRANSITIONS: dict[EngagementStatus, frozenset[EngagementStatus]] = {
    _S.DRAFT: frozenset({_S.ACTIVE, _S.CLOSED}),
    _S.ACTIVE: frozenset({_S.PAUSED, _S.CLOSED}),
    _S.PAUSED: frozenset({_S.ACTIVE, _S.CLOSED}),
    _S.CLOSED: frozenset(),  # terminal
}


def can_transition(current: EngagementStatus, target: EngagementStatus) -> bool:
    return target in ALLOWED_TRANSITIONS[current]
