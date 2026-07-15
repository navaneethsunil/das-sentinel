"""Engagement lifecycle rules (M1-B6).

The status machine is draft → active → paused → closed. Pausing an active
engagement and resuming it are both allowed; closed is terminal. Enforced here
(pure, deterministic) so the router and any future caller share one definition.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.engagement import Engagement, EngagementStatus

_S = EngagementStatus


async def get_org_engagement(
    db: AsyncSession, engagement_id: uuid.UUID, org_id: uuid.UUID
) -> Engagement | None:
    """Fetch a live (non-soft-deleted) engagement within an org, or None.
    Routers map None → 404 (no cross-org existence leak); services stay free of
    HTTP concerns (ARCHITECTURE layering)."""
    return (
        await db.execute(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.organization_id == org_id,
                Engagement.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()


ALLOWED_TRANSITIONS: dict[EngagementStatus, frozenset[EngagementStatus]] = {
    _S.DRAFT: frozenset({_S.ACTIVE, _S.CLOSED}),
    _S.ACTIVE: frozenset({_S.PAUSED, _S.CLOSED}),
    _S.PAUSED: frozenset({_S.ACTIVE, _S.CLOSED}),
    _S.CLOSED: frozenset(),  # terminal
}


def can_transition(current: EngagementStatus, target: EngagementStatus) -> bool:
    return target in ALLOWED_TRANSITIONS[current]
