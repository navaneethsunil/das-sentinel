"""Scan schemas (M2-W2, M2-F1).

`ScanOut` is the read-only projection for status/list/cancel responses.
`ScanLaunchIn` is the suite launcher's request body (M2-F1): the caller chooses
a target, one or more LLM test suites, and an intensity. Intensity is expressed
as a small, safe subset of `OperationKind` — the server derives the *effective*
intensity from that kind and checks it against the engagement's ceiling; it is
never taken from a caller-declared number (the M1-B9 rule). High-risk kinds are
deliberately not launchable here (they need an approval gate — M3-F1).
"""

import enum
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.scope import OperationKind
from app.models.scan import ScanIntensity, ScanStatus, TestSuite

# The LLM suites that exist today (M2). agent_permission is M5 — not launchable yet.
_LAUNCHABLE_SUITES = frozenset({TestSuite.PROMPT_INJECTION, TestSuite.DATA_LEAKAGE})


class LaunchIntensity(enum.Enum):
    """The intensity the launcher exposes for LLM suites. Each maps to a typed
    OperationKind whose effective intensity the scope keystone derives. Only the
    non-high-risk kinds are offered (high-risk needs an approval gate)."""

    SAFE_ACTIVE = "safe_active"
    AUTHENTICATED_ACTIVE = "authenticated_active"


_LAUNCH_KIND: dict[LaunchIntensity, OperationKind] = {
    LaunchIntensity.SAFE_ACTIVE: OperationKind.SAFE_ACTIVE_SCAN,
    LaunchIntensity.AUTHENTICATED_ACTIVE: OperationKind.AUTHENTICATED_SCAN,
}


class ScanLaunchIn(BaseModel):
    target_id: uuid.UUID
    suites: list[TestSuite] = Field(min_length=1)
    intensity: LaunchIntensity = LaunchIntensity.SAFE_ACTIVE

    @field_validator("suites")
    @classmethod
    def _only_launchable(cls, suites: list[TestSuite]) -> list[TestSuite]:
        unavailable = [s.value for s in suites if s not in _LAUNCHABLE_SUITES]
        if unavailable:
            raise ValueError(f"suite(s) not available yet: {sorted(set(unavailable))}")
        return suites

    def operation_kind(self) -> OperationKind:
        return _LAUNCH_KIND[self.intensity]

    def unique_suites(self) -> list[TestSuite]:
        """De-dupe while preserving the caller's order."""
        seen: set[TestSuite] = set()
        ordered: list[TestSuite] = []
        for suite in self.suites:
            if suite not in seen:
                seen.add(suite)
                ordered.append(suite)
        return ordered


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
