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

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.scope import OperationKind
from app.models.scan import ScanIntensity, ScanStatus, TestSuite
from app.models.target import TargetType

# The LLM suites that exist today (M2). agent_permission is M5 — not launchable yet.
_LAUNCHABLE_SUITES = frozenset({TestSuite.PROMPT_INJECTION, TestSuite.DATA_LEAKAGE})


class ScannerKind(enum.Enum):
    """The external scanners the launcher can drive (M3-W2/W3)."""

    SEMGREP = "semgrep"  # SAST — source code
    ZAP = "zap"  # DAST — running web/API app


# Which target types each scanner can legitimately run against. A SAST tool needs
# source; a DAST tool needs a reachable web/API endpoint.
_SCANNER_TARGET_TYPES: dict[ScannerKind, frozenset[TargetType]] = {
    ScannerKind.SEMGREP: frozenset({TargetType.SOURCE_ARCHIVE, TargetType.SOURCE_REPO}),
    ScannerKind.ZAP: frozenset({TargetType.WEB_APP, TargetType.REST_API, TargetType.GRAPHQL_API}),
}


def scanner_target_error(target_type: TargetType, scanners: list[ScannerKind]) -> str | None:
    """Return a message if any chosen scanner can't run against this target type,
    else None. Enforced at the launch endpoint (fail-closed → 422)."""
    for scanner in scanners:
        if target_type not in _SCANNER_TARGET_TYPES[scanner]:
            allowed = ", ".join(sorted(t.value for t in _SCANNER_TARGET_TYPES[scanner]))
            return (
                f"{scanner.value} cannot run against a {target_type.value} target "
                f"(supported: {allowed})"
            )
    return None


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
    """Launch either an LLM test-suite scan (`suites`) or an external-scanner scan
    (`scanners`) against a target — exactly one of the two. Intensity is a safe,
    non-high-risk subset; high-risk kinds need an approval gate and aren't launchable
    here (the scope keystone blocks them → the UI surfaces the requirement)."""

    target_id: uuid.UUID
    suites: list[TestSuite] = Field(default_factory=list)
    scanners: list[ScannerKind] = Field(default_factory=list)
    intensity: LaunchIntensity = LaunchIntensity.SAFE_ACTIVE

    @field_validator("suites")
    @classmethod
    def _only_launchable(cls, suites: list[TestSuite]) -> list[TestSuite]:
        unavailable = [s.value for s in suites if s not in _LAUNCHABLE_SUITES]
        if unavailable:
            raise ValueError(f"suite(s) not available yet: {sorted(set(unavailable))}")
        return suites

    @model_validator(mode="after")
    def _exactly_one_kind(self) -> "ScanLaunchIn":
        if bool(self.suites) == bool(self.scanners):
            raise ValueError("provide exactly one of 'suites' or 'scanners'")
        return self

    @property
    def is_scanner_launch(self) -> bool:
        return bool(self.scanners)

    def operation_kind(self) -> OperationKind:
        return _LAUNCH_KIND[self.intensity]

    def _unique(self, values: list) -> list:  # noqa: ANN001 - generic order-preserving dedupe
        seen: set = set()
        ordered: list = []
        for value in values:
            if value not in seen:
                seen.add(value)
                ordered.append(value)
        return ordered

    def unique_suites(self) -> list[TestSuite]:
        return self._unique(self.suites)

    def unique_scanners(self) -> list[ScannerKind]:
        return self._unique(self.scanners)


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
