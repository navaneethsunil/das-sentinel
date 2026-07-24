"""M3-B3 CVSS scoring — CI-safe unit tests (no DB).

Covers the pure compute/parse path (values checked against the `cvss` package),
version detection, severity-band mapping, the insert-only supersede behaviour of
`set_cvss_score` via a fake session, the fail-closed manual-override rule, and the
input-schema justification validator. The full HTTP + real-DB history path is
proven in scripts/verify_cvss.py.
"""

import uuid
from types import SimpleNamespace

import pytest

from app.models.cvss import CvssScore, CvssVersion
from app.models.finding import Severity
from app.schemas.cvss import CvssScoreIn
from app.services.cvss import (
    CvssComputeError,
    compute,
    detect_version,
    set_cvss_score,
)

V40_CRITICAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
V31_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_ZERO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
V31_LOW = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
V40_MEDIUM = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"


def test_detect_version() -> None:
    assert detect_version(V40_CRITICAL) is CvssVersion.V4_0
    assert detect_version(V31_CRITICAL) is CvssVersion.V3_1
    assert detect_version("  " + V40_CRITICAL + "  ") is CvssVersion.V4_0


@pytest.mark.parametrize("vector", ["", "garbage", "CVSS:3.0/AV:N", "CVSS:2.0/AV:N/AC:L"])
def test_detect_version_rejects_unsupported(vector: str) -> None:
    with pytest.raises(CvssComputeError):
        detect_version(vector)


def test_compute_v4_critical() -> None:
    c = compute(V40_CRITICAL)
    assert c.version is CvssVersion.V4_0
    assert c.base_score == 10.0
    assert c.severity_band is Severity.CRITICAL
    assert c.vector_string == V40_CRITICAL  # already canonical


def test_compute_v31_critical_and_normalizes_order() -> None:
    unordered = "CVSS:3.1/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U"
    c = compute(unordered)
    assert c.version is CvssVersion.V3_1
    assert c.base_score == 9.8
    assert c.severity_band is Severity.CRITICAL
    # clean_vector normalizes metric ordering back to canonical.
    assert c.vector_string == V31_CRITICAL


def test_compute_severity_bands() -> None:
    assert compute(V31_ZERO).severity_band is Severity.INFORMATIONAL  # 'None' label → INFO
    assert compute(V31_ZERO).base_score == 0.0
    assert compute(V31_LOW).severity_band is Severity.LOW
    assert compute(V31_LOW).base_score == 3.7
    assert compute(V40_MEDIUM).severity_band is Severity.MEDIUM
    assert compute(V40_MEDIUM).base_score == 5.3


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",  # bad metric value
        "CVSS:3.1/AV:N/AC:L",  # incomplete
        "CVSS:4.0/",  # empty body
    ],
)
def test_compute_rejects_malformed(vector: str) -> None:
    with pytest.raises(CvssComputeError):
        compute(vector)


class _FakeSession:
    """Minimal AsyncSession stand-in for set_cvss_score (no DB)."""

    def __init__(self) -> None:
        self.executed: list[object] = []
        self.added: list[object] = []
        self.flushed = False

    async def execute(self, stmt: object) -> object:
        self.executed.append(stmt)
        return SimpleNamespace(rowcount=0)

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushed = True


@pytest.mark.asyncio
async def test_set_cvss_score_computes_and_supersedes() -> None:
    session = _FakeSession()
    finding = SimpleNamespace(id=uuid.uuid4())
    user = uuid.uuid4()

    score = await set_cvss_score(
        session,  # type: ignore[arg-type]
        finding=finding,  # type: ignore[arg-type]
        vector_string=V40_CRITICAL,
        scored_by=user,
    )

    assert isinstance(score, CvssScore)
    assert score.finding_id == finding.id
    assert score.version is CvssVersion.V4_0
    assert score.base_score == 10.0
    assert score.severity_band is Severity.CRITICAL
    assert score.is_current is True
    assert score.is_manual_override is False
    assert score.override_justification is None
    assert score.scored_by == user
    # Prior current row is superseded (one UPDATE) before the INSERT+flush.
    assert len(session.executed) == 1
    assert session.added == [score]
    assert session.flushed is True


@pytest.mark.asyncio
async def test_set_cvss_score_manual_override_requires_justification() -> None:
    session = _FakeSession()
    finding = SimpleNamespace(id=uuid.uuid4())
    with pytest.raises(CvssComputeError):
        await set_cvss_score(
            session,  # type: ignore[arg-type]
            finding=finding,  # type: ignore[arg-type]
            vector_string=V31_CRITICAL,
            is_manual_override=True,
            override_justification="   ",  # whitespace-only is not a justification
        )
    # Nothing written on the fail-closed path.
    assert session.added == []
    assert session.flushed is False


@pytest.mark.asyncio
async def test_set_cvss_score_manual_override_stores_stripped_justification() -> None:
    session = _FakeSession()
    finding = SimpleNamespace(id=uuid.uuid4())
    score = await set_cvss_score(
        session,  # type: ignore[arg-type]
        finding=finding,  # type: ignore[arg-type]
        vector_string=V31_CRITICAL,
        is_manual_override=True,
        override_justification="  environmental context raises impact  ",
    )
    assert score.is_manual_override is True
    assert score.override_justification == "environmental context raises impact"


def test_input_schema_requires_justification_on_override() -> None:
    with pytest.raises(ValueError):
        CvssScoreIn(vector_string=V40_CRITICAL, is_manual_override=True)
    with pytest.raises(ValueError):
        CvssScoreIn(vector_string=V40_CRITICAL, is_manual_override=True, override_justification=" ")
    # Non-override needs no justification; override with one is fine.
    assert CvssScoreIn(vector_string=V40_CRITICAL).is_manual_override is False
    ok = CvssScoreIn(
        vector_string=V40_CRITICAL, is_manual_override=True, override_justification="x"
    )
    assert ok.override_justification == "x"
