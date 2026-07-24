"""T1 production wiring — scan dispatch (kind classification + queue routing +
owner selection). CI-safe (fake session; no infra, no tool imports triggered).
"""

import uuid
from datetime import UTC, datetime

import pytest

from app.workers.dispatch import (
    QUEUE_FOR_KIND,
    SCANNER_KIND,
    SUITE_KIND,
    build_owner_for_kind,
    kind_for_config,
    load_scan_kind,
)
from app.workers.execution import InProcessOwner

NOW = datetime(2026, 7, 24, tzinfo=UTC)


def test_kind_for_config_scanner() -> None:
    assert kind_for_config({"kind": "safe_active_scan", "scanners": ["semgrep"]}) == SCANNER_KIND


def test_kind_for_config_suite() -> None:
    config = {"kind": "safe_active_scan", "suites": ["prompt_injection"]}
    assert kind_for_config(config) == SUITE_KIND


def test_kind_for_config_empty_or_missing_scanners_is_suite() -> None:
    assert kind_for_config({"scanners": []}) == SUITE_KIND  # empty list → not a scanner run
    assert kind_for_config({}) == SUITE_KIND
    assert kind_for_config("not-a-dict") == SUITE_KIND  # type: ignore[arg-type]


def test_queue_mapping_matches_worker_images() -> None:
    # LLM suites need PyRIT (redteam image); scanners need semgrep/ZAP.
    assert QUEUE_FOR_KIND[SUITE_KIND] == "redteam"
    assert QUEUE_FOR_KIND[SCANNER_KIND] == "scanners"


class _Result:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _FakeSession:
    def __init__(self, config: object) -> None:
        self._config = config

    async def execute(self, _stmt: object) -> _Result:
        return _Result(self._config)


async def test_load_scan_kind_scanner() -> None:
    session = _FakeSession({"scanners": ["semgrep"]})
    assert await load_scan_kind(session, uuid.uuid4()) == SCANNER_KIND  # type: ignore[arg-type]


async def test_load_scan_kind_suite() -> None:
    session = _FakeSession({"suites": ["data_leakage"]})
    assert await load_scan_kind(session, uuid.uuid4()) == SUITE_KIND  # type: ignore[arg-type]


async def test_load_scan_kind_missing_envelope_raises() -> None:
    with pytest.raises(ValueError, match="no execution authorization"):
        await load_scan_kind(_FakeSession(None), uuid.uuid4())  # type: ignore[arg-type]


def test_build_owner_for_kind_returns_inprocess_owner() -> None:
    # Owner construction wraps a run_fn closure — it does not touch the (None)
    # sessionmaker/store until launched, so this exercises the branch selection.
    for kind in (SUITE_KIND, SCANNER_KIND):
        owner = build_owner_for_kind(kind, None, None, scan_id=uuid.uuid4(), now=NOW)  # type: ignore[arg-type]
        assert isinstance(owner, InProcessOwner)
