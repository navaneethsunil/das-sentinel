"""CI-safe unit tests for the scanner framework (M3-W1).

Cover the pure, DB-free, subprocess-free surface: the stub adapter's
build_command/normalize contract, the envelope→scanners resolution, result
serialization determinism, and the finding dedup identity. The full execution
path (SubprocessOwner launch → raw capture → persist → cancel) is proven live in
scripts/verify_scanner_framework.py.
"""

import json
from dataclasses import dataclass

import pytest

from app.models.finding import Severity
from app.scanners.base import (
    OutputMode,
    RawScannerResult,
    ScannerConfig,
    ScannerError,
    ScannerResult,
    serialize_scanner_result,
)
from app.scanners.stub import StubScanner
from app.services.scanner_findings import _hash_code
from app.workers.scanner_run import ScannerRunError, scanners_from_config


@dataclass
class _Target:
    primary_value: str


def _cfg(**params) -> ScannerConfig:
    return ScannerConfig(rate_limit_rps=5, params=params)


def test_build_command_echo_mode_is_argv_vector() -> None:
    inv = StubScanner().build_command(_Target(primary_value="https://app.example.com"), _cfg())
    assert inv.output_mode is OutputMode.STDOUT
    assert inv.argv[0].endswith("echo")
    # The target value is carried as JSON data in a single argv element, never
    # concatenated into a shell string (TM-6).
    payload = json.loads(inv.argv[1])
    assert all(f["fingerprint"].endswith("@https://app.example.com") for f in payload)
    assert inv.persisted_config["mode"] == "echo"
    assert inv.persisted_config["rate_limit_rps"] == 5
    assert inv.rules_digest == "stub-rules-v1"


def test_build_command_hang_mode_is_cancellable_sleep() -> None:
    inv = StubScanner().build_command(_Target(primary_value="x"), _cfg(hang=True))
    assert inv.argv[0].endswith("sleep")
    assert inv.persisted_config["mode"] == "hang"


def test_normalize_parses_findings() -> None:
    scanner = StubScanner()
    inv = scanner.build_command(_Target(primary_value="pkg"), _cfg())
    raw = RawScannerResult(exit_code=0, output=inv.argv[1].encode(), stderr=b"")
    findings = scanner.normalize(raw)
    assert len(findings) == 2
    sevs = {f.severity for f in findings}
    assert Severity.HIGH in sevs and Severity.MEDIUM in sevs
    assert all(f.rule_id and f.fingerprint for f in findings)


def test_normalize_empty_output_is_no_findings() -> None:
    assert StubScanner().normalize(RawScannerResult(exit_code=0, output=b"", stderr=b"")) == []


@pytest.mark.parametrize("bad", [b"{not json", b"null", b'"a string"', b"42"])
def test_normalize_hostile_output_fails_safe(bad: bytes) -> None:
    # Malformed or non-list output raises ScannerError (surfaced), never crashes
    # the worker or silently returns findings (TM-8).
    with pytest.raises(ScannerError):
        StubScanner().normalize(RawScannerResult(exit_code=0, output=bad, stderr=b""))


def test_scanners_from_config_orders_and_dedups() -> None:
    assert scanners_from_config({"scanners": ["stub", "stub"]}) == ["stub"]


def test_scanners_from_config_unknown_raises() -> None:
    with pytest.raises(ScannerRunError):
        scanners_from_config({"scanners": ["nope"]})


def test_scanners_from_config_empty_raises() -> None:
    with pytest.raises(ScannerRunError):
        scanners_from_config({"scanners": []})
    with pytest.raises(ScannerRunError):
        scanners_from_config({})


def test_serialize_scanner_result_is_deterministic() -> None:
    result = ScannerResult(
        scanner_name="stub",
        scanner_version="0.1.0",
        findings=(),
        config={"mode": "echo"},
        metadata={"b": 1, "a": 2},
    )
    assert serialize_scanner_result(result) == serialize_scanner_result(result)
    # sorted keys → stable content addressing
    assert b'"a":2' in serialize_scanner_result(result)


def test_hash_code_is_stable_and_distinct() -> None:
    import uuid

    eng, tgt = uuid.uuid4(), uuid.uuid4()
    a = _hash_code(eng, tgt, "stub", "rule@x")
    assert a == _hash_code(eng, tgt, "stub", "rule@x")
    assert a != _hash_code(eng, tgt, "stub", "rule@y")
    assert a != _hash_code(eng, tgt, "semgrep", "rule@x")
