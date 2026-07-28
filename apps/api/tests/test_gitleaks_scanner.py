"""M4 next-wave: the Gitleaks adapter's pure build_command + normalize.

CI-safe (no gitleaks binary, no infra): covers argv construction (redacted, JSON
report to the run workdir, source_path preference) and normalization of a
Gitleaks JSON report into the shared finding vocabulary, including hostile-shaped
output that must never crash the worker (TM-8). The real binary end-to-end is
proven in scripts/verify_gitleaks_scanner.py.
"""

import json

from app.models.finding import Severity
from app.scanners.base import OutputMode, RawScannerResult, ScannerConfig, ScannerError
from app.scanners.gitleaks import GitleaksScanner


class _Target:
    def __init__(self, primary_value: str) -> None:
        self.primary_value = primary_value


def _raw(payload: object) -> RawScannerResult:
    return RawScannerResult(exit_code=0, output=json.dumps(payload).encode(), stderr=b"")


def test_build_command_scans_source_path_redacted_to_file() -> None:
    inv = GitleaksScanner(binary="gitleaks").build_command(
        _Target("https://github.com/acme/repo"),
        ScannerConfig(rate_limit_rps=5, params={"source_path": "/src/extracted"}),
    )
    assert inv.argv[:3] == ["gitleaks", "dir", "/src/extracted"]  # source_path wins
    assert "--redact" in inv.argv  # never write the raw secret (§2.5)
    assert inv.output_mode is OutputMode.FILE and inv.output_filename == "gitleaks-report.json"
    assert inv.persisted_config["redacted"] is True


def test_build_command_falls_back_to_primary_value() -> None:
    inv = GitleaksScanner(binary="gitleaks").build_command(
        _Target("/checkout/path"), ScannerConfig(rate_limit_rps=5)
    )
    assert inv.argv[2] == "/checkout/path"


def test_build_command_rejects_leading_dash_target() -> None:
    # SEC-DEBT-9: a '-'-prefixed target could be read as a gitleaks flag. Fail closed.
    import pytest

    with pytest.raises(ScannerError, match="must not start with '-'"):
        GitleaksScanner(binary="gitleaks").build_command(
            _Target("/repo"), ScannerConfig(rate_limit_rps=5, params={"source_path": "--version"})
        )


def test_normalize_maps_leak_to_high_finding() -> None:
    findings = GitleaksScanner().normalize(
        _raw(
            [
                {
                    "RuleID": "aws-access-token",
                    "Description": "AWS Access Key",
                    "File": "config/app.py",
                    "StartLine": 12,
                    "EndLine": 12,
                    "Match": "REDACTED",
                    "Secret": "REDACTED",
                    "Tags": ["key", "AWS"],
                    "Fingerprint": "config/app.py:aws-access-token:12",
                }
            ]
        )
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.HIGH
    assert f.rule_id == "aws-access-token"
    assert f.fingerprint == "config/app.py:aws-access-token:12"
    assert f.location["file"] == "config/app.py" and f.location["start_line"] == 12
    assert f.location["match"] == "REDACTED"  # secret never surfaced
    assert "revoke" in (f.recommendation or "").lower()


def test_normalize_empty_and_null_reports() -> None:
    assert GitleaksScanner().normalize(_raw([])) == []
    assert GitleaksScanner().normalize(_raw(None)) == []  # gitleaks emits null when clean
    assert GitleaksScanner().normalize(RawScannerResult(exit_code=0, output=b"", stderr=b"")) == []


def test_normalize_rejects_non_array_and_bad_json() -> None:
    for bad in (b"{not json", json.dumps({"results": []}).encode()):
        try:
            GitleaksScanner().normalize(RawScannerResult(exit_code=0, output=bad, stderr=b""))
        except ScannerError:
            continue
        raise AssertionError(f"expected ScannerError for {bad!r}")


def test_normalize_survives_hostile_field_shapes() -> None:
    # Every field is the wrong type / missing — must not raise, must degrade safely.
    findings = GitleaksScanner().normalize(
        _raw([{"File": ["x"], "StartLine": "nope", "Tags": "notalist"}, "junk", 5])
    )
    assert len(findings) == 1  # only the dict entry becomes a finding
    f = findings[0]
    assert f.rule_id == "gitleaks.generic" and f.location["file"] is None
    assert f.location["start_line"] is None and f.location["tags"] == []
    assert f.severity is Severity.HIGH
