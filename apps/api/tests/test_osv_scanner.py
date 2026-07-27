"""M4 next-wave: the OSV-Scanner adapter's pure build_command + normalize.

CI-safe (no binary, no network): covers argv construction and normalization of an
OSV-Scanner JSON report into the shared finding vocabulary — the CVSS→band map
(incl. unscored→LOW and unparseable→HIGH fail-closed) and hostile-shaped output
that must never crash the worker (TM-8). The real binary end-to-end is proven in
scripts/verify_osv_scanner.py.
"""

import json

from app.models.finding import Severity
from app.scanners.base import OutputMode, RawScannerResult, ScannerConfig, ScannerError
from app.scanners.osv import OsvScanner, _severity_for


class _Target:
    def __init__(self, primary_value: str) -> None:
        self.primary_value = primary_value


def _raw(payload: object) -> RawScannerResult:
    return RawScannerResult(exit_code=1, output=json.dumps(payload).encode(), stderr=b"")


def _report(*groups: dict) -> dict:
    return {
        "results": [
            {
                "source": {"path": "/src/requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"},
                        "groups": list(groups),
                    }
                ],
            }
        ]
    }


def test_build_command_scans_source_recursively() -> None:
    inv = OsvScanner(binary="osv-scanner").build_command(
        _Target("https://github.com/acme/repo"),
        ScannerConfig(rate_limit_rps=5, params={"source_path": "/src/extracted"}),
    )
    assert inv.argv == [
        "osv-scanner",
        "scan",
        "source",
        "--format",
        "json",
        "--recursive",
        "/src/extracted",
    ]
    assert inv.output_mode is OutputMode.STDOUT


def test_severity_bands() -> None:
    assert _severity_for("9.8") is Severity.CRITICAL
    assert _severity_for("7.0") is Severity.HIGH
    assert _severity_for("5.5") is Severity.MEDIUM
    assert _severity_for("1.0") is Severity.LOW
    assert _severity_for("") is Severity.LOW  # unscored → report-only band
    assert _severity_for(None) is Severity.LOW
    assert _severity_for("not-a-number") is Severity.HIGH  # unparseable → fail-closed


def test_normalize_maps_group_to_finding() -> None:
    findings = OsvScanner().normalize(
        _raw(_report({"ids": ["CVE-2020-28493", "GHSA-g3rq-g295-4j3m"], "max_severity": "7.5"}))
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.HIGH
    assert f.rule_id == "CVE-2020-28493"
    assert f.fingerprint == "PyPI:jinja2@2.10:CVE-2020-28493"
    assert f.location["package"] == "jinja2" and f.location["version"] == "2.10"
    assert f.location["lockfile"] == "/src/requirements.txt"
    assert "GHSA-g3rq-g295-4j3m" in f.message
    assert "upgrade" in (f.recommendation or "").lower()


def test_normalize_multiple_groups_per_package() -> None:
    findings = OsvScanner().normalize(
        _raw(
            _report(
                {"ids": ["CVE-A"], "max_severity": "9.9"},
                {"ids": ["CVE-B"], "max_severity": ""},
            )
        )
    )
    assert {f.rule_id for f in findings} == {"CVE-A", "CVE-B"}
    by_id = {f.rule_id: f for f in findings}
    assert by_id["CVE-A"].severity is Severity.CRITICAL
    assert by_id["CVE-B"].severity is Severity.LOW  # unscored


def test_normalize_clean_report_is_empty() -> None:
    assert OsvScanner().normalize(_raw({"results": []})) == []
    assert OsvScanner().normalize(RawScannerResult(exit_code=0, output=b"", stderr=b"")) == []


def test_normalize_rejects_non_object() -> None:
    for bad in (b"[]", b"not json"):
        try:
            OsvScanner().normalize(RawScannerResult(exit_code=0, output=bad, stderr=b""))
        except ScannerError:
            continue
        raise AssertionError(f"expected ScannerError for {bad!r}")


def test_normalize_survives_hostile_shapes() -> None:
    # results/packages/groups the wrong type, missing package fields — no crash.
    findings = OsvScanner().normalize(
        _raw(
            {
                "results": [
                    "junk",
                    {"packages": "notalist"},
                    {"packages": [{"groups": [{"ids": "notalist", "max_severity": ["x"]}]}]},
                ]
            }
        )
    )
    assert len(findings) == 1  # only the well-formed-enough group yields a finding
    f = findings[0]
    assert f.location["package"] == "unknown" and f.rule_id == "OSV-UNKNOWN"
    assert f.severity is Severity.HIGH  # non-numeric max_severity → unparseable → fail-closed
