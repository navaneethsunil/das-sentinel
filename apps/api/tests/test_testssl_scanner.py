"""M4 recon (slice 3): the testssl.sh adapter's pure build_command + normalize.

CI-safe (no binary, no network): covers argv construction (bounded TLS checks,
non-interactive, JSON to the run workdir) and normalization of testssl's JSON
array into findings — mapping testssl severities, dropping OK/INFO status lines,
and surviving hostile-shaped output (TM-8). The real TLS assessment is proven in
scripts/verify_testssl_scanner.py.
"""

import json

from app.models.finding import Severity
from app.scanners.base import OutputMode, RawScannerResult, ScannerConfig, ScannerError
from app.scanners.testssl import TestsslScanner


class _Target:
    def __init__(self, primary_value: str) -> None:
        self.primary_value = primary_value


def _raw(payload: object) -> RawScannerResult:
    return RawScannerResult(exit_code=0, output=json.dumps(payload).encode(), stderr=b"")


def test_build_command_is_a_bounded_tls_assessment() -> None:
    inv = TestsslScanner(binary="testssl.sh").build_command(
        _Target("https://tls-target:443"), ScannerConfig(rate_limit_rps=5)
    )
    argv = inv.argv
    assert argv[0] == "testssl.sh" and argv[-1] == "https://tls-target:443"
    assert argv[argv.index("--jsonfile") + 1] == "testssl-report.json"
    assert argv[argv.index("--warnings") + 1] == "batch"  # non-interactive
    assert "-p" in argv and "-S" in argv and "-h" in argv  # bounded check set
    assert "--connect-timeout" in argv and "--openssl-timeout" in argv
    assert inv.output_mode is OutputMode.FILE and inv.output_filename == "testssl-report.json"
    assert inv.persisted_config["mode"] == "recon-tls"


def test_normalize_maps_severities_and_drops_status_lines() -> None:
    findings = TestsslScanner().normalize(
        _raw(
            [
                {
                    "id": "cert_trust",
                    "severity": "HIGH",
                    "finding": "certificate not trusted",
                    "ip": "10.0.0.5",
                    "port": "443",
                    "cwe": "CWE-295",
                },
                {"id": "TLS1", "severity": "MEDIUM", "finding": "TLS 1.0 offered"},
                {"id": "HSTS", "severity": "LOW", "finding": "no HSTS"},
                {"id": "scanTime", "severity": "INFO", "finding": "42"},  # status, dropped
                {"id": "TLS1_3", "severity": "OK", "finding": "offered"},  # status, dropped
            ]
        )
    )
    assert len(findings) == 3
    by = {f.rule_id: f for f in findings}
    assert by["cert_trust"].severity is Severity.HIGH
    assert (
        by["cert_trust"].location["ip"] == "10.0.0.5"
        and by["cert_trust"].location["cwe"] == "CWE-295"
    )
    assert by["cert_trust"].fingerprint == "cert_trust:10.0.0.5:443"
    assert by["TLS1"].severity is Severity.MEDIUM
    assert by["HSTS"].severity is Severity.LOW


def test_normalize_warn_maps_to_low() -> None:
    findings = TestsslScanner().normalize(_raw([{"id": "x", "severity": "WARN", "finding": "w"}]))
    assert len(findings) == 1 and findings[0].severity is Severity.LOW


def test_normalize_empty_and_no_findings() -> None:
    assert TestsslScanner().normalize(_raw([])) == []
    assert TestsslScanner().normalize(RawScannerResult(exit_code=0, output=b"", stderr=b"")) == []
    # all-status report → no findings
    assert TestsslScanner().normalize(_raw([{"id": "a", "severity": "OK"}])) == []


def test_normalize_rejects_non_array() -> None:
    for bad in (b"{not json", json.dumps({"scanResult": []}).encode()):
        try:
            TestsslScanner().normalize(RawScannerResult(exit_code=0, output=bad, stderr=b""))
        except ScannerError:
            continue
        raise AssertionError(f"expected ScannerError for {bad!r}")


def test_normalize_survives_hostile_shapes() -> None:
    findings = TestsslScanner().normalize(
        _raw([{"severity": "HIGH", "id": 5, "ip": ["x"], "finding": None}, "junk", 7])
    )
    assert len(findings) == 1  # only the dict with a mapped severity
    f = findings[0]
    assert f.rule_id == "5" and f.location["ip"] is None  # non-str coerced to None
    assert f.severity is Severity.HIGH
