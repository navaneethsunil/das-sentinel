"""M4 recon (slice 2): the katana adapter's pure build_command + normalize.

CI-safe (no binary, no network): covers argv construction (safe-crawl limits +
same-host scope + no form-fill/headless) and normalization of katana JSONL into
INFORMATIONAL endpoint-discovery facts, deduped per (method, endpoint), including
hostile-shaped output that must never crash the worker (TM-8). The real crawl is
proven in scripts/verify_katana_recon.py.
"""

from app.models.finding import Severity
from app.scanners.base import OutputMode, RawScannerResult, ScannerConfig, ScannerError
from app.scanners.katana_recon import KatanaReconScanner


class _Target:
    def __init__(self, primary_value: str) -> None:
        self.primary_value = primary_value


def _raw(text: str) -> RawScannerResult:
    return RawScannerResult(exit_code=0, output=text.encode(), stderr=b"")


def test_build_command_enforces_safe_crawl_limits() -> None:
    inv = KatanaReconScanner(binary="katana").build_command(
        _Target("http://vuln-target:8000"), ScannerConfig(rate_limit_rps=5)
    )
    argv = inv.argv
    assert argv[argv.index("-u") + 1] == "http://vuln-target:8000"
    assert argv[argv.index("-field-scope") + 1] == "fqdn"  # never leaves the seed host
    assert argv[argv.index("-depth") + 1] == "2"
    assert "-crawl-duration" in argv  # bounded
    assert argv[argv.index("-rate-limit") + 1] == "5"  # floored to engagement ceiling
    assert "-jsonl" in argv and "-disable-update-check" in argv
    # NO intrusive/heavy modes
    assert "-automatic-form-fill" not in argv and "-aff" not in argv
    assert "-headless" not in argv and "-hl" not in argv
    assert inv.output_mode is OutputMode.STDOUT
    assert (
        inv.persisted_config["field_scope"] == "fqdn" and inv.persisted_config["form_fill"] is False
    )


def test_build_command_allows_bounded_overrides() -> None:
    inv = KatanaReconScanner(binary="katana").build_command(
        _Target("http://t"),
        ScannerConfig(rate_limit_rps=3, params={"depth": 1, "crawl_duration": "30"}),
    )
    assert inv.argv[inv.argv.index("-depth") + 1] == "1"
    assert inv.argv[inv.argv.index("-crawl-duration") + 1] == "30"


def test_normalize_maps_endpoints_and_dedups() -> None:
    lines = "\n".join(
        [
            '{"request":{"method":"GET","endpoint":"http://t:8000/","tag":"a","source":"root"},'
            '"response":{"status_code":200}}',
            '{"request":{"method":"GET","endpoint":"http://t:8000/login"}}',
            # duplicate of the first — deduped
            '{"request":{"method":"GET","endpoint":"http://t:8000/"}}',
        ]
    )
    findings = KatanaReconScanner().normalize(_raw(lines + "\n"))
    assert len(findings) == 2  # / and /login, dup dropped
    assert all(f.severity is Severity.INFORMATIONAL for f in findings)
    assert all(f.rule_id == "katana-endpoint" for f in findings)
    root = next(f for f in findings if f.location["url"].endswith("/"))
    assert root.location["method"] == "GET" and root.location["status_code"] == 200
    assert root.fingerprint == "endpoint:GET:http://t:8000/"


def test_normalize_skips_lines_without_endpoint() -> None:
    findings = KatanaReconScanner().normalize(
        _raw('{"request":{"method":"GET"}}\n{"response":{"status_code":404}}\n')
    )
    assert findings == []


def test_normalize_empty_and_blank() -> None:
    assert KatanaReconScanner().normalize(_raw("\n \n")) == []
    assert (
        KatanaReconScanner().normalize(RawScannerResult(exit_code=0, output=b"", stderr=b"")) == []
    )


def test_normalize_raises_on_bad_json_line() -> None:
    try:
        KatanaReconScanner().normalize(_raw('{"request":{"endpoint":"http://t/"}}\n{broken\n'))
    except ScannerError:
        return
    raise AssertionError("expected ScannerError on malformed JSONL")


def test_normalize_survives_hostile_shapes() -> None:
    # request/response wrong types, endpoint present at top level, bare non-objects.
    findings = KatanaReconScanner().normalize(
        _raw('{"request":"nope","response":"nope","endpoint":"http://t/x"}\n"junk"\n7\n')
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.location["url"] == "http://t/x" and f.location["method"] == "GET"  # default
    assert f.location["status_code"] is None and f.severity is Severity.INFORMATIONAL
