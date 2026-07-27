"""M4 next-wave: the Nuclei adapter's pure build_command + normalize.

CI-safe (no binary, no network): covers argv construction (safe-active flags, URL
target, vendored templates, rate-limit floor, no OOB) and normalization of Nuclei
JSONL into the shared finding vocabulary — including hostile-shaped lines that
must never crash the worker (TM-8). The real binary end-to-end (active scan of the
sandbox target) is proven in scripts/verify_nuclei_scanner.py.
"""

from app.models.finding import Severity
from app.scanners.base import OutputMode, RawScannerResult, ScannerConfig, ScannerError
from app.scanners.nuclei import NucleiScanner


class _Target:
    def __init__(self, primary_value: str) -> None:
        self.primary_value = primary_value


def _raw(text: str) -> RawScannerResult:
    return RawScannerResult(exit_code=0, output=text.encode(), stderr=b"")


def test_build_command_is_safe_active_against_the_url() -> None:
    inv = NucleiScanner(binary="nuclei").build_command(
        _Target("http://vuln-target:8000"),
        ScannerConfig(rate_limit_rps=5, params={"templates_path": "/tpl"}),
    )
    argv = inv.argv
    assert argv[0] == "nuclei"
    assert "-target" in argv and argv[argv.index("-target") + 1] == "http://vuln-target:8000"
    assert argv[argv.index("-templates") + 1] == "/tpl"  # vendored bundle, not a registry
    assert "-disable-update-check" in argv  # never fetch floating templates
    assert "-no-interactsh" in argv  # no out-of-band callbacks
    assert argv[argv.index("-rate-limit") + 1] == "5"  # floored to the engagement ceiling
    assert argv[argv.index("-exclude-tags") + 1] == "intrusive,dos,fuzz,fuzzing,brute-force"
    assert inv.output_mode is OutputMode.STDOUT
    assert inv.persisted_config["profile"] == "safe-active"


def test_rate_limit_floor_is_at_least_one() -> None:
    inv = NucleiScanner(binary="nuclei").build_command(
        _Target("http://t"), ScannerConfig(rate_limit_rps=0)
    )
    assert inv.argv[inv.argv.index("-rate-limit") + 1] == "1"


def test_normalize_maps_jsonl_findings() -> None:
    line1 = (
        '{"template-id":"das-missing-security-headers","matched-at":"http://t:8000",'
        '"type":"http","matcher-name":"","host":"t:8000",'
        '"info":{"name":"Missing HTTP security headers","severity":"low",'
        '"tags":["http","headers"],"description":"no XCTO","remediation":"set nosniff"}}'
    )
    line2 = (
        '{"template-id":"das-insecure-session-cookie","matched-at":"http://t:8000/login",'
        '"info":{"name":"Insecure cookie","severity":"medium"}}'
    )
    findings = NucleiScanner().normalize(_raw(line1 + "\n" + line2 + "\n"))
    assert len(findings) == 2
    hdr = next(f for f in findings if f.rule_id == "das-missing-security-headers")
    assert hdr.severity is Severity.LOW
    assert hdr.location["url"] == "http://t:8000" and hdr.location["type"] == "http"
    assert hdr.recommendation == "set nosniff"
    assert "das-missing-security-headers:http://t:8000:" in hdr.fingerprint
    cookie = next(f for f in findings if f.rule_id == "das-insecure-session-cookie")
    assert cookie.severity is Severity.MEDIUM


def test_normalize_ignores_blank_lines_and_empty_output() -> None:
    assert NucleiScanner().normalize(_raw("\n\n  \n")) == []
    assert NucleiScanner().normalize(RawScannerResult(exit_code=0, output=b"", stderr=b"")) == []


def test_normalize_raises_on_malformed_json_line() -> None:
    try:
        NucleiScanner().normalize(_raw('{"template-id":"ok"}\n{not json\n'))
    except ScannerError:
        return
    raise AssertionError("expected ScannerError on a malformed JSONL line")


def test_normalize_survives_hostile_shapes() -> None:
    # info not a dict, tags not a list, missing fields, a bare non-object line.
    findings = NucleiScanner().normalize(
        _raw('{"template-id":123,"info":"nope","tags":"x"}\n"junk"\n42\n')
    )
    assert len(findings) == 1  # only the object line becomes a finding
    f = findings[0]
    assert f.rule_id == "123" and f.severity is Severity.INFORMATIONAL
    assert f.location["tags"] == []
