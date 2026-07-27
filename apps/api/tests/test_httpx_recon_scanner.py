"""M4 recon (slice 1): the httpx adapter's pure build_command + normalize.

CI-safe (no binary, no network): covers argv construction (non-intrusive recon
flags, URL target, rate-limit floor, no floating update) and normalization of
httpx JSON into INFORMATIONAL recon facts — an endpoint fingerprint plus one
finding per detected technology — including hostile-shaped output that must never
crash the worker (TM-8). The real binary end-to-end is proven in
scripts/verify_httpx_recon.py.
"""

from app.models.finding import Severity
from app.scanners.base import OutputMode, RawScannerResult, ScannerConfig, ScannerError
from app.scanners.httpx_recon import HttpxReconScanner


class _Target:
    def __init__(self, primary_value: str) -> None:
        self.primary_value = primary_value


def _raw(text: str) -> RawScannerResult:
    return RawScannerResult(exit_code=0, output=text.encode(), stderr=b"")


def test_build_command_is_non_intrusive_recon() -> None:
    inv = HttpxReconScanner(binary="httpx").build_command(
        _Target("http://vuln-target:8000"), ScannerConfig(rate_limit_rps=5)
    )
    argv = inv.argv
    assert argv[0] == "httpx"
    assert argv[argv.index("-u") + 1] == "http://vuln-target:8000"
    assert "-json" in argv and "-tech-detect" in argv and "-web-server" in argv
    assert "-disable-update-check" in argv  # no floating data fetched at run time
    assert argv[argv.index("-rate-limit") + 1] == "5"  # floored to engagement ceiling
    assert inv.output_mode is OutputMode.STDOUT
    assert inv.persisted_config["intrusive"] is False


def test_rate_limit_floor_is_at_least_one() -> None:
    inv = HttpxReconScanner(binary="httpx").build_command(
        _Target("http://t"), ScannerConfig(rate_limit_rps=0)
    )
    assert inv.argv[inv.argv.index("-rate-limit") + 1] == "1"


def test_normalize_emits_fingerprint_and_tech_facts() -> None:
    line = (
        '{"url":"http://t:8000","scheme":"http","status_code":200,"title":"Vulnerable Demo",'
        '"webserver":"BaseHTTP/0.6 Python/3.12","tech":["Python","BaseHTTP"],'
        '"content_type":"text/html","tls":{"tls_version":"tls12"}}'
    )
    findings = HttpxReconScanner().normalize(_raw(line + "\n"))
    # 1 fingerprint + 2 tech facts
    assert len(findings) == 3
    assert all(f.severity is Severity.INFORMATIONAL for f in findings)
    fp = next(f for f in findings if f.rule_id == "httpx-fingerprint")
    assert fp.location["status_code"] == 200
    assert fp.location["webserver"] == "BaseHTTP/0.6 Python/3.12"
    assert fp.location["technologies"] == ["Python", "BaseHTTP"]
    assert fp.fingerprint == "fingerprint:http://t:8000"
    techs = {f.location["technology"] for f in findings if f.rule_id == "httpx-tech"}
    assert techs == {"Python", "BaseHTTP"}


def test_normalize_fingerprint_only_when_no_tech() -> None:
    findings = HttpxReconScanner().normalize(
        _raw('{"url":"http://t","status_code":200,"webserver":"nginx"}\n')
    )
    assert len(findings) == 1 and findings[0].rule_id == "httpx-fingerprint"
    assert findings[0].location["technologies"] == []


def test_normalize_empty_and_blank() -> None:
    assert HttpxReconScanner().normalize(_raw("\n  \n")) == []
    assert (
        HttpxReconScanner().normalize(RawScannerResult(exit_code=0, output=b"", stderr=b"")) == []
    )


def test_normalize_raises_on_bad_json_line() -> None:
    try:
        HttpxReconScanner().normalize(_raw('{"url":"ok"}\n{broken\n'))
    except ScannerError:
        return
    raise AssertionError("expected ScannerError on malformed JSONL")


def test_normalize_survives_hostile_shapes() -> None:
    # tech/tls the wrong type, missing url, a bare non-object line — no crash.
    findings = HttpxReconScanner().normalize(
        _raw('{"status_code":"nope","tech":"notalist","tls":"nope"}\n"junk"\n5\n')
    )
    assert len(findings) == 1  # only the object line, fingerprint only
    f = findings[0]
    assert f.rule_id == "httpx-fingerprint" and f.location["url"] == "target"
    assert f.location["status_code"] is None and f.location["technologies"] == []
    assert f.severity is Severity.INFORMATIONAL
