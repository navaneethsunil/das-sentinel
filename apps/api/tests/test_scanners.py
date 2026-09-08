"""CI-safe unit tests for the scanner framework (M3-W1).

Cover the pure, DB-free, subprocess-free surface: the stub adapter's
build_command/normalize contract, the envelope→scanners resolution, result
serialization determinism, and the finding dedup identity. The full execution
path (SubprocessOwner launch → raw capture → persist → cancel) is proven live in
scripts/verify_scanner_framework.py.
"""

import json
import re
from dataclasses import dataclass

import pytest

from app.models.finding import Severity
from app.scanners.base import (
    ApiScannerAdapter,
    OutputMode,
    RawScannerResult,
    ScannerAdapter,
    ScannerConfig,
    ScannerError,
    ScannerPrerequisiteError,
    ScannerResult,
    serialize_scanner_result,
)
from app.scanners.semgrep import SemgrepScanner
from app.scanners.stub import StubScanner
from app.scanners.zap import ZapScanner
from app.services.finding_hash import compute_hash_code as _hash_code
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


# ── Semgrep adapter (pure build_command / normalize; no binary needed) ──────────

_SEMGREP_JSON = json.dumps(
    {
        "version": "1.169.0",
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "sandbox/vulnerable_sample/vulnerable.py",
                "start": {"line": 27, "col": 12},
                "end": {"line": 27, "col": 30},
                "extra": {
                    "message": "Detected eval(); this can execute arbitrary code.",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-95"],
                        "owasp": ["A03:2021"],
                        "category": "security",
                        "references": ["https://owasp.org/"],
                    },
                    "fingerprint": "abc123",
                },
            },
            {
                "check_id": "python.lang.security.insecure-hash.md5",
                "path": "sandbox/vulnerable_sample/vulnerable.py",
                "start": {"line": 33, "col": 12},
                "end": {"line": 33, "col": 30},
                "extra": {"message": "MD5 is weak.", "severity": "WARNING", "metadata": {}},
            },
        ],
        "errors": [],
    }
).encode()


def test_semgrep_normalize_maps_results() -> None:
    findings = SemgrepScanner(binary="/opt/semgrep").normalize(
        RawScannerResult(exit_code=1, output=_SEMGREP_JSON, stderr=b"")
    )
    assert len(findings) == 2
    ev = next(f for f in findings if f.rule_id.endswith("eval-detected"))
    assert ev.severity is Severity.HIGH  # ERROR → HIGH
    assert ev.fingerprint == "abc123"  # prefers Semgrep's own fingerprint
    assert ev.location["file"].endswith("vulnerable.py")
    assert ev.location["start_line"] == 27
    assert ev.location["cwe"] == ["CWE-95"]
    md5 = next(f for f in findings if "md5" in f.rule_id)
    assert md5.severity is Severity.MEDIUM  # WARNING → MEDIUM
    # composed fingerprint when Semgrep gives none: rule:path:line:col
    assert md5.fingerprint.endswith(":33:12")


def test_semgrep_normalize_ignores_requires_login_fingerprint() -> None:
    """Semgrep CE emits the constant "requires login" fingerprint for every result
    when unauthenticated; normalize must NOT trust it, or all findings collapse into
    one via the dedup hash_code. Distinct issues must get distinct fingerprints."""
    raw = json.dumps(
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-subprocess-use",
                    "path": "vulnerable.py",
                    "start": {"line": 17, "col": 5},
                    "end": {"line": 17, "col": 40},
                    "extra": {"severity": "ERROR", "fingerprint": "requires login"},
                },
                {
                    "check_id": "python.lang.security.audit.eval-detected",
                    "path": "vulnerable.py",
                    "start": {"line": 24, "col": 12},
                    "end": {"line": 24, "col": 30},
                    "extra": {"severity": "WARNING", "fingerprint": "requires login"},
                },
            ],
            "errors": [],
        }
    ).encode()
    findings = SemgrepScanner(binary="/opt/semgrep").normalize(
        RawScannerResult(exit_code=1, output=raw, stderr=b"")
    )
    fps = [f.fingerprint for f in findings]
    assert "requires login" not in fps  # placeholder rejected
    assert len(set(fps)) == 2  # distinct → no dedup collapse


def test_semgrep_build_command_uses_local_bundle_no_registry() -> None:
    inv = SemgrepScanner(binary="/opt/semgrep").build_command(
        _Target(primary_value="/app/sandbox/vulnerable_sample"), _cfg()
    )
    assert inv.argv[:2] == ["/opt/semgrep", "scan"]
    assert "--json" in inv.argv and "--metrics=off" in inv.argv
    # local rule path, never a floating registry alias (CLAUDE.md §3)
    assert "--config" in inv.argv
    cfg_path = inv.argv[inv.argv.index("--config") + 1]
    # an absolute local path, not a floating registry alias (p/…, r/…, auto)
    assert cfg_path.startswith("/")
    assert not cfg_path.startswith(("p/", "r/")) and cfg_path != "auto"
    assert inv.argv[-1] == "/app/sandbox/vulnerable_sample"  # the scan target
    assert inv.output_mode is OutputMode.STDOUT
    assert inv.persisted_config["rate_limit_rps"] == 5
    assert inv.env.get("HOME")  # secret-free, writable child env


def test_semgrep_build_command_rejects_leading_dash_target() -> None:
    # SEC-DEBT-9: a '-'-prefixed target could be read as a scanner flag. Fail closed.
    with pytest.raises(ScannerError, match="must not start with '-'"):
        SemgrepScanner(binary="/opt/semgrep").build_command(
            _Target(primary_value="/repo"), _cfg(source_path="-rf")
        )


@pytest.mark.parametrize("bad", [b"{not json", b"[]", b'"str"'])
def test_semgrep_normalize_hostile_output_fails_safe(bad: bytes) -> None:
    with pytest.raises(ScannerError):
        SemgrepScanner(binary="/opt/semgrep").normalize(
            RawScannerResult(exit_code=2, output=bad, stderr=b"")
        )


# ── ZAP adapter (pure alert mapping / prereqs; no daemon needed) ────────────────


class _RecordingLock:
    """Test stand-in for the cross-process ZAP daemon lock (sec-17): records the
    acquire/release sequence so tests can prove the daemon is held for the whole
    scan. `held` mirrors the real lock's state."""

    def __init__(self, *, cancelled_while_waiting: bool = False) -> None:
        self.events: list[str] = []
        self.held = False
        self._cancel_wait = cancelled_while_waiting

    async def acquire(self, cancel) -> bool:  # noqa: ANN001
        if self._cancel_wait:
            self.events.append("acquire:cancelled")
            return False
        self.events.append("acquire")
        self.held = True
        return True

    async def release(self) -> None:
        self.events.append("release")
        self.held = False


def _zap(lock=None) -> ZapScanner:  # noqa: ANN001
    return ZapScanner(
        base_url="http://zap:8090",
        api_key="k",
        image_digest="ghcr.io/zaproxy/zaproxy@sha256:deadbeef",
        lock=lock if lock is not None else _RecordingLock(),
    )


def test_zap_is_api_adapter_not_subprocess() -> None:
    z = _zap()
    assert isinstance(z, ApiScannerAdapter)  # dispatched via the in-process API path
    assert not isinstance(z, ScannerAdapter)  # no build_command/normalize


def test_zap_to_finding_maps_alert() -> None:
    f = _zap()._to_finding(
        {
            "alert": "Missing Anti-clickjacking Header",
            "risk": "Medium",
            "confidence": "Medium",
            "url": "https://app.example.com/login",
            "method": "GET",
            "param": "",
            "pluginId": "10020",
            "cweid": "1021",
            "description": "X-Frame-Options header is not set.",
            "solution": "Set X-Frame-Options.",
            "evidence": "",
        }
    )
    assert f.severity is Severity.MEDIUM
    assert f.rule_id == "zap.10020"
    assert f.location["url"].endswith("/login") and f.location["method"] == "GET"
    assert f.location["cweid"] == "1021"
    assert f.recommendation == "Set X-Frame-Options."
    assert f.fingerprint.startswith("zap:10020:")


def test_zap_risk_mapping_covers_all_levels() -> None:
    z = _zap()
    got = {
        lvl: z._to_finding({"alert": "a", "risk": lvl, "url": "u", "pluginId": "1"}).severity
        for lvl in ("High", "Medium", "Low", "Informational")
    }
    assert got == {
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        "Informational": Severity.INFORMATIONAL,
    }
    # unknown risk fails safe to informational
    assert (
        z._to_finding({"alert": "a", "risk": "??", "url": "u"}).severity is Severity.INFORMATIONAL
    )


def test_zap_validate_prerequisites_requires_api_key() -> None:
    with pytest.raises(ScannerPrerequisiteError):
        ZapScanner(
            base_url="http://zap:8090", api_key="", image_digest="img"
        ).validate_prerequisites()
    # a configured adapter validates cleanly (no network)
    _zap().validate_prerequisites()


def test_zap_access_url_does_not_follow_redirects(monkeypatch) -> None:
    """sec-3: the initial accessUrl request must NOT follow redirects — only the
    submitted URL was scope-vetted, so a malicious in-scope target must not be
    able to bounce the dual-homed ZAP daemon to an internal service via Location.
    Captures the real request ZAP would receive through an httpx MockTransport."""
    import asyncio

    import httpx

    from app.scanners import zap as zapmod
    from app.workers.execution import CancelToken

    captured: dict[str, dict[str, str]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        params = dict(request.url.params)
        if path.endswith("/core/action/accessUrl/"):
            captured["accessUrl"] = params
            return httpx.Response(200, json={})
        if path.endswith("/spider/action/scan/"):
            return httpx.Response(200, json={"scan": "1"})
        if path.endswith("/spider/view/status/"):
            return httpx.Response(200, json={"status": "100"})
        if path.endswith("/pscan/view/recordsToScan/"):
            return httpx.Response(200, json={"recordsToScan": "0"})
        if path.endswith("/core/view/version/"):
            return httpx.Response(200, json={"version": "2.17.0"})
        if path.endswith("/core/view/alerts/"):
            return httpx.Response(200, json={"alerts": []})
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def client_with_transport(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(zapmod.httpx, "AsyncClient", client_with_transport)

    @dataclass
    class _T:
        primary_value: str

    asyncio.run(
        _zap().scan(
            _T(primary_value="https://app.example.com"),
            _cfg(max_wait_s=1, pinned_ip="203.0.113.7"),
            CancelToken(),
        )
    )
    assert captured["accessUrl"]["followRedirects"] == "false"


def _run_zap_capturing(  # noqa: ANN001
    monkeypatch, primary_value: str, *, lock=None, daemon=None, calls=None, **params
):
    """Drive a full mocked ZAP baseline and capture every API call ZAP receives.
    `daemon` (optional) is a stateful fake replacer: {"rules": [...], "fail_remove": bool}."""
    import asyncio

    import httpx

    from app.scanners import zap as zapmod
    from app.workers.execution import CancelToken

    calls = calls if calls is not None else []
    lock = lock if lock is not None else _RecordingLock()
    daemon = daemon if daemon is not None else {"rules": []}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append((path, dict(request.url.params)))
        assert lock.held, f"ZAP API call {path} made without holding the daemon lock"
        if path.endswith("/replacer/view/rules/"):
            return httpx.Response(200, json={"rules": list(daemon["rules"])})
        if path.endswith("/replacer/action/addRule/"):
            daemon["rules"].append({"description": request.url.params["description"]})
            return httpx.Response(200, json={"Result": "OK"})
        if path.endswith("/replacer/action/removeRule/"):
            if daemon.get("fail_remove"):
                return httpx.Response(500, json={"message": "internal error"})
            desc = request.url.params["description"]
            daemon["rules"] = [r for r in daemon["rules"] if r["description"] != desc]
            return httpx.Response(200, json={"Result": "OK"})
        if path.endswith("/spider/action/scan/"):
            return httpx.Response(200, json={"scan": "1"})
        if path.endswith("/spider/view/status/"):
            return httpx.Response(200, json={"status": "100"})
        if path.endswith("/pscan/view/recordsToScan/"):
            return httpx.Response(200, json={"recordsToScan": "0"})
        if path.endswith("/core/view/version/"):
            return httpx.Response(200, json={"version": "2.17.0"})
        if path.endswith("/core/view/alerts/"):
            return httpx.Response(200, json={"alerts": []})
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def client_with_transport(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(zapmod.httpx, "AsyncClient", client_with_transport)

    @dataclass
    class _T:
        primary_value: str

    result, _raw = asyncio.run(
        _zap(lock).scan(
            _T(primary_value=primary_value), _cfg(max_wait_s=1, **params), CancelToken()
        )
    )
    return result, calls


def test_zap_pins_every_target_url_to_the_vetted_ip(monkeypatch) -> None:
    """sec-14 (DNS rebinding): ZAP resolves hostnames itself, so the hostname must
    never reach it — every target URL ZAP receives carries the vetted pinned IP,
    with the real hostname restored via a Host-header replacer rule that is
    removed again after the run (the daemon is shared and long-lived)."""
    result, calls = _run_zap_capturing(
        monkeypatch, "https://app.example.com/shop", pinned_ip="203.0.113.7"
    )
    by_path = {p: params for p, params in calls}
    assert by_path["/JSON/core/action/accessUrl/"]["url"] == "https://203.0.113.7/shop"
    assert by_path["/JSON/spider/action/scan/"]["url"] == "https://203.0.113.7/shop"
    assert by_path["/JSON/core/view/alerts/"]["baseurl"] == "https://203.0.113.7/shop"
    add = by_path["/JSON/replacer/action/addRule/"]
    assert (add["matchType"], add["matchString"]) == ("REQ_HEADER", "Host")
    assert add["replacement"] == "app.example.com"
    # sec-17: the rule applies ONLY to this run's pinned origin and only to the
    # spider (3) + accessUrl/manual (6) initiators — never to another scan's traffic
    assert add["initiators"] == "3,6"
    pattern = re.compile(add["url"])
    assert pattern.fullmatch("https://203.0.113.7/shop")
    assert pattern.fullmatch("https://203.0.113.7:443/shop/cart")
    assert not pattern.fullmatch("https://203.0.113.8/shop")  # another scan's pinned IP
    assert not pattern.fullmatch("http://203.0.113.7/shop")  # other scheme
    assert not pattern.fullmatch("https://203.0.113.7.evil.example/")
    remove = by_path["/JSON/replacer/action/removeRule/"]
    assert remove["description"] == add["description"]
    # the rule is installed before the first target request and removed after the last
    paths = [p for p, _ in calls]
    assert paths.index("/JSON/replacer/action/addRule/") < paths.index(
        "/JSON/core/action/accessUrl/"
    )
    assert paths.index("/JSON/replacer/action/removeRule/") > paths.index("/JSON/core/view/alerts/")
    # the connect address is recorded for the audit trail
    assert result.config["pinned_ip"] == "203.0.113.7"
    assert result.config["target_host"] == "app.example.com"


def test_zap_host_header_keeps_a_nonstandard_port(monkeypatch) -> None:
    _, calls = _run_zap_capturing(monkeypatch, "http://juice-shop:3000/", pinned_ip="203.0.113.7")
    by_path = {p: params for p, params in calls}
    assert by_path["/JSON/core/action/accessUrl/"]["url"] == "http://203.0.113.7:3000/"
    assert by_path["/JSON/replacer/action/addRule/"]["replacement"] == "juice-shop:3000"


def test_zap_refuses_an_unpinned_hostname_target(monkeypatch) -> None:
    # Fail closed: a hostname with no vetted pin must never reach the daemon —
    # ZAP would resolve it itself, reopening the rebinding hole (sec-14).
    with pytest.raises(ScannerError, match="pinned IP"):
        _run_zap_capturing(monkeypatch, "https://app.example.com")


def test_framework_pins_a_daemon_target_to_the_scope_vetted_ip() -> None:
    """sec-14: the framework resolves the DAST host ONCE, immediately before the
    daemon run, asserts every address is in scope, and returns the pin. A host
    that rebinds into a blocked range — or stops resolving — fails the run."""
    from app.models.engagement import ScopeKind, ScopeMatcher
    from app.models.target import TargetType
    from app.workers.scanner_run import SSRFBlocked, _pinned_daemon_target_ip

    @dataclass
    class _T:
        primary_value: str
        target_type: TargetType = TargetType.WEB_APP

    @dataclass
    class _S:
        kind: ScopeKind
        matcher_type: ScopeMatcher
        value: str

    scope = [_S(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "app.example.com")]
    assert (
        _pinned_daemon_target_ip(
            _T("https://app.example.com"), scope, resolve=lambda _h: ["93.184.216.34"]
        )
        == "93.184.216.34"
    )
    # rebound to an internal address at run time → refused, not scanned
    with pytest.raises(SSRFBlocked):
        _pinned_daemon_target_ip(
            _T("https://app.example.com"), scope, resolve=lambda _h: ["169.254.169.254"]
        )
    # stopped resolving at run time → refused (fail closed)
    with pytest.raises(SSRFBlocked):
        _pinned_daemon_target_ip(_T("https://app.example.com"), scope, resolve=lambda _h: [])
    # IP-literal and non-URL targets need no pin (nothing to rebind)
    assert _pinned_daemon_target_ip(_T("http://203.0.113.9:8080/"), scope) is None
    assert _pinned_daemon_target_ip(_T("some/archive/key"), scope) is None


def test_zap_ip_literal_target_needs_no_pin(monkeypatch) -> None:
    # A literal IP cannot rebind; it is scope-vetted at the launch gates and
    # scanned as-is, with no replacer rule.
    _, calls = _run_zap_capturing(monkeypatch, "http://203.0.113.9:8080/")
    by_path = {p: params for p, params in calls}
    assert by_path["/JSON/core/action/accessUrl/"]["url"] == "http://203.0.113.9:8080/"
    assert "/JSON/replacer/action/addRule/" not in by_path


def test_zap_holds_the_daemon_lock_for_the_whole_scan(monkeypatch) -> None:
    """sec-17: the shared daemon is locked before the first API call and released
    only after the last one (the pin-rule removal), so two scans can never overlap
    on the daemon — the fake handler asserts every call happens while held."""
    lock = _RecordingLock()
    result, calls = _run_zap_capturing(
        monkeypatch, "https://app.example.com/", lock=lock, pinned_ip="203.0.113.7"
    )
    assert lock.events == ["acquire", "release"]
    assert lock.held is False
    assert result.config["daemon_serialized"] is True
    assert calls[-2][0] == "/JSON/replacer/action/removeRule/"  # removed…
    assert calls[-1][0] == "/JSON/replacer/view/rules/"  # …and PROVEN gone


def test_zap_cancelled_while_waiting_for_the_daemon_is_a_cancelled_run(monkeypatch) -> None:
    lock = _RecordingLock(cancelled_while_waiting=True)
    result, calls = _run_zap_capturing(
        monkeypatch, "https://app.example.com/", lock=lock, pinned_ip="203.0.113.7"
    )
    assert result.cancelled is True
    assert calls == []  # never touched the daemon
    assert "release" not in lock.events  # never held, nothing to release


def test_zap_cleans_a_stale_pin_rule_before_reusing_the_daemon(monkeypatch) -> None:
    """A Host-pin rule left by a crashed earlier run would rewrite THIS run's Host
    headers. Under the lock nothing else runs, so it is removed before scanning."""
    daemon = {"rules": [{"description": "das-host-pin-stale0001"}, {"description": "Remove CSP"}]}
    _, calls = _run_zap_capturing(
        monkeypatch, "https://app.example.com/", daemon=daemon, pinned_ip="203.0.113.7"
    )
    removes = [p for path, p in calls if path.endswith("/replacer/action/removeRule/")]
    assert removes[0]["description"] == "das-host-pin-stale0001"  # stale rule cleaned first
    assert daemon["rules"] == [{"description": "Remove CSP"}]  # ours removed too; ZAP's kept
    paths = [p for p, _ in calls]
    assert paths.index("/JSON/replacer/action/removeRule/") < paths.index(
        "/JSON/replacer/action/addRule/"
    )


def test_zap_refuses_a_daemon_whose_stale_rule_cannot_be_removed(monkeypatch) -> None:
    daemon = {"rules": [{"description": "das-host-pin-stale0001"}], "fail_remove": True}
    calls: list = []
    with pytest.raises(ScannerError, match="refusing to reuse the daemon"):
        _run_zap_capturing(
            monkeypatch,
            "https://app.example.com/",
            daemon=daemon,
            calls=calls,
            pinned_ip="203.0.113.7",
        )
    paths = [p for p, _ in calls]
    assert "/JSON/core/action/accessUrl/" not in paths  # the target was never touched
    assert "/JSON/replacer/action/addRule/" not in paths  # and no new rule was installed


def test_zap_failed_rule_cleanup_fails_the_run_and_releases_the_lock(monkeypatch) -> None:
    """sec-17: a pin rule we cannot prove removed is a daemon-health failure — this
    run fails LOUD (never a silent pass) and the lock is still released so the
    next run's pre-check can refuse/clean the daemon."""
    lock = _RecordingLock()
    daemon = {"rules": [], "fail_remove": False}

    # removal succeeds for stale-check, fails for OUR rule: flip after addRule.
    class _Daemon(dict):
        def get(self, key, default=None):  # noqa: ANN001
            if key == "fail_remove":
                return any(r["description"].startswith("das-host-pin-") for r in self["rules"])
            return super().get(key, default)

    with pytest.raises(ScannerError, match="daemon must not be reused"):
        _run_zap_capturing(
            monkeypatch,
            "https://app.example.com/",
            lock=lock,
            daemon=_Daemon(daemon),
            pinned_ip="203.0.113.7",
        )
    assert lock.events == ["acquire", "release"]


def test_zap_validate_prerequisites_rejects_weak_keys() -> None:
    # sec-5: a known placeholder must not be an operational ZAP credential — the
    # daemon is dual-homed onto the targets network, so a default key would let a
    # popped lab drive the scanner.
    for weak in ("change-me", "changeme", "CHANGE-ME", "password", "  change-me  "):
        with pytest.raises(ScannerPrerequisiteError):
            ZapScanner(
                base_url="http://zap:8090", api_key=weak, image_digest="img"
            ).validate_prerequisites()
    # a strong unique key still validates
    ZapScanner(
        base_url="http://zap:8090",
        api_key="a-real-unique-key-not-a-placeholder",
        image_digest="img",
    ).validate_prerequisites()


def test_framework_derives_target_only_sandbox_egress() -> None:
    """sec-18: a network scanner's sandbox may reach ONLY the scope-vetted pinned
    target plus the online DBs its adapter declares — each resolved immediately
    before launch and refused if it points at a blocked address."""
    from app.models.engagement import ScopeKind, ScopeMatcher
    from app.models.target import TargetType
    from app.workers.scanner_run import SSRFBlocked, _sandbox_egress

    @dataclass
    class _T:
        primary_value: str
        target_type: TargetType = TargetType.WEB_APP

    @dataclass
    class _S:
        kind: ScopeKind
        matcher_type: ScopeMatcher
        value: str

    @dataclass
    class _Inv:
        egress_hosts: tuple[str, ...] = ()

    scope = [_S(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "app.example.com")]
    answers = {"app.example.com": ["93.184.216.34"], "api.osv.dev": ["104.18.1.1", "2606::1"]}
    ips, hosts, pin = _sandbox_egress(
        _Inv(("api.osv.dev",)), _T("https://app.example.com/x"), scope, resolve=answers.__getitem__
    )
    assert ips == ("93.184.216.34", "104.18.1.1")  # IPv4 only — the sandbox has no v6
    assert hosts == (("93.184.216.34", "app.example.com"), ("104.18.1.1", "api.osv.dev"))
    assert pin == "93.184.216.34"
    # a literal-IP target is its own (already scope-vetted) destination
    ips, hosts, pin = _sandbox_egress(_Inv(), _T("http://203.0.113.9:8080/"), scope)
    assert (ips, hosts, pin) == (("203.0.113.9",), (), None)
    # a declared online DB that resolves internally is a poisoned answer → refused
    with pytest.raises(SSRFBlocked, match="blocked address"):
        _sandbox_egress(
            _Inv(("api.osv.dev",)),
            _T("http://203.0.113.9/"),
            scope,
            resolve=lambda _h: ["172.28.0.5"],
        )
    # nothing authorized at all → refused before any launch (fail closed)
    with pytest.raises(ScannerError, match="no authorized egress destination"):
        _sandbox_egress(_Inv(), _T("some/archive/key"), scope)
