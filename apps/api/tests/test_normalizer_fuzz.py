"""M3-SEC2 (TM-8): fuzz the SARIF + scanner-output normalizers. CI-safe (no infra).

Every parser that ingests scanner/tool output treats it as hostile: malformed,
truncated, oversized, deeply-nested, or wrong-typed input must fail *safe* — a
typed error or a graceful skip — never crash the worker with an unhandled
exception and never reach an unsafe deserializer. This is the granular matrix;
the release-blocking pins live in test_safety_negatives.py.
"""

import json

import httpx
import pytest

from app.scanners.base import RawScannerResult, ScannerError
from app.scanners.semgrep import SemgrepScanner
from app.scanners.zap import ZapScanner
from app.services.sarif import SarifError, iter_results, parse_sarif


def _deeply_nested(depth: int) -> bytes:
    # A JSON array nested `depth` deep — json.loads raises RecursionError well
    # before this, which the parsers must catch (not crash) (TM-8).
    return ("[" * depth + "]" * depth).encode()


# ── SARIF parse: hostile bytes fail closed ───────────────────────────────────
@pytest.mark.parametrize(
    "raw",
    [
        b"",  # empty
        b"not json",  # not JSON
        b'{"version": "2.1.0"',  # truncated
        b"[1, 2, 3]",  # non-object root
        b'{"version": "9.9.9", "runs": []}',  # unsupported version
        b'{"version": "2.1.0"}',  # missing runs
        b'{"version": "2.1.0", "runs": "nope"}',  # runs not a list
    ],
)
def test_sarif_parse_hostile_fails_closed(raw: bytes) -> None:
    with pytest.raises(SarifError):
        parse_sarif(raw)


def test_sarif_parse_deeply_nested_fails_closed() -> None:
    body = b'{"version": "2.1.0", "runs": ' + _deeply_nested(50_000) + b"}"
    with pytest.raises(SarifError):
        parse_sarif(body)


# ── SARIF iter_results: wrong-typed structures degrade, never crash ──────────
def test_sarif_iter_results_tolerates_hostile_result_shapes() -> None:
    doc = {
        "version": "2.1.0",
        "runs": [
            "not-a-run",  # skipped
            123,  # skipped
            {"tool": "not-a-dict", "results": "not-a-list"},  # results skipped
            {
                "tool": {"driver": {"name": "t"}},
                "results": [
                    "bad",  # non-dict result skipped
                    42,  # skipped
                    {"ruleId": 999, "level": ["weird"], "message": "str-not-dict"},
                    {"ruleId": "ok", "partialFingerprints": "not-a-dict", "locations": "nope"},
                    {"ruleId": "ok2", "locations": [{"physicalLocation": "not-a-dict"}]},
                    {"ruleId": "ok3", "partialFingerprints": {"dasHash/v1": "not-hex-zz"}},
                ],
            },
        ],
    }
    parsed = iter_results(parse_sarif(json.dumps(doc).encode()))
    # the four dict results survive; none crashed the parser
    assert len(parsed) == 4
    assert parsed[0].rule_id == "999"  # numeric ruleId coerced to str
    assert parsed[3].exported_hash is None  # invalid hex hash → no exported hash


# ── Semgrep normalize: hostile output fails safe ─────────────────────────────
@pytest.mark.parametrize(
    "bad",
    [
        b"not json",
        b'{"results": [1,2,3]',  # truncated
        b"\xff\xfe not utf-8",  # undecodable
        b'["results"]',  # non-object root
    ],
)
def test_semgrep_normalize_hostile_fails_closed(bad: bytes) -> None:
    with pytest.raises(ScannerError):
        SemgrepScanner(binary="/opt/semgrep").normalize(
            RawScannerResult(exit_code=2, output=bad, stderr=b"")
        )


def test_semgrep_normalize_deeply_nested_fails_closed() -> None:
    body = b'{"results": ' + _deeply_nested(50_000) + b"}"
    with pytest.raises(ScannerError):
        SemgrepScanner(binary="/opt/semgrep").normalize(
            RawScannerResult(exit_code=2, output=body, stderr=b"")
        )


def test_semgrep_normalize_results_not_a_list_is_empty() -> None:
    out = json.dumps({"results": {"not": "a list"}}).encode()
    assert (
        SemgrepScanner(binary="/opt/semgrep").normalize(
            RawScannerResult(exit_code=0, output=out, stderr=b"")
        )
        == []
    )


def test_semgrep_normalize_wrong_typed_result_fields_do_not_crash() -> None:
    # A dict result whose sub-objects are the WRONG type must not raise
    # AttributeError/TypeError — they are coerced to safe defaults (TM-8).
    hostile = {
        "results": [
            {
                "check_id": "r.evil",
                "path": ["not", "a", "string"],
                "start": "not-a-dict",
                "end": 12345,
                "extra": ["not", "a", "dict"],
            },
            {
                "check_id": "r.refs",
                "extra": {"metadata": {"references": [1, 2, {"x": 1}, "https://ok"]}},
            },
            "not-a-dict-skipped",
        ]
    }
    findings = SemgrepScanner(binary="/opt/semgrep").normalize(
        RawScannerResult(exit_code=1, output=json.dumps(hostile).encode(), stderr=b"")
    )
    assert len(findings) == 2  # both dict results normalized; the string skipped
    # only the string reference survived the coercion into the recommendation
    assert "https://ok" in (findings[1].recommendation or "")


# ── ZAP normalizer: hostile alert / response fails safe ──────────────────────
def _zap() -> ZapScanner:
    return ZapScanner(base_url="http://zap:8090", api_key="k", image_digest="img@sha256:d")


# Module-level MockTransport handlers (kept out of the test bodies so the vendored
# `useless-inner-function` rule doesn't false-positive on a used closure).
def _resp_non_json(_req: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=b"<html>not json</html>")


def _resp_non_dict_body(_req: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=["not", "an", "object"])


def _resp_garbage(_req: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=b"garbage")


def test_zap_to_finding_tolerates_wrong_typed_alert_fields() -> None:
    # Every alert field wrong-typed — str() coercions must keep it from crashing.
    f = _zap()._to_finding(
        {
            "alert": {"nested": "obj"},
            "risk": 3,
            "pluginId": ["10020"],
            "url": 12345,
            "method": None,
            "description": {"x": 1},
        }
    )
    assert f.severity  # produced a finding without raising
    assert f.rule_id.startswith("zap.")


async def test_zap_alerts_non_json_response_fails_closed() -> None:
    async with httpx.AsyncClient(
        base_url="http://zap:8090", transport=httpx.MockTransport(_resp_non_json)
    ) as client:
        with pytest.raises(ScannerError):
            await _zap()._alerts(client, "http://target.local")


async def test_zap_alerts_non_dict_body_degrades_to_empty() -> None:
    async with httpx.AsyncClient(
        base_url="http://zap:8090", transport=httpx.MockTransport(_resp_non_dict_body)
    ) as client:
        _raw, alerts = await _zap()._alerts(client, "http://target.local")
        assert alerts == []


async def test_zap_get_non_json_fails_closed() -> None:
    async with httpx.AsyncClient(
        base_url="http://zap:8090", transport=httpx.MockTransport(_resp_garbage)
    ) as client:
        with pytest.raises(ScannerError):
            await _zap()._get(client, "/JSON/core/view/version/")
