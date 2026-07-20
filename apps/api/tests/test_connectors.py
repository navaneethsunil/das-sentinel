"""M2-B6 LLM target connector — CI-safe unit tests.

No network, no PyRIT: an httpx.MockTransport stands in for the target endpoint and
DNS/secret resolvers are injected. Covers request-body building, response
extraction, multi-turn history replay, the per-request/per-redirect egress guard
(scope + SSRF), auth-header injection with credential-never-in-transcript, and
fail-safe parsing. Real PyRIT suites driven through this connector against a live
mock chatbot are proven in scripts/verify_llm_target_connector.py.
"""

import json

import httpx
import pytest

from app.connectors import (
    HttpLLMTargetConnector,
    TargetConnectionConfig,
    TargetConnectorError,
    build_llm_target_connector,
)
from app.connectors.llm_target import ConnectorConfigError, json_pointer_get
from app.core.scope import ScopeViolation, SSRFBlocked
from app.models.engagement import ScopeItem, ScopeKind, ScopeMatcher
from app.models.target import Target, TargetType

_ENDPOINT = "https://bot.example.com/v1/chat/completions"
_PUBLIC = ["93.184.216.34"]


def _scope(kind: ScopeKind, matcher: ScopeMatcher, value: str) -> ScopeItem:
    return ScopeItem(kind=kind, matcher_type=matcher, value=value)


_ALLOW_BOT = [_scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "bot.example.com")]


def _target(
    *, connector_config=None, auth_config=None, target_type=TargetType.AI_CHATBOT
) -> Target:
    return Target(
        name="bot",
        target_type=target_type,
        primary_value=_ENDPOINT,
        connector_config=connector_config,
        auth_config=auth_config,
    )


def _chat_response(content: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def _transport(responder):
    """MockTransport + a captured list of every request it handled. `calls == []`
    after a blocked send proves no egress reached the network."""
    calls: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return responder(request, len(calls))

    return httpx.MockTransport(handle), calls


def _connect(target, scope, *, responder, resolve=lambda _h: list(_PUBLIC), secret_resolver=None):
    transport, calls = _transport(responder)
    kwargs = {"resolve": resolve, "transport": transport}
    if secret_resolver is not None:
        kwargs["secret_resolver"] = secret_resolver
    return build_llm_target_connector(target, scope, **kwargs), calls


# ── JSON pointer ──────────────────────────────────────────────────────────
def test_json_pointer_get_navigates_dicts_and_lists() -> None:
    doc = {"choices": [{"message": {"content": "hi"}}]}
    assert json_pointer_get(doc, "/choices/0/message/content") == "hi"


def test_json_pointer_get_missing_path_raises() -> None:
    with pytest.raises(TargetConnectorError):
        json_pointer_get({"choices": []}, "/choices/0/message/content")


# ── config validation ──────────────────────────────────────────────────────
def test_unknown_connector_config_key_rejected() -> None:
    with pytest.raises(ConnectorConfigError):
        TargetConnectionConfig.from_target(_target(connector_config={"bogus": 1}))


def test_bad_max_redirects_rejected() -> None:
    with pytest.raises(ConnectorConfigError):
        TargetConnectionConfig.from_target(_target(connector_config={"max_redirects": 99}))


def test_non_llm_target_type_rejected() -> None:
    with pytest.raises(TargetConnectorError):
        build_llm_target_connector(_target(target_type=TargetType.WEB_APP), _ALLOW_BOT)


# ── happy path ──────────────────────────────────────────────────────────────
async def test_send_builds_body_and_extracts_response() -> None:
    def responder(request, _n):
        body = json.loads(request.content)
        assert body["messages"] == [{"role": "user", "content": "ping"}]
        return _chat_response("pong")

    connector, calls = _connect(_target(), _ALLOW_BOT, responder=responder)
    try:
        assert await connector.send("ping") == "pong"
        assert len(calls) == 1
    finally:
        await connector.aclose()


async def test_multi_turn_replays_full_history() -> None:
    def responder(request, n):
        body = json.loads(request.content)
        if n == 1:
            assert [m["content"] for m in body["messages"]] == ["a"]
            return _chat_response("reply-1")
        assert [m["role"] for m in body["messages"]] == ["user", "assistant", "user"]
        assert [m["content"] for m in body["messages"]] == ["a", "reply-1", "b"]
        return _chat_response("reply-2")

    connector, calls = _connect(_target(), _ALLOW_BOT, responder=responder)
    try:
        convo = connector.open_conversation()
        assert await convo.send("a") == "reply-1"
        assert await convo.send("b") == "reply-2"
        assert len(calls) == 2
    finally:
        await connector.aclose()


async def test_single_prompt_mode_places_prompt_at_pointer() -> None:
    target = _target(connector_config={"mode": "single_prompt", "prompt_pointer": "/input"})

    def responder(request, _n):
        assert json.loads(request.content) == {"input": "hello"}
        return _chat_response("ok")

    connector, _calls = _connect(target, _ALLOW_BOT, responder=responder)
    try:
        assert await connector.send("hello") == "ok"
    finally:
        await connector.aclose()


# ── TM-5: credential handling ────────────────────────────────────────────────
async def test_auth_header_injected_and_credential_not_in_body() -> None:
    target = _target(auth_config={"api_key_ref": "env:TARGET_KEY"})
    seen = {}

    def responder(request, _n):
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.content.decode()
        return _chat_response("ok")

    connector, _calls = _connect(
        target, _ALLOW_BOT, responder=responder, secret_resolver=lambda _ref: "s3cr3t-value"
    )
    try:
        await connector.send("probe")
    finally:
        await connector.aclose()
    assert seen["auth"] == "Bearer s3cr3t-value"  # resolved reference → header
    assert "s3cr3t-value" not in seen["body"]  # never in the request body/transcript


# ── TM-1: egress guard (scope + SSRF), per request and per redirect hop ───────
async def test_out_of_scope_endpoint_blocked_no_egress() -> None:
    scope = [_scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "allowed.example.com")]
    connector, calls = _connect(_target(), scope, responder=lambda r, n: _chat_response("x"))
    try:
        with pytest.raises(ScopeViolation):
            await connector.send("probe")
        assert calls == []  # blocked before any request left the box
    finally:
        await connector.aclose()


async def test_ssrf_resolved_ip_blocked_no_egress() -> None:
    # Endpoint is name-in-scope, but its host resolves to the cloud-metadata IP.
    connector, calls = _connect(
        _target(),
        _ALLOW_BOT,
        responder=lambda r, n: _chat_response("x"),
        resolve=lambda _h: ["169.254.169.254"],
    )
    try:
        with pytest.raises(SSRFBlocked):
            await connector.send("probe")
        assert calls == []
    finally:
        await connector.aclose()


async def test_redirect_followed_within_scope() -> None:
    target = _target(connector_config={"max_redirects": 2})

    def responder(request, n):
        if n == 1:
            return httpx.Response(307, headers={"location": "https://bot.example.com/v2/chat"})
        return _chat_response("after-redirect")

    resolve_calls = []

    def resolve(host):
        resolve_calls.append(host)
        return list(_PUBLIC)

    connector, calls = _connect(target, _ALLOW_BOT, responder=responder, resolve=resolve)
    try:
        assert await connector.send("probe") == "after-redirect"
        assert len(calls) == 2
        assert len(resolve_calls) == 2  # egress guard re-ran on the redirect hop
    finally:
        await connector.aclose()


async def test_redirect_to_out_of_scope_host_blocked() -> None:
    target = _target(connector_config={"max_redirects": 2})

    def responder(request, n):
        if n == 1:
            return httpx.Response(307, headers={"location": "https://evil.example.org/x"})
        raise AssertionError("must never request the off-scope redirect target")

    connector, calls = _connect(target, _ALLOW_BOT, responder=responder)
    try:
        with pytest.raises(ScopeViolation):
            await connector.send("probe")
        assert len(calls) == 1  # only the first hop; the evil host was never hit
    finally:
        await connector.aclose()


# ── fail-safe parsing (TM-8-adjacent) ────────────────────────────────────────
async def test_non_json_response_fails_safe() -> None:
    connector, _calls = _connect(
        _target(), _ALLOW_BOT, responder=lambda r, n: httpx.Response(200, text="not json")
    )
    try:
        with pytest.raises(TargetConnectorError):
            await connector.send("probe")
    finally:
        await connector.aclose()


async def test_http_error_status_fails_loud() -> None:
    connector, _calls = _connect(
        _target(), _ALLOW_BOT, responder=lambda r, n: httpx.Response(500, json={})
    )
    try:
        with pytest.raises(TargetConnectorError):
            await connector.send("probe")
    finally:
        await connector.aclose()


async def test_response_pointer_to_non_string_fails() -> None:
    target = _target(connector_config={"response_pointer": "/choices"})
    connector, _calls = _connect(target, _ALLOW_BOT, responder=lambda r, n: _chat_response("x"))
    try:
        with pytest.raises(TargetConnectorError):
            await connector.send("probe")
    finally:
        await connector.aclose()


def test_connector_satisfies_suite_target_protocol() -> None:
    connector, _calls = _connect(_target(), _ALLOW_BOT, responder=lambda r, n: _chat_response("x"))
    # structural check: send (RunnerTarget/SuiteTarget) + open_conversation (SuiteTarget)
    assert hasattr(connector, "send") and hasattr(connector, "open_conversation")
    assert isinstance(connector, HttpLLMTargetConnector)
