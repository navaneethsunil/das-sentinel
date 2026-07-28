"""SEC-DEBT-6 — DNS-rebinding defense: the connection pins the scope-validated
IP so the address checked is the address connected to.

CI-safe: an httpx.MockTransport stands in for the socket layer, so we assert the
exact request the transport hands down (pinned host, preserved Host header + TLS
SNI) and that a host which rebinds to an internal IP *between* the egress guard's
check and the connect is blocked before any request reaches the inner transport.
The real-socket end-to-end proof is scripts/verify_dns_rebinding.py.
"""

import httpx
import pytest

from app.connectors import build_llm_target_connector
from app.connectors.pinned_transport import ScopePinnedDNSTransport
from app.core.scope import SSRFBlocked
from app.models.engagement import ScopeItem, ScopeKind, ScopeMatcher
from app.models.target import Target, TargetType

_ENDPOINT = "https://bot.example.com/v1/chat/completions"
_SAFE = "93.184.216.34"
_METADATA = "169.254.169.254"

_ALLOW_BOT = [
    ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.DOMAIN, value="bot.example.com")
]


def _target() -> Target:
    return Target(name="bot", target_type=TargetType.AI_CHATBOT, primary_value=_ENDPOINT)


def _recording_inner() -> tuple[httpx.MockTransport, list[httpx.Request]]:
    calls: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    return httpx.MockTransport(handle), calls


async def test_pins_connection_to_validated_ip_preserving_hostname() -> None:
    inner, calls = _recording_inner()
    transport = ScopePinnedDNSTransport(
        scope_items=_ALLOW_BOT, resolve=lambda _h: [_SAFE], inner=inner
    )
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await client.get("https://bot.example.com/v1/chat/completions")
    assert resp.status_code == 200
    req = calls[0]
    assert req.url.host == _SAFE  # socket target is the vetted IP, not the hostname
    assert req.headers["Host"] == "bot.example.com"  # vhost routing preserved
    assert req.extensions.get("sni_hostname") == "bot.example.com"  # TLS SNI + cert host


async def test_rebinding_to_internal_ip_blocked_before_connect() -> None:
    # The classic TOCTOU: the host resolves to a safe public IP when the egress
    # guard checks it, then rebinds to the cloud-metadata IP by the time the
    # client connects. The pin re-resolves+re-validates at connect → blocked.
    inner, calls = _recording_inner()
    n = {"c": 0}

    def rebinding_resolve(_host: str) -> list[str]:
        n["c"] += 1
        return [_SAFE] if n["c"] == 1 else [_METADATA]  # 1 = guard pre-check, 2 = connect

    pinning = ScopePinnedDNSTransport(
        scope_items=_ALLOW_BOT, resolve=rebinding_resolve, inner=inner
    )
    connector = build_llm_target_connector(
        _target(), _ALLOW_BOT, resolve=rebinding_resolve, transport=pinning
    )
    try:
        with pytest.raises(SSRFBlocked):
            await connector.send("probe")
        assert calls == []  # the rebound (internal) IP was never connected to
        assert n["c"] == 2  # guard resolved once, the pin resolved again at connect
    finally:
        await connector.aclose()


async def test_pin_blocks_directly_dangerous_resolution() -> None:
    inner, calls = _recording_inner()
    transport = ScopePinnedDNSTransport(
        scope_items=_ALLOW_BOT, resolve=lambda _h: [_METADATA], inner=inner
    )
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(SSRFBlocked):
            await client.get("https://bot.example.com/x")
    assert calls == []


async def test_ip_literal_passthrough_not_reresolved() -> None:
    # A literal-IP endpoint cannot rebind; the transport must not re-resolve it.
    inner, calls = _recording_inner()

    def resolve(_host: str) -> list[str]:
        raise AssertionError("literal IP must not be resolved")

    allow_ip = [
        ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.IP_CIDR, value=f"{_SAFE}/32")
    ]
    transport = ScopePinnedDNSTransport(scope_items=allow_ip, resolve=resolve, inner=inner)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await client.get(f"https://{_SAFE}/x")
    assert resp.status_code == 200
    assert calls[0].url.host == _SAFE


async def test_production_build_wraps_pinning_transport() -> None:
    connector = build_llm_target_connector(_target(), _ALLOW_BOT, resolve=lambda _h: [_SAFE])
    try:
        assert isinstance(connector._client._transport, ScopePinnedDNSTransport)
    finally:
        await connector.aclose()
