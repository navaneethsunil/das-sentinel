"""sec-16: runtime Ollama connections are re-vetted and pinned on EVERY request,
not only at registration — a hostname that resolved publicly when the model was
registered and later rebinds to an internal address must never be connected to.
"""

import httpx
import pytest

from app.connectors.pinned_transport import DESTINATION_EXTENSION, PinnedDNSTransport
from app.llm.base import LLMBackendError, LLMMessage, LLMRequest
from app.llm.ollama_adapter import OllamaAdapter
from app.services.ai_models import AIModelVerificationError, vet_provider_host

_TRUSTED = frozenset({"localhost", "127.0.0.1", "host.docker.internal"})
_PUBLIC = "93.184.216.34"
_INTERNAL = "172.28.0.5"

_OK_BODY = {"model": "llama3.1:8b", "message": {"content": "hi"}, "done_reason": "stop"}


def _request() -> LLMRequest:
    return LLMRequest(
        model="llama3.1:8b", messages=[LLMMessage(role="user", content="x")], max_tokens=8
    )


def _adapter(resolve, *, base_url="http://ollama.example.com:11434", seen: list) -> OllamaAdapter:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_OK_BODY)

    def vet(host: str):
        return vet_provider_host(host, trusted_hosts=_TRUSTED, resolve=resolve)

    transport = PinnedDNSTransport(vet=vet, inner=httpx.MockTransport(handler))
    return OllamaAdapter(base_url=base_url, transport=transport)


async def test_chat_request_is_pinned_to_the_vetted_ip_with_host_and_sni_preserved() -> None:
    seen: list[httpx.Request] = []
    adapter = _adapter(lambda _h: [_PUBLIC], seen=seen)
    result = await adapter.complete(_request())
    req = seen[0]
    assert req.url.host == _PUBLIC  # socket goes to the address that was validated
    assert req.url.path == "/api/chat"
    assert req.headers["Host"] == "ollama.example.com:11434"  # vhost preserved
    assert req.extensions["sni_hostname"] == "ollama.example.com"  # TLS name preserved
    assert result.destination == f"{_PUBLIC}:11434"  # effective destination for audit


async def test_rebinding_hostname_is_blocked_at_runtime() -> None:
    """Public at first (registration would have passed), internal on the next
    resolution: the runtime call must refuse, and nothing reaches the internal IP."""
    answers = iter([[_PUBLIC], [_INTERNAL]])
    seen: list[httpx.Request] = []
    adapter = _adapter(lambda _h: next(answers), seen=seen)
    await adapter.complete(_request())  # first call: vetted + pinned
    with pytest.raises(LLMBackendError, match="blocked address"):
        await adapter.complete(_request())  # rebinding answer → refused
    assert [r.url.host for r in seen] == [_PUBLIC]  # the internal address was never connected


async def test_trusted_local_endpoint_is_not_pinned() -> None:
    seen: list[httpx.Request] = []
    adapter = _adapter(lambda _h: pytest.fail("trusted host must not resolve"), seen=seen)
    adapter._client = httpx.AsyncClient(  # same transport, trusted-local base URL
        base_url="http://localhost:11434", transport=adapter._client._transport
    )
    result = await adapter.complete(_request())
    assert seen[0].url.host == "localhost"
    assert result.destination == "localhost:11434"


async def test_dangerous_ip_literal_endpoint_is_refused() -> None:
    seen: list[httpx.Request] = []
    adapter = _adapter(lambda _h: [], base_url="http://169.254.169.254", seen=seen)
    with pytest.raises(LLMBackendError, match="blocked address"):
        await adapter.complete(_request())
    assert seen == []


def test_transport_re_vets_every_request_including_redirect_hops() -> None:
    """A redirect target re-enters the transport with its own host — it is vetted
    like any other request (the adapter additionally never follows redirects)."""
    hosts: list[str] = []

    def vet(host: str):
        hosts.append(host)
        if host == "evil.internal":
            raise AIModelVerificationError("blocked")
        return [_PUBLIC]

    transport = PinnedDNSTransport(
        vet=vet, inner=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
    )
    import asyncio

    async def go() -> None:
        async with httpx.AsyncClient(transport=transport) as client:
            r = await client.get("http://ollama.example.com/api/chat")
            assert r.extensions[DESTINATION_EXTENSION] == _PUBLIC
            with pytest.raises(AIModelVerificationError):
                await client.get("http://evil.internal/")

    asyncio.run(go())
    assert hosts == ["ollama.example.com", "evil.internal"]


def test_adapter_client_never_follows_redirects() -> None:
    adapter = _adapter(lambda _h: [_PUBLIC], seen=[])
    assert adapter._client.follow_redirects is False
