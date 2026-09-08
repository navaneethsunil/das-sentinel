"""Ollama adapter — the local (on-box / air-gapped dev) backend (M2-B2).

`hosted` reflects ENDPOINT trust (sec-6), so the redaction and
`hosted_models_allowed` gates in the facade apply to a remote Ollama origin and
not to the deployment's own trusted-local endpoint.

Every connection is opened through `PinnedDNSTransport` with the provider SSRF
policy (sec-16): the endpoint host is re-resolved and re-vetted on EVERY request
(private/loopback/link-local/metadata/reserved addresses refused unless the host is
on the deployment trusted-local allowlist) and the socket is pinned to the vetted
IP while the original hostname stays in the Host header and TLS SNI. Redirects are
never followed. The address actually connected to is returned on `LLMResult.
destination` so the facade can record it with the interaction.

Structured output uses Ollama's `format` field (a JSON Schema); `effort` has no
analog locally and is ignored.
"""

import json
from collections.abc import Callable
from typing import Any

import httpx

from app.connectors.pinned_transport import DESTINATION_EXTENSION, PinnedDNSTransport
from app.llm.base import LLMBackendError, LLMRequest, LLMResult, LLMUsage

_TIMEOUT_S = 300.0


class OllamaAdapter:
    provider = "ollama"

    def __init__(
        self,
        *,
        base_url: str,
        hosted: bool = False,
        trusted_hosts: frozenset[str] | None = None,
        resolve: Callable[[str], list[str]] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        # `hosted` reflects ENDPOINT trust, not the provider name (sec-6): a remote
        # Ollama origin is off-box egress and must be treated as hosted so the
        # consent gate and redaction apply. The caller (registry) decides this from
        # the deployment's trusted-local allowlist; it defaults to False only for
        # the deployment's own env-configured local endpoint.
        self.hosted = hosted
        if transport is None:
            # Lazy: app.services imports the connector package; keep the adapter
            # importable without dragging the service graph in at module load.
            from app.services.ai_models import system_dns_resolver, vet_provider_host

            if trusted_hosts is None:
                from app.core.config import get_settings

                trusted_hosts = get_settings().trusted_local_llm_host_set
            resolver = resolve or system_dns_resolver

            def vet(host: str) -> list[str] | None:
                return vet_provider_host(host, trusted_hosts=trusted_hosts, resolve=resolver)

            transport = PinnedDNSTransport(vet=vet, inner=httpx.AsyncHTTPTransport())
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=_TIMEOUT_S,
            transport=transport,
            follow_redirects=False,  # a redirect is never followed to an unvetted origin
        )

    async def complete(self, request: LLMRequest) -> LLMResult:
        messages: list[dict[str, str]] = []
        if request.system is not None:
            messages.append({"role": "system", "content": request.system})
        messages.extend({"role": m.role, "content": m.content} for m in request.messages)

        payload: dict[str, Any] = {
            "model": request.model,
            "messages": messages,
            "stream": False,
            "options": {"num_predict": request.max_tokens},
        }
        if request.output_schema is not None:
            payload["format"] = request.output_schema

        try:
            response = await self._client.post("/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            raise LLMBackendError(f"ollama call failed: {exc}") from exc

        text = data.get("message", {}).get("content", "")
        structured = None
        if request.output_schema is not None and text:
            try:
                structured = json.loads(text)
            except json.JSONDecodeError as exc:
                raise LLMBackendError(f"structured output was not valid JSON: {exc}") from exc

        return LLMResult(
            text=text,
            model=data.get("model", request.model),
            provider=self.provider,
            usage=LLMUsage(
                input_tokens=data.get("prompt_eval_count"),
                output_tokens=data.get("eval_count"),
            ),
            structured=structured,
            stop_reason=data.get("done_reason"),
            destination=response.extensions.get(DESTINATION_EXTENSION),
        )

    async def aclose(self) -> None:
        await self._client.aclose()
