"""SSRF-safe httpx transport that pins connections to a validated IP
(SEC-DEBT-6 / sec-13 / sec-16 — DNS-rebinding TOCTOU).

An egress guard resolves a host and validates its IPs before a request, but a
plain httpx client then RE-resolves the host at connect time via its own DNS.
A hostname that rebinds between the guard's check and the client's connect could
therefore still reach an internal address (169.254.169.254, 127.0.0.1, RFC-1918).

This transport closes that gap for EVERY request that passes through it (each
manually-followed redirect re-enters the transport with its new URL): it calls
the injected `vet` on the request host, which resolves ONCE and validates every
resolved IP, and rewrites the request so the socket connects to a *vetted* IP —
the address validated is the address connected to. The original hostname is
preserved for the `Host` header and the TLS SNI (`sni_hostname` extension), so
virtual-host routing and certificate verification still use the real hostname.

The address actually connected to is recorded on the response as
`extensions["das_destination"]` so callers can audit the effective destination.

Two vetting policies use it:
  - `ScopePinnedDNSTransport` — engagement scope (LLM target connector).
  - the provider-endpoint policy in `app.services.ai_models.vet_provider_host`
    (registered Ollama endpoints: deployment allowlist + dangerous-address deny).
"""

import ipaddress
from collections.abc import Callable

import httpx

from app.core.scope import resolve_and_assert_host_in_scope
from app.models.engagement import ScopeItem

Resolver = Callable[[str], list[str]]
# host -> vetted IPs to pin the socket to; None/[] = connect to the host as given
# (a literal IP that cannot rebind, or an explicitly trusted local name). Raises
# to refuse the request — fail closed.
Vetter = Callable[[str], list[str] | None]

DESTINATION_EXTENSION = "das_destination"


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class PinnedDNSTransport(httpx.AsyncBaseTransport):
    """Wraps an inner async transport; vets + pins the host on every request."""

    def __init__(self, *, vet: Vetter, inner: httpx.AsyncBaseTransport) -> None:
        self._vet = vet
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        vetted = self._vet(host)  # raises on a disallowed destination
        if vetted:
            # Pin the connection to a validated IP; keep the hostname for Host
            # header, TLS SNI, and certificate verification. httpx set the Host
            # header from the original URL when the request was built — preserve
            # it before rewriting.
            host_header = request.headers.get("Host")
            request.url = request.url.copy_with(host=vetted[0])
            if host_header is not None:
                request.headers["Host"] = host_header
            request.extensions = {**request.extensions, "sni_hostname": host}
        response = await self._inner.handle_async_request(request)
        response.extensions[DESTINATION_EXTENSION] = request.url.netloc.decode("ascii")
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


class ScopePinnedDNSTransport(PinnedDNSTransport):
    """Engagement-scope policy: every non-literal host is resolved once and
    scope-validated through the keystone (raises ScopeError/SSRFBlocked)."""

    def __init__(
        self,
        *,
        scope_items: list[ScopeItem],
        resolve: Resolver,
        inner: httpx.AsyncBaseTransport,
    ) -> None:
        def vet(host: str) -> list[str] | None:
            # A literal IP cannot rebind (nothing to re-resolve); the egress guard
            # has already scope-validated it.
            if _is_ip_literal(host):
                return None
            return resolve_and_assert_host_in_scope(host, scope_items, resolve)

        super().__init__(vet=vet, inner=inner)
