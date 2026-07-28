"""SSRF-safe httpx transport that pins connections to a scope-validated IP
(SEC-DEBT-6 — DNS-rebinding TOCTOU).

The egress guard resolves a host and validates its IPs before a request, but a
plain httpx client then RE-resolves the host at connect time via its own DNS.
A hostname that rebinds between the guard's check and the client's connect could
therefore still reach an internal address (169.254.169.254, 127.0.0.1, RFC-1918).

This transport closes that gap: it resolves the host ONCE, validates every
resolved IP through the scope keystone, and rewrites the request so the socket
connects to a *vetted* IP — the address validated is the address connected to.
The original hostname is preserved for the `Host` header and the TLS SNI
(`sni_hostname` extension), so virtual-host routing and certificate verification
still use the real hostname, not the pinned IP.
"""

import ipaddress
from collections.abc import Callable

import httpx

from app.core.scope import resolve_and_assert_host_in_scope
from app.models.engagement import ScopeItem

Resolver = Callable[[str], list[str]]


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class ScopePinnedDNSTransport(httpx.AsyncBaseTransport):
    """Wraps an inner async transport; resolves + scope-validates + pins the host
    to a vetted IP on every request (including each manually-followed redirect,
    which re-enters the transport with the new URL)."""

    def __init__(
        self,
        *,
        scope_items: list[ScopeItem],
        resolve: Resolver,
        inner: httpx.AsyncBaseTransport,
    ) -> None:
        self._scope_items = scope_items
        self._resolve = resolve
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        # A literal IP cannot rebind (nothing to re-resolve); the egress guard has
        # already scope-validated it. Pass through untouched.
        if _is_ip_literal(host):
            return await self._inner.handle_async_request(request)

        # Resolve ONCE and validate; raises ScopeError/SSRFBlocked on a bad IP.
        vetted = resolve_and_assert_host_in_scope(host, self._scope_items, self._resolve)

        # Pin the connection to a validated IP; keep the hostname for Host header,
        # TLS SNI, and certificate verification. httpx set the Host header from the
        # original URL when the request was built — preserve it before rewriting.
        host_header = request.headers.get("Host")
        request.url = request.url.copy_with(host=vetted[0])
        if host_header is not None:
            request.headers["Host"] = host_header
        request.extensions = {**request.extensions, "sni_hostname": host}
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()
