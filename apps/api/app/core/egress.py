"""Engagement-aware egress shaper (M2-SEC1, TM-1/TM-5) — the run-traffic choke point.

Every outbound request a run makes — to the LLM/chatbot target and (later) to a
configured model provider — is constructed to pass through ONE `EgressShaper`.
The shaper is the single place two controls live:

  1. **Default-deny reachability.** A URL is reachable only if it either matches a
     configured provider endpoint (operator-trusted egress) OR passes the scope
     keystone (`app.core.scope.assert_egress_allowed`): an in-scope allow rule
     (deny wins) AND a resolved-IP SSRF re-check. A decoy internal service and a
     cloud-metadata-IP probe (169.254.169.254) have neither, so they are blocked.
     Reachability is decided BEFORE any rate slot is consumed, so a blocked call
     never waits and never leaks timing.
  2. **Aggregate rate ceiling.** The engagement's `rate_limit_rps` is enforced as a
     ceiling across *all concurrent runs* for that engagement, not per-tool. The
     `ValkeyEgressLimiter` schedules every acquire onto a shared per-engagement
     leaky bucket in Valkey, so the observed outbound rate stays ≤ the ceiling even
     when several runs (in different worker processes) fire at once.

**Fail-closed** (CLAUDE.md §11.6): if the rate-limiter backend cannot be reached the
egress decision cannot be made safely, so `acquire` raises `EgressUnavailable` and
the request is denied — never waved through.

Deployment note (MVP): this is an *application-level* choke point — every run
request is built to call `EgressShaper.aguard` and there is no other outbound path
in the code. A *network-level* default-deny (a per-run network namespace whose only
egress route is the shaper, enforced with nftables) is the documented hardening
seam and belongs with the rootless per-run sandbox (M2-W3, deferred). The clock used
to space requests is the calling process's wall clock; co-located workers share one
host clock, so the aggregate ceiling holds — a multi-host deployment would move the
clock server-side (Valkey `TIME`).
"""

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Protocol
from urllib.parse import urlsplit

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.scope import Resolver, assert_egress_allowed
from app.models.engagement import ScopeItem

_DEFAULT_PORTS = {"http": 80, "https": 443}


class EgressError(Exception):
    """Egress could not be permitted. Surfaced as a run failure, never swallowed."""


class EgressUnavailable(EgressError):
    """The rate-limiter backend is unreachable or misconfigured, so the egress
    decision cannot be made safely. Fail-closed: the request is denied."""


class EgressGate(Protocol):
    """What the target connector calls before every request and every redirect hop.
    Both the bare scope guard (M2-B6) and the full shaper satisfy it."""

    async def aguard(self, url: str) -> None: ...


class RateLimiter(Protocol):
    """Shapes outbound requests for one engagement to its aggregate ceiling.
    `acquire` returns once this request may proceed (after waiting if needed), or
    raises `EgressUnavailable` if the ceiling cannot be enforced (fail-closed)."""

    async def acquire(self, *, engagement_id: uuid.UUID, rate_limit_rps: int) -> None: ...


def parse_provider_allowlist(raw: str | None) -> frozenset[str]:
    """Parse the comma-separated EGRESS_PROVIDER_ALLOWLIST into a normalized set of
    `host` / `host:port` entries (lowercased). These are operator-trusted model
    provider endpoints that run traffic may reach even though they are not
    engagement targets."""
    if not raw:
        return frozenset()
    return frozenset(entry.strip().lower() for entry in raw.split(",") if entry.strip())


def _host_and_port(url: str) -> tuple[str | None, int | None]:
    parts = urlsplit(url)
    host = parts.hostname
    if host is None:
        return None, None
    port = parts.port or _DEFAULT_PORTS.get(parts.scheme.lower())
    return host.lower(), port


# Leaky-bucket scheduler. Each acquire reserves the next emission slot (spaced by
# the emission interval T = 1/rps) on a shared per-engagement key, then the caller
# waits until that slot. Serializing all callers onto one schedule caps the
# aggregate rate at ≤ rps across concurrent runs/processes. TTL always exceeds the
# scheduled horizon so an idle key self-expires without dropping a live backlog.
_ACQUIRE_LUA = """
local now = tonumber(ARGV[1])
local t = tonumber(ARGV[2])
local last = tonumber(redis.call('GET', KEYS[1]) or '0')
if last < now then last = now end
local ttl = math.ceil((last + t - now) * 1000) + 60000
redis.call('SET', KEYS[1], last + t, 'PX', ttl)
return tostring(last - now)
"""


class ValkeyEgressLimiter:
    """Aggregate per-engagement rate ceiling backed by a shared Valkey leaky bucket
    (production limiter). Enforces the ceiling across concurrent runs in different
    worker processes. Fail-closed: any backend error denies egress."""

    def __init__(
        self,
        cache: Redis,
        *,
        now: Callable[[], float] = time.time,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._script = cache.register_script(_ACQUIRE_LUA)
        self._now = now
        self._sleep = sleep

    @staticmethod
    def _key(engagement_id: uuid.UUID) -> str:
        return f"egress:rate:{engagement_id}"

    async def acquire(self, *, engagement_id: uuid.UUID, rate_limit_rps: int) -> None:
        if rate_limit_rps <= 0:
            raise EgressUnavailable(f"invalid egress rate ceiling: {rate_limit_rps}")
        emission_interval = 1.0 / rate_limit_rps
        try:
            raw = await self._script(
                keys=[self._key(engagement_id)],
                args=[repr(self._now()), repr(emission_interval)],
            )
            wait = float(raw)
        except (RedisError, ValueError, TypeError) as exc:
            raise EgressUnavailable("egress rate limiter unavailable") from exc
        if wait > 0:
            await self._sleep(wait)


class InProcessRateLimiter:
    """Single-process leaky bucket — for tests and single-worker dev ONLY. NOT
    aggregate across processes, so it must never back a multi-worker deployment;
    production uses `ValkeyEgressLimiter` so the ceiling holds across concurrent
    runs. Same scheduling math as the Valkey limiter."""

    def __init__(
        self,
        *,
        now: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._next: dict[str, float] = {}
        self._now = now
        self._sleep = sleep
        self._lock = asyncio.Lock()

    async def acquire(self, *, engagement_id: uuid.UUID, rate_limit_rps: int) -> None:
        if rate_limit_rps <= 0:
            raise EgressUnavailable(f"invalid egress rate ceiling: {rate_limit_rps}")
        emission_interval = 1.0 / rate_limit_rps
        key = str(engagement_id)
        async with self._lock:
            now = self._now()
            last = max(self._next.get(key, 0.0), now)
            self._next[key] = last + emission_interval
            wait = last - now
        if wait > 0:
            await self._sleep(wait)


class EgressShaper:
    """The single egress choke point for one engagement's run traffic (M2-SEC1).

    `aguard` decides reachability (default-deny) FIRST, then shapes to the aggregate
    rate ceiling. A blocked URL raises before consuming a rate slot."""

    def __init__(
        self,
        *,
        engagement_id: uuid.UUID,
        rate_limit_rps: int,
        scope_items: list[ScopeItem],
        resolve: Resolver,
        limiter: RateLimiter,
        provider_allowlist: frozenset[str] = frozenset(),
    ) -> None:
        self._engagement_id = engagement_id
        self._rate_limit_rps = rate_limit_rps
        self._scope_items = scope_items
        self._resolve = resolve
        self._limiter = limiter
        self._provider_allowlist = provider_allowlist

    def _assert_reachable(self, url: str) -> None:
        host, port = _host_and_port(url)
        if host is not None and self._provider_allowlist:
            if host in self._provider_allowlist:
                return
            if port is not None and f"{host}:{port}" in self._provider_allowlist:
                return
        # Not a configured provider endpoint → must pass target scope + SSRF.
        # Raises ScopeViolation / SSRFBlocked (both ScopeError) — the shaper never
        # re-implements scope matching (the keystone stays the single authority).
        assert_egress_allowed(url=url, scope_items=self._scope_items, resolve=self._resolve)

    async def aguard(self, url: str) -> None:
        self._assert_reachable(url)
        await self._limiter.acquire(
            engagement_id=self._engagement_id, rate_limit_rps=self._rate_limit_rps
        )
