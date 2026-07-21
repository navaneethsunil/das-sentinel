"""M2-SEC1 engagement-aware egress shaper — CI-safe unit tests.

No network, no Valkey: DNS is an injected resolver, the rate limiter is a stub or
the in-process bucket with a fake clock. Covers the two controls the shaper owns —
default-deny reachability (scope/SSRF + provider allowlist) and the aggregate rate
ceiling — plus the fail-closed behavior when the limiter backend is down. The
observed aggregate rate under concurrent runs against a live Valkey is proven in
scripts/verify_egress_shaper.py.
"""

import uuid

import pytest
from redis.exceptions import RedisError

from app.core.egress import (
    EgressShaper,
    EgressUnavailable,
    InProcessRateLimiter,
    ValkeyEgressLimiter,
    parse_provider_allowlist,
)
from app.core.scope import ScopeViolation, SSRFBlocked
from app.models.engagement import ScopeItem, ScopeKind, ScopeMatcher

_ENG = uuid.uuid4()
_PUBLIC = ["93.184.216.34"]
_METADATA = ["169.254.169.254"]


def _scope(kind: ScopeKind, matcher: ScopeMatcher, value: str) -> ScopeItem:
    return ScopeItem(kind=kind, matcher_type=matcher, value=value)


_ALLOW_BOT = [_scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "bot.example.com")]


class CountingLimiter:
    """Records every acquire; optionally raises to simulate a down backend."""

    def __init__(self, exc: Exception | None = None) -> None:
        self.calls: list[tuple[uuid.UUID, int]] = []
        self._exc = exc

    async def acquire(self, *, engagement_id: uuid.UUID, rate_limit_rps: int) -> None:
        self.calls.append((engagement_id, rate_limit_rps))
        if self._exc is not None:
            raise self._exc


def _shaper(
    *,
    scope_items=_ALLOW_BOT,
    resolve=lambda _h: list(_PUBLIC),
    limiter=None,
    provider_allowlist=frozenset(),
    rate_limit_rps=5,
) -> tuple[EgressShaper, CountingLimiter]:
    limiter = limiter or CountingLimiter()
    shaper = EgressShaper(
        engagement_id=_ENG,
        rate_limit_rps=rate_limit_rps,
        scope_items=scope_items,
        resolve=resolve,
        limiter=limiter,
        provider_allowlist=provider_allowlist,
    )
    return shaper, limiter


# ── Provider allowlist parsing ─────────────────────────────────────────────
def test_parse_provider_allowlist_normalizes_and_drops_blanks() -> None:
    assert parse_provider_allowlist(" API.Provider.Test , host:8443 ,, ") == frozenset(
        {"api.provider.test", "host:8443"}
    )
    assert parse_provider_allowlist("") == frozenset()
    assert parse_provider_allowlist(None) == frozenset()


# ── Reachability (default-deny) ────────────────────────────────────────────
async def test_in_scope_url_allowed_and_rate_slot_taken() -> None:
    shaper, limiter = _shaper()
    await shaper.aguard("https://bot.example.com/v1/chat/completions")
    assert limiter.calls == [(_ENG, 5)]


async def test_out_of_scope_url_blocked_before_rate_slot() -> None:
    shaper, limiter = _shaper()
    with pytest.raises(ScopeViolation):
        await shaper.aguard("https://evil.example.net/x")
    # Reachability decided first: a blocked URL never consumes a rate slot.
    assert limiter.calls == []


async def test_metadata_ip_blocked_before_rate_slot() -> None:
    # Host is name-in-scope, but it resolves to the cloud-metadata IP (TM-1).
    shaper, limiter = _shaper(resolve=lambda _h: list(_METADATA))
    with pytest.raises(SSRFBlocked):
        await shaper.aguard("https://bot.example.com/v1/chat/completions")
    assert limiter.calls == []


async def test_provider_endpoint_allowed_without_scope_and_without_dns() -> None:
    def _resolve(_host: str) -> list[str]:  # must never run for a provider endpoint
        raise AssertionError("provider endpoint should bypass DNS/scope")

    shaper, limiter = _shaper(
        scope_items=[], resolve=_resolve, provider_allowlist=frozenset({"api.provider.test"})
    )
    await shaper.aguard("https://api.provider.test/v1/messages")
    assert limiter.calls == [(_ENG, 5)]


async def test_provider_endpoint_host_port_and_default_port_match() -> None:
    shaper, _ = _shaper(
        scope_items=[],
        resolve=lambda _h: (_ for _ in ()).throw(AssertionError("no dns")),
        provider_allowlist=frozenset({"api.provider.test:8443"}),
    )
    await shaper.aguard("https://api.provider.test:8443/v1")

    # An entry with the scheme's default port matches a URL that omits the port.
    shaper2, _ = _shaper(
        scope_items=[],
        resolve=lambda _h: (_ for _ in ()).throw(AssertionError("no dns")),
        provider_allowlist=frozenset({"api.provider.test:443"}),
    )
    await shaper2.aguard("https://api.provider.test/v1")


async def test_non_allowlisted_provider_host_falls_through_to_scope() -> None:
    shaper, limiter = _shaper(scope_items=[], provider_allowlist=frozenset({"api.provider.test"}))
    with pytest.raises(ScopeViolation):
        await shaper.aguard("https://other.provider.test/v1")
    assert limiter.calls == []


# ── Fail-closed ────────────────────────────────────────────────────────────
async def test_reachable_but_limiter_down_denies_egress() -> None:
    shaper, _ = _shaper(limiter=CountingLimiter(exc=EgressUnavailable("valkey down")))
    with pytest.raises(EgressUnavailable):
        await shaper.aguard("https://bot.example.com/v1/chat/completions")


# ── In-process leaky bucket (test/single-process limiter) ──────────────────
async def test_inprocess_limiter_spaces_by_emission_interval() -> None:
    waits: list[float] = []

    async def _sleep(seconds: float) -> None:
        waits.append(seconds)

    limiter = InProcessRateLimiter(now=lambda: 100.0, sleep=_sleep)
    for _ in range(3):
        await limiter.acquire(engagement_id=_ENG, rate_limit_rps=5)
    # rps=5 → T=0.2s. First request fires immediately; each subsequent one waits
    # one more interval, so the aggregate rate is capped at the ceiling.
    assert waits == pytest.approx([0.2, 0.4])


async def test_inprocess_limiter_rejects_nonpositive_rate() -> None:
    limiter = InProcessRateLimiter()
    with pytest.raises(EgressUnavailable):
        await limiter.acquire(engagement_id=_ENG, rate_limit_rps=0)


# ── Valkey limiter (stubbed script) ────────────────────────────────────────
class FakeCache:
    """Minimal stand-in for redis.asyncio.Redis: register_script returns an async
    callable that yields a canned result or raises."""

    def __init__(self, *, result: str | None = None, exc: Exception | None = None) -> None:
        self._result = result
        self._exc = exc

    def register_script(self, _lua: str):
        async def _script(keys=None, args=None):  # noqa: ANN001, ANN202 — test stub
            if self._exc is not None:
                raise self._exc
            return self._result

        return _script


async def test_valkey_limiter_sleeps_for_returned_wait() -> None:
    waits: list[float] = []

    async def _sleep(seconds: float) -> None:
        waits.append(seconds)

    limiter = ValkeyEgressLimiter(FakeCache(result="0.5"), sleep=_sleep)
    await limiter.acquire(engagement_id=_ENG, rate_limit_rps=5)
    assert waits == [0.5]


async def test_valkey_limiter_no_wait_when_zero() -> None:
    waits: list[float] = []

    async def _sleep(seconds: float) -> None:
        waits.append(seconds)

    limiter = ValkeyEgressLimiter(FakeCache(result="0"), sleep=_sleep)
    await limiter.acquire(engagement_id=_ENG, rate_limit_rps=5)
    assert waits == []


async def test_valkey_limiter_fail_closed_on_backend_error() -> None:
    limiter = ValkeyEgressLimiter(FakeCache(exc=RedisError("connection refused")))
    with pytest.raises(EgressUnavailable):
        await limiter.acquire(engagement_id=_ENG, rate_limit_rps=5)


async def test_valkey_limiter_fail_closed_on_unparseable_reply() -> None:
    limiter = ValkeyEgressLimiter(FakeCache(result="not-a-number"))
    with pytest.raises(EgressUnavailable):
        await limiter.acquire(engagement_id=_ENG, rate_limit_rps=5)


async def test_valkey_limiter_rejects_nonpositive_rate() -> None:
    limiter = ValkeyEgressLimiter(FakeCache(result="0"))
    with pytest.raises(EgressUnavailable):
        await limiter.acquire(engagement_id=_ENG, rate_limit_rps=-1)
