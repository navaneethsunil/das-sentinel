"""M1-SEC5 (CI-safe half): login rate-limiter logic against an in-memory
counter store (no Valkey needed). The full HTTP throttle — 429, Retry-After,
correct-password-still-blocked, window recovery — is proven live in
scripts/verify_login_ratelimit.py.
"""

import pytest

from app.core.config import Settings
from app.core.ratelimit import LoginRateLimiter

IP = "203.0.113.7"
EMAIL = "victim@example.com"


class FakeCache:
    """Minimal async subset of redis.asyncio.Redis: incr/expire/get/ttl/delete.
    Enough to exercise the limiter deterministically; `broken=True` simulates an
    unreachable store so the fail-closed path can be tested."""

    def __init__(self, broken: bool = False) -> None:
        self._counts: dict[str, int] = {}
        self._ttls: dict[str, int] = {}
        self.broken = broken

    async def get(self, key: str):
        if self.broken:
            raise ConnectionError("cache down")
        v = self._counts.get(key)
        return None if v is None else str(v).encode()

    async def incr(self, key: str) -> int:
        if self.broken:
            raise ConnectionError("cache down")
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]

    async def expire(self, key: str, seconds: int) -> None:
        self._ttls[key] = seconds

    async def ttl(self, key: str) -> int:
        return self._ttls.get(key, -1)

    async def delete(self, key: str) -> None:
        self._counts.pop(key, None)
        self._ttls.pop(key, None)


@pytest.fixture()
def settings(env: dict[str, str]) -> Settings:  # noqa: ARG001 - env sets config
    return Settings(_env_file=None)


async def test_allows_below_threshold_then_blocks_at_email_limit(settings: Settings) -> None:
    cache = FakeCache()
    limiter = LoginRateLimiter(cache, settings)
    for _ in range(settings.login_rate_limit_max_per_email):
        assert (await limiter.check(IP, EMAIL)).blocked is False
        await limiter.register_failure(IP, EMAIL)
    decision = await limiter.check(IP, EMAIL)
    assert decision.blocked is True
    assert decision.retry_after_seconds == settings.login_rate_limit_window_seconds


async def test_per_ip_limit_blocks_across_different_emails(settings: Settings) -> None:
    # A spraying attacker rotating emails from one IP still trips the IP gate.
    cache = FakeCache()
    limiter = LoginRateLimiter(cache, settings)
    for i in range(settings.login_rate_limit_max_per_ip):
        await limiter.register_failure(IP, f"user{i}@example.com")
    # A brand-new email from the same IP is blocked by the per-IP counter,
    # even though that account has zero failures.
    assert (await limiter.check(IP, "fresh@example.com")).blocked is True


async def test_success_reset_clears_account_but_not_ip(settings: Settings) -> None:
    cache = FakeCache()
    limiter = LoginRateLimiter(cache, settings)
    for _ in range(settings.login_rate_limit_max_per_email):
        await limiter.register_failure(IP, EMAIL)
    assert (await limiter.check(IP, EMAIL)).blocked is True
    await limiter.reset_account(EMAIL)
    # Account counter cleared → that email is allowed again...
    assert (await limiter.check(IP, EMAIL)).blocked is False
    # ...but the per-IP counter survives (still counting the spraying source).
    ip_count = cache._counts.get(LoginRateLimiter._ip_key(IP))
    assert ip_count == settings.login_rate_limit_max_per_email


async def test_first_failure_sets_window_ttl(settings: Settings) -> None:
    cache = FakeCache()
    limiter = LoginRateLimiter(cache, settings)
    await limiter.register_failure(IP, EMAIL)
    window = settings.login_rate_limit_window_seconds
    assert cache._ttls[LoginRateLimiter._email_key(EMAIL)] == window
    assert cache._ttls[LoginRateLimiter._ip_key(IP)] == window


async def test_check_fails_closed_when_store_unreachable(settings: Settings) -> None:
    # A store error must raise (the caller turns it into 503), never silently
    # report "not blocked" — that would be a fail-open brute-force bypass.
    limiter = LoginRateLimiter(FakeCache(broken=True), settings)
    with pytest.raises(ConnectionError):
        await limiter.check(IP, EMAIL)


async def test_email_key_is_case_insensitive(settings: Settings) -> None:
    cache = FakeCache()
    limiter = LoginRateLimiter(cache, settings)
    for _ in range(settings.login_rate_limit_max_per_email):
        await limiter.register_failure(None, EMAIL.upper())
    assert (await limiter.check(None, EMAIL.lower())).blocked is True
