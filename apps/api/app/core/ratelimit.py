"""Login rate limiting (M1-SEC5 / SEC-DEBT-1, TM-10) — anti-brute-force.

Valkey sliding-window counters gate /auth/login. Two independent keys:
  - per-IP     the primary anti-automation gate (a spraying attacker)
  - per-email  a temporary, auto-expiring per-account throttle

Design choices (CLAUDE.md §2.5 "no default denial-of-service"):
  - Failures increment both counters; a *successful* login clears the account
    counter so a legitimate user who mistyped recovers immediately.
  - The account throttle is temporary (window TTL), never an indefinite
    lockout — otherwise an attacker who knows a victim's email could lock them
    out. The per-IP gate is the durable brute-force defense.
  - The block decision runs BEFORE credential verification, so a throttled
    caller cannot keep burning Argon2id verifications, and the 429 is generic
    (it never reveals whether the account exists — no enumeration oracle).

Fail-closed (CLAUDE.md §11.6): if the counter store cannot be reached the
decision cannot be made safely, so the check raises rather than waving the
attempt through. Login already requires Valkey (session-cache write on
success), so this adds no new availability dependency.
"""

from dataclasses import dataclass

from redis.asyncio import Redis

from app.core.config import Settings


@dataclass(frozen=True)
class RateLimitDecision:
    blocked: bool
    retry_after_seconds: int  # 0 when not blocked


class LoginRateLimiter:
    def __init__(self, cache: Redis, settings: Settings) -> None:
        self._cache = cache
        self._window = settings.login_rate_limit_window_seconds
        self._max_ip = settings.login_rate_limit_max_per_ip
        self._max_email = settings.login_rate_limit_max_per_email

    @staticmethod
    def _ip_key(ip: str) -> str:
        return f"login_fail_ip:{ip}"

    @staticmethod
    def _email_key(email: str) -> str:
        return f"login_fail_email:{email.lower()}"

    def _limits(self, ip: str | None, email: str) -> list[tuple[str, int]]:
        limits: list[tuple[str, int]] = [(self._email_key(email), self._max_email)]
        if ip:
            limits.append((self._ip_key(ip), self._max_ip))
        return limits

    async def check(self, ip: str | None, email: str) -> RateLimitDecision:
        """Block if any counter has already reached its limit. Raises on a
        store error (fail-closed) — the caller turns that into a 503."""
        retry_after = 0
        for key, limit in self._limits(ip, email):
            raw = await self._cache.get(key)
            count = int(raw) if raw is not None else 0
            if count >= limit:
                ttl = await self._cache.ttl(key)
                retry_after = max(retry_after, ttl if ttl and ttl > 0 else self._window)
        return RateLimitDecision(blocked=retry_after > 0, retry_after_seconds=retry_after)

    async def register_failure(self, ip: str | None, email: str) -> None:
        """Count a failed attempt against both keys, setting the window TTL on
        the first increment so the counter self-expires."""
        for key, _ in self._limits(ip, email):
            count = await self._cache.incr(key)
            if count == 1:
                await self._cache.expire(key, self._window)

    async def reset_account(self, email: str) -> None:
        """Clear the per-account counter after a successful login (the per-IP
        counter is intentionally left to keep gating a spraying source)."""
        await self._cache.delete(self._email_key(email))
