"""M1-B2: opaque-session pure logic (token, hashing, cookie attributes).

The store lifecycle (create/validate/revoke/kill-all + Valkey write-through)
runs against live Postgres+Valkey and is verified by
scripts/verify_sessions.py, not here — CI's pytest has no backends.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import Response

from app.core.config import Settings
from app.core.sessions import (
    TOKEN_BYTES,
    SessionService,
    clear_session_cookie,
    generate_token,
    hash_token,
)
from app.models.identity import UserRole


def _settings() -> Settings:
    return Settings(_env_file=None)


def test_token_is_high_entropy_and_unique() -> None:
    tokens = {generate_token() for _ in range(1000)}
    assert len(tokens) == 1000  # no collisions
    # token_urlsafe(32) → ~43 base64url chars, well above the 64-bit floor.
    assert all(len(t) >= 43 for t in tokens)


def test_hash_is_sha256_deterministic_and_binding() -> None:
    token = generate_token()
    assert hash_token(token) == hashlib.sha256(token.encode()).digest()
    assert len(hash_token(token)) == 32
    assert hash_token(token) != hash_token(generate_token())


def test_token_bytes_meets_entropy_floor() -> None:
    assert TOKEN_BYTES * 8 >= 256


def test_set_cookie_has_host_prefix_security_attributes(env: dict[str, str]) -> None:
    settings = _settings()
    response = Response()
    # Import here so a missing dependency surfaces as this test, not collection.
    from app.core.sessions import set_session_cookie

    set_session_cookie(response, "raw-token-value", settings)
    header = response.headers["set-cookie"].lower()

    assert response.headers["set-cookie"].startswith(settings.session_cookie_name + "=")
    assert "httponly" in header
    assert "secure" in header
    assert "samesite=strict" in header
    assert "path=/" in header
    assert "domain=" not in header  # __Host- forbids Domain
    assert "max-age=" not in header  # session cookie; server enforces expiry


def test_clear_cookie_expires_it(env: dict[str, str]) -> None:
    settings = _settings()
    response = Response()
    clear_session_cookie(response, settings)
    header = response.headers["set-cookie"].lower()
    assert settings.session_cookie_name.lower() in header
    assert "max-age=0" in header or "expires=" in header


# ── cache-TTL backstop (UAT: a cache-hit slide must not re-arm the TTL) ───────
class _FakeCache:
    """Valkey stand-in that honours the SET options this module relies on."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.ttl: dict[str, int | None] = {}

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def set(
        self, key: str, value: str, ex: int | None = None, xx: bool = False, keepttl: bool = False
    ) -> bool | None:
        if xx and key not in self.values:
            return None  # SET XX on a missing key is a no-op
        self.values[key] = value
        if not keepttl:
            self.ttl[key] = ex
        return True

    async def delete(self, key: str) -> None:
        self.values.pop(key, None)
        self.ttl.pop(key, None)


class _FakeDb:
    async def execute(self, *args: object, **kwargs: object) -> None:
        return None

    async def flush(self) -> None:
        return None


async def test_slide_refreshes_idle_window_without_re_arming_cache_ttl(
    env: dict[str, str],
) -> None:
    """A revoked session must not outlive the cache-TTL backstop: only an
    authoritative DB revalidation may arm a new cache window, so sliding on a
    cache hit keeps the original expiry (SET XX KEEPTTL)."""
    settings = _settings()
    cache = _FakeCache()
    service = SessionService(_FakeDb(), cache, settings)  # type: ignore[arg-type]
    token_hash = hash_token(generate_token())
    key = f"session:{token_hash.hex()}"
    now = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
    cache.values[key] = json.dumps(
        {
            "session_id": str(uuid.uuid4()),
            "user_id": str(uuid.uuid4()),
            "role": UserRole.TESTER.value,
            "idle_expires_at": (now + timedelta(minutes=15)).isoformat(),
            "absolute_expires_at": (now + timedelta(hours=8)).isoformat(),
        }
    )
    cache.ttl[key] = settings.session_cache_ttl_seconds  # armed by the last DB check

    later = now + timedelta(minutes=5)
    await service._slide(token_hash, later)

    assert cache.ttl[key] == settings.session_cache_ttl_seconds  # NOT re-armed
    slid = json.loads(cache.values[key])
    assert (
        slid["idle_expires_at"]
        == (later + timedelta(seconds=settings.session_idle_ttl_seconds)).isoformat()
    )


async def test_slide_does_not_resurrect_an_expired_cache_entry(env: dict[str, str]) -> None:
    """If the entry expired between the read and the write, SET XX must not
    recreate it — a keepttl write on a missing key would store it forever."""
    settings = _settings()
    cache = _FakeCache()
    service = SessionService(_FakeDb(), cache, settings)  # type: ignore[arg-type]
    token_hash = hash_token(generate_token())
    await service._slide(token_hash, datetime(2026, 8, 6, 12, 0, tzinfo=UTC))
    assert cache.values == {}
