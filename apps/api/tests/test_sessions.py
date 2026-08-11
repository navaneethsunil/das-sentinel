"""M1-B2: opaque-session pure logic (token, hashing, cookie attributes).

The store lifecycle (create/validate/revoke/kill-all + Valkey write-through)
runs against live Postgres+Valkey and is verified by
scripts/verify_sessions.py, not here — CI's pytest has no backends.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import Response
from redis.exceptions import ConnectionError as RedisConnectionError

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


# ── cache outage degrades to Postgres; revocation stays fail-loud (DEF-023) ───
class _DownCache:
    """Valkey stand-in for an outage: every operation raises."""

    async def get(self, key: str) -> str | None:
        raise RedisConnectionError("cache down")

    async def set(self, *args: object, **kwargs: object) -> bool | None:
        raise RedisConnectionError("cache down")

    async def delete(self, key: str) -> None:
        raise RedisConnectionError("cache down")


class _Result:
    def __init__(self, row: object = None, scalar: object = None) -> None:
        self._row, self._scalar = row, scalar

    def one_or_none(self) -> object:
        return self._row

    def scalar_one_or_none(self) -> object:
        return self._scalar


class _SeqDb:
    """Hands back canned results in order; accepts writes as no-ops."""

    def __init__(self, results: list[_Result] | None = None) -> None:
        self._results = list(results or [])

    async def execute(self, *args: object, **kwargs: object) -> _Result:
        return self._results.pop(0) if self._results else _Result()

    async def flush(self) -> None:
        return None

    def add(self, obj: object) -> None:
        return None


def _db_session_row(now: datetime, *, revoked: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        revoked_at=(now - timedelta(minutes=1)) if revoked else None,
        idle_expires_at=now + timedelta(minutes=15),
        absolute_expires_at=now + timedelta(hours=8),
        last_seen_at=now,
    )


async def test_validate_session_survives_cache_outage_via_postgres(
    env: dict[str, str],
) -> None:
    """DEF-023: Valkey down used to raise out of validate_session and 500 every
    authenticated request. Postgres is authoritative — validation must degrade
    to the DB row, or a cache outage signs every operator out exactly when they
    need /health."""
    now = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
    session = _db_session_row(now)
    db = _SeqDb([_Result(row=(session, UserRole.TESTER)), _Result(scalar=True)])
    service = SessionService(db, _DownCache(), _settings())  # type: ignore[arg-type]

    validated = await service.validate_session(generate_token(), now=now)

    assert validated is not None
    assert validated.user_id == session.user_id
    assert validated.role is UserRole.TESTER


async def test_validate_session_still_denies_revoked_during_cache_outage(
    env: dict[str, str],
) -> None:
    """Degrading to Postgres must not weaken the decision: a revoked session is
    denied (None, not an exception) even when the stale-entry cache drop fails."""
    now = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
    session = _db_session_row(now, revoked=True)
    db = _SeqDb([_Result(row=(session, UserRole.TESTER))])
    service = SessionService(db, _DownCache(), _settings())  # type: ignore[arg-type]

    assert await service.validate_session(generate_token(), now=now) is None


async def test_create_session_tolerates_cache_write_failure(env: dict[str, str]) -> None:
    """The Postgres row is the session; caching it is an optimization."""
    service = SessionService(_SeqDb(), _DownCache(), _settings())  # type: ignore[arg-type]
    token = await service.create_session(
        uuid.uuid4(), UserRole.TESTER, now=datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
    )
    assert token


async def test_revoke_session_fails_loud_when_cache_invalidation_fails(
    env: dict[str, str],
) -> None:
    """NEGATIVE (write-through invalidation is the security property): a revoke
    that cannot drop the cache entry must raise — swallowing it would leave the
    revoked session usable from cache until the TTL backstop."""
    service = SessionService(_SeqDb(), _DownCache(), _settings())  # type: ignore[arg-type]
    with pytest.raises(RedisConnectionError):
        await service.revoke_session(generate_token(), now=datetime(2026, 8, 11, tzinfo=UTC))
