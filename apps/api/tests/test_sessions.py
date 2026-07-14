"""M1-B2: opaque-session pure logic (token, hashing, cookie attributes).

The store lifecycle (create/validate/revoke/kill-all + Valkey write-through)
runs against live Postgres+Valkey and is verified by
scripts/verify_sessions.py, not here — CI's pytest has no backends.
"""

import hashlib

from fastapi import Response

from app.core.config import Settings
from app.core.sessions import (
    TOKEN_BYTES,
    clear_session_cookie,
    generate_token,
    hash_token,
)


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
