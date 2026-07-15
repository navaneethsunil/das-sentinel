"""M1-SEC2 (CI-safe half): the double-submit CSRF middleware rejects forged
state-changing requests before any handler or backend is touched.

Backends are down here (`.env.example` hostnames don't resolve) and that is
the point: a 403 proves the middleware fired first, and a non-403 on allowed
paths proves it stood aside (the request then fails deeper, on the dead
backends, as 401/500 — never the CSRF 403). The full authenticated
cookie-issuing flow is proven live in scripts/verify_auth_csrf.py.
"""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.config import Settings

SESSION_TOKEN = "fake-session-token"  # noqa: S105 - inert fixture value
CSRF_TOKEN = "fake-csrf-token"  # noqa: S105


@pytest.fixture()
def settings(env: dict[str, str]) -> Settings:  # noqa: ARG001 - env sets config
    return Settings(_env_file=None)


@pytest.fixture()
def client(settings: Settings) -> Iterator[TestClient]:
    application = main.create_app(settings)
    # Server errors surface as 500 (not raised): dead backends are expected on
    # paths the middleware lets through.
    with TestClient(application, raise_server_exceptions=False) as test_client:
        yield test_client


def test_state_change_without_csrf_token_is_403(client: TestClient, settings: Settings) -> None:
    client.cookies.set(settings.session_cookie_name, SESSION_TOKEN)
    response = client.post("/auth/logout")
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_header_without_cookie_is_403(client: TestClient, settings: Settings) -> None:
    client.cookies.set(settings.session_cookie_name, SESSION_TOKEN)
    response = client.post("/auth/logout", headers={settings.csrf_header_name: CSRF_TOKEN})
    assert response.status_code == 403


def test_mismatched_header_and_cookie_is_403(client: TestClient, settings: Settings) -> None:
    client.cookies.set(settings.session_cookie_name, SESSION_TOKEN)
    client.cookies.set(settings.csrf_cookie_name, CSRF_TOKEN)
    response = client.post("/auth/logout", headers={settings.csrf_header_name: "attacker-guess"})
    assert response.status_code == 403


def test_matching_tokens_pass_the_middleware(client: TestClient, settings: Settings) -> None:
    client.cookies.set(settings.session_cookie_name, SESSION_TOKEN)
    client.cookies.set(settings.csrf_cookie_name, CSRF_TOKEN)
    response = client.post("/auth/logout", headers={settings.csrf_header_name: CSRF_TOKEN})
    # Fails deeper (session validation against dead backends), never as CSRF.
    assert response.status_code != 403


def test_safe_method_is_exempt(client: TestClient, settings: Settings) -> None:
    client.cookies.set(settings.session_cookie_name, SESSION_TOKEN)
    response = client.get("/healthz")
    assert response.status_code == 200


def test_login_is_exempt(client: TestClient) -> None:
    response = client.post(
        "/auth/login",
        json={"email": "someone@example.com", "password": "irrelevant-password"},
    )
    assert response.status_code != 403


def test_login_is_exempt_even_with_a_stale_session_cookie(
    client: TestClient, settings: Settings
) -> None:
    # Re-login with a lingering session cookie must not dead-lock on a CSRF
    # token the client no longer has.
    client.cookies.set(settings.session_cookie_name, SESSION_TOKEN)
    response = client.post(
        "/auth/login",
        json={"email": "someone@example.com", "password": "irrelevant-password"},
    )
    assert response.status_code != 403


def test_anonymous_state_change_passes_through_to_auth(client: TestClient) -> None:
    # No session cookie ⇒ nothing to forge; the auth layer answers 401.
    response = client.post("/auth/logout")
    assert response.status_code == 401
