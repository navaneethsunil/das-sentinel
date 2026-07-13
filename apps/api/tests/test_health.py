"""M0-B1: liveness/readiness endpoints.

`.env.example` points at compose-internal hostnames (`postgres`, `valkey`)
that don't resolve on the test host — exactly the "backends down" condition
the fail-closed tests need.
"""

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.config import Settings


@pytest.fixture()
def client(env: dict[str, str]) -> TestClient:
    application = main.create_app(Settings(_env_file=None))
    with TestClient(application) as test_client:
        yield test_client


def test_healthz_ok_without_backends(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_fails_closed_when_backends_down(client: TestClient) -> None:
    response = client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "unavailable"
    assert body["checks"] == {"database": "unavailable", "valkey": "unavailable"}


def test_readyz_does_not_leak_backend_detail(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Hostnames distinct from the check names, so a leak is unambiguous.
    monkeypatch.setenv("POSTGRES_HOST", "db-internal.test")
    monkeypatch.setenv("VALKEY_HOST", "cache-internal.test")
    application = main.create_app(Settings(_env_file=None))
    with TestClient(application) as test_client:
        response = test_client.get("/readyz")
    assert response.status_code == 503
    assert env["POSTGRES_PASSWORD"] not in response.text
    assert "db-internal.test" not in response.text
    assert "cache-internal.test" not in response.text


def test_readyz_ok_when_backends_up(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    async def check_ok(_backend: object) -> None:
        return None

    monkeypatch.setattr(main, "check_database", check_ok)
    monkeypatch.setattr(main, "check_valkey", check_ok)
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "checks": {"database": "ok", "valkey": "ok"}}


def test_no_cors_headers(client: TestClient) -> None:
    # Same-origin behind the proxy — CORS stays off (M0-B1).
    response = client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in response.headers


def test_root_path_is_configured(client: TestClient, env: dict[str, str]) -> None:
    assert client.app.root_path == env["API_ROOT_PATH"]
