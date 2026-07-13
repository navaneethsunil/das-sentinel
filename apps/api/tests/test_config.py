"""M0-I3: the Settings object loads entirely from the environment.

Uses the repo-root `.env.example` as the fixture so the template is proven
loadable — if a new required field lands in Settings without a placeholder
there, these tests break.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings

ENV_EXAMPLE = Path(__file__).resolve().parents[3] / ".env.example"


def example_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            env[key] = value
    return env


@pytest.fixture()
def env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    values = example_env()
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values


def make_settings() -> Settings:
    return Settings(_env_file=None)  # env vars only; ignore any developer .env


def test_loads_from_env_example(env: dict[str, str]) -> None:
    settings = make_settings()
    assert settings.das_env == "dev"
    assert settings.postgres_host == env["POSTGRES_HOST"]
    assert settings.evidence_bucket == env["EVIDENCE_BUCKET"]


def test_secrets_are_not_exposed_in_repr(env: dict[str, str]) -> None:
    settings = make_settings()
    assert env["POSTGRES_PASSWORD"] not in repr(settings)


def test_derived_urls(env: dict[str, str]) -> None:
    settings = make_settings()
    assert settings.database_url == (
        "postgresql+asyncpg://dassentinel:change-me@postgres:5432/dassentinel"
    )
    # redis:// scheme with separate logical DBs (M0-W1)
    assert settings.celery_broker_url == "redis://valkey:6379/0"
    assert settings.celery_result_backend_url == "redis://valkey:6379/1"
    assert settings.cache_url == "redis://valkey:6379/2"
    assert settings.session_store_url == "redis://valkey:6379/3"


def test_database_url_quotes_credentials(env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", "p@ss:w/rd")
    settings = make_settings()
    assert "p%40ss%3Aw%2Frd" in settings.database_url


def test_minio_credentials_fall_back_to_root(env: dict[str, str]) -> None:
    settings = make_settings()
    assert settings.minio_access_key == env["MINIO_ROOT_USER"]
    assert settings.minio_secret_key.get_secret_value() == env["MINIO_ROOT_PASSWORD"]


def test_minio_scoped_credentials_win(env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MINIO_ACCESS_KEY", "scoped-user")
    monkeypatch.setenv("MINIO_SECRET_KEY", "scoped-secret")
    settings = make_settings()
    assert settings.minio_access_key == "scoped-user"
    assert settings.minio_secret_key.get_secret_value() == "scoped-secret"


def test_missing_required_var_fails_loud(env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POSTGRES_HOST")
    with pytest.raises(ValidationError):
        make_settings()


def test_llm_backend_check_fails_without_key(env: dict[str, str]) -> None:
    settings = make_settings()  # .env.example ships ANTHROPIC_API_KEY empty
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        settings.require_llm_backend()


def test_llm_backend_check_passes_with_key(env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    make_settings().require_llm_backend()
