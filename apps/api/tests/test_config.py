"""M0-I3: the Settings object loads entirely from the environment.

The `env` fixture (conftest) seeds the repo-root `.env.example` values — if a
new required field lands in Settings without a placeholder there, these break.
"""

import pytest
from pydantic import ValidationError

from app.core.config import Settings


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


def test_prod_rejects_weak_default_secrets(env: dict[str, str]) -> None:  # noqa: ARG001
    # SEC-DEBT-11: .env.example ships POSTGRES_PASSWORD=change-me — fine for dev,
    # must fail closed if a prod deployment forgets to override it.
    with pytest.raises(ValidationError, match="POSTGRES_PASSWORD"):
        Settings(_env_file=None, das_env="prod")


def test_prod_accepts_strong_secrets(
    env: dict[str, str],  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", "s7rong-Db-P@ss-x9")
    monkeypatch.setenv("MINIO_SECRET_KEY", "s7rong-Minio-K3y-z2")
    settings = Settings(_env_file=None, das_env="prod")
    assert settings.das_env == "prod"


def test_dev_keeps_weak_defaults(env: dict[str, str]) -> None:
    # No-op outside prod: dev/test must still boot on the template values.
    assert make_settings().das_env == "dev"


def test_app_role_url_selection(env: dict[str, str]) -> None:  # noqa: ARG001
    # SEC-DEBT-4: migrations always run as the owner; the runtime URL only
    # switches to the restricted role when use_app_role is on.
    owner = "postgresql+asyncpg://dassentinel:change-me@postgres:5432/dassentinel"
    app = "postgresql+asyncpg://das_app:change-me@postgres:5432/dassentinel"

    off = make_settings()  # .env.example ships POSTGRES_USE_APP_ROLE=false
    assert off.owner_database_url == owner
    assert off.database_url == owner  # dev stays single-role
    assert off.app_role_database_url == app  # still available for verification

    on = Settings(_env_file=None, postgres_use_app_role=True)
    assert on.owner_database_url == owner  # migrations unaffected
    assert on.database_url == app  # runtime restricted


def test_prod_requires_strong_app_password_when_used(
    env: dict[str, str],  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", "s7rong-Db-P@ss-x9")
    monkeypatch.setenv("MINIO_SECRET_KEY", "s7rong-Minio-K3y-z2")
    # app role in use but on the weak template password → fail closed
    with pytest.raises(ValidationError, match="POSTGRES_APP_PASSWORD"):
        Settings(_env_file=None, das_env="prod", postgres_use_app_role=True)
    # not in use → its password is irrelevant, boots fine
    assert Settings(_env_file=None, das_env="prod", postgres_use_app_role=False).das_env == "prod"


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
