"""M0-W1: Celery app wiring — broker/backend URLs from Settings, JSON-only, ping task."""

from app.core.config import get_settings


def make_celery_app(env: dict[str, str]):
    # get_settings() is lru_cached; clear so the app is built from this test's env.
    get_settings.cache_clear()
    from app.workers.celery_app import create_celery_app

    try:
        return create_celery_app()
    finally:
        get_settings.cache_clear()


def test_broker_and_backend_use_valkey_logical_dbs(env: dict[str, str]) -> None:
    app = make_celery_app(env)
    assert app.conf.broker_url == "redis://valkey:6379/0"
    assert app.conf.result_backend == "redis://valkey:6379/1"


def test_json_only_serialization(env: dict[str, str]) -> None:
    # pickle off the table: broker payloads must never be executable (§2, TM-*)
    app = make_celery_app(env)
    assert app.conf.task_serializer == "json"
    assert app.conf.result_serializer == "json"
    assert app.conf.accept_content == ["json"]


def test_ping_task_registered_and_runs_eagerly(env: dict[str, str]) -> None:
    app = make_celery_app(env)
    app.conf.task_always_eager = True

    from app.workers import tasks  # noqa: F401  (registers app.ping)

    assert "app.ping" in app.tasks
    assert app.tasks["app.ping"].apply().get() == "pong"
