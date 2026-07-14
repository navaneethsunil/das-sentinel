"""Celery application wired to Valkey (M0-W1).

Broker and result backend use the redis:// scheme URLs derived in Settings —
Valkey is protocol-compatible and Celery does not recognize valkey://. Broker
and results live in separate logical DBs (0/1) so cache (2) and sessions (3)
can be flushed independently.

The worker container runs:  celery -A app.workers.celery_app:celery_app worker
"""

from celery import Celery

from app.core.config import get_settings


def create_celery_app() -> Celery:
    settings = get_settings()
    app = Celery(
        "das_sentinel",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend_url,
        include=["app.workers.tasks"],
    )
    app.conf.update(
        # JSON only — pickle deserialization from the broker is arbitrary code
        # execution if the broker is ever reachable by an attacker.
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        # STARTED state is visible in the results backend — scan status and the
        # audit trail need to distinguish queued from running (§2.8, §6a).
        task_track_started=True,
        result_expires=3600,
        broker_connection_retry_on_startup=True,
        # Long-running scanner jobs: don't hoard tasks in worker prefetch.
        worker_prefetch_multiplier=1,
        # Heartbeat/cancellation plumbing per §6a lands with real scanner tasks;
        # per-scanner timeouts are enforced inside adapters, not globally here.
    )
    return app


celery_app = create_celery_app()
