"""Baseline tasks (M0-W1). Real scanner/LLM tasks arrive with M2/M3."""

from app.workers.celery_app import celery_app


@celery_app.task(name="app.ping")
def ping() -> str:
    """Round-trip probe: broker → worker → result backend."""
    return "pong"
