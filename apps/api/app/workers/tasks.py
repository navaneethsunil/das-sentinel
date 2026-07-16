"""Baseline + maintenance tasks. Real scanner/LLM tasks arrive with M2-W/M3."""

import asyncio

from app.workers.celery_app import celery_app


@celery_app.task(name="app.ping")
def ping() -> str:
    """Round-trip probe: broker → worker → result backend."""
    return "pong"


@celery_app.task(name="app.sweep_orphan_evidence")
def sweep_orphan_evidence() -> list[str]:
    """Reconcile evidence blobs whose metadata commit failed (M2-B1). Deletes
    object-store blobs with no `evidence` row and returns the keys removed;
    blobs under object-lock retention are rejected by the backend, not
    force-deleted. Imports are local so the API process never pulls boto3."""
    from app.core.config import get_settings
    from app.core.db import create_engine, create_sessionmaker
    from app.storage import create_evidence_store, sweep_orphans

    settings = get_settings()
    store = create_evidence_store(settings)

    async def _run() -> list[str]:
        engine = create_engine(settings)
        sessionmaker = create_sessionmaker(engine)
        try:
            async with sessionmaker() as session:
                return await sweep_orphans(session, store)
        finally:
            await engine.dispose()

    return asyncio.run(_run())
