"""Baseline + maintenance tasks. Real scanner/LLM tasks arrive with M2-W/M3."""

import asyncio

from app.workers.celery_app import celery_app


@celery_app.task(name="app.ping")
def ping() -> str:
    """Round-trip probe: broker → worker → result backend."""
    return "pong"


@celery_app.task(name="app.run_scan")
def run_scan(scan_id: str) -> str:
    """Orchestrate one queued scan (M2-W1): re-derive the authorization from the
    live DB, refuse on divergence, atomically consume any high-risk approval,
    then run it through the uniform execution owner. The task carries only the
    id; all authorization state is reconstructed. Imports are local so the API
    process never pulls the worker/orchestration graph."""
    import uuid

    from app.core.config import get_settings
    from app.core.db import create_engine, create_sessionmaker
    from app.core.sessions import utcnow
    from app.workers.execution import SubprocessOwner
    from app.workers.orchestration import orchestrate_scan

    settings = get_settings()

    async def _run() -> str:
        engine = create_engine(settings)
        sessionmaker = create_sessionmaker(engine)
        try:
            status = await orchestrate_scan(
                sessionmaker,
                scan_id=uuid.UUID(scan_id),
                owner=SubprocessOwner(),
                now=utcnow(),
            )
            return status.value
        finally:
            await engine.dispose()

    return asyncio.run(_run())


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
