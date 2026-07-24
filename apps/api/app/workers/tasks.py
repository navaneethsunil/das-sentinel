"""Baseline + maintenance tasks. Real scanner/LLM tasks arrive with M2-W/M3."""

import asyncio

from app.workers.celery_app import celery_app


@celery_app.task(name="app.ping")
def ping() -> str:
    """Round-trip probe: broker → worker → result backend."""
    return "pong"


@celery_app.task(name="app.run_scan")
def run_scan(scan_id: str) -> str:
    """Orchestrate one queued scan (M2-W1 + T1 production wiring): re-derive the
    authorization from the live DB, refuse on divergence, atomically consume any
    high-risk approval, then run the REAL payload through the uniform execution
    owner — an LLM-suite run (PyRIT) or a scanner run (semgrep/ZAP), selected by
    the frozen envelope's kind. The task carries only the id; all state
    (including the kind) is reconstructed from the DB. Imports are local so the
    API process never pulls the worker/orchestration graph, and the tool imports
    (PyRIT/semgrep/ZAP) stay lazy inside the owners so only the matching image
    needs them."""
    import uuid

    from app.core.config import get_settings
    from app.core.db import create_engine, create_sessionmaker
    from app.core.sessions import utcnow
    from app.storage import create_evidence_store
    from app.workers.dispatch import build_owner_for_kind, load_scan_kind
    from app.workers.orchestration import orchestrate_scan

    settings = get_settings()
    sid = uuid.UUID(scan_id)
    store = create_evidence_store(settings)

    async def _run() -> str:
        engine = create_engine(settings)
        sessionmaker = create_sessionmaker(engine)
        try:
            async with sessionmaker() as db:
                kind = await load_scan_kind(db, sid)
            now = utcnow()
            owner = build_owner_for_kind(kind, sessionmaker, store, scan_id=sid, now=now)
            status = await orchestrate_scan(
                sessionmaker,
                scan_id=sid,
                owner=owner,
                now=now,
                cancel_poll_s=settings.scan_cancel_poll_seconds,
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
