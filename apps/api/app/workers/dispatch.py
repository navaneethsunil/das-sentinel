"""Route a queued scan to its execution owner + Celery queue by kind (T1).

The Celery task carries only the scan id; the kind is read from the *frozen DB
envelope* (never trusted from the message), mirroring the re-derive-from-DB
principle the orchestrator follows. A scanner envelope carries a non-empty
`scanners` list; otherwise it is an LLM-suite run.

Owner construction imports the suite/scanner builder lazily so importing this
module (e.g. from the API to pick a routing queue) never pulls a
redteam/scanner-only dependency (PyRIT / semgrep / ZAP).
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.scan import ExecutionAuthorization

if TYPE_CHECKING:
    # Kept out of the runtime import graph so the API can import QUEUE_FOR_KIND /
    # the kind helpers without pulling boto3 (BlobStore) or the execution owner.
    from app.storage.evidence import BlobStore
    from app.workers.execution import InProcessOwner

SUITE_KIND = "suite"
SCANNER_KIND = "scanner"

# Each worker consumes exactly one queue (see docker-compose worker commands):
# the redteam image (PyRIT) runs LLM suites; the scanners image (semgrep/ZAP)
# runs scanner scans. The base worker consumes only the default `celery` queue.
QUEUE_FOR_KIND = {SUITE_KIND: "redteam", SCANNER_KIND: "scanners"}


def kind_for_config(normalized_config: dict) -> str:
    """Classify a frozen envelope's normalized_config as a scanner or suite run."""
    scanners = normalized_config.get("scanners") if isinstance(normalized_config, dict) else None
    return SCANNER_KIND if scanners else SUITE_KIND


async def load_scan_kind(db: AsyncSession, scan_id: uuid.UUID) -> str:
    """Read the frozen envelope from the DB and classify the scan (fail-loud if
    there is no envelope — the worker must never guess)."""
    config = (
        await db.execute(
            select(ExecutionAuthorization.normalized_config).where(
                ExecutionAuthorization.scan_id == scan_id
            )
        )
    ).scalar_one_or_none()
    if config is None:
        raise ValueError(f"no execution authorization for scan {scan_id}")
    return kind_for_config(config)


def build_owner_for_kind(
    kind: str,
    sessionmaker: async_sessionmaker[AsyncSession],
    store: "BlobStore",
    *,
    scan_id: uuid.UUID,
    now: datetime,
) -> "InProcessOwner":
    """Build the execution owner matching the scan kind (tool imports stay lazy
    inside the respective run functions)."""
    if kind == SCANNER_KIND:
        from app.workers.scanner_run import build_scanner_owner

        return build_scanner_owner(sessionmaker, store, scan_id=scan_id, now=now)
    from app.workers.suite_run import build_suite_owner

    return build_suite_owner(sessionmaker, store, scan_id=scan_id, now=now)
