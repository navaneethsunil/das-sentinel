"""Audit-log archival to the WORM evidence store (SEC-DEBT-5, log retention).

The audit tables are append-only and tamper-evident in the hot DB (raising
triggers + the least-privilege runtime role has no UPDATE/DELETE). This exports a
time window of `audit_events` as deterministic NDJSON to the object store with a
COMPLIANCE object-lock — an off-box, immutable, content-hashed copy for the
defined retention window. Deterministic serialization (sorted keys) means an
identical set of events always produces identical bytes and the same SHA-256, so
an archive's integrity can be re-verified by re-hashing it.

Run via scripts/archive_audit_log.py (owner role); off-box shipping of the
container's structured stdout logs and NTP are deployment concerns — see
security/log-retention-runbook.md.
"""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent
from app.storage.evidence import BlobStore

_CONTENT_TYPE = "application/x-ndjson"


def _serialize(e: AuditEvent) -> dict:
    return {
        "id": str(e.id),
        "ts": e.created_at.isoformat(),
        "organization_id": str(e.organization_id),
        "actor_user_id": str(e.actor_user_id) if e.actor_user_id else None,
        "action": e.action,
        "object_type": e.object_type,
        "object_id": str(e.object_id) if e.object_id else None,
        "engagement_id": str(e.engagement_id) if e.engagement_id else None,
        "outcome": e.outcome.value,
        "detail": e.detail,
        # asyncpg maps the INET column to an ipaddress object → stringify for JSON.
        "ip_address": str(e.ip_address) if e.ip_address is not None else None,
    }


def build_archive_bytes(events: Sequence[AuditEvent]) -> bytes:
    """Deterministic NDJSON: one sorted-key JSON object per line. Identical events
    → identical bytes → identical hash (re-verifiable integrity)."""
    lines = [json.dumps(_serialize(e), sort_keys=True, ensure_ascii=False) for e in events]
    return ("\n".join(lines) + "\n").encode() if lines else b""


@dataclass(frozen=True)
class ArchiveManifest:
    count: int
    since: datetime | None
    until: datetime
    content_sha256: str
    object_key: str
    retain_until: datetime | None


async def export_audit_window(
    db: AsyncSession,
    store: BlobStore,
    *,
    until: datetime,
    since: datetime | None = None,
    retention_days: int = 0,
    now: datetime | None = None,
) -> ArchiveManifest | None:
    """Export (since, until] of audit_events to a WORM-locked NDJSON blob. Returns
    the manifest, or None when the window holds no events (nothing written)."""
    now = now or datetime.now(UTC)
    q = (
        select(AuditEvent)
        .where(AuditEvent.created_at <= until)
        .order_by(AuditEvent.created_at, AuditEvent.id)
    )
    if since is not None:
        q = q.where(AuditEvent.created_at > since)
    events = list((await db.execute(q)).scalars())
    if not events:
        return None

    content = build_archive_bytes(events)
    digest = hashlib.sha256(content).digest()
    key = f"audit-archive/{until.strftime('%Y%m%dT%H%M%SZ')}-{digest.hex()[:16]}.ndjson"
    retain_until = now + timedelta(days=retention_days) if retention_days > 0 else None
    store.put_object(key, content, _CONTENT_TYPE, retain_until)
    return ArchiveManifest(
        count=len(events),
        since=since,
        until=until,
        content_sha256=digest.hex(),
        object_key=key,
        retain_until=retain_until,
    )
