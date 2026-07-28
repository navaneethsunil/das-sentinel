"""Archive audit_events to the WORM evidence store (SEC-DEBT-5). Operator/cron
tool, run as the owner DB role inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/archive_audit_log.py \
          --since 2026-07-01T00:00:00Z --until 2026-08-01T00:00:00Z"

Emits a one-line JSON manifest (count, SHA-256, object key, retain-until) to
stdout for the operator's chain-of-custody record. --since defaults to the whole
history; --until defaults to now. Retention lock comes from
AUDIT_ARCHIVE_RETENTION_DAYS. See security/log-retention-runbook.md.
"""

import argparse
import asyncio
import dataclasses
import json
import sys
from datetime import UTC, datetime

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.services.audit_archive import export_audit_window
from app.storage.evidence import create_evidence_store


def _parse_ts(value: str) -> datetime:
    # Accept trailing Z (ISO-8601 UTC) which fromisoformat historically rejected.
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


async def main() -> int:
    parser = argparse.ArgumentParser(description="Archive audit_events to the WORM store.")
    parser.add_argument("--since", type=_parse_ts, default=None, help="exclusive lower bound (ISO)")
    parser.add_argument("--until", type=_parse_ts, default=None, help="inclusive upper bound (ISO)")
    args = parser.parse_args()

    settings = get_settings()
    until = args.until or datetime.now(UTC)
    store = create_evidence_store(settings)
    store.ensure_bucket()

    # Owner role: a maintenance job reading the full audit history.
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    try:
        async with sessionmaker() as db:
            manifest = await export_audit_window(
                db,
                store,
                since=args.since,
                until=until,
                retention_days=settings.audit_archive_retention_days,
            )
    finally:
        await engine.dispose()

    if manifest is None:
        print(json.dumps({"count": 0, "note": "no audit events in window"}))
        return 0
    out = dataclasses.asdict(manifest)
    out["since"] = manifest.since.isoformat() if manifest.since else None
    out["until"] = manifest.until.isoformat()
    out["retain_until"] = manifest.retain_until.isoformat() if manifest.retain_until else None
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
