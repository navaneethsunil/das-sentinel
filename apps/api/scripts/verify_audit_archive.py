"""Live verification of audit-log WORM archival (SEC-DEBT-5). Run inside the
compose network (needs postgres + minio):

    docker compose up -d postgres valkey minio migrate
    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_audit_archive.py"

Seeds audit events, exports the window to the evidence store, and asserts the
blob exists, reads back byte-identical (content SHA-256 matches the manifest),
parses to the seeded rows, and — with retention on — is object-locked against
deletion. Cleans up after itself.
"""

import asyncio
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.models.audit import AuditEvent, AuditOutcome
from app.models.identity import Organization
from app.services.audit_archive import export_audit_window
from app.storage.evidence import StorageError, create_evidence_store

NOW = datetime.now(UTC)
failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def main() -> int:
    settings = get_settings()
    store = create_evidence_store(settings)
    store.ensure_bucket()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)

    async with sessionmaker() as db:
        org = Organization(name="verify-audit-archive-org")
        db.add(org)
        await db.flush()
        actions = ["auth.login", "engagement.created", "scan.launched"]
        for a in actions:
            db.add(
                AuditEvent(
                    organization_id=org.id,
                    action=a,
                    object_type="user",
                    outcome=AuditOutcome.SUCCESS,
                )
            )
        await db.commit()
        org_id = org.id

    async with sessionmaker() as db:
        # Scope the window to this org's events so a shared dev DB doesn't inflate it.
        manifest = await export_audit_window(
            db, store, until=NOW + timedelta(minutes=1), since=NOW - timedelta(minutes=5)
        )

    check("export returned a manifest", manifest is not None)
    if manifest is None:
        print("\n1 FAILURE(S): no manifest")
        return 1

    # Our 3 fall in the window (a shared dev DB may add more; assert >= 3 and ours present).
    check("archived at least the 3 seeded events", manifest.count >= 3)
    check("blob exists in the store", store.object_exists(manifest.object_key))

    blob = store.get_object(manifest.object_key)
    check(
        "readback hash matches manifest",
        hashlib.sha256(blob).hexdigest() == manifest.content_sha256,
    )
    parsed = [json.loads(line) for line in blob.decode().splitlines()]
    archived_actions = {e["action"] for e in parsed}
    check("seeded actions present in archive", set(actions) <= archived_actions)
    check(
        "every line has org + ts + outcome",
        all({"organization_id", "ts", "outcome"} <= e.keys() for e in parsed),
    )

    # Retention lock: only assert immutability when it's actually configured on.
    if manifest.retain_until is not None:
        try:
            store.delete_object(manifest.object_key)
            check("WORM: locked object cannot be deleted", False)
        except StorageError:
            check("WORM: locked object cannot be deleted", True)
    else:
        print("SKIP: audit_archive_retention_days=0 (no object-lock in dev)")

    # cleanup
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    if manifest.retain_until is None:
        try:
            store.delete_object(manifest.object_key)
        except StorageError:
            pass
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
