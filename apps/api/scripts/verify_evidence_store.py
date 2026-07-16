"""Live verification of M2-B1 evidence storage against real MinIO + Postgres.
Run inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_evidence_store.py"

Proves: bucket bootstrap; two-phase write (blob present + row committed);
content-addressed dedup (identical bytes → same row, one blob); read-back
re-verifies the hash; a tampered blob is rejected (EvidenceIntegrityError);
the evidence row is immutable (trigger); and orphan-sweep removes a stray blob
while leaving referenced ones. Cleans up after itself.
"""

import asyncio
import hashlib
import sys

from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.models.evidence import Evidence, EvidenceKind
from app.models.identity import Organization
from app.storage import (
    EvidenceIntegrityError,
    create_evidence_store,
    load_evidence,
    object_key_for,
    store_evidence,
    sweep_orphans,
)

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def main() -> int:  # noqa: C901, PLR0915 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    store = create_evidence_store(settings)

    store.ensure_bucket()
    check("bucket bootstrap idempotent", True)  # no raise
    store.ensure_bucket()  # second call must be a no-op

    content = b"raw scanner output " + b"x" * 500
    digest = hashlib.sha256(content).digest()
    key = object_key_for(digest)
    stray_key = "sha256/" + "de" * 32  # a blob with no row (orphan)
    org_id = None
    ev_id = None

    async with sessionmaker() as session:
        org = Organization(name="verify-evidence-org")
        session.add(org)
        await session.flush()
        org_id = org.id

        ev = await store_evidence(
            session,
            store,
            organization_id=org.id,
            content=content,
            kind=EvidenceKind.RAW_SCANNER_OUTPUT,
            content_type="text/plain",
        )
        await session.commit()
        ev_id = ev.id
        check("two-phase: blob written to object store", store.object_exists(key))
        check("two-phase: evidence row persisted", ev.object_key == key)
        check(
            "row records size + hash", ev.size_bytes == len(content) and ev.content_sha256 == digest
        )

    # dedup: identical bytes reuse the same row + blob (no duplicate)
    async with sessionmaker() as session:
        ev2 = await store_evidence(
            session,
            store,
            organization_id=org_id,
            content=content,
            kind=EvidenceKind.RAW_SCANNER_OUTPUT,
            content_type="text/plain",
        )
        check("dedup: identical content returns the existing row", ev2.id == ev_id)
        rows = (
            (await session.execute(select(Evidence).where(Evidence.content_sha256 == digest)))
            .scalars()
            .all()
        )
        check("dedup: exactly one row for the content hash", len(rows) == 1)

    # read-back re-verifies the hash
    async with sessionmaker() as session:
        data = await load_evidence(session, store, ev_id)
        check("read-back returns the exact bytes", data == content)

    # tamper detection: overwrite the blob with different bytes → load raises
    store.put_object(key, b"tampered", "text/plain", None)
    async with sessionmaker() as session:
        try:
            await load_evidence(session, store, ev_id)
            check("tampered blob rejected", False)
        except EvidenceIntegrityError:
            check("tampered blob rejected", True)
    store.put_object(key, content, "text/plain", None)  # restore for clean sweep

    # immutability: the evidence row cannot be updated (DB trigger)
    async with sessionmaker() as session:
        try:
            await session.execute(
                text("UPDATE evidence SET size_bytes = 0 WHERE id = :i"), {"i": str(ev_id)}
            )
            await session.commit()
            check("evidence row immutable (UPDATE denied)", False)
        except Exception:
            await session.rollback()
            check("evidence row immutable (UPDATE denied)", True)

    # orphan-sweep: a stray blob is removed; the referenced one survives
    store.put_object(stray_key, b"orphan", "text/plain", None)
    async with sessionmaker() as session:
        deleted = await sweep_orphans(session, store)
    check("orphan-sweep deletes the stray blob", stray_key in deleted)
    check("orphan-sweep keeps the referenced blob", store.object_exists(key))
    check("orphan-sweep did not delete the referenced blob", key not in deleted)

    # cleanup (evidence is insert-only → dev-superuser trigger bypass)
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(Evidence).where(Evidence.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    store.delete_object(key)
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
