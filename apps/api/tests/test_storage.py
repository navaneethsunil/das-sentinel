"""M2-B1 (CI-safe half): content-addressing + the integrity-verify path, using
a fake in-memory blob store and a stub session. The full two-phase write,
dedup, and orphan-sweep against real Postgres + MinIO are proven live in
scripts/verify_evidence_store.py.
"""

import hashlib
import uuid
from datetime import UTC, datetime

import pytest

from app.models.evidence import Evidence, EvidenceKind
from app.storage import (
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    load_evidence,
    object_key_for,
    store_evidence,
)


class FakeBlobStore:
    def __init__(self, retention_days: int = 0) -> None:
        self.objects: dict[str, bytes] = {}
        self.retention_days = retention_days
        self.last_retain_until: datetime | None = None

    def ensure_bucket(self) -> None:
        pass

    def put_object(self, key, data, content_type, retain_until) -> None:  # noqa: ANN001
        self.objects[key] = data
        self.last_retain_until = retain_until

    def get_object(self, key: str) -> bytes:
        return self.objects[key]

    def object_exists(self, key: str) -> bool:
        return key in self.objects

    def list_keys(self, prefix: str = "") -> list[str]:
        return [k for k in self.objects if k.startswith(prefix)]

    def delete_object(self, key: str) -> None:
        self.objects.pop(key, None)


class FakeSession:
    """Minimal stand-in exposing only .get() (what load_evidence needs)."""

    def __init__(self, obj: Evidence | None) -> None:
        self._obj = obj

    async def get(self, model, ident):  # noqa: ANN001, ARG002
        return self._obj


def test_object_key_is_content_addressed() -> None:
    digest = hashlib.sha256(b"raw scanner output").digest()
    key = object_key_for(digest)
    assert key == f"sha256/{digest.hex()}"
    # Same content → same key (dedup); different content → different key.
    assert object_key_for(hashlib.sha256(b"raw scanner output").digest()) == key
    assert object_key_for(hashlib.sha256(b"other").digest()) != key


async def test_load_evidence_returns_bytes_when_hash_matches() -> None:
    content = b"transcript bytes"
    digest = hashlib.sha256(content).digest()
    key = object_key_for(digest)
    store = FakeBlobStore()
    store.objects[key] = content
    ev = Evidence(object_key=key, content_sha256=digest)
    data = await load_evidence(FakeSession(ev), store, uuid.uuid4())
    assert data == content


async def test_load_evidence_raises_on_tamper() -> None:
    content = b"original"
    digest = hashlib.sha256(content).digest()
    key = object_key_for(digest)
    store = FakeBlobStore()
    store.objects[key] = b"tampered!"  # blob no longer matches the recorded hash
    ev = Evidence(object_key=key, content_sha256=digest)
    with pytest.raises(EvidenceIntegrityError):
        await load_evidence(FakeSession(ev), store, uuid.uuid4())


async def test_load_evidence_missing_row() -> None:
    with pytest.raises(EvidenceNotFoundError):
        await load_evidence(FakeSession(None), FakeBlobStore(), uuid.uuid4())


class _WriteSession:
    """Stub for store_evidence's write path: no existing row, captures the add."""

    def __init__(self) -> None:
        self.added: list[Evidence] = []

    async def execute(self, _stmt: object):  # noqa: ANN202
        class _R:
            def scalar_one_or_none(self) -> None:
                return None

        return _R()

    def add(self, obj: Evidence) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        pass


async def test_worm_retention_default_applied_when_enabled() -> None:
    store = FakeBlobStore(retention_days=90)
    session = _WriteSession()
    before = datetime.now(UTC)
    ev = await store_evidence(
        session,
        store,
        organization_id=uuid.uuid4(),
        content=b"raw output",
        kind=EvidenceKind.RAW_SCANNER_OUTPUT,
        content_type="application/json",
    )
    # Same retain_until lands on both the object-lock and the DB row, ~90 days out.
    assert ev.retain_until == store.last_retain_until is not None
    assert 89 < (ev.retain_until - before).days < 91


async def test_worm_retention_off_by_default() -> None:
    store = FakeBlobStore()  # retention_days=0
    ev = await store_evidence(
        _WriteSession(),
        store,
        organization_id=uuid.uuid4(),
        content=b"raw output",
        kind=EvidenceKind.RAW_SCANNER_OUTPUT,
        content_type="application/json",
    )
    assert ev.retain_until is None
    assert store.last_retain_until is None
