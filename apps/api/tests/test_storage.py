"""M2-B1 (CI-safe half): content-addressing + the integrity-verify path, using
a fake in-memory blob store and a stub session. The full two-phase write,
dedup, and orphan-sweep against real Postgres + MinIO are proven live in
scripts/verify_evidence_store.py.
"""

import hashlib
import uuid

import pytest

from app.models.evidence import Evidence
from app.storage import (
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    load_evidence,
    object_key_for,
)


class FakeBlobStore:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def ensure_bucket(self) -> None:
        pass

    def put_object(self, key, data, content_type, retain_until) -> None:  # noqa: ANN001
        self.objects[key] = data

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
