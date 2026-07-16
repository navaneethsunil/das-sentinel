"""S3-compatible evidence store + two-phase evidence recording (M2-B1).

DATABASE_SCHEMA §6 / ARCHITECTURE §13: raw evidence blobs live in the object
store; Postgres holds only queryable metadata + the SHA-256 for integrity.

Two-phase, non-transactional write: the blob goes to the object store FIRST,
then the `evidence` row commits. A metadata commit that fails leaves an orphan
blob, reconciled by `sweep_orphans` — we never commit a row pointing at a blob
that isn't there. Content is addressed by its own SHA-256, so identical bytes
dedup to one blob + one row (the `ux_evidence_hash` unique index).

Reads re-verify the hash (`load_evidence`) — a corrupted or tampered blob is a
loud failure, never silently served.

Backend note: dev/MVP runs the (archived) MinIO OSS build purely through this
S3 abstraction; the production WORM backend is a separate blocking gate. WORM
retention is supported (`retain_until` → COMPLIANCE object-lock) but OFF by
default so dev blobs stay deletable; production sets it and its enforcement is
verified before go-live.
"""

import hashlib
import uuid
from datetime import datetime
from typing import Protocol

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.evidence import Evidence, EvidenceKind


class StorageError(Exception):
    """Object-store operation failed."""


class EvidenceNotFoundError(StorageError):
    """No evidence row for the given id."""


class EvidenceIntegrityError(StorageError):
    """A fetched blob's SHA-256 does not match the recorded hash."""


class BlobStore(Protocol):
    """The blob operations the evidence layer needs. A fake implementing this
    substitutes for the real S3 client in unit tests."""

    def ensure_bucket(self) -> None: ...

    def put_object(
        self, key: str, data: bytes, content_type: str, retain_until: datetime | None
    ) -> None: ...

    def get_object(self, key: str) -> bytes: ...

    def object_exists(self, key: str) -> bool: ...

    def list_keys(self, prefix: str = "") -> list[str]: ...

    def delete_object(self, key: str) -> None: ...


class S3EvidenceStore:
    """boto3-backed BlobStore for any S3-compatible endpoint (dev: MinIO).

    Path-style addressing is required by MinIO. Object-lock is enabled at bucket
    creation so per-object COMPLIANCE retention can be applied later."""

    def __init__(
        self, *, endpoint_url: str, access_key: str, secret_key: str, bucket: str, secure: bool
    ) -> None:
        self._bucket = bucket
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name="us-east-1",  # ignored by MinIO; required by boto3
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
            use_ssl=secure,
        )

    def ensure_bucket(self) -> None:
        try:
            self._client.head_bucket(Bucket=self._bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("404", "NoSuchBucket", "NoSuchKey"):
                raise StorageError(f"head_bucket failed: {exc}") from exc
        try:
            # Object-lock can only be enabled at creation — required for WORM.
            self._client.create_bucket(Bucket=self._bucket, ObjectLockEnabledForBucket=True)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") == "BucketAlreadyOwnedByYou":
                return
            raise StorageError(f"create_bucket failed: {exc}") from exc

    def put_object(
        self, key: str, data: bytes, content_type: str, retain_until: datetime | None
    ) -> None:
        extra: dict[str, object] = {}
        if retain_until is not None:
            extra["ObjectLockMode"] = "COMPLIANCE"
            extra["ObjectLockRetainUntilDate"] = retain_until
        try:
            self._client.put_object(
                Bucket=self._bucket, Key=key, Body=data, ContentType=content_type, **extra
            )
        except ClientError as exc:
            raise StorageError(f"put_object {key} failed: {exc}") from exc

    def get_object(self, key: str) -> bytes:
        try:
            resp = self._client.get_object(Bucket=self._bucket, Key=key)
            return resp["Body"].read()
        except ClientError as exc:
            raise StorageError(f"get_object {key} failed: {exc}") from exc

    def object_exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") in ("404", "NoSuchKey"):
                return False
            raise StorageError(f"head_object {key} failed: {exc}") from exc

    def list_keys(self, prefix: str = "") -> list[str]:
        keys: list[str] = []
        paginator = self._client.get_paginator("list_objects_v2")
        try:
            for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
                keys.extend(obj["Key"] for obj in page.get("Contents", []))
        except ClientError as exc:
            raise StorageError(f"list_objects_v2 failed: {exc}") from exc
        return keys

    def delete_object(self, key: str) -> None:
        try:
            self._client.delete_object(Bucket=self._bucket, Key=key)
        except ClientError as exc:
            raise StorageError(f"delete_object {key} failed: {exc}") from exc


def create_evidence_store(settings: Settings) -> S3EvidenceStore:
    scheme = "https" if settings.minio_secure else "http"
    return S3EvidenceStore(
        endpoint_url=f"{scheme}://{settings.minio_endpoint}",
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key.get_secret_value(),
        bucket=settings.evidence_bucket,
        secure=settings.minio_secure,
    )


def object_key_for(content_sha256: bytes) -> str:
    """Content-addressed key: identical bytes → one object (dedup)."""
    return f"sha256/{content_sha256.hex()}"


async def store_evidence(
    session: AsyncSession,
    store: BlobStore,
    *,
    organization_id: uuid.UUID,
    content: bytes,
    kind: EvidenceKind,
    content_type: str,
    retain_until: datetime | None = None,
) -> Evidence:
    """Two-phase content-addressed write. Returns the (flushed, not committed)
    Evidence row so it commits atomically with the caller's transaction. Dedups
    on content SHA-256 — identical bytes reuse the existing blob + row."""
    digest = hashlib.sha256(content).digest()
    existing = (
        await session.execute(select(Evidence).where(Evidence.content_sha256 == digest))
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    key = object_key_for(digest)
    # Blob FIRST — a row is never committed pointing at a missing blob.
    store.put_object(key, content, content_type, retain_until)
    evidence = Evidence(
        organization_id=organization_id,
        object_key=key,
        content_sha256=digest,
        size_bytes=len(content),
        content_type=content_type,
        kind=kind,
        retain_until=retain_until,
    )
    session.add(evidence)
    await session.flush()
    return evidence


async def load_evidence(session: AsyncSession, store: BlobStore, evidence_id: uuid.UUID) -> bytes:
    """Fetch a blob and re-verify its SHA-256 against the recorded hash."""
    evidence = await session.get(Evidence, evidence_id)
    if evidence is None:
        raise EvidenceNotFoundError(str(evidence_id))
    data = store.get_object(evidence.object_key)
    if hashlib.sha256(data).digest() != evidence.content_sha256:
        raise EvidenceIntegrityError(
            f"evidence {evidence_id} hash mismatch — blob corrupted or tampered"
        )
    return data


async def sweep_orphans(
    session: AsyncSession, store: BlobStore, *, prefix: str = "sha256/"
) -> list[str]:
    """Delete blobs that have no `evidence` row (a metadata commit that failed
    after the blob was written). Never touches a blob under object-lock
    retention — the backend rejects that delete, which we surface. Returns the
    keys deleted."""
    blob_keys = set(store.list_keys(prefix))
    row_keys = set((await session.execute(select(Evidence.object_key))).scalars())
    orphans = sorted(blob_keys - row_keys)
    for key in orphans:
        store.delete_object(key)
    return orphans
