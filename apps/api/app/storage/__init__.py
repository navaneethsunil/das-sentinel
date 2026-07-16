"""Evidence object storage (M2-B1). All raw-evidence blobs go through this
abstraction so the S3-compatible backend stays swappable (the production
WORM backend is a blocking pre-go-live gate — DATABASE_SCHEMA §6, ROADMAP)."""

from app.storage.evidence import (
    BlobStore,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    S3EvidenceStore,
    StorageError,
    create_evidence_store,
    load_evidence,
    object_key_for,
    store_evidence,
    sweep_orphans,
)

__all__ = [
    "BlobStore",
    "EvidenceIntegrityError",
    "EvidenceNotFoundError",
    "S3EvidenceStore",
    "StorageError",
    "create_evidence_store",
    "load_evidence",
    "object_key_for",
    "store_evidence",
    "sweep_orphans",
]
