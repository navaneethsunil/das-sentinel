"""Evidence model (M2-D1) — DATABASE_SCHEMA §6.

An immutable, content-addressable pointer to a blob in the S3-compatible
evidence store. The large blob lives in object storage; Postgres holds only the
queryable metadata + integrity hash. Never mutated, never soft-deleted — a DB
trigger enforces insert-only (chain of custody, matching audit_events).

Write order is blob→object store first, then this row (two-phase, ARCHITECTURE
§13); an orphan-sweep job reconciles blobs whose metadata commit failed.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, ForeignKey, Index, LargeBinary, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.identity import GEN_UUID, NOW, UUID_PK


class EvidenceKind(enum.Enum):
    RAW_SCANNER_OUTPUT = "raw_scanner_output"
    HTTP_TRANSCRIPT = "http_transcript"
    LLM_TRANSCRIPT = "llm_transcript"
    SOURCE_ARCHIVE = "source_archive"


EVIDENCE_KIND_ENUM = Enum(
    EvidenceKind, name="evidence_kind", values_callable=lambda e: [m.value for m in e]
)


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        # Content-addressable dedup: the same blob is stored once.
        Index("ux_evidence_hash", "content_sha256", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT")
    )
    object_key: Mapped[str] = mapped_column(Text, unique=True)
    content_sha256: Mapped[bytes] = mapped_column(LargeBinary)  # verified on read
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    content_type: Mapped[str] = mapped_column(Text)
    kind: Mapped[EvidenceKind] = mapped_column(EVIDENCE_KIND_ENUM)
    # Mirrors object-lock retention (compliance-mode WORM).
    retain_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
