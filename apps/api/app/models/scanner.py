"""Scanner-run model (M3-D1) — DATABASE_SCHEMA §6.

A scanner_run is one external-tool invocation (Semgrep, ZAP, Nuclei, …) within a
scan. It mirrors test_runs (the LLM/agent-suite sibling) but captures the
tool-specific reproducibility fields: exact tool version, the digest-pinned
scanner image, and the content-hash of the vendored rule/template bundle
(CLAUDE.md §6 — pin by digest, never a floating tag).

config is the typed, REDACTED persisted config (args/policy/rule-bundle ref +
license). It MUST NOT hold runtime secret material — e.g. the ZAP API key is
injected at launch from the secrets manager and never written here, to logs, to
evidence, to errors, or to exports (CLAUDE.md §3 scanner-secret rule, TR-23).

os_process_group records the spawned PID/PGID so emergency stop (§2.10) can
terminate the process tree, matching scans.runner_ref for the LLM path.

scan_status is reused (it already exists from the M2-D1 scan migration).
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.identity import GEN_UUID, UUID_PK
from app.models.scan import SCAN_STATUS_ENUM, ScanStatus


class ScannerRun(Base):
    """External-tool invocation within a scan (M3) — mirrors test_runs."""

    __tablename__ = "scanner_runs"
    __table_args__ = (Index("ix_scanner_runs_scan", "scan_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    scanner_name: Mapped[str] = mapped_column(Text)  # 'semgrep','zap','nuclei',…
    scanner_version: Mapped[str] = mapped_column(Text)
    # Digest-pinned scanner image (…@sha256:<digest>), never a floating tag.
    image_digest: Mapped[str | None] = mapped_column(Text)
    # SHA-256 of the vendored rule/template bundle (Semgrep rules, Nuclei templates).
    rules_digest: Mapped[str | None] = mapped_column(Text)
    # Typed, REDACTED config: args/policy/rule-bundle ref + license. No secrets.
    config: Mapped[dict[str, Any]] = mapped_column(JSONB)
    status: Mapped[ScanStatus] = mapped_column(
        SCAN_STATUS_ENUM, server_default=ScanStatus.QUEUED.value
    )
    # Recorded PID/PGID for emergency-stop teardown (§2.10).
    os_process_group: Mapped[int | None] = mapped_column(Integer)
    # The immutable raw tool output (raw evidence blob pointer).
    raw_evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_summary: Mapped[str | None] = mapped_column(Text)
