"""Scan, execution-authorization, and test-run models (M2-D1) — DATABASE_SCHEMA §6.

A scan is one user-initiated unit of work against one target at one intensity.
It fans out into scanner_runs (external tools, M3) and/or test_runs (LLM/agent
suites, M2), all producing evidence.

execution_authorizations is the immutable envelope: the frozen record of WHAT
was authorized for one scan, written once after the scope gate passes and never
mutated (a DB trigger enforces insert-only, matching audit_events/
roe_acknowledgements). The worker carries only scan_id, re-reads this envelope,
re-derives every field from the live DB, and refuses to launch on any mismatch.

Same-engagement composite FKs (target/approval) are defence-in-depth behind the
org/engagement-qualified query rule: a valid-but-cross-engagement target or
approval can never be spliced into another engagement's scan.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, TSTZRANGE, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.engagement import SCAN_INTENSITY_ENUM, ScanIntensity
from app.models.identity import GEN_UUID, NOW, UUID_PK


class ScanStatus(enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TestSuite(enum.Enum):
    # Not a pytest test class despite the `Test` prefix (silences a collection
    # warning when imported into a test module); a dunder is not an enum member.
    __test__ = False

    PROMPT_INJECTION = "prompt_injection"
    DATA_LEAKAGE = "data_leakage"
    AGENT_PERMISSION = "agent_permission"


SCAN_STATUS_ENUM = Enum(
    ScanStatus, name="scan_status", values_callable=lambda e: [m.value for m in e]
)
TEST_SUITE_ENUM = Enum(TestSuite, name="test_suite", values_callable=lambda e: [m.value for m in e])


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        # Force target AND approval to belong to THIS scan's engagement. The
        # approval pair is enforced only when approval_gate_id is set (a NULL in
        # the composite makes the FK pass — Postgres MATCH SIMPLE).
        ForeignKeyConstraint(
            ["target_id", "engagement_id"],
            ["targets.id", "targets.engagement_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["approval_gate_id", "engagement_id"],
            ["approval_gates.id", "approval_gates.engagement_id"],
        ),
        Index("ix_scans_engagement", "engagement_id"),
        Index(
            "ix_scans_status",
            "status",
            postgresql_where=text("status IN ('queued','running')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engagements.id", ondelete="RESTRICT")
    )
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    intensity: Mapped[ScanIntensity] = mapped_column(SCAN_INTENSITY_ENUM)
    status: Mapped[ScanStatus] = mapped_column(
        SCAN_STATUS_ENUM, server_default=ScanStatus.QUEUED.value
    )
    # Required when intensity='high_risk'; the composite FK binds it same-engagement.
    approval_gate_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    initiated_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Emergency-stop flag (§2.10); the worker checks it between steps.
    cancel_requested: Mapped[bool] = mapped_column(Boolean, server_default="false")
    # Child process/container id of the spawned run (M2-W1) — the exact target
    # emergency stop terminates (M2-W2). NULL until the run is launched.
    runner_ref: Mapped[str | None] = mapped_column(Text)
    # Liveness beat updated between steps; a watchdog reads it to distinguish a
    # live run from a wedged one.
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_summary: Mapped[str | None] = mapped_column(Text)


class ExecutionAuthorization(Base):
    """Immutable authorization envelope, one per scan. Insert-only (DB trigger)."""

    __tablename__ = "execution_authorizations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["target_id", "engagement_id"],
            ["targets.id", "targets.engagement_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["approval_gate_id", "engagement_id"],
            ["approval_gates.id", "approval_gates.engagement_id"],
        ),
        Index("ix_exec_auth_engagement", "engagement_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="RESTRICT"), unique=True
    )
    engagement_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    # SERVER-derived from the typed config classification, never caller-declared.
    effective_intensity: Mapped[ScanIntensity] = mapped_column(SCAN_INTENSITY_ENUM)
    # Typed, canonicalized, REDACTED operation config — no runtime secrets.
    normalized_config: Mapped[dict[str, Any]] = mapped_column(JSONB)
    server_capabilities: Mapped[dict[str, Any]] = mapped_column(JSONB)
    roe_ack_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roe_acknowledgements.id"))
    policy_version: Mapped[str] = mapped_column(Text)
    approval_gate_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    # SHA-256 over the canonical subject; == approval_gates.operation_digest when high-risk.
    operation_digest: Mapped[bytes] = mapped_column(LargeBinary)
    # Authorized window from the ROE (NULL ⇒ any time while the engagement is active).
    test_window: Mapped[Any | None] = mapped_column(TSTZRANGE)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)


class TestRun(Base):
    """LLM/agent test suite within a scan (M2/M5) — mirrors scanner_runs."""

    # Not a pytest test class despite the `Test` prefix (silences a collection
    # warning when this model is imported into a test module).
    __test__ = False

    __tablename__ = "test_runs"
    __table_args__ = (Index("ix_test_runs_scan", "scan_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    suite: Mapped[TestSuite] = mapped_column(TEST_SUITE_ENUM)
    engine: Mapped[str | None] = mapped_column(Text)  # 'pyrit','garak','promptfoo','bespoke'
    engine_version: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB)  # corpus refs, endpoint, params
    status: Mapped[ScanStatus] = mapped_column(
        SCAN_STATUS_ENUM, server_default=ScanStatus.QUEUED.value
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_summary: Mapped[str | None] = mapped_column(Text)
