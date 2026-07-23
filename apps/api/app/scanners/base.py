"""Scanner adapter contract + engine-neutral result schema (M3-W1, CLAUDE.md §6).

A `ScannerAdapter` wraps one external tool (Semgrep in M3-W2, ZAP in M3-W3) behind
a uniform interface so tools can be added or removed without touching
orchestration. The framework — not the adapter — owns execution: the adapter
declares HOW to invoke the tool (`build_command`) and how to read its output
(`normalize`), and the uniform execution owner (M2-W3 `SubprocessOwner`) actually
spawns the killable, confined child. This keeps every adapter free of subprocess,
sandbox, and cancellation concerns and keeps the safety-critical launch in one
place.

Contract (mirrors the §6 sketch; run() is provided by the framework, not the
adapter):

    name: str
    version() -> str                         # captured on every run for repro
    validate_prerequisites() -> None         # tool installed / reachable
    build_command(target, config) -> ScannerInvocation   # never runs; pure
    normalize(raw: RawScannerResult) -> list[NormalizedFinding]

Adapter rules (CLAUDE.md §6):
  - Scope is validated BEFORE the framework runs the tool (the orchestrator
    re-derives authorization via the scope keystone before launch); the adapter
    trusts nothing and never reaches the network itself.
  - `build_command` builds an argv vector, never a shell string — no target value
    is ever concatenated into a command line (TM-6).
  - Raw tool output and normalized findings are stored separately (raw → the
    immutable evidence store; normalized → findings); the adapter never mutates
    raw.
  - Control secrets (e.g. a ZAP API key) are injected into `env` at launch and
    never persisted into `config` (that is what lands in scanner_runs.config).

The schema is engine-neutral so SARIF import/export (M3-B2) and the Semgrep/ZAP
adapters map into the same `findings` normalization the reporting slice builds on.
"""

import enum
import json
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from app.models.finding import Severity


class ScannerError(Exception):
    """A scanner adapter could not run or normalize. Surfaced loud as a job
    failure — never swallowed into a fake-empty result (§5, TM-14)."""


class ScannerPrerequisiteError(ScannerError):
    """`validate_prerequisites` found the tool missing/unreachable."""


class OutputMode(enum.Enum):
    """Where the tool writes its machine-readable report."""

    STDOUT = "stdout"  # tool prints the report to stdout (e.g. Semgrep --json)
    FILE = "file"  # tool writes a report file in the run workdir (e.g. ZAP)


@runtime_checkable
class ScannerTarget(Protocol):
    """The minimal view of a target an adapter needs. The real `Target` model
    satisfies it; tests pass a lightweight stand-in."""

    primary_value: str  # URL for DAST, filesystem path / archive for SAST


@dataclass(frozen=True)
class ScannerConfig:
    """Typed, non-secret run configuration. `rate_limit_rps` is the engagement's
    aggregate ceiling, passed so an adapter can set the tool's NATIVE throttle as
    a floor under it (M3-W3); `params` carries tool-specific knobs without
    widening this type. Everything here is safe to persist to scanner_runs.config
    — secrets travel only in the launch env, never here."""

    rate_limit_rps: int
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScannerInvocation:
    """What the framework should launch and how to read the result. `argv` is a
    controlled vector (never a shell string). `env` is the COMPLETE child
    environment (scoped, short-lived; secrets injected here only). `image_digest`
    / `rules_digest` pin the tool image and rule/template bundle for repro
    (CLAUDE.md §6). `persisted_config` is the redacted record for
    scanner_runs.config."""

    argv: list[str]
    env: dict[str, str] = field(default_factory=dict)
    output_mode: OutputMode = OutputMode.STDOUT
    output_filename: str | None = None  # relative to the run workdir when FILE
    raw_content_type: str = "application/json"
    image_digest: str | None = None
    rules_digest: str | None = None
    timeout_s: float = 300.0
    persisted_config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RawScannerResult:
    """The tool's raw output plus how the run ended. `output` is the raw report
    bytes (stdout for STDOUT mode, the report file for FILE mode) — this is what
    is stored, verbatim and immutable, as raw evidence. `stderr` aids failure
    diagnosis and is never treated as findings."""

    exit_code: int | None
    output: bytes
    stderr: bytes
    duration_ms: int | None = None
    cancelled: bool = False
    timed_out: bool = False


@dataclass(frozen=True)
class NormalizedFinding:
    """One finding, mapped from a tool's native shape into the shared vocabulary.
    `fingerprint` is a stable, per-finding identity within this scanner's output
    (rule + location); the framework folds it into the finding `hash_code` so the
    same issue dedups across re-runs (M3-B2)."""

    fingerprint: str
    title: str
    message: str
    severity: Severity
    rule_id: str | None = None
    location: dict[str, Any] = field(default_factory=dict)
    description: str | None = None
    recommendation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "location": self.location,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class ScannerResult:
    """Engine-agnostic outcome of one scanner invocation. `config` is the redacted
    record persisted to scanner_runs.config. `cancelled` marks a run halted
    mid-scan so a partial result is never mistaken for a complete one."""

    scanner_name: str
    scanner_version: str
    findings: tuple[NormalizedFinding, ...]
    config: dict[str, Any]
    raw_content_type: str = "application/json"
    image_digest: str | None = None
    rules_digest: str | None = None
    os_process_group: int | None = None
    cancelled: bool = False
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "image_digest": self.image_digest,
            "rules_digest": self.rules_digest,
            "cancelled": self.cancelled,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": dict(sorted(self.metadata.items())),
        }


@runtime_checkable
class ScannerAdapter(Protocol):
    """One external scanner. `build_command` and `normalize` are pure; execution
    is the framework's job (workers/scanner_run.py)."""

    name: str

    def version(self) -> str: ...

    def validate_prerequisites(self) -> None: ...

    def build_command(self, target: ScannerTarget, config: ScannerConfig) -> ScannerInvocation: ...

    def normalize(self, raw: RawScannerResult) -> list[NormalizedFinding]: ...


def serialize_scanner_result(result: ScannerResult) -> bytes:
    """Canonical JSON bytes of a normalized result — deterministic (sorted keys)
    so identical results content-address to one evidence blob."""
    return json.dumps(
        result.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
