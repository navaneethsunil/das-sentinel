"""AI/LLM test-suite contract + shared result schema (M2-B4).

A *suite* is a curated set of probes (M2-B4 prompt-injection, M2-B5 data-leakage)
run against one LLM target through the M2-B3 `Runner`/target seam. The suite's job
is to drive probes, score each with a DETERMINISTIC detector, and hand back a
`SuiteResult` the findings service (services/findings.py) turns into evidence-backed
findings. The LLM is never the judge (§2.6): a probe "succeeds" only when a
deterministic detector matches concrete response evidence — never because a model
said so.

Targets. `SuiteTarget.send` is the stateless single-shot seam (single-turn probes;
also what PyRITRunner drives). `open_conversation` yields a stateful `Conversation`
for multi-turn probes so the suite can check the CancelToken *between every turn*
(§2.10 for multi-turn). The scope-validated connector (M2-B6) implements both; a
mock implements both for tests/verify.
"""

import enum
import json
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from app.models.finding import Severity


class TechniqueFamily(enum.Enum):
    """Prompt-injection technique families (M2-B4). Multi-turn is scripted here;
    PyRIT's adaptive Crescendo (needs an adversarial LLM target) is a follow-up."""

    DIRECT = "direct"
    JAILBREAK = "jailbreak"
    INSTRUCTION_HIERARCHY = "instruction_hierarchy"
    MULTI_TURN = "multi_turn"


@dataclass(frozen=True)
class DetectorSpec:
    """How a probe decides success — a deterministic rule, never an LLM. `kind`
    selects the detector (canary/regex/refusal_absence); `params` configures it."""

    kind: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Probe:
    """One attack probe. `turns` has one entry for single-turn, more for a scripted
    multi-turn conversation. `owasp` maps the finding (LLM01 for prompt injection)."""

    probe_id: str
    technique: TechniqueFamily
    title: str
    turns: tuple[str, ...]
    detector: DetectorSpec
    severity: Severity
    owasp: str
    description: str
    recommendation: str

    @property
    def is_multi_turn(self) -> bool:
        return len(self.turns) > 1


@dataclass(frozen=True)
class DetectionVerdict:
    """Deterministic detector output. `succeeded` = the attack achieved its
    objective (a candidate weakness). `evidence` is the concrete matched text."""

    succeeded: bool
    evidence: str | None = None


@runtime_checkable
class Detector(Protocol):
    def detect(self, response: str) -> DetectionVerdict: ...


@dataclass(frozen=True)
class Turn:
    role: str  # "user" | "assistant"
    content: str


@dataclass(frozen=True)
class ProbeResult:
    """One probe's outcome: its verdict + the full conversation transcript (the
    evidence a finding cites). `error` is set if the probe could not run."""

    probe: Probe
    succeeded: bool
    transcript: tuple[Turn, ...]
    evidence: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe.probe_id,
            "technique": self.probe.technique.value,
            "title": self.probe.title,
            "owasp": self.probe.owasp,
            "severity": self.probe.severity.value,
            "succeeded": self.succeeded,
            "evidence": self.evidence,
            "error": self.error,
            "transcript": [{"role": t.role, "content": t.content} for t in self.transcript],
        }


@dataclass(frozen=True)
class SuiteResult:
    """The whole suite run. `cancelled` marks a run halted mid-suite by the
    CancelToken so a partial result is never mistaken for complete."""

    suite: str
    engine: str
    engine_version: str
    bundle_id: str
    bundle_sha256: str
    probe_results: tuple[ProbeResult, ...]
    cancelled: bool = False

    @property
    def succeeded(self) -> tuple[ProbeResult, ...]:
        """Probes whose attack succeeded — the ones that become findings."""
        return tuple(r for r in self.probe_results if r.succeeded)

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "bundle_id": self.bundle_id,
            "bundle_sha256": self.bundle_sha256,
            "cancelled": self.cancelled,
            "probe_results": [r.to_dict() for r in self.probe_results],
        }


@runtime_checkable
class Conversation(Protocol):
    """A stateful multi-turn conversation with the target (one probe = one
    conversation). The suite sends turns one at a time so it can check the
    CancelToken between them."""

    async def send(self, prompt: str) -> str: ...


@runtime_checkable
class SuiteTarget(Protocol):
    """The LLM target the suites drive. `send` is the single-shot seam (also used
    by PyRITRunner via the RunnerTarget protocol); `open_conversation` scopes a
    multi-turn conversation. The M2-B6 connector implements both."""

    async def send(self, prompt: str) -> str: ...

    def open_conversation(self) -> Conversation: ...


def serialize_probe_transcript(result: ProbeResult) -> bytes:
    """Canonical JSON bytes of ONE probe's transcript + verdict — the evidence blob
    for its finding. Deterministic (sorted keys) so identical transcripts
    content-address to one evidence object."""
    return json.dumps(
        result.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def serialize_suite_transcript(result: SuiteResult) -> bytes:
    """Canonical JSON bytes of the whole suite run (all probes) — the run-level
    transcript evidence."""
    return json.dumps(
        result.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
