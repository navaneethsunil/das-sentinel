"""AI/LLM red-team runner contract + engine-neutral result schema (M2-B3).

A `Runner` drives an attack suite against one LLM target and returns a
`NormalizedResult` — the engine-agnostic evidence shape every red-team engine
maps into. PyRIT is the only engine implemented for the MVP (`pyrit_runner.py`);
the schema is deliberately engine-neutral so garak (subprocess + JSONL report)
and promptfoo (Node CLI) can drop in post-MVP without changing this contract or
the `findings` normalization the suites (M2-B4/B5) build on top of it.

Cancellation identity (CLAUDE.md §6a / §2.10): PyRIT is a native Python library
embedded in the worker with no subprocess, so `killpg` cannot select it. Every
runner therefore honours a **bounded cooperative `CancelToken`** — the SAME
token type M2-W2's `signal_cancellation` trips — checked between every
prompt/turn. `make_suite_run_fn` + `InProcessOwner` (workers/execution.py) give
that in-process suite a uniform, cancellable execution identity so it still runs
"through the execution owner" like a subprocess scanner does.

The runner is NOT the adjudicator. It captures what happened (objective sent,
model response, engine outcome, conversation pointer); turning that into
pass/fail findings with OWASP-LLM mappings is the suites' job (M2-B4/B5) and the
target connector's job (M2-B6). The LLM is never the source of truth (§2.6): a
result carries concrete transcript evidence, not a model's say-so.
"""

import enum
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from app.workers.execution import CancelToken, RunOutcome

# Bound on how much of a model response is retained inline on each attempt (the
# queryable/UI-facing excerpt). The full conversation stays addressable in the
# engine's memory via `conversation_ref`; suites (B4/B5) capture the complete
# transcript as evidence. Keeps a normalized result bounded regardless of engine.
RESPONSE_EXCERPT_LIMIT = 4000


class RunnerError(Exception):
    """A runner could not execute (engine missing/failed to initialize). Surfaced
    loud as a job failure — never swallowed into a fake-empty result (§5, TM-14)."""


class AttemptOutcome(enum.Enum):
    """Engine-neutral outcome of one attack attempt. Mirrors PyRIT's
    AttackOutcome and maps cleanly from garak detector verdicts / promptfoo
    assertions. SUCCESS means the *attack* achieved its objective — i.e. a
    candidate weakness — not that the run succeeded."""

    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    UNDETERMINED = "undetermined"


@runtime_checkable
class RunnerTarget(Protocol):
    """The LLM target seam. The scope-validated connector (M2-B6) implements this;
    the runner sends attacker-influenced prompts through it and never reaches the
    network itself. `send` returns the model's text response for one prompt."""

    async def send(self, prompt: str) -> str: ...


@dataclass(frozen=True)
class RunnerConfig:
    """What to run. `objectives` are the attack prompts/goals (real corpora are
    supplied by the suites, M2-B4/B5; B3 accepts any list). `probe_ids` are stable
    per-objective identifiers for dedup/finding identity; when absent they default
    to positional ids. `max_objectives` bounds the run (and the cancellation
    budget). `params` carries engine-specific knobs without widening this type."""

    suite: str
    objectives: tuple[str, ...]
    probe_ids: tuple[str, ...] | None = None
    max_objectives: int | None = None
    params: dict[str, Any] = field(default_factory=dict)

    def planned_objectives(self) -> list[tuple[str, str]]:
        """(probe_id, objective) pairs actually scheduled, after the bound."""
        objectives = list(self.objectives)
        if self.max_objectives is not None:
            objectives = objectives[: self.max_objectives]
        ids = list(self.probe_ids) if self.probe_ids is not None else []
        pairs: list[tuple[str, str]] = []
        for i, obj in enumerate(objectives):
            probe_id = ids[i] if i < len(ids) else f"{self.suite}.{i}"
            pairs.append((probe_id, obj))
        return pairs


@dataclass(frozen=True)
class AttemptRecord:
    """One attack attempt, normalized. `conversation_ref` points at the full
    transcript in the engine's memory so a suite can attach it as evidence."""

    probe_id: str
    objective: str
    outcome: AttemptOutcome
    outcome_reason: str | None = None
    response_excerpt: str | None = None
    turns: int = 1
    duration_ms: int | None = None
    error: str | None = None
    labels: dict[str, str] = field(default_factory=dict)
    conversation_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "objective": self.objective,
            "outcome": self.outcome.value,
            "outcome_reason": self.outcome_reason,
            "response_excerpt": self.response_excerpt,
            "turns": self.turns,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "labels": dict(sorted(self.labels.items())),
            "conversation_ref": self.conversation_ref,
        }


@dataclass(frozen=True)
class NormalizedResult:
    """Engine-agnostic outcome of a whole suite run. `objective_count` is what was
    scheduled; `cancelled` marks a run halted mid-suite by the CancelToken, so a
    partial result is never mistaken for a complete one."""

    engine: str
    engine_version: str
    suite: str
    attempts: tuple[AttemptRecord, ...]
    objective_count: int
    cancelled: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def count(self, outcome: AttemptOutcome) -> int:
        return sum(1 for a in self.attempts if a.outcome is outcome)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "engine_version": self.engine_version,
            "suite": self.suite,
            "objective_count": self.objective_count,
            "cancelled": self.cancelled,
            "attempts": [a.to_dict() for a in self.attempts],
            "metadata": dict(sorted(self.metadata.items())),
        }


@runtime_checkable
class Runner(Protocol):
    """One red-team engine. `run` drives `config` against `target`, checking
    `cancel` between every prompt/turn, and returns the normalized result."""

    engine: str

    async def run(
        self, target: RunnerTarget, config: RunnerConfig, cancel: CancelToken
    ) -> NormalizedResult: ...


def truncate_response(text: str | None, limit: int = RESPONSE_EXCERPT_LIMIT) -> str | None:
    if text is None:
        return None
    if len(text) <= limit:
        return text
    return text[:limit] + f"…[+{len(text) - limit} chars]"


def serialize_transcript(result: NormalizedResult) -> bytes:
    """Canonical JSON bytes of a normalized result — deterministic (sorted keys)
    so identical transcripts content-address to one evidence blob. Suitable for
    `store_evidence(kind=LLM_TRANSCRIPT, content_type='application/json')`."""
    return json.dumps(
        result.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def make_suite_run_fn(
    runner: Runner,
    target: RunnerTarget,
    config: RunnerConfig,
    on_result: Callable[[NormalizedResult], None],
) -> Callable[[CancelToken], Awaitable[RunOutcome]]:
    """Adapt a Runner into the in-process thunk `InProcessOwner` launches: run the
    suite under the owner's CancelToken, hand the NormalizedResult to `on_result`
    (so the caller can persist evidence/findings), and report a RunOutcome so the
    run finalizes uniformly. A run that completes is ok=True regardless of how many
    attacks *succeeded* — a successful attack is a finding, not a run failure. The
    owner receives the same token the suite checks, so emergency stop (M2-W2)
    halts it within one objective's budget."""

    async def _run(cancel: CancelToken) -> RunOutcome:
        result = await runner.run(target, config, cancel)
        on_result(result)
        if result.cancelled:
            return RunOutcome(ok=False, detail="cancelled")
        return RunOutcome(ok=True, detail=f"{len(result.attempts)} attempt(s)")

    return _run
