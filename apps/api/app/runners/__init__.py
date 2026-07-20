"""AI/LLM red-team runners (M2-B3).

`base` holds the engine-agnostic `Runner` contract + `NormalizedResult` schema;
`pyrit_runner` is the MVP PyRIT engine (lazy-imported). garak/promptfoo are
deferred post-MVP and drop in behind the same contract.
"""

from app.runners.base import (
    AttemptOutcome,
    AttemptRecord,
    NormalizedResult,
    Runner,
    RunnerConfig,
    RunnerError,
    RunnerTarget,
    make_suite_run_fn,
    serialize_transcript,
)

__all__ = [
    "AttemptOutcome",
    "AttemptRecord",
    "NormalizedResult",
    "Runner",
    "RunnerConfig",
    "RunnerError",
    "RunnerTarget",
    "make_suite_run_fn",
    "serialize_transcript",
]
