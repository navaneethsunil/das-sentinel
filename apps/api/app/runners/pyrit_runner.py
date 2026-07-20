"""PyRIT red-team engine runner (M2-B3) — the MVP `Runner` implementation.

PyRIT (Microsoft Python Risk Identification Tool, MIT, github.com/microsoft/PyRIT)
is pinned to an exact version + hash in `requirements-redteam.txt` and installed
only into the `redteam` worker image stage. It is a native Python library that
embeds in the worker with no subprocess, so it is imported LAZILY here — importing
this module never pulls PyRIT (or its 107-package ML stack) into the base image,
API startup, or the CI test run. If the engine is not installed, `run` raises
`RunnerError` loudly rather than degrading to an empty result (§5, TM-14).

Cancellation (§2.10, M2-W2): the CancelToken is checked before every objective —
the turn boundary for the single-turn `PromptSendingAttack`. A stop requested
mid-suite halts the run within one objective's round-trip (the bounded
cooperative budget). Multi-turn suites (Crescendo etc., M2-B4) must additionally
check the token between conversation turns; the same token is the seam.

Isolation: each run initializes PyRIT with an IN-MEMORY store (no persistence, no
egress from the engine itself) and drives the target only through the injected
`RunnerTarget.send` seam — the engine never opens its own network connection.

Version note: PyRIT 0.14.0's `PromptChatTarget` is the working base for a custom
target; it is deprecated for removal in 0.16.0 in favor of `PromptTarget` +
`TargetConfiguration(TargetCapabilities(...))`. We pin 0.14.0 exactly, so this is
correct for the pinned version; the 0.16 migration is a tracked bump (re-verify
before adopting, per CLAUDE.md §3 currency rule).
"""

from typing import Any

from app.runners.base import (
    AttemptOutcome,
    AttemptRecord,
    NormalizedResult,
    Runner,
    RunnerConfig,
    RunnerError,
    RunnerTarget,
    truncate_response,
)
from app.workers.execution import CancelToken

_OUTCOME_MAP = {
    "SUCCESS": AttemptOutcome.SUCCESS,
    "FAILURE": AttemptOutcome.FAILURE,
    "ERROR": AttemptOutcome.ERROR,
    "UNDETERMINED": AttemptOutcome.UNDETERMINED,
}


def _extract_response_text(last_response: Any) -> str | None:
    """Pull the model's text out of a PyRIT result's `last_response`, which may be
    a MessagePiece (`converted_value`) or a Message (`message_pieces[-1]`)."""
    if last_response is None:
        return None
    if hasattr(last_response, "converted_value"):
        return last_response.converted_value
    pieces = getattr(last_response, "message_pieces", None)
    if pieces:
        return pieces[-1].converted_value
    return str(last_response)


class PyRITRunner(Runner):
    engine = "pyrit"

    async def run(
        self, target: RunnerTarget, config: RunnerConfig, cancel: CancelToken
    ) -> NormalizedResult:
        try:
            import pyrit
            from pyrit.executor.attack import PromptSendingAttack
            from pyrit.models import AttackOutcome, construct_response_from_request
            from pyrit.prompt_target import PromptChatTarget
            from pyrit.setup import initialize_pyrit_async
        except ImportError as exc:  # engine not installed in this image
            raise RunnerError(
                "PyRIT is not installed — run the suite in the `redteam` worker "
                "image (requirements-redteam.txt), not the base image"
            ) from exc

        # In-memory store: no persistence, no engine-side egress (isolation).
        await initialize_pyrit_async("InMemory", silent=True)

        class _SinkTarget(PromptChatTarget):
            """A PyRIT target that forwards each prompt to the injected, scope-
            validated `RunnerTarget` — the engine never reaches the network."""

            def __init__(self, sink: RunnerTarget) -> None:
                super().__init__()
                self._sink = sink

            async def _send_prompt_to_target_async(
                self, *, normalized_conversation: list[Any]
            ) -> list[Any]:
                piece = normalized_conversation[-1].message_pieces[-1]
                reply = await self._sink.send(piece.converted_value)
                return [
                    construct_response_from_request(request=piece, response_text_pieces=[reply])
                ]

            def is_json_response_supported(self) -> bool:
                return False

        attack = PromptSendingAttack(objective_target=_SinkTarget(target))

        planned = config.planned_objectives()
        attempts: list[AttemptRecord] = []
        cancelled = False
        for probe_id, objective in planned:
            # Cooperative cancel checked at every turn boundary (§2.10).
            if cancel.cancelled:
                cancelled = True
                break
            attempts.append(await self._run_one(attack, AttackOutcome, probe_id, objective))

        return NormalizedResult(
            engine=self.engine,
            engine_version=pyrit.__version__,
            suite=config.suite,
            attempts=tuple(attempts),
            objective_count=len(planned),
            cancelled=cancelled,
            metadata={"memory": "in_memory"},
        )

    async def _run_one(
        self, attack: Any, attack_outcome: Any, probe_id: str, objective: str
    ) -> AttemptRecord:
        """Execute one objective. An engine error on a single attempt is captured
        as an ERROR attempt and does not abort the suite — the run keeps going and
        surfaces the failure per-attempt (fail-loud, not fail-whole)."""
        try:
            result = await attack.execute_async(objective=objective)
        except Exception as exc:  # noqa: BLE001 — engine faults are captured, not swallowed
            return AttemptRecord(
                probe_id=probe_id,
                objective=objective,
                outcome=AttemptOutcome.ERROR,
                error=f"{type(exc).__name__}: {exc}",
            )
        raw_outcome = result.outcome
        name = raw_outcome.name if isinstance(raw_outcome, attack_outcome) else str(raw_outcome)
        return AttemptRecord(
            probe_id=probe_id,
            objective=objective,
            outcome=_OUTCOME_MAP.get(name, AttemptOutcome.UNDETERMINED),
            outcome_reason=result.outcome_reason,
            response_excerpt=truncate_response(_extract_response_text(result.last_response)),
            turns=result.executed_turns or 1,
            duration_ms=result.execution_time_ms,
            error=result.error_message,
            conversation_ref=result.conversation_id,
        )
