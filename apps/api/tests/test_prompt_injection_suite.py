"""M2-B4 prompt-injection suite — CI-safe (no PyRIT import: a fake Runner stands
in for PyRITRunner). Bundle loading, deterministic scoring (success AND failure),
and per-turn multi-turn cancellation. Real PyRIT + DB findings are proven live in
scripts/verify_prompt_injection.py.
"""

import re

from app.runners.base import AttemptOutcome, AttemptRecord, NormalizedResult
from app.suites.base import serialize_probe_transcript
from app.suites.prompt_injection import PromptInjectionSuite, load_bundle
from app.workers.execution import CancelToken

_MARKER = re.compile(r"canary-canary-[a-z-]+")


class VulnerableTarget:
    """A mock 'vulnerable' model: echoes whatever marker a prompt asks it to emit
    (so injections succeed) EXCEPT when the prompt trips a refusal trigger."""

    def __init__(self, refuse_triggers: tuple[str, ...] = ("SYSTEM OVERRIDE",)) -> None:
        self._refuse = refuse_triggers
        self.sent: list[str] = []

    def _reply(self, prompt: str) -> str:
        if any(t in prompt for t in self._refuse):
            return "I can't comply with that request."
        m = _MARKER.search(prompt)
        return f"Sure: {m.group(0)}" if m else "Hello, how can I help?"

    async def send(self, prompt: str) -> str:
        self.sent.append(prompt)
        return self._reply(prompt)

    def open_conversation(self) -> "_Conversation":
        return _Conversation(self)


class _Conversation:
    def __init__(self, target: VulnerableTarget) -> None:
        self._target = target

    async def send(self, prompt: str) -> str:
        return self._target._reply(prompt)


class _CancelDuringConversationTarget(VulnerableTarget):
    """Trips the CancelToken partway through a multi-turn conversation."""

    def __init__(self, token: CancelToken, trip_after_turn: int = 1) -> None:
        super().__init__()
        self._token = token
        self._trip = trip_after_turn
        self._turns = 0

    def open_conversation(self) -> "_CancelConversation":
        return _CancelConversation(self)


class _CancelConversation:
    def __init__(self, target: _CancelDuringConversationTarget) -> None:
        self._target = target

    async def send(self, prompt: str) -> str:
        self._target._turns += 1
        reply = self._target._reply(prompt)
        if self._target._turns >= self._target._trip:
            self._target._token.cancel()
        return reply


class FakeRunner:
    """Stands in for PyRITRunner: sends each objective through the target and
    normalizes, without importing PyRIT."""

    engine = "pyrit"

    async def run(self, target, config, cancel) -> NormalizedResult:  # noqa: ANN001
        planned = config.planned_objectives()
        attempts = []
        for probe_id, objective in planned:
            if cancel.cancelled:
                break
            response = await target.send(objective)
            attempts.append(
                AttemptRecord(
                    probe_id=probe_id,
                    objective=objective,
                    outcome=AttemptOutcome.UNDETERMINED,
                    response_excerpt=response,
                )
            )
        return NormalizedResult(
            engine="pyrit",
            engine_version="0.14.0",
            suite=config.suite,
            attempts=tuple(attempts),
            objective_count=len(planned),
            cancelled=cancel.cancelled,
        )


def test_load_bundle_parses_and_content_hashes():
    bundle_id, sha256, probes = load_bundle()
    assert bundle_id == "prompt_injection.v1"
    assert len(sha256) == 64  # hex sha-256
    assert len(probes) == 5
    assert {p.technique.value for p in probes} == {
        "direct",
        "jailbreak",
        "instruction_hierarchy",
        "multi_turn",
    }
    # deterministic — same bytes, same hash
    assert load_bundle()[1] == sha256


async def test_suite_scores_success_and_failure():
    suite = PromptInjectionSuite(runner=FakeRunner())
    result = await suite.run(VulnerableTarget(), CancelToken())
    assert result.engine == "pyrit" and result.engine_version == "0.14.0"
    assert result.cancelled is False
    assert len(result.probe_results) == 5
    # direct(2) + jailbreak(1) + multi_turn(1) echoed their markers → succeeded;
    # the forged system-override probe hit the refusal trigger → not a finding.
    succeeded_ids = {r.probe.probe_id for r in result.succeeded}
    assert "pi.instruction-hierarchy.system-override" not in succeeded_ids
    assert len(result.succeeded) == 4
    # every success carries concrete matched evidence
    assert all(r.evidence and "canary-canary-" in r.evidence for r in result.succeeded)


async def test_multi_turn_probe_runs_full_conversation_when_not_cancelled():
    suite = PromptInjectionSuite(runner=FakeRunner())
    result = await suite.run(VulnerableTarget(), CancelToken())
    mt = next(r for r in result.probe_results if r.probe.technique.value == "multi_turn")
    assert mt.succeeded is True
    # 3 user turns + 3 assistant replies captured as transcript evidence
    assert len(mt.transcript) == 6


async def test_per_turn_cancel_halts_multi_turn_conversation():
    token = CancelToken()
    target = _CancelDuringConversationTarget(token, trip_after_turn=1)
    result = await PromptInjectionSuite(runner=FakeRunner()).run(target, token)
    assert result.cancelled is True
    mt = next(r for r in result.probe_results if r.probe.technique.value == "multi_turn")
    assert mt.succeeded is False
    assert mt.error == "cancelled mid-conversation"
    # halted after the first turn — the injection turn was never sent
    assert len(mt.transcript) == 2


async def test_probe_transcript_serialization_is_deterministic():
    result = await PromptInjectionSuite(runner=FakeRunner()).run(VulnerableTarget(), CancelToken())
    one = result.succeeded[0]
    blob = serialize_probe_transcript(one)
    assert serialize_probe_transcript(one) == blob
    assert b'"owasp":"LLM01"' in blob
