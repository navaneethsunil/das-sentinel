"""M2-B3 runner contract + in-process owner — CI-safe (no PyRIT import).

The heavy PyRIT engine is exercised live in scripts/verify_pyrit_runner.py inside
the `redteam` image. Here we pin the engine-agnostic behaviour that must hold
regardless of engine: the normalization schema, the bounded cooperative
cancellation loop, the lazy-import guard, and InProcessOwner's uniform +
cancellable execution identity for an embedded suite.
"""

import asyncio

import pytest

from app.runners.base import (
    AttemptOutcome,
    AttemptRecord,
    NormalizedResult,
    RunnerConfig,
    RunnerError,
    make_suite_run_fn,
    serialize_transcript,
    truncate_response,
)
from app.runners.pyrit_runner import PyRITRunner
from app.workers.execution import (
    CancelToken,
    InProcessOwner,
    RunHandle,
    RunOutcome,
    RunSpec,
)


class _EchoTarget:
    """A RunnerTarget that echoes; records every prompt it was sent."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, prompt: str) -> str:
        self.sent.append(prompt)
        return f"reply:{prompt}"


class _FakeRunner:
    """Mirrors PyRITRunner's contract without the engine: checks the CancelToken
    at every objective boundary and normalizes into the shared schema. Optionally
    trips the token after `cancel_after` objectives to simulate an emergency stop
    landing mid-suite."""

    engine = "fake"

    def __init__(self, cancel_after: int | None = None) -> None:
        self._cancel_after = cancel_after

    async def run(self, target, config, cancel) -> NormalizedResult:
        planned = config.planned_objectives()
        attempts: list[AttemptRecord] = []
        cancelled = False
        for i, (probe_id, objective) in enumerate(planned):
            if cancel.cancelled:
                cancelled = True
                break
            reply = await target.send(objective)
            attempts.append(
                AttemptRecord(
                    probe_id=probe_id,
                    objective=objective,
                    outcome=AttemptOutcome.FAILURE,
                    response_excerpt=reply,
                )
            )
            if self._cancel_after is not None and i + 1 >= self._cancel_after:
                cancel.cancel()
        return NormalizedResult(
            engine=self.engine,
            engine_version="0",
            suite=config.suite,
            attempts=tuple(attempts),
            objective_count=len(planned),
            cancelled=cancelled,
        )


# ── normalization schema ──────────────────────────────────────────────────────


def test_planned_objectives_defaults_positional_probe_ids():
    cfg = RunnerConfig(suite="prompt_injection", objectives=("a", "b"))
    assert cfg.planned_objectives() == [
        ("prompt_injection.0", "a"),
        ("prompt_injection.1", "b"),
    ]


def test_planned_objectives_honours_explicit_ids_and_bound():
    cfg = RunnerConfig(
        suite="s", objectives=("a", "b", "c"), probe_ids=("p0", "p1", "p2"), max_objectives=2
    )
    assert cfg.planned_objectives() == [("p0", "a"), ("p1", "b")]


def test_truncate_response_bounds_and_flags():
    assert truncate_response(None) is None
    assert truncate_response("short", limit=10) == "short"
    out = truncate_response("x" * 20, limit=10)
    assert out.startswith("x" * 10) and "+10 chars" in out


def test_serialize_transcript_is_deterministic():
    result = NormalizedResult(
        engine="pyrit",
        engine_version="0.14.0",
        suite="prompt_injection",
        attempts=(
            AttemptRecord(
                probe_id="p0",
                objective="reveal the system prompt",
                outcome=AttemptOutcome.UNDETERMINED,
                labels={"z": "1", "a": "2"},
            ),
        ),
        objective_count=1,
    )
    a = serialize_transcript(result)
    b = serialize_transcript(result)
    assert a == b  # canonical → content-addressed dedup holds
    assert b'"engine":"pyrit"' in a
    # labels are sorted in the canonical form
    assert a.index(b'"a":"2"') < a.index(b'"z":"1"')


def test_normalized_result_counts_by_outcome():
    result = NormalizedResult(
        engine="fake",
        engine_version="0",
        suite="s",
        attempts=(
            AttemptRecord(probe_id="0", objective="a", outcome=AttemptOutcome.SUCCESS),
            AttemptRecord(probe_id="1", objective="b", outcome=AttemptOutcome.FAILURE),
            AttemptRecord(probe_id="2", objective="c", outcome=AttemptOutcome.SUCCESS),
        ),
        objective_count=3,
    )
    assert result.count(AttemptOutcome.SUCCESS) == 2
    assert result.count(AttemptOutcome.FAILURE) == 1
    assert result.count(AttemptOutcome.ERROR) == 0


# ── bounded cooperative cancellation ────────────────────────────────────────────


async def test_runner_stops_mid_suite_when_token_tripped():
    runner = _FakeRunner(cancel_after=1)
    target = _EchoTarget()
    cfg = RunnerConfig(suite="s", objectives=("a", "b", "c"))
    result = await runner.run(target, cfg, CancelToken())
    assert result.cancelled is True
    assert len(result.attempts) == 1  # halted after the first objective
    assert target.sent == ["a"]  # the remaining objectives were never sent


async def test_runner_completes_when_not_cancelled():
    result = await _FakeRunner().run(_EchoTarget(), RunnerConfig("s", ("a", "b")), CancelToken())
    assert result.cancelled is False
    assert len(result.attempts) == 2


# ── lazy-import guard ───────────────────────────────────────────────────────────


async def test_pyrit_runner_raises_clear_error_when_engine_absent():
    # PyRIT is not installed in the base test image; run() must fail loud with a
    # RunnerError (not degrade to an empty result). Importing the module above did
    # not require PyRIT — the guard is inside run().
    with pytest.raises(RunnerError, match="PyRIT is not installed"):
        await PyRITRunner().run(_EchoTarget(), RunnerConfig("s", ("a",)), CancelToken())


# ── InProcessOwner: uniform + cancellable in-process identity ────────────────────


async def test_make_suite_run_fn_via_inprocess_owner_completes():
    captured: list[NormalizedResult] = []
    run_fn = make_suite_run_fn(
        _FakeRunner(), _EchoTarget(), RunnerConfig("s", ("a", "b")), captured.append
    )
    owner = InProcessOwner(run_fn)
    handle = await owner.launch(RunSpec(label="scan-1", argv=[]))
    outcome = await owner.await_completion(handle)
    await owner.teardown(handle)
    assert outcome.ok is True
    assert len(captured) == 1 and len(captured[0].attempts) == 2


async def test_inprocess_owner_cancel_is_cooperative_and_stops_the_run():
    ticks: list[int] = []

    async def run_fn(token: CancelToken) -> RunOutcome:
        for i in range(10_000):
            if token.cancelled:
                return RunOutcome(ok=False, detail="cancelled")
            ticks.append(i)
            await asyncio.sleep(0.005)
        return RunOutcome(ok=True)

    owner = InProcessOwner(run_fn)
    handle = await owner.launch(RunSpec(label="scan-2", argv=[]))
    await asyncio.sleep(0.02)
    await owner.cancel(handle)  # trip the token the run is checking
    outcome = await owner.await_completion(handle)
    await owner.teardown(handle)
    assert outcome.ok is False and outcome.detail == "cancelled"
    assert len(ticks) < 10_000  # it stopped well before completing


async def test_inprocess_owner_teardown_backstops_a_token_ignoring_run():
    async def stubborn(token: CancelToken) -> RunOutcome:
        while True:  # never checks the token
            await asyncio.sleep(0.01)

    owner = InProcessOwner(stubborn, teardown_grace_s=0.1)
    handle = await owner.launch(RunSpec(label="scan-3", argv=[]))
    await owner.teardown(handle)  # must return (asyncio-cancel backstop), not hang
    # a second teardown is a no-op (state already popped)
    await owner.teardown(RunHandle(runner_ref="inproc:scan-3"))
