"""Shared probe-suite run engine (M2-B4/B5).

One run engine drives every AI/LLM suite so the prompt-injection (B4) and
data-leakage (B5) suites cannot diverge: single-turn probes run through the M2-B3
`Runner` (i.e. genuinely "on PyRIT") in one batch, then each is scored post-hoc by
its DETERMINISTIC detector; scripted multi-turn probes run through a stateful
conversation so the CancelToken is checked BEFORE every turn (§2.10 for a
subprocess-less multi-turn suite). A conversation cut short mid-way is never scored
a success (fail-closed). Because the detector is deterministic pattern-matching, a
probe "succeeds" only on concrete response evidence — the LLM is never the judge
(§2.6, TM-4).
"""

from app.runners.base import Runner, RunnerConfig
from app.suites.base import (
    Probe,
    ProbeResult,
    SuiteResult,
    SuiteTarget,
    Turn,
)
from app.suites.detectors import build_detector
from app.workers.execution import CancelToken

CANCELLED_MID_CONVERSATION = "cancelled mid-conversation"


async def run_probe_suite(
    runner: Runner,
    target: SuiteTarget,
    cancel: CancelToken,
    *,
    suite_name: str,
    bundle_id: str,
    bundle_sha256: str,
    probes: tuple[Probe, ...],
) -> SuiteResult:
    """Run a bundle of probes against one target and return a scored SuiteResult
    (services/findings.py turns the successes into findings). Preserves bundle
    order so evidence is stable across runs."""
    results: dict[str, ProbeResult] = {}
    cancelled = False
    engine = runner.engine
    engine_version = ""

    single = [p for p in probes if not p.is_multi_turn]
    if single:
        cfg = RunnerConfig(
            suite=suite_name,
            objectives=tuple(p.turns[0] for p in single),
            probe_ids=tuple(p.probe_id for p in single),
        )
        nres = await runner.run(target, cfg, cancel)
        cancelled = cancelled or nres.cancelled
        engine, engine_version = nres.engine, nres.engine_version
        attempts = {a.probe_id: a for a in nres.attempts}
        for probe in single:
            attempt = attempts.get(probe.probe_id)
            if attempt is None:
                continue  # not reached (cancelled before this objective)
            response = attempt.response_excerpt or ""
            verdict = build_detector(probe.detector).detect(response)
            results[probe.probe_id] = ProbeResult(
                probe=probe,
                succeeded=verdict.succeeded,
                transcript=(Turn("user", probe.turns[0]), Turn("assistant", response)),
                evidence=verdict.evidence,
                error=attempt.error,
            )

    for probe in (p for p in probes if p.is_multi_turn):
        if cancel.cancelled:
            cancelled = True
            break
        result = await _run_multi_turn(target, probe, cancel)
        results[probe.probe_id] = result
        if result.error == CANCELLED_MID_CONVERSATION:
            cancelled = True

    ordered = tuple(results[p.probe_id] for p in probes if p.probe_id in results)
    return SuiteResult(
        suite=suite_name,
        engine=engine,
        engine_version=engine_version,
        bundle_id=bundle_id,
        bundle_sha256=bundle_sha256,
        probe_results=ordered,
        cancelled=cancelled,
    )


async def _run_multi_turn(target: SuiteTarget, probe: Probe, cancel: CancelToken) -> ProbeResult:
    """Drive a scripted multi-turn conversation, checking the CancelToken BEFORE
    every turn (the per-turn cancellation budget). A conversation cut short mid-way
    is never scored as a success (fail-closed)."""
    conversation = target.open_conversation()
    transcript: list[Turn] = []
    last = ""
    for turn in probe.turns:
        if cancel.cancelled:
            return ProbeResult(
                probe=probe,
                succeeded=False,
                transcript=tuple(transcript),
                error=CANCELLED_MID_CONVERSATION,
            )
        last = await conversation.send(turn)
        transcript.extend((Turn("user", turn), Turn("assistant", last)))
    verdict = build_detector(probe.detector).detect(last)
    return ProbeResult(
        probe=probe,
        succeeded=verdict.succeeded,
        transcript=tuple(transcript),
        evidence=verdict.evidence,
    )
