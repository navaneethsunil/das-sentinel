"""Prompt-injection suite on PyRIT (M2-B4) — LLM01.

Runs the vendored, content-hashed probe corpus against an LLM target and scores
each probe with a DETERMINISTIC detector (services/findings.py turns the successes
into LLM01 findings with transcript evidence). Single-turn probes run through the
M2-B3 PyRITRunner (i.e. genuinely "on PyRIT"); the one scripted multi-turn probe
runs through a stateful conversation so the CancelToken is checked between every
turn (§2.10 for a subprocess-less multi-turn suite). PyRIT's adaptive Crescendo
(needs an adversarial LLM target) and the external corpora are tracked follow-ups.

Provenance: the detector is deterministic pattern-matching, so successes are
`automated` findings — the LLM is never the judge (§2.6).
"""

import hashlib
import json
from pathlib import Path

from app.models.finding import Severity
from app.runners.base import Runner, RunnerConfig
from app.runners.pyrit_runner import PyRITRunner
from app.suites.base import (
    DetectorSpec,
    Probe,
    ProbeResult,
    SuiteResult,
    SuiteTarget,
    TechniqueFamily,
    Turn,
)
from app.suites.detectors import build_detector
from app.suites.owasp_llm import owasp_llm_ref
from app.workers.execution import CancelToken

SUITE_NAME = "prompt_injection"
_DEFAULT_BUNDLE = Path(__file__).parent / "probes" / "prompt_injection.v1.json"
_CANCELLED_MID_CONVERSATION = "cancelled mid-conversation"


class ProbeBundleError(Exception):
    """The probe bundle is missing, malformed, or references an unknown
    technique/severity/OWASP code — fail loud, never run a half-parsed corpus."""


def load_bundle(path: Path = _DEFAULT_BUNDLE) -> tuple[str, str, tuple[Probe, ...]]:
    """Load + content-hash the probe bundle. Returns (bundle_id, sha256_hex,
    probes). The hash pins exactly which probes produced a finding (provenance),
    mirroring the vendored-scanner-rule discipline (CLAUDE.md §3)."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProbeBundleError(f"probe bundle unreadable: {path}") from exc
    sha256 = hashlib.sha256(raw).hexdigest()
    try:
        doc = json.loads(raw)
        probes = tuple(_parse_probe(p) for p in doc["probes"])
        bundle_id = doc["bundle_id"]
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        raise ProbeBundleError(f"probe bundle malformed: {exc}") from exc
    if not probes:
        raise ProbeBundleError("probe bundle contains no probes")
    return bundle_id, sha256, probes


def _parse_probe(p: dict) -> Probe:
    owasp = p["owasp"]
    owasp_llm_ref(owasp)  # validate the code exists (raises on typo/stale)
    return Probe(
        probe_id=p["probe_id"],
        technique=TechniqueFamily(p["technique"]),
        title=p["title"],
        turns=tuple(p["turns"]),
        detector=DetectorSpec(
            kind=p["detector"]["kind"], params=dict(p["detector"].get("params", {}))
        ),
        severity=Severity(p["severity"]),
        owasp=owasp,
        description=p["description"],
        recommendation=p["recommendation"],
    )


class PromptInjectionSuite:
    def __init__(
        self, runner: Runner | None = None, *, bundle_path: Path = _DEFAULT_BUNDLE
    ) -> None:
        self._runner = runner if runner is not None else PyRITRunner()
        self._bundle_path = bundle_path

    async def run(self, target: SuiteTarget, cancel: CancelToken) -> SuiteResult:
        bundle_id, bundle_sha256, probes = load_bundle(self._bundle_path)
        results: dict[str, ProbeResult] = {}
        cancelled = False
        engine = self._runner.engine
        engine_version = ""

        single = [p for p in probes if not p.is_multi_turn]
        if single:
            cfg = RunnerConfig(
                suite=SUITE_NAME,
                objectives=tuple(p.turns[0] for p in single),
                probe_ids=tuple(p.probe_id for p in single),
            )
            nres = await self._runner.run(target, cfg, cancel)
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
            result = await self._run_multi_turn(target, probe, cancel)
            results[probe.probe_id] = result
            if result.error == _CANCELLED_MID_CONVERSATION:
                cancelled = True

        ordered = tuple(results[p.probe_id] for p in probes if p.probe_id in results)
        return SuiteResult(
            suite=SUITE_NAME,
            engine=engine,
            engine_version=engine_version,
            bundle_id=bundle_id,
            bundle_sha256=bundle_sha256,
            probe_results=ordered,
            cancelled=cancelled,
        )

    async def _run_multi_turn(
        self, target: SuiteTarget, probe: Probe, cancel: CancelToken
    ) -> ProbeResult:
        """Drive a scripted multi-turn conversation, checking the CancelToken
        BEFORE every turn (the per-turn cancellation budget). A conversation cut
        short mid-way is never scored as a success (fail-closed)."""
        conversation = target.open_conversation()
        transcript: list[Turn] = []
        last = ""
        for turn in probe.turns:
            if cancel.cancelled:
                return ProbeResult(
                    probe=probe,
                    succeeded=False,
                    transcript=tuple(transcript),
                    error=_CANCELLED_MID_CONVERSATION,
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
