"""Prompt-injection suite on PyRIT (M2-B4) — LLM01.

Runs the vendored, content-hashed probe corpus against an LLM target and scores
each probe with a DETERMINISTIC detector (services/findings.py turns the successes
into LLM01 findings with transcript evidence). The run engine is shared with the
data-leakage suite (app/suites/engine.py): single-turn probes run through the
M2-B3 PyRITRunner (i.e. genuinely "on PyRIT"); the one scripted multi-turn probe
runs through a stateful conversation so the CancelToken is checked between every
turn (§2.10). PyRIT's adaptive Crescendo (needs an adversarial LLM target) and the
external corpora are tracked follow-ups.

Provenance: the detector is deterministic pattern-matching, so successes are
`automated` findings — the LLM is never the judge (§2.6).
"""

from pathlib import Path

from app.runners.base import Runner
from app.runners.pyrit_runner import PyRITRunner
from app.suites.base import (
    Probe,
    ProbeBundleError,
    SuiteResult,
    SuiteTarget,
    TechniqueFamily,
    load_probe_bundle,
)
from app.suites.engine import run_probe_suite
from app.workers.execution import CancelToken

SUITE_NAME = "prompt_injection"
_DEFAULT_BUNDLE = Path(__file__).parent / "probes" / "prompt_injection.v1.json"

__all__ = ["SUITE_NAME", "ProbeBundleError", "PromptInjectionSuite", "load_bundle"]


def load_bundle(path: Path = _DEFAULT_BUNDLE) -> tuple[str, str, tuple[Probe, ...]]:
    """Load + content-hash the prompt-injection bundle (technique = TechniqueFamily)."""
    return load_probe_bundle(path, TechniqueFamily)


class PromptInjectionSuite:
    def __init__(
        self, runner: Runner | None = None, *, bundle_path: Path = _DEFAULT_BUNDLE
    ) -> None:
        self._runner = runner if runner is not None else PyRITRunner()
        self._bundle_path = bundle_path

    async def run(self, target: SuiteTarget, cancel: CancelToken) -> SuiteResult:
        bundle_id, bundle_sha256, probes = load_bundle(self._bundle_path)
        return await run_probe_suite(
            self._runner,
            target,
            cancel,
            suite_name=SUITE_NAME,
            bundle_id=bundle_id,
            bundle_sha256=bundle_sha256,
            probes=probes,
        )
