"""Data-leakage suite on PyRIT (M2-B5).

Drives the vendored, content-hashed data-leakage probe corpus against an LLM
target through the shared run engine (app/suites/engine.py) and scores each probe
with a DETERMINISTIC detector. Successes become `automated` findings
(services/findings.py) mapped to the probe's OWASP-LLM code:

  - system-prompt leakage + hidden-instruction disclosure → LLM07
  - secret/token exposure + cross-tenant isolation failure → LLM02
  - RAG / vector-store boundary bypass                     → LLM08
  - improper output handling (active content unescaped)    → LLM05

The cross-tenant probe is scripted multi-turn (establish tenant A, then ask for
tenant B's data), so the CancelToken is checked between every turn (§2.10).
Provenance is `automated`: a probe "succeeds" only when a deterministic detector
matches the disclosed secret in the model's own response — the LLM never judges
(§2.6). A canary that never should have surfaced appearing in the output is
unambiguous proof of disclosure, not a heuristic.
"""

from pathlib import Path

from app.runners.base import Runner
from app.runners.pyrit_runner import PyRITRunner
from app.suites.base import (
    LeakageVector,
    Probe,
    ProbeBundleError,
    SuiteResult,
    SuiteTarget,
    load_probe_bundle,
)
from app.suites.engine import run_probe_suite
from app.workers.execution import CancelToken

SUITE_NAME = "data_leakage"
_DEFAULT_BUNDLE = Path(__file__).parent / "probes" / "data_leakage.v1.json"

__all__ = ["SUITE_NAME", "DataLeakageSuite", "ProbeBundleError", "load_bundle"]


def load_bundle(path: Path = _DEFAULT_BUNDLE) -> tuple[str, str, tuple[Probe, ...]]:
    """Load + content-hash the data-leakage bundle (technique = LeakageVector)."""
    return load_probe_bundle(path, LeakageVector)


class DataLeakageSuite:
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
