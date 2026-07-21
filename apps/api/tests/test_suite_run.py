"""CI-safe unit tests for the LLM suite-run wiring (M2-T1).

Covers the pure envelope→suites resolution and the suite-class mapping. The full
integration (connector → PyRIT → findings → orchestration, incl. mid-run cancel)
is proven live in the redteam image by scripts/verify_e2e_llm_scan.py — importing
this module never pulls PyRIT (the runner imports it lazily)."""

import pytest

from app.models.scan import TestSuite
from app.workers.suite_run import (
    _SUITE_CLASSES,
    SuiteRunError,
    suites_from_config,
)


def test_suites_from_config_preserves_order_and_dedupes() -> None:
    cfg = {"suites": ["data_leakage", "prompt_injection", "data_leakage"]}
    assert suites_from_config(cfg) == [TestSuite.DATA_LEAKAGE, TestSuite.PROMPT_INJECTION]


def test_suites_from_config_rejects_unknown_suite() -> None:
    with pytest.raises(SuiteRunError, match="unknown suite"):
        suites_from_config({"suites": ["prompt_injection", "not_a_suite"]})


def test_suites_from_config_rejects_suite_without_runner() -> None:
    # agent_permission is a real TestSuite (M5) but has no runner in M2.
    with pytest.raises(SuiteRunError, match="no runner"):
        suites_from_config({"suites": ["agent_permission"]})


def test_suites_from_config_rejects_empty() -> None:
    with pytest.raises(SuiteRunError, match="no runnable suites"):
        suites_from_config({"suites": []})
    with pytest.raises(SuiteRunError, match="no runnable suites"):
        suites_from_config({})


def test_suite_class_mapping_covers_only_launchable_suites() -> None:
    assert set(_SUITE_CLASSES) == {TestSuite.PROMPT_INJECTION, TestSuite.DATA_LEAKAGE}
    assert TestSuite.AGENT_PERMISSION not in _SUITE_CLASSES
