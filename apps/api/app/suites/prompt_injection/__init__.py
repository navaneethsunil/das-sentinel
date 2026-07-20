"""Prompt-injection suite (M2-B4, LLM01)."""

from app.suites.prompt_injection.suite import (
    SUITE_NAME,
    ProbeBundleError,
    PromptInjectionSuite,
    load_bundle,
)

__all__ = ["SUITE_NAME", "ProbeBundleError", "PromptInjectionSuite", "load_bundle"]
