"""AI/LLM test suites (M2-B4 prompt-injection, M2-B5 data-leakage).

Suites run curated probes against an LLM target through the M2-B3 Runner/target
seam, score each with a deterministic detector, and return a `SuiteResult` that
services/findings.py turns into evidence-backed, OWASP-LLM-mapped findings.
"""
