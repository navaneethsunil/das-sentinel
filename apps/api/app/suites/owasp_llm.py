"""Minimal OWASP Top 10 for LLM Applications — 2025 code→title reference (M2-B4).

Just enough to label M2 suite findings with their OWASP-LLM category. The FULL
compliance mapping knowledge base (OWASP + NIST cross-references, POA&M mapping;
`packages/compliance/`) lands in M6 (compliance & reporting). Codes/titles per the
2025 edition pinned in CLAUDE.md §1 (note LLM05 Improper Output Handling, LLM07
System Prompt Leakage, LLM08 Vector and Embedding Weaknesses).
"""

OWASP_LLM_2025: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


class UnknownOwaspCodeError(ValueError):
    """A suite referenced an OWASP-LLM code that is not in the 2025 list — a
    typo/stale code must fail loud, not silently mislabel a finding."""


def owasp_llm_ref(code: str) -> dict[str, str]:
    """Return a stable reference block for a finding's compliance mapping."""
    title = OWASP_LLM_2025.get(code)
    if title is None:
        raise UnknownOwaspCodeError(code)
    return {"framework": "OWASP-LLM-2025", "code": code, "title": title}
