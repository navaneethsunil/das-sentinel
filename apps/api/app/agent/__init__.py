"""Agent permission testing (M5).

Tests whether an AI agent respects its allowed tool-permission boundaries: a
deterministic policy-decision engine (`policy`) evaluates each attempted tool call
against an `AgentPolicy`, and the monitor (`monitor`) executes only the permitted
calls against sandboxed, side-effect-free fake tools — recording an auditable
allow/block transcript. Findings map to OWASP LLM06 (Excessive Agency) + the OWASP
Top 10 for Agentic Applications 2026 ASI02 (Tool Misuse). ROADMAP §M5.
"""
