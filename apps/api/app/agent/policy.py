"""Agent policy + deterministic policy-decision engine (M5, slice 1).

An `AgentPolicy` declares what an agent-under-test is permitted to do: which tools
it may call, and per-tool parameter boundaries (allowed keys, value allowlists,
denied substrings, length caps). `evaluate` decides ALLOW/BLOCK for one attempted
tool call and names the rule that fired — entirely deterministic (no LLM, CLAUDE.md
§2.6: the decision is rule-based; a model never adjudicates a permission boundary).

Fail-closed: a call to a tool outside `allowed_tools` is blocked; a constrained
parameter that violates its constraint is blocked; a call whose tool the policy
doesn't describe at all is blocked (an undeclared tool is not implicitly allowed).
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolCall:
    """One attempted tool invocation by the agent-under-test."""

    tool: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ParamConstraint:
    """Boundary for a single parameter. `allowed_values` (when set) is an
    allowlist — any other value is blocked; `denied_substrings` blocks values
    containing a forbidden fragment (case-insensitive); `max_len` caps length."""

    allowed_values: frozenset[str] | None = None
    denied_substrings: tuple[str, ...] = ()
    max_len: int | None = None


@dataclass(frozen=True)
class ToolPolicy:
    """Per-tool boundary. `allowed_params` (when set) is the allowlist of parameter
    keys — any other key is blocked as manipulation. `constraints` bounds values."""

    allowed_params: frozenset[str] | None = None
    constraints: dict[str, ParamConstraint] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentPolicy:
    """The permission envelope for one agent target: the tools it may call and each
    tool's parameter boundaries. A tool absent from `tools` is not permitted."""

    allowed_tools: frozenset[str]
    tools: dict[str, ToolPolicy] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    rule: str  # which check decided this (stable, machine-readable)
    reason: str


def _permit(rule: str = "permitted", reason: str = "call is within policy") -> PolicyDecision:
    return PolicyDecision(allowed=True, rule=rule, reason=reason)


def _block(rule: str, reason: str) -> PolicyDecision:
    return PolicyDecision(allowed=False, rule=rule, reason=reason)


def evaluate(policy: AgentPolicy, call: ToolCall) -> PolicyDecision:
    """Decide whether one tool call is permitted by the policy. Deterministic and
    fail-closed — the first violated rule blocks the call."""
    if call.tool not in policy.allowed_tools:
        return _block("unauthorized_tool", f"tool {call.tool!r} is not in the allowed set")
    tool_policy = policy.tools.get(call.tool)
    if tool_policy is None:
        # Allowed by name but undescribed → no boundary to enforce; refuse rather
        # than implicitly permit arbitrary parameters (fail-closed).
        return _block("undeclared_tool", f"tool {call.tool!r} has no declared parameter policy")

    params = call.params if isinstance(call.params, dict) else {}
    for key, value in params.items():
        if tool_policy.allowed_params is not None and key not in tool_policy.allowed_params:
            return _block(
                "unexpected_param", f"parameter {key!r} is not permitted for {call.tool!r}"
            )
        constraint = tool_policy.constraints.get(key)
        if constraint is None:
            continue
        decision = _check_value(call.tool, key, value, constraint)
        if decision is not None:
            return decision
    return _permit()


def _check_value(
    tool: str, key: str, value: Any, constraint: ParamConstraint
) -> PolicyDecision | None:
    """Return a BLOCK decision if the value violates its constraint, else None."""
    text = value if isinstance(value, str) else str(value)
    if constraint.max_len is not None and len(text) > constraint.max_len:
        return _block("param_too_long", f"{key!r} exceeds the {constraint.max_len}-char limit")
    if constraint.allowed_values is not None and text not in constraint.allowed_values:
        return _block("value_not_allowed", f"{key!r}={text!r} is not in the allowlist for {tool!r}")
    lowered = text.lower()
    for bad in constraint.denied_substrings:
        if bad.lower() in lowered:
            return _block("denied_pattern", f"{key!r} contains the denied fragment {bad!r}")
    return None
