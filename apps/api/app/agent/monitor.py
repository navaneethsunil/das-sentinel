"""Tool-call monitor (M5, slice 1) — enforce the policy while executing calls.

Given an agent's attempted tool calls, the monitor consults the deterministic
policy engine for each one and executes ONLY the permitted calls against the
sandboxed fake tools; a blocked call is never executed (fail-closed). It returns
an ordered, auditable transcript of (call, decision, executed?, result) — the raw
material a permission-boundary finding cites (evidence), and the substrate the M5
attack suites drive.

The tool registry is injected (a mapping of tool name → callable), so the monitor
has no dependency on the concrete sandbox tools and is trivially testable.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from app.agent.policy import AgentPolicy, PolicyDecision, ToolCall, evaluate

ToolCallable = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class MonitoredCall:
    call: ToolCall
    decision: PolicyDecision
    executed: bool
    result: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.call.tool,
            "params": self.call.params,
            "allowed": self.decision.allowed,
            "rule": self.decision.rule,
            "reason": self.decision.reason,
            "executed": self.executed,
            "result": self.result,
            "error": self.error,
        }


def run_monitored(
    policy: AgentPolicy, tools: Mapping[str, ToolCallable], calls: list[ToolCall]
) -> list[MonitoredCall]:
    """Evaluate each attempted call against the policy and execute only the
    permitted ones on the sandboxed tools. A blocked call is recorded but NEVER
    executed (fail-closed); a permitted call whose tool is missing from the
    registry is recorded as not-executed with an error (never a silent pass)."""
    transcript: list[MonitoredCall] = []
    for call in calls:
        decision = evaluate(policy, call)
        if not decision.allowed:
            transcript.append(MonitoredCall(call=call, decision=decision, executed=False))
            continue
        tool = tools.get(call.tool)
        if tool is None:
            transcript.append(
                MonitoredCall(
                    call=call,
                    decision=decision,
                    executed=False,
                    error=f"permitted tool {call.tool!r} is not available in the sandbox",
                )
            )
            continue
        try:
            result = tool(dict(call.params))
        except Exception as exc:  # a fake tool must never crash the monitor
            transcript.append(
                MonitoredCall(call=call, decision=decision, executed=False, error=str(exc))
            )
            continue
        transcript.append(MonitoredCall(call=call, decision=decision, executed=True, result=result))
    return transcript
