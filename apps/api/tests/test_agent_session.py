"""M5 slice 2: the agent session runner (agentic loop) — pure, no LLM.

CI-safe: a scripted async `send` stands in for the agent target, returning
tool-call JSON per turn. Covers the loop (parse → monitor → feed back), the
tool-call parser's fail-safe handling of untrusted replies (TM-8), the turn
bound, and cooperative cancellation between turns.
"""

import sys
from pathlib import Path

from app.agent.policy import AgentPolicy, ParamConstraint, ToolPolicy
from app.agent.session import parse_tool_calls, run_agent_session

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "sandbox"))
from agent_tools import build_sandbox_tools  # noqa: E402


def _policy() -> AgentPolicy:
    return AgentPolicy(
        allowed_tools=frozenset({"query_database", "send_email"}),
        tools={
            "query_database": ToolPolicy(
                allowed_params=frozenset({"table"}),
                constraints={"table": ParamConstraint(allowed_values=frozenset({"public_faq"}))},
            ),
            "send_email": ToolPolicy(
                allowed_params=frozenset({"to", "subject", "body"}),
                constraints={"to": ParamConstraint(denied_substrings=("@attacker.",))},
            ),
        },
    )


def _scripted(replies: list[str]):
    """An async send() that returns queued replies in order, then a final."""
    seq = list(replies)

    async def send(_prompt: str) -> str:
        return seq.pop(0) if seq else '{"final": "done"}'

    return send


# ── parser ────────────────────────────────────────────────────────────────────
def test_parse_extracts_wellformed_calls() -> None:
    calls = parse_tool_calls(
        '{"tool_calls":[{"tool":"query_database","params":{"table":"users"}}]}'
    )
    assert (
        len(calls) == 1
        and calls[0].tool == "query_database"
        and calls[0].params == {"table": "users"}
    )


def test_parse_tolerates_surrounding_prose() -> None:
    calls = parse_tool_calls(
        'Sure! {"tool_calls":[{"tool":"send_email","params":{}}]} hope that helps'
    )
    assert len(calls) == 1 and calls[0].tool == "send_email"


def test_parse_failsafe_on_malformed_or_final() -> None:
    assert parse_tool_calls("not json at all") == []
    assert parse_tool_calls('{"final": "done"}') == []  # no tool_calls key
    assert parse_tool_calls("") == []
    # hostile shapes: non-dict entries, missing/nonstring tool, params wrong type
    calls = parse_tool_calls(
        '{"tool_calls":[42,{"params":{}},{"tool":"","params":{}},{"tool":"ok","params":"x"}]}'
    )
    assert len(calls) == 1 and calls[0].tool == "ok" and calls[0].params == {}


def test_parse_caps_calls_per_turn() -> None:
    many = ",".join(['{"tool":"query_database","params":{}}'] * 100)
    calls = parse_tool_calls('{"tool_calls":[' + many + "]}")
    assert len(calls) == 25  # _MAX_CALLS_PER_TURN


# ── session loop ────────────────────────────────────────────────────────────────
async def test_session_monitors_calls_and_feeds_results_back() -> None:
    registry, tools = build_sandbox_tools()
    send = _scripted(
        [
            '{"tool_calls":[{"tool":"query_database","params":{"table":"public_faq"}}]}',  # allowed
            '{"tool_calls":[{"tool":"query_database","params":{"table":"users"}}]}',  # blocked
            '{"final":"done"}',
        ]
    )
    result = await run_agent_session(
        send, _policy(), registry, task="help", tools_description="query_database, send_email"
    )
    assert result.stopped == "no_tool_calls" and result.turns == 3
    assert [m.executed for m in result.transcript] == [True, False]
    assert result.attempted == 2 and len(result.blocked) == 1
    # fail-closed: the sensitive 'users' query never reached the tool
    qdb = next(t for t in tools if t.name == "query_database")
    assert qdb.calls == [{"table": "public_faq"}]


async def test_session_stops_at_max_turns() -> None:
    registry, _ = build_sandbox_tools()
    # always asks for a permitted call → never emits final
    send = _scripted(
        ['{"tool_calls":[{"tool":"query_database","params":{"table":"public_faq"}}]}'] * 10
    )
    result = await run_agent_session(
        send, _policy(), registry, task="t", tools_description="x", max_turns=3
    )
    assert result.stopped == "max_turns" and result.turns == 3 and result.attempted == 3


async def test_session_cancellation_between_turns() -> None:
    registry, _ = build_sandbox_tools()
    send = _scripted(
        ['{"tool_calls":[{"tool":"query_database","params":{"table":"public_faq"}}]}'] * 10
    )
    calls_seen = {"n": 0}

    def cancel() -> bool:
        calls_seen["n"] += 1
        return calls_seen["n"] > 2  # cancel before the 3rd turn

    result = await run_agent_session(
        send, _policy(), registry, task="t", tools_description="x", max_turns=10, cancel=cancel
    )
    assert result.stopped == "cancelled" and result.turns == 2
