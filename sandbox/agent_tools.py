"""Sandboxed fake agent tools for permission testing (M5).

The implementation moved into the app package (`app/agent/harness.py`) so the base
worker image — which does not mount this `sandbox/` tree — can run agent-permission
scans. This module re-exports it, keeping the documented sandbox entry point and
the tests/verify scripts that import `agent_tools` working unchanged.
"""

from app.agent.harness import (  # noqa: F401 — re-export
    CallWebhookTool,
    CreateTicketTool,
    FakeTool,
    QueryDatabaseTool,
    SendEmailTool,
    build_sandbox_tools,
)

if __name__ == "__main__":  # tiny self-check (no framework, per repo convention)
    registry, tools = build_sandbox_tools()
    assert set(registry) == {"send_email", "query_database", "create_ticket", "call_webhook"}
    assert registry["send_email"]({"to": "x@y"})["sent"] is False
    assert registry["call_webhook"]({"url": "http://evil"})["delivered"] is False
    assert registry["query_database"]({"table": "users"})["row_count"] == 2
    assert registry["query_database"]({"table": "nope"})["row_count"] == 0
    assert registry["create_ticket"]({"title": "t"})["ticket_id"] == 1
    assert tools[0].calls == [{"to": "x@y"}]  # invocations are recorded
    print("agent_tools self-check OK")
