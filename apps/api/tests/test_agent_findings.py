"""M5 slice 4: pure helpers for agent-permission findings.

CI-safe: the evidence serialization + the OWASP-Agentic reference. The full DB
persistence path (create_findings_from_agent_suite → findings + evidence +
LLM06/ASI02 mapping) is proven against real Postgres+MinIO in
scripts/verify_agent_permission.py.
"""

import json

from app.agent.corpus import DEFAULT_CORPUS, agentic_ref
from app.agent.monitor import MonitoredCall
from app.agent.policy import PolicyDecision, ToolCall
from app.agent.session import AgentSessionResult
from app.agent.suite import AgentProbeResult
from app.services.agent_findings import serialize_probe_result


def test_agentic_ref_maps_asi02() -> None:
    ref = agentic_ref("ASI02")
    assert ref == {
        "framework": "OWASP-Agentic-2026",
        "code": "ASI02",
        "title": "Tool Misuse & Exploitation",
    }


def _probe_result() -> AgentProbeResult:
    probe = DEFAULT_CORPUS[0]
    blocked = MonitoredCall(
        call=ToolCall("call_webhook", {"url": "http://x"}),
        decision=PolicyDecision(allowed=False, rule="unauthorized_tool", reason="not allowed"),
        executed=False,
    )
    session = AgentSessionResult(transcript=[blocked], turns=1, stopped="no_tool_calls")
    return AgentProbeResult(probe=probe, succeeded=True, session=session, evidence="attempted ...")


def test_serialize_probe_result_is_canonical_json_with_transcript() -> None:
    raw = serialize_probe_result(_probe_result())
    # deterministic (sorted keys) + carries the verdict + monitored transcript
    parsed = json.loads(raw)
    assert parsed["succeeded"] is True
    assert parsed["owasp"] == "LLM06" and parsed["asi"] == "ASI02"
    assert parsed["session"]["transcript"][0]["allowed"] is False
    assert parsed["session"]["transcript"][0]["rule"] == "unauthorized_tool"
    # stable/canonical: re-serializing the same result yields identical bytes
    assert serialize_probe_result(_probe_result()) == raw
