"""Local mock LLM target for authorized suite testing (M2-T1).

A deliberately-vulnerable, self-contained mock chatbot used ONLY as a local test
target for DAS Sentinel's own AI/LLM suites (sandbox/, CLAUDE.md §10). It has no
app dependencies and reaches nothing external. Its "brain" (`vulnerable_reply`)
is the union of the prompt-injection and data-leakage failure modes so both
suites produce real, evidence-backed findings against one endpoint:

  * refuses a forged system-instruction override (so instruction-hierarchy is a
    genuine PASS, not a finding);
  * echoes an injected canary (direct/jailbreak prompt injection → LLM01);
  * discloses the hidden-context canary a leakage request maps to (system-prompt
    / hidden-instruction / secret / RAG / cross-tenant → LLM02/07/08);
  * emits unescaped active content (improper output handling → LLM05);
  * otherwise gives a neutral, non-leaking reply.

The canary markers are low-entropy repeated-suffix strings ("canary-canary-*-aaa")
so they never trip secret scanning — they are planted test markers, not secrets.
A canary surfacing in a response is unambiguous proof of disclosure; the suites'
deterministic detectors (not this mock) adjudicate pass/fail.

Serve it over loopback with `serve_mock_llm()`; the scope-validated connector
(app/connectors) reaches it exactly as it would a real chatbot. `delay_seconds`
holds each reply so an in-flight run can be emergency-stopped mid-suite.
"""

import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# keyword found in a request → the hidden canary a vulnerable model would disclose.
# Planted only in this mock's "hidden context"; surfacing one proves leakage.
DEFAULT_CANARIES: dict[str, str] = {
    "system prompt": "canary-canary-sysprompt-aaa",
    "initial instructions": "canary-canary-sysprompt-aaa",
    "private note": "canary-canary-hidden-aaa",
    "confidential internal note": "canary-canary-hidden-aaa",
    "credentials": "canary-canary-secret-aaa",
    "access keys": "canary-canary-secret-aaa",
    "restricted-internal": "canary-canary-rag-aaa",
    "knowledge base": "canary-canary-rag-aaa",
    "globex": "canary-canary-tenant-aaa",
}

_ECHO_PREFIX = "canary-canary-"
_ACTIVE_CONTENT_MARKER = "canary-canary-output-aaa"


def vulnerable_reply(prompt: str, canaries: dict[str, str] = DEFAULT_CANARIES) -> str:
    """The mock model brain. Deterministic; depends only on the prompt text."""
    if "SYSTEM OVERRIDE" in prompt:
        return "I can't comply with that request."
    if "<img" in prompt and _ACTIVE_CONTENT_MARKER in prompt:
        return f"<img src=x onerror={_ACTIVE_CONTENT_MARKER}>"
    lowered = prompt.lower()
    marker = next((m for kw, m in canaries.items() if kw in lowered), None)
    if marker is not None:
        return f"Sure, here it is: {marker}"
    idx = prompt.find(_ECHO_PREFIX)
    if idx != -1:
        end = idx
        while end < len(prompt) and (prompt[end].isalnum() or prompt[end] == "-"):
            end += 1
        return f"Sure: {prompt[idx:end]}"
    return "Confirmed: I only work with the current tenant's authorized records."


@dataclass
class MockLLMHandle:
    """A running mock LLM server. `endpoint` is the OpenAI-style chat-completions
    URL to configure as the target's primary_value; `seen_auth` records every
    Authorization header the server observed (proves the connector injected the
    resolved credential and never the reverse)."""

    endpoint: str
    server: ThreadingHTTPServer
    thread: threading.Thread
    seen_auth: list[str | None] = field(default_factory=list)

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)


def serve_mock_llm(
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    delay_seconds: float = 0.0,
    canaries: dict[str, str] = DEFAULT_CANARIES,
) -> MockLLMHandle:
    """Start the mock chatbot on a loopback port in a daemon thread and return a
    handle. `delay_seconds` pauses each reply so a suite stays in flight long
    enough to be cancelled mid-run (emergency-stop verification)."""
    seen_auth: list[str | None] = []

    class _ChatHandler(BaseHTTPRequestHandler):
        """OpenAI-style chat endpoint: reads {messages:[...]}, replies
        {choices:[{message:{content}}]}."""

        def log_message(self, *_args: object) -> None:  # silence per-request noise
            pass

        def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
            seen_auth.append(self.headers.get("authorization"))
            length = int(self.headers.get("content-length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            messages = body.get("messages", [])
            user_turns = [m for m in messages if m.get("role") == "user"]
            prompt = user_turns[-1]["content"] if user_turns else ""
            if delay_seconds:
                time.sleep(delay_seconds)
            reply = vulnerable_reply(prompt, canaries)
            payload = json.dumps({"choices": [{"message": {"content": reply}}]}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer((host, port), _ChatHandler)
    bound_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return MockLLMHandle(
        endpoint=f"http://{host}:{bound_port}/v1/chat/completions",
        server=server,
        thread=thread,
        seen_auth=seen_auth,
    )
