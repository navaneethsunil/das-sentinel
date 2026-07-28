"""Live real-socket proof of the DNS-rebinding pin (SEC-DEBT-6).

Unlike the CI unit tests (which use a mock inner transport), this drives the
PRODUCTION connector path — `build_llm_target_connector` with no injected
transport builds the real `ScopePinnedDNSTransport` around a real
`httpx.AsyncHTTPTransport` — against an actual local HTTP server over real
sockets. It proves three things end to end:

  A. PIN — a request to a hostname whose ONLY resolution is the injected one
     reaches the pinned IP. `pinned-target.test` is not in the OS resolver, so if
     the connection lands on our local server it can only be because the transport
     connected to the vetted IP it was given (not system DNS), and the server sees
     the original hostname in the Host header.
  B. REBIND BLOCKED — a resolver that returns a safe in-scope IP for the guard's
     pre-check and then the cloud-metadata IP at connect is blocked before any
     socket to the internal address is opened (the TOCTOU the pin closes).
  C. NO EGRESS on block — the server records zero hits for case B.

Run (no compose services needed — self-contained local server):
    cd apps/api && PYTHONPATH=. uv run --no-sync python scripts/verify_dns_rebinding.py
"""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from app.connectors import build_llm_target_connector
from app.core.scope import SSRFBlocked
from app.models.engagement import ScopeItem, ScopeKind, ScopeMatcher
from app.models.target import Target, TargetType

HOSTNAME = "pinned-target.test"  # deliberately NOT resolvable by the OS
METADATA_IP = "169.254.169.254"

_hits: list[str] = []  # Host header seen on each request that actually connected


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


class _Handler(BaseHTTPRequestHandler):
    def _reply(self) -> None:
        _hits.append(self.headers.get("Host", ""))
        body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        self._reply()

    def log_message(self, *_args: object) -> None:  # silence stdout noise
        pass


def _scope() -> list[ScopeItem]:
    # Domain allow for the hostname + an ip_cidr ALLOW so loopback counts as an
    # in-scope "public" IP for this local harness (real deployments never allow it).
    return [
        ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.DOMAIN, value=HOSTNAME),
        ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.IP_CIDR, value="127.0.0.1/32"),
    ]


def _target(port: int) -> Target:
    return Target(
        name="pinned",
        target_type=TargetType.AI_CHATBOT,
        primary_value=f"http://{HOSTNAME}:{port}/v1/chat",
    )


async def _run() -> None:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        scope = _scope()

        # ── A. PIN reaches the vetted IP over a real socket ──────────────────
        _hits.clear()
        connector = build_llm_target_connector(
            _target(port), scope, resolve=lambda _h: ["127.0.0.1"]
        )
        try:
            reply = await connector.send("probe")
        finally:
            await connector.aclose()
        _require(reply == "ok", f"expected reply 'ok', got {reply!r}")
        _require(_hits == [f"{HOSTNAME}:{port}"], f"Host header not preserved: {_hits}")
        print("A. PASS — connected to the pinned IP; server saw Host", _hits[0])

        # ── B/C. Rebind between guard and connect is blocked, no egress ──────
        _hits.clear()
        n = {"c": 0}

        def rebinding_resolve(_host: str) -> list[str]:
            n["c"] += 1
            return ["127.0.0.1"] if n["c"] == 1 else [METADATA_IP]

        connector = build_llm_target_connector(_target(port), scope, resolve=rebinding_resolve)
        try:
            try:
                await connector.send("probe")
            except SSRFBlocked as exc:
                print("B. PASS — rebind to internal IP blocked at connect:", exc)
            else:
                raise AssertionError("rebinding was NOT blocked — pin failed")
        finally:
            await connector.aclose()
        _require(_hits == [], f"C. FAIL — egress reached the server despite block: {_hits}")
        _require(n["c"] == 2, f"expected guard+pin to resolve twice, got {n['c']}")
        print("C. PASS — zero egress on the blocked request")

        print("\nALL PASS — DNS-rebinding pin verified over real sockets (SEC-DEBT-6).")
    finally:
        server.shutdown()


if __name__ == "__main__":
    asyncio.run(_run())
