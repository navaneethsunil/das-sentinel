"""Deliberately-insecure web target for exercising the ZAP DAST adapter (M3-W3).

A tiny stdlib HTTP server that serves an HTML login form and OMITS every security
response header (no X-Content-Type-Options, no Content-Security-Policy, no
anti-clickjacking header, no cache-control, sets an insecure cookie). ZAP's
passive scanner reliably raises alerts on these, so the adapter's live proof
(scripts/verify_zap_scanner.py) always has real findings to normalize — without
needing a heavyweight app like Juice Shop (that full E2E is M3-T1).

Runs as the `vuln-target` compose service on the internal network; never exposed
to a host port. No app dependencies (pure stdlib), so it runs in a plain
python:3.12-slim container.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_PAGE = b"""<!doctype html>
<html><head><title>Vulnerable Demo</title></head>
<body>
  <h1>Login</h1>
  <form method="POST" action="/login">
    <input name="username" type="text"/>
    <input name="password" type="password"/>
    <button type="submit">Sign in</button>
  </form>
  <a href="/account">Account</a>
</body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _serve(self) -> None:
        body = _PAGE
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        # Deliberately NO security headers and an insecure session cookie — this is
        # the whole point of the fixture (ZAP passive rules flag these).
        self.send_header("Set-Cookie", "session=abc123; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 — stdlib handler name
        self._serve()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(length)
        self._serve()

    def log_message(self, *_a: object) -> None:  # silence per-request logging
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8000), _Handler)  # noqa: S104 — container-internal only
    server.serve_forever()


if __name__ == "__main__":
    main()
