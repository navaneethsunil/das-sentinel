"""Double-submit CSRF protection (M1-SEC2, TM-10) — ARCHITECTURE §13.

SameSite=Strict on the session cookie is the first line of defense; this
middleware is the required second: every authenticated state-changing request
must echo the non-HttpOnly CSRF cookie in a custom header. A cross-origin
attacker page can neither read the cookie nor attach a custom header to a
credentialed form/img request, so header == cookie proves same-origin intent.

Requests without a session cookie pass through untouched — there is no
authenticated state to forge and the auth layer answers 401. /auth/login is
exempt: no session exists yet, and its response is what mints the CSRF cookie.
"""

import hmac
import secrets
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
EXEMPT_PATHS = frozenset({"/auth/login"})

CSRF_TOKEN_BYTES = 32


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(CSRF_TOKEN_BYTES)


def register_csrf_middleware(app: Any) -> None:
    """Register AFTER the audit middleware so CSRF runs outermost — a forged
    request is rejected before any inner layer (or handler) can act on it."""

    @app.middleware("http")
    async def enforce_csrf(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method in SAFE_METHODS:
            return await call_next(request)

        settings = request.app.state.settings
        path = request.url.path
        root_path = request.scope.get("root_path", "")
        if root_path and path.startswith(root_path):
            path = path[len(root_path) :]
        if path in EXEMPT_PATHS:
            return await call_next(request)

        if settings.session_cookie_name not in request.cookies:
            return await call_next(request)

        cookie_token = request.cookies.get(settings.csrf_cookie_name, "")
        header_token = request.headers.get(settings.csrf_header_name, "")
        # compare_digest needs both operands non-empty to stay constant-time.
        if not cookie_token or not hmac.compare_digest(cookie_token, header_token):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF token missing or invalid"},
            )
        return await call_next(request)
