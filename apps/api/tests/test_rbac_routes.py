"""M1-T2 (structural half): prove every domain route is guarded by the right
capability. This catches the highest-risk RBAC regression — a route shipped
without a guard, or with a mutating verb behind mere VIEW. The per-role
allow/deny over HTTP and immediate session revocation are proven live in
scripts/verify_rbac.py; the capability↔role matrix itself in test_deps_rbac.py.
"""

from collections.abc import Iterator

import pytest
from fastapi.routing import APIRoute

from app.core.config import Settings
from app.core.deps import Capability
from app.main import create_app

# Routes that are intentionally public (no auth): health/liveness + docs.
_PUBLIC_PATHS = {"/healthz", "/readyz", "/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}

# Exact expected capability for security-critical routes (drift catcher).
_EXPECTED: dict[tuple[str, str], Capability] = {
    ("POST", "/users"): Capability.MANAGE_USERS,
    ("GET", "/users"): Capability.MANAGE_USERS,  # listing users is admin-only
    ("PATCH", "/users/{user_id}/role"): Capability.MANAGE_USERS,
    ("POST", "/users/{user_id}/deactivate"): Capability.MANAGE_USERS,
    ("POST", "/engagements"): Capability.MANAGE_ENGAGEMENTS,
    ("POST", "/engagements/{engagement_id}/scope-items"): Capability.MANAGE_ENGAGEMENTS,
    ("POST", "/engagements/{engagement_id}/roe/accept"): Capability.ACCEPT_ROE,
    ("POST", "/engagements/{engagement_id}/targets"): Capability.MANAGE_ENGAGEMENTS,
    ("POST", "/engagements/{engagement_id}/targets/{target_id}/source-archive"): (
        Capability.MANAGE_ENGAGEMENTS
    ),
    ("POST", "/engagements/{engagement_id}/approvals"): Capability.LAUNCH_SCANS,
    ("POST", "/engagements/{engagement_id}/approvals/{approval_id}/decide"): (
        Capability.APPROVE_HIGH_RISK
    ),
    ("POST", "/engagements/{engagement_id}/approvals/{approval_id}/revoke"): (
        Capability.APPROVE_HIGH_RISK
    ),
    # Suite launcher (M2-F1) + emergency stop (M2-W2): both need LAUNCH_SCANS.
    ("POST", "/engagements/{engagement_id}/scans"): Capability.LAUNCH_SCANS,
    ("POST", "/engagements/{engagement_id}/scans/{scan_id}/cancel"): Capability.LAUNCH_SCANS,
    # SARIF import (M3-B2) creates findings — a mutation, MANAGE_ENGAGEMENTS.
    ("POST", "/engagements/{engagement_id}/findings/import-sarif"): Capability.MANAGE_ENGAGEMENTS,
    # CVSS scoring (M3-B3) is a human validation action, not plain VIEW.
    ("POST", "/engagements/{engagement_id}/findings/{finding_id}/cvss"): (
        Capability.VALIDATE_FINDINGS
    ),
    # Compliance mapping (M3-B4) — auto-map + manual edit are validation actions.
    ("POST", "/engagements/{engagement_id}/findings/{finding_id}/compliance/auto-map"): (
        Capability.VALIDATE_FINDINGS
    ),
    ("POST", "/engagements/{engagement_id}/findings/{finding_id}/compliance"): (
        Capability.VALIDATE_FINDINGS
    ),
    ("DELETE", "/engagements/{engagement_id}/findings/{finding_id}/compliance/{control_id}"): (
        Capability.VALIDATE_FINDINGS
    ),
    ("POST", "/engagements/{engagement_id}/compliance/auto-map"): Capability.VALIDATE_FINDINGS,
    # Remediation guidance (M4-B1) — generating a draft drives our LLM.
    ("POST", "/engagements/{engagement_id}/findings/{finding_id}/remediation/generate"): (
        Capability.VALIDATE_FINDINGS
    ),
    # Reports (M3-B5) — authoring, finalize, and export are EXPORT_REPORTS.
    ("POST", "/engagements/{engagement_id}/reports"): Capability.EXPORT_REPORTS,
    ("PATCH", "/engagements/{engagement_id}/reports/{report_id}"): Capability.EXPORT_REPORTS,
    ("POST", "/engagements/{engagement_id}/reports/{report_id}/finalize"): (
        Capability.EXPORT_REPORTS
    ),
    ("POST", "/engagements/{engagement_id}/reports/{report_id}/export"): (
        Capability.EXPORT_REPORTS
    ),
    ("DELETE", "/engagements/{engagement_id}/reports/{report_id}"): Capability.EXPORT_REPORTS,
    # Audit reads are oversight-only — never plain VIEW (read_only excluded).
    ("GET", "/audit-events"): Capability.VIEW_AUDIT,
}


def _collect_api_routes(routes: object) -> list[APIRoute]:
    """Recurse into included routers. FastAPI ≥0.139 nests each included router
    under an _IncludedRouter mount exposing `original_router`, rather than
    flattening APIRoutes into app.routes."""
    found: list[APIRoute] = []
    for route in routes:  # type: ignore[attr-defined]
        if isinstance(route, APIRoute):
            found.append(route)
        elif hasattr(route, "original_router"):
            found.extend(_collect_api_routes(route.original_router.routes))
        elif hasattr(route, "routes"):
            found.extend(_collect_api_routes(route.routes))
    return found


@pytest.fixture()
def app_routes(env: dict[str, str]) -> list[APIRoute]:  # noqa: ARG001 - env sets config
    app = create_app(Settings(_env_file=None))
    return _collect_api_routes(app.routes)


def _route_capabilities(route: APIRoute) -> set[Capability]:
    def _walk(dep) -> Iterator[Capability]:
        cap = getattr(dep.call, "_required_capability", None)
        if cap is not None:
            yield cap
        for sub in dep.dependencies:
            yield from _walk(sub)

    return set(_walk(route.dependant))


def _domain_routes(routes: list[APIRoute]) -> list[APIRoute]:
    return [
        r
        for r in routes
        if r.path not in _PUBLIC_PATHS
        and (r.path.startswith(("/users", "/engagements", "/audit-events")))
    ]


def test_every_domain_route_is_guarded(app_routes: list[APIRoute]) -> None:
    for route in _domain_routes(app_routes):
        caps = _route_capabilities(route)
        assert caps, f"unguarded domain route: {sorted(route.methods)} {route.path}"


def test_mutating_routes_require_more_than_view(app_routes: list[APIRoute]) -> None:
    for route in _domain_routes(app_routes):
        if route.methods & {"POST", "PATCH", "PUT", "DELETE"}:
            caps = _route_capabilities(route)
            assert caps != {Capability.VIEW}, (
                f"mutating route behind VIEW only: {sorted(route.methods)} {route.path}"
            )


def test_engagement_reads_allow_view(app_routes: list[APIRoute]) -> None:
    # Reads under /engagements are for every authenticated role (VIEW). (User
    # listing is the deliberate admin-only exception, asserted in the map below.)
    for route in _domain_routes(app_routes):
        if route.methods == {"GET"} and route.path.startswith("/engagements"):
            assert Capability.VIEW in _route_capabilities(route), (
                f"GET route not VIEW-guarded: {route.path}"
            )


def test_security_critical_routes_have_exact_capability(app_routes: list[APIRoute]) -> None:
    by_key: dict[tuple[str, str], set[Capability]] = {}
    for route in app_routes:
        for method in route.methods:
            by_key[(method, route.path)] = _route_capabilities(route)
    for key, expected in _EXPECTED.items():
        assert key in by_key, f"expected route missing: {key}"
        assert by_key[key] == {expected}, f"{key}: expected {expected}, got {by_key[key]}"
