"""Live proof of the sec-1 fail-closed gate using the REAL system resolver.

Unlike the CI unit tests (injected resolvers), this drives the production
`assert_resolved_ip_in_scope` with `app.core.scope._system_resolver`, proving:

  A. A native-scanner (WEB_APP) target whose host does NOT resolve is REFUSED
     (SSRFBlocked) — the fail-open hole is closed.
  B. A WEB_APP target that resolves to a public IP passes the gate.
  C. An LLM target (AI_CHATBOT) whose host does not resolve is NOT hard-blocked
     (best-effort retained — its connector pins per request).

Run (no compose services needed):
    cd apps/api && PYTHONPATH=. uv run --no-sync python scripts/verify_scanner_fail_closed.py
"""

import sys

from app.core.scope import SSRFBlocked, assert_resolved_ip_in_scope, best_effort_resolver
from app.models.engagement import ScopeItem, ScopeKind, ScopeMatcher
from app.models.target import Target, TargetType
from app.services.scans import _system_resolver

# Reserved by RFC 6761 to never resolve — a stable "unresolvable host" anywhere.
UNRESOLVABLE = "nonexistent-host.invalid"

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


def _target(target_type: TargetType, host: str) -> Target:
    import uuid

    return Target(
        id=uuid.uuid4(),
        engagement_id=uuid.uuid4(),
        name="t",
        target_type=target_type,
        primary_value=f"https://{host}/",
    )


def _allow(host: str) -> list[ScopeItem]:
    return [ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.DOMAIN, value=host)]


def main() -> int:
    # Exactly the production wrapping: an unresolvable host becomes [] here, and
    # the gate then decides fail-closed (scanner) vs best-effort (LLM).
    resolve = best_effort_resolver(_system_resolver())

    # A. WEB_APP + unresolvable host → refused (fail-closed).
    try:
        assert_resolved_ip_in_scope(
            _target(TargetType.WEB_APP, UNRESOLVABLE), _allow(UNRESOLVABLE), resolve=resolve
        )
        check("unresolvable DAST target is refused (fail-closed)", False)
    except SSRFBlocked:
        check("unresolvable DAST target is refused (fail-closed)", True)

    # B. WEB_APP + resolvable public host → passes.
    try:
        assert_resolved_ip_in_scope(
            _target(TargetType.WEB_APP, "example.com"), _allow("example.com"), resolve=resolve
        )
        check("resolvable public DAST target passes", True)
    except SSRFBlocked as exc:
        # example.com resolves to a public IP; a block here would be a false positive.
        check(f"resolvable public DAST target passes (got {exc})", False)

    # C. LLM target + unresolvable host → NOT hard-blocked (best-effort).
    try:
        assert_resolved_ip_in_scope(
            _target(TargetType.AI_CHATBOT, UNRESOLVABLE), _allow(UNRESOLVABLE), resolve=resolve
        )
        check("unresolvable LLM target keeps best-effort (not hard-blocked)", True)
    except SSRFBlocked:
        check("unresolvable LLM target keeps best-effort (not hard-blocked)", False)

    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
