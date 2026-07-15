"""Rules-of-Engagement rendering, snapshots, and content hashing (M1-B8).

Acceptance freezes three things and hashes them together:
  - roe_text        the full authorization text shown to the accepting user
  - scope_snapshot  the allow/deny items (authorization-relevant fields only)
  - terms_snapshot  {test_window_start, test_window_end, rate_limit_rps, max_intensity}

content_hash = SHA-256 over (roe_text ‖ canonical(scope) ‖ canonical(terms)).
The same functions run at acceptance and at every re-acceptance check, so if
scope OR any frozen term changes the recomputed hash diverges from the stored
one and re-acceptance is required (DATABASE_SCHEMA §4, CLAUDE.md §2.1). Pure and
deterministic — the scope-enforcement keystone (M1-B9) reuses these to prove the
live engagement still matches what was accepted.
"""

import hashlib
import json
from collections.abc import Iterable
from datetime import datetime

from app.models.engagement import Engagement, ScopeItem

# Bump when the ROE template text changes — old acknowledgements keep their
# frozen roe_text, but new renders differ, correctly forcing re-acceptance.
ROE_TEMPLATE_VERSION = "1"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def build_terms_snapshot(engagement: Engagement) -> dict[str, object]:
    return {
        "test_window_start": _iso(engagement.test_window_start),
        "test_window_end": _iso(engagement.test_window_end),
        "rate_limit_rps": engagement.rate_limit_rps,
        "max_intensity": engagement.max_intensity.value,
    }


def build_scope_snapshot(scope_items: Iterable[ScopeItem]) -> list[dict[str, str]]:
    """Authorization-relevant fields only (kind/matcher/value), sorted for a
    stable hash. Notes are descriptive, not authorizing, so editing a note does
    not force re-acceptance."""
    rows = [
        {"kind": s.kind.value, "matcher_type": s.matcher_type.value, "value": s.value}
        for s in scope_items
    ]
    return sorted(rows, key=lambda r: (r["kind"], r["matcher_type"], r["value"]))


def render_roe_text(
    engagement: Engagement, scope_snapshot: list[dict[str, str]], terms: dict[str, object]
) -> str:
    """Deterministic authorization text. Must be reproducible from the same
    inputs so the content hash is stable across renders."""
    allow = [r for r in scope_snapshot if r["kind"] == "allow"]
    deny = [r for r in scope_snapshot if r["kind"] == "deny"]

    def _lines(rows: list[dict[str, str]]) -> str:
        if not rows:
            return "  (none)"
        return "\n".join(f"  - {r['matcher_type']}: {r['value']}" for r in rows)

    return (
        f"DAS Sentinel Rules of Engagement (template v{ROE_TEMPLATE_VERSION})\n"
        f"Engagement: {engagement.name}\n"
        f"Client system: {engagement.client_system_name}\n"
        f"Test window: {terms['test_window_start']} .. {terms['test_window_end']}\n"
        f"Maximum intensity: {terms['max_intensity']}\n"
        f"Rate limit (rps): {terms['rate_limit_rps']}\n"
        "In-scope (allow):\n"
        f"{_lines(allow)}\n"
        "Out-of-scope (deny — always wins):\n"
        f"{_lines(deny)}\n"
        "Testing is authorized only against in-scope targets, within the test "
        "window, at or below the maximum intensity, and never against out-of-scope "
        "targets. High-risk actions require a separate approval."
    )


def _canonical(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_content_hash(
    roe_text: str, scope_snapshot: list[dict[str, str]], terms_snapshot: dict[str, object]
) -> bytes:
    payload = f"{roe_text}\n{_canonical(scope_snapshot)}\n{_canonical(terms_snapshot)}"
    return hashlib.sha256(payload.encode("utf-8")).digest()


def render_current_roe(
    engagement: Engagement, scope_items: Iterable[ScopeItem]
) -> tuple[str, list[dict[str, str]], dict[str, object], bytes]:
    """Render the ROE for the engagement's CURRENT state and hash it.
    Returns (roe_text, scope_snapshot, terms_snapshot, content_hash)."""
    terms = build_terms_snapshot(engagement)
    scope_snapshot = build_scope_snapshot(scope_items)
    roe_text = render_roe_text(engagement, scope_snapshot, terms)
    return roe_text, scope_snapshot, terms, compute_content_hash(roe_text, scope_snapshot, terms)
