"""M1-B8: ROE snapshotting + content hashing. The endpoint accept/re-accept
flow is verified live (scripts/verify_roe.py); here we pin that the hash is
deterministic and changes iff scope or a frozen term changes (the re-acceptance
trigger)."""

import uuid
from datetime import UTC, datetime

from app.models.engagement import Engagement, ScanIntensity, ScopeItem, ScopeKind, ScopeMatcher
from app.services.roe import (
    build_scope_snapshot,
    compute_content_hash,
    render_current_roe,
)


def _engagement(**overrides: object) -> Engagement:
    base = {
        "id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "name": "Acme",
        "client_system_name": "acme-web",
        "test_window_start": datetime(2026, 8, 1, tzinfo=UTC),
        "test_window_end": datetime(2026, 8, 31, tzinfo=UTC),
        "rate_limit_rps": 5,
        "max_intensity": ScanIntensity.SAFE_ACTIVE,
        "hosted_models_allowed": False,
    }
    base.update(overrides)
    return Engagement(**base)


def _scope(kind: ScopeKind, matcher: ScopeMatcher, value: str) -> ScopeItem:
    return ScopeItem(kind=kind, matcher_type=matcher, value=value)


ALLOW_DOMAIN = _scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "app.example.com")


def test_hash_is_deterministic() -> None:
    eng = _engagement()
    _, _, _, h1 = render_current_roe(eng, [ALLOW_DOMAIN])
    _, _, _, h2 = render_current_roe(eng, [ALLOW_DOMAIN])
    assert h1 == h2
    assert len(h1) == 32  # SHA-256


def test_scope_snapshot_order_independent() -> None:
    a = _scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "a.example.com")
    b = _scope(ScopeKind.DENY, ScopeMatcher.IP_CIDR, "10.0.0.0/24")
    assert build_scope_snapshot([a, b]) == build_scope_snapshot([b, a])
    eng = _engagement()
    _, _, _, h1 = render_current_roe(eng, [a, b])
    _, _, _, h2 = render_current_roe(eng, [b, a])
    assert h1 == h2  # hash stable regardless of row order


def test_hash_changes_when_scope_changes() -> None:
    eng = _engagement()
    _, _, _, base = render_current_roe(eng, [ALLOW_DOMAIN])
    extra = _scope(ScopeKind.DENY, ScopeMatcher.DOMAIN, "secret.example.com")
    _, _, _, changed = render_current_roe(eng, [ALLOW_DOMAIN, extra])
    assert base != changed


def test_hash_changes_when_each_frozen_term_changes() -> None:
    eng = _engagement()
    _, _, _, base = render_current_roe(eng, [ALLOW_DOMAIN])
    for override in (
        {"rate_limit_rps": 10},
        {"max_intensity": ScanIntensity.HIGH_RISK},
        {"test_window_start": datetime(2026, 9, 1, tzinfo=UTC)},
        {"test_window_end": datetime(2026, 9, 30, tzinfo=UTC)},
    ):
        _, _, _, h = render_current_roe(_engagement(**override), [ALLOW_DOMAIN])
        assert h != base, f"changing {override} must change the hash"


def test_notes_do_not_affect_hash() -> None:
    eng = _engagement()
    plain = _scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "app.example.com")
    noted = _scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "app.example.com")
    noted.notes = "primary web app"
    _, _, _, h1 = render_current_roe(eng, [plain])
    _, _, _, h2 = render_current_roe(eng, [noted])
    assert h1 == h2  # notes are descriptive, not authorization-relevant


def test_content_hash_matches_manual_recompute() -> None:
    eng = _engagement()
    roe_text, scope_snapshot, terms, content_hash = render_current_roe(eng, [ALLOW_DOMAIN])
    assert compute_content_hash(roe_text, scope_snapshot, terms) == content_hash
