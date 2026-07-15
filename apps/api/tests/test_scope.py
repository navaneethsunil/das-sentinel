"""M1-B9: scope-enforcement keystone. Pure/deterministic, so verified
exhaustively here (no infra) — every typed failure mode, deny-wins precedence,
matcher matching, server-derived intensity, and high-risk approval validity.
This is the product-safety core; negatives are mandatory (CLAUDE.md §5)."""

import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.core.scope import (
    EngagementInactive,
    ExecutionAuthorization,
    HighRiskNotApproved,
    IntensityNotAuthorized,
    Operation,
    OperationKind,
    OutsideTestWindow,
    ROENotAccepted,
    ROEStale,
    ROETermsMismatch,
    ScopeViolation,
    authorize_operation,
    compute_operation_digest,
    derive_effective_intensity,
)
from app.models.engagement import (
    ApprovalGate,
    ApprovalStatus,
    Engagement,
    EngagementStatus,
    ROEAcknowledgement,
    ScanIntensity,
    ScopeItem,
    ScopeKind,
    ScopeMatcher,
)
from app.models.target import Target, TargetType

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
ENG_ID = uuid.uuid4()
TARGET_ID = uuid.uuid4()


def _scope(kind: ScopeKind, matcher: ScopeMatcher, value: str) -> ScopeItem:
    return ScopeItem(kind=kind, matcher_type=matcher, value=value)


def _engagement(**overrides: object) -> Engagement:
    base: dict[str, object] = {
        "id": ENG_ID,
        "organization_id": uuid.uuid4(),
        "name": "Acme",
        "client_system_name": "acme-web",
        "status": EngagementStatus.ACTIVE,
        "test_window_start": NOW - timedelta(days=1),
        "test_window_end": NOW + timedelta(days=1),
        "rate_limit_rps": 5,
        "max_intensity": ScanIntensity.SAFE_ACTIVE,
        "hosted_models_allowed": False,
    }
    base.update(overrides)
    return Engagement(**base)


def _target(primary_value: str = "https://app.example.com/") -> Target:
    return Target(
        id=TARGET_ID,
        engagement_id=ENG_ID,
        name="web",
        target_type=TargetType.WEB_APP,
        primary_value=primary_value,
    )


def _accepted_roe(engagement: Engagement, scope_items: list[ScopeItem]) -> ROEAcknowledgement:
    """A ROE ack consistent with the engagement's current state (matches hash)."""
    from app.services.roe import render_current_roe

    _, _, terms, content_hash = render_current_roe(engagement, scope_items)
    return ROEAcknowledgement(
        id=uuid.uuid4(),
        engagement_id=engagement.id,
        accepted_by=uuid.uuid4(),
        accepted_at=NOW - timedelta(hours=1),
        roe_text="frozen",
        scope_snapshot=[],
        terms_snapshot=terms,
        content_hash=content_hash,
    )


ALLOW = [_scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "app.example.com")]
SAFE_OP = Operation(target_id=TARGET_ID, kind=OperationKind.SAFE_ACTIVE_SCAN)


def _authorize(engagement, target, scope_items, op=SAFE_OP, roe_ack=..., **kw):
    if roe_ack is ...:
        roe_ack = _accepted_roe(engagement, scope_items)
    return authorize_operation(
        engagement=engagement,
        target=target,
        scope_items=scope_items,
        op=op,
        roe_ack=roe_ack,
        now=kw.pop("now", NOW),
        **kw,
    )


# ── happy path ───────────────────────────────────────────────────────────────
def test_authorizes_valid_operation() -> None:
    eng = _engagement()
    auth = _authorize(eng, _target(), ALLOW)
    assert isinstance(auth, ExecutionAuthorization)
    assert auth.effective_intensity == ScanIntensity.SAFE_ACTIVE
    assert auth.approval_id is None
    assert auth.authorized_at == NOW
    assert len(auth.operation_digest) == 32


# ── typed failure modes ──────────────────────────────────────────────────────
def test_inactive_engagement() -> None:
    eng = _engagement(status=EngagementStatus.DRAFT)
    with pytest.raises(EngagementInactive):
        _authorize(eng, _target(), ALLOW)


def test_roe_not_accepted() -> None:
    eng = _engagement()
    with pytest.raises(ROENotAccepted):
        _authorize(eng, _target(), ALLOW, roe_ack=None)


def test_roe_ack_for_other_engagement() -> None:
    eng = _engagement()
    ack = _accepted_roe(eng, ALLOW)
    ack.engagement_id = uuid.uuid4()  # belongs elsewhere
    with pytest.raises(ROENotAccepted):
        _authorize(eng, _target(), ALLOW, roe_ack=ack)


def test_roe_terms_mismatch() -> None:
    eng = _engagement()
    ack = _accepted_roe(eng, ALLOW)
    # Engagement's live rate now differs from the frozen terms.
    changed = _engagement(rate_limit_rps=99)
    with pytest.raises(ROETermsMismatch):
        _authorize(changed, _target(), ALLOW, roe_ack=ack)


def test_roe_stale_on_scope_change() -> None:
    eng = _engagement()
    ack = _accepted_roe(eng, ALLOW)
    # Scope changed after acceptance (terms unchanged) → stale hash.
    new_scope = [*ALLOW, _scope(ScopeKind.DENY, ScopeMatcher.DOMAIN, "secret.example.com")]
    with pytest.raises(ROEStale):
        _authorize(eng, _target(), new_scope, roe_ack=ack)


def test_outside_test_window_before() -> None:
    eng = _engagement()
    with pytest.raises(OutsideTestWindow):
        _authorize(eng, _target(), ALLOW, now=eng.test_window_start - timedelta(seconds=1))


def test_outside_test_window_after() -> None:
    eng = _engagement()
    with pytest.raises(OutsideTestWindow):
        _authorize(eng, _target(), ALLOW, now=eng.test_window_end + timedelta(seconds=1))


def test_missing_window_fails_closed() -> None:
    eng = _engagement(test_window_start=None, test_window_end=None)
    ack = _accepted_roe(eng, ALLOW)
    with pytest.raises(OutsideTestWindow):
        _authorize(eng, _target(), ALLOW, roe_ack=ack)


def test_scope_violation_no_allow_match() -> None:
    eng = _engagement()
    with pytest.raises(ScopeViolation):
        _authorize(eng, _target("https://other.example.org/"), ALLOW)


def test_scope_violation_target_wrong_engagement() -> None:
    eng = _engagement()
    target = _target()
    target.engagement_id = uuid.uuid4()
    with pytest.raises(ScopeViolation):
        _authorize(eng, target, ALLOW)


def test_deny_wins_over_allow() -> None:
    eng = _engagement()
    scope = [
        _scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "app.example.com"),
        _scope(ScopeKind.DENY, ScopeMatcher.DOMAIN, "app.example.com"),
    ]
    with pytest.raises(ScopeViolation):
        _authorize(eng, _target(), scope)


def test_intensity_not_authorized() -> None:
    eng = _engagement(max_intensity=ScanIntensity.PASSIVE)
    op = Operation(target_id=TARGET_ID, kind=OperationKind.SAFE_ACTIVE_SCAN)
    with pytest.raises(IntensityNotAuthorized):
        _authorize(eng, _target(), ALLOW, op=op)


# ── matcher matching ─────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("matcher", "value", "primary", "should_match"),
    [
        (ScopeMatcher.DOMAIN, "app.example.com", "https://app.example.com/x", True),
        (ScopeMatcher.DOMAIN, "*.example.com", "https://api.example.com", True),
        (ScopeMatcher.DOMAIN, "*.example.com", "https://example.com", True),
        (ScopeMatcher.DOMAIN, "app.example.com", "https://evil.example.com", False),
        (ScopeMatcher.IP_CIDR, "10.0.0.0/24", "http://10.0.0.7/", True),
        (ScopeMatcher.IP_CIDR, "10.0.0.0/24", "http://10.0.1.7/", False),
        (ScopeMatcher.IP_CIDR, "10.0.0.0/24", "https://app.example.com", False),  # host, not IP
        (
            ScopeMatcher.URL,
            "https://app.example.com/admin",
            "https://app.example.com/admin/x",
            True,
        ),
        (ScopeMatcher.URL, "https://app.example.com/admin", "https://app.example.com/other", False),
        (ScopeMatcher.URL, "https://app.example.com/admin", "http://app.example.com/admin", False),
    ],
)
def test_scope_matching(
    matcher: ScopeMatcher, value: str, primary: str, should_match: bool
) -> None:
    eng = _engagement()
    scope = [_scope(ScopeKind.ALLOW, matcher, value)]
    ack = _accepted_roe(eng, scope)
    if should_match:
        assert _authorize(eng, _target(primary), scope, roe_ack=ack)
    else:
        with pytest.raises(ScopeViolation):
            _authorize(eng, _target(primary), scope, roe_ack=ack)


# ── server-derived intensity ─────────────────────────────────────────────────
def test_effective_intensity_is_derived_not_declared() -> None:
    # BRUTE_FORCE always derives HIGH_RISK regardless of what a caller might wish.
    assert (
        derive_effective_intensity(Operation(target_id=TARGET_ID, kind=OperationKind.BRUTE_FORCE))
        == ScanIntensity.HIGH_RISK
    )
    assert (
        derive_effective_intensity(Operation(target_id=TARGET_ID, kind=OperationKind.PASSIVE_RECON))
        == ScanIntensity.PASSIVE
    )


# ── high-risk approval ───────────────────────────────────────────────────────
HR_OP = Operation(target_id=TARGET_ID, kind=OperationKind.EXPLOIT_VALIDATION)


def _valid_approval(eng: Engagement, roe_ack: ROEAcknowledgement) -> ApprovalGate:
    digest = compute_operation_digest(eng.id, HR_OP, ScanIntensity.HIGH_RISK)
    return ApprovalGate(
        id=uuid.uuid4(),
        engagement_id=eng.id,
        target_id=TARGET_ID,
        requested_by=uuid.uuid4(),
        action_type="exploit_validation",
        justification="approved",
        operation_digest=digest,
        roe_ack_id=roe_ack.id,
        policy_version="v1",
        status=ApprovalStatus.APPROVED,
        decided_by=uuid.uuid4(),
        decided_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
    )


def _hr_engagement() -> Engagement:
    return _engagement(max_intensity=ScanIntensity.HIGH_RISK)


def test_high_risk_requires_approval() -> None:
    eng = _hr_engagement()
    with pytest.raises(HighRiskNotApproved):
        _authorize(eng, _target(), ALLOW, op=HR_OP, approval=None)


def test_high_risk_with_valid_approval_succeeds() -> None:
    eng = _hr_engagement()
    ack = _accepted_roe(eng, ALLOW)
    approval = _valid_approval(eng, ack)
    auth = _authorize(eng, _target(), ALLOW, op=HR_OP, roe_ack=ack, approval=approval)
    assert auth.effective_intensity == ScanIntensity.HIGH_RISK
    assert auth.approval_id == approval.id


@pytest.mark.parametrize(
    "mutate",
    [
        lambda a: setattr(a, "status", ApprovalStatus.PENDING),
        lambda a: setattr(a, "status", ApprovalStatus.DENIED),
        lambda a: setattr(a, "revoked_at", NOW),
        lambda a: setattr(a, "expires_at", NOW - timedelta(seconds=1)),
        lambda a: setattr(a, "target_id", uuid.uuid4()),
        lambda a: setattr(a, "engagement_id", uuid.uuid4()),
        lambda a: setattr(a, "roe_ack_id", uuid.uuid4()),
        lambda a: setattr(a, "operation_digest", b"\x00" * 32),
    ],
)
def test_high_risk_rejects_invalid_approval(mutate) -> None:
    eng = _hr_engagement()
    ack = _accepted_roe(eng, ALLOW)
    approval = _valid_approval(eng, ack)
    mutate(approval)
    with pytest.raises(HighRiskNotApproved):
        _authorize(eng, _target(), ALLOW, op=HR_OP, roe_ack=ack, approval=approval)


def test_high_risk_policy_version_mismatch() -> None:
    eng = _hr_engagement()
    ack = _accepted_roe(eng, ALLOW)
    approval = _valid_approval(eng, ack)
    with pytest.raises(HighRiskNotApproved):
        _authorize(
            eng, _target(), ALLOW, op=HR_OP, roe_ack=ack, approval=approval, policy_version="v2"
        )


def test_operation_digest_is_stable_and_binds_fields() -> None:
    d1 = compute_operation_digest(ENG_ID, HR_OP, ScanIntensity.HIGH_RISK)
    d2 = compute_operation_digest(ENG_ID, HR_OP, ScanIntensity.HIGH_RISK)
    assert d1 == d2
    other = compute_operation_digest(
        ENG_ID, replace(HR_OP, kind=OperationKind.BRUTE_FORCE), ScanIntensity.HIGH_RISK
    )
    assert d1 != other
