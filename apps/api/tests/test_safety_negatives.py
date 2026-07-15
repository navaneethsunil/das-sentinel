"""M1-T1: release-blocking negative safety tests (CLAUDE.md §5, exit gate).

Every way an operation can be unsafe must be blocked AND audited. These drive
the audited authorization wrapper so each case asserts both the typed refusal
and an audit event with outcome='blocked' carrying the right machine reason.
The pure keystone's raise-paths are covered exhaustively in test_scope.py; this
suite pins the *audited* behavior that the exit gate requires."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

from app.core.scope import Operation, OperationKind, compute_operation_digest
from app.models.audit import AuditOutcome
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
from app.services.authorization import authorize_audited
from app.services.roe import render_current_roe

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
ENG_ID = uuid.uuid4()
TARGET_ID = uuid.uuid4()
ORG_ID = uuid.uuid4()
ACTOR = uuid.uuid4()


def _scope(kind: ScopeKind, matcher: ScopeMatcher, value: str) -> ScopeItem:
    return ScopeItem(kind=kind, matcher_type=matcher, value=value)


ALLOW = [_scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "app.example.com")]


def _engagement(**overrides: object) -> Engagement:
    base: dict[str, object] = {
        "id": ENG_ID,
        "organization_id": ORG_ID,
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


def _target() -> Target:
    return Target(
        id=TARGET_ID,
        engagement_id=ENG_ID,
        name="web",
        target_type=TargetType.WEB_APP,
        primary_value="https://app.example.com/",
    )


def _accepted_roe(engagement: Engagement, scope_items: list[ScopeItem]) -> ROEAcknowledgement:
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


def _mock_audit() -> MagicMock:
    audit = MagicMock()
    audit.log = AsyncMock()
    return audit


SAFE_OP = Operation(target_id=TARGET_ID, kind=OperationKind.SAFE_ACTIVE_SCAN)


async def _run(engagement, scope_items, *, op=SAFE_OP, roe_ack=..., now=NOW, approval=None):
    if roe_ack is ...:
        roe_ack = _accepted_roe(engagement, scope_items)
    audit = _mock_audit()
    from app.core.scope import ScopeError

    raised: ScopeError | None = None
    try:
        await authorize_audited(
            audit,
            actor_user_id=ACTOR,
            organization_id=ORG_ID,
            engagement=engagement,
            target=_target(),
            scope_items=scope_items,
            op=op,
            roe_ack=roe_ack,
            now=now,
            approval=approval,
        )
    except ScopeError as exc:
        raised = exc
    return raised, audit


def _blocked_reason(audit: MagicMock) -> str | None:
    audit.log.assert_awaited_once()
    kwargs = audit.log.await_args.kwargs
    assert kwargs["outcome"] is AuditOutcome.BLOCKED
    return kwargs["detail"]["reason"]


# ── the exit-gate negative matrix ────────────────────────────────────────────
async def test_blocked_when_engagement_inactive() -> None:
    raised, audit = await _run(_engagement(status=EngagementStatus.DRAFT), ALLOW)
    assert raised is not None and _blocked_reason(audit) == "engagement_inactive"


async def test_blocked_when_roe_not_accepted() -> None:
    raised, audit = await _run(_engagement(), ALLOW, roe_ack=None)
    assert raised is not None and _blocked_reason(audit) == "roe_not_accepted"


async def test_blocked_on_roe_terms_drift() -> None:
    eng = _engagement()
    ack = _accepted_roe(eng, ALLOW)
    raised, audit = await _run(_engagement(rate_limit_rps=99), ALLOW, roe_ack=ack)
    assert raised is not None and _blocked_reason(audit) == "roe_terms_mismatch"


async def test_blocked_on_scope_change_stale_roe() -> None:
    eng = _engagement()
    ack = _accepted_roe(eng, ALLOW)
    new_scope = [*ALLOW, _scope(ScopeKind.DENY, ScopeMatcher.DOMAIN, "x.example.com")]
    raised, audit = await _run(eng, new_scope, roe_ack=ack)
    assert raised is not None and _blocked_reason(audit) == "roe_stale"


async def test_blocked_outside_test_window() -> None:
    eng = _engagement()
    raised, audit = await _run(eng, ALLOW, now=eng.test_window_end + timedelta(seconds=1))
    assert raised is not None and _blocked_reason(audit) == "outside_test_window"


async def test_blocked_when_no_scope_defined() -> None:
    eng = _engagement()
    ack = _accepted_roe(eng, [])
    raised, audit = await _run(eng, [], roe_ack=ack)
    assert raised is not None and _blocked_reason(audit) == "scope_violation"


async def test_blocked_out_of_scope_target() -> None:
    eng = _engagement()
    scope = [_scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "other.example.org")]
    ack = _accepted_roe(eng, scope)
    raised, audit = await _run(eng, scope, roe_ack=ack)
    assert raised is not None and _blocked_reason(audit) == "scope_violation"


async def test_blocked_blocklist_overrides_allowlist() -> None:
    eng = _engagement()
    scope = [
        _scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "app.example.com"),
        _scope(ScopeKind.DENY, ScopeMatcher.DOMAIN, "app.example.com"),
    ]
    ack = _accepted_roe(eng, scope)
    raised, audit = await _run(eng, scope, roe_ack=ack)
    assert raised is not None and _blocked_reason(audit) == "scope_violation"


async def test_blocked_over_max_intensity() -> None:
    eng = _engagement(max_intensity=ScanIntensity.PASSIVE)
    raised, audit = await _run(eng, ALLOW)
    assert raised is not None and _blocked_reason(audit) == "intensity_not_authorized"


async def test_blocked_intensity_escalation_via_high_risk_without_approval() -> None:
    # A high-risk op needs an approval; without one it is blocked even if the
    # engagement max permits high-risk (the escalation-via-config guard).
    eng = _engagement(max_intensity=ScanIntensity.HIGH_RISK)
    op = Operation(target_id=TARGET_ID, kind=OperationKind.EXPLOIT_VALIDATION)
    raised, audit = await _run(eng, ALLOW, op=op, approval=None)
    assert raised is not None and _blocked_reason(audit) == "high_risk_not_approved"


# ── the allow path is audited too ────────────────────────────────────────────
async def test_authorized_operation_is_audited_success() -> None:
    eng = _engagement()
    audit = _mock_audit()
    from app.services.authorization import authorize_audited as run

    auth = await run(
        audit,
        actor_user_id=ACTOR,
        organization_id=ORG_ID,
        engagement=eng,
        target=_target(),
        scope_items=ALLOW,
        op=SAFE_OP,
        roe_ack=_accepted_roe(eng, ALLOW),
        now=NOW,
    )
    assert auth.effective_intensity is ScanIntensity.SAFE_ACTIVE
    audit.log.assert_awaited_once()
    assert audit.log.await_args.kwargs["outcome"] is AuditOutcome.SUCCESS


async def test_high_risk_with_valid_approval_authorized_and_audited() -> None:
    eng = _engagement(max_intensity=ScanIntensity.HIGH_RISK)
    ack = _accepted_roe(eng, ALLOW)
    op = Operation(target_id=TARGET_ID, kind=OperationKind.EXPLOIT_VALIDATION)
    digest = compute_operation_digest(eng.id, op, ScanIntensity.HIGH_RISK)
    approval = ApprovalGate(
        id=uuid.uuid4(),
        engagement_id=eng.id,
        target_id=TARGET_ID,
        requested_by=uuid.uuid4(),
        action_type="exploit_validation",
        justification="ok",
        operation_digest=digest,
        roe_ack_id=ack.id,
        policy_version="1",
        status=ApprovalStatus.APPROVED,
        decided_by=uuid.uuid4(),
        decided_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
    )
    audit = _mock_audit()
    auth = await authorize_audited(
        audit,
        actor_user_id=ACTOR,
        organization_id=ORG_ID,
        engagement=eng,
        target=_target(),
        scope_items=ALLOW,
        op=op,
        roe_ack=ack,
        now=NOW,
        approval=approval,
    )
    assert auth.approval_id == approval.id
    assert audit.log.await_args.kwargs["outcome"] is AuditOutcome.SUCCESS
