"""Scope-enforcement keystone (M1-B9) — the safety core (CLAUDE.md §2).

authorize_operation is the single gate every scan/action passes through, at
request time AND again in the worker (ARCHITECTURE §5.2). It is PURE and
DETERMINISTIC: `now`, `roe_ack`, `scope_items`, and any `approval` are injected,
nothing is read from the DB or clock here, so it is exhaustively unit-testable
and behaves identically in the API and the worker.

Effective intensity is SERVER-DERIVED from the typed operation kind — never the
caller's declared value — so a client cannot smuggle a high-risk action in at a
low intensity. Every failure raises a specific typed error (subclass of
ScopeError, each carrying a machine `reason`); the caller audits the block with
outcome='blocked'. Fail closed: anything unproven is denied.
"""

import enum
import hashlib
import ipaddress
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse

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
from app.models.target import Target
from app.services.roe import build_terms_snapshot, render_current_roe

# host → list of resolved IP strings. Injected so the keystone stays pure.
Resolver = Callable[[str], list[str]]


# ── Typed operation ──────────────────────────────────────────────────────────
class OperationKind(enum.Enum):
    """What the caller wants to do. Intensity is derived from this, not declared."""

    PASSIVE_RECON = "passive_recon"
    SAFE_ACTIVE_SCAN = "safe_active_scan"
    AUTHENTICATED_SCAN = "authenticated_scan"
    EXPLOIT_VALIDATION = "exploit_validation"
    BRUTE_FORCE = "brute_force"
    LARGE_CRAWL = "large_crawl"
    DATA_MODIFYING = "data_modifying"


# Server-side derivation of effective intensity (extended as scanners land in M3).
OPERATION_INTENSITY: dict[OperationKind, ScanIntensity] = {
    OperationKind.PASSIVE_RECON: ScanIntensity.PASSIVE,
    OperationKind.SAFE_ACTIVE_SCAN: ScanIntensity.SAFE_ACTIVE,
    OperationKind.AUTHENTICATED_SCAN: ScanIntensity.AUTHENTICATED_ACTIVE,
    OperationKind.EXPLOIT_VALIDATION: ScanIntensity.HIGH_RISK,
    OperationKind.BRUTE_FORCE: ScanIntensity.HIGH_RISK,
    OperationKind.LARGE_CRAWL: ScanIntensity.HIGH_RISK,
    OperationKind.DATA_MODIFYING: ScanIntensity.HIGH_RISK,
}

# Total order for "effective <= engagement max".
INTENSITY_ORDER: dict[ScanIntensity, int] = {
    ScanIntensity.PASSIVE: 0,
    ScanIntensity.SAFE_ACTIVE: 1,
    ScanIntensity.AUTHENTICATED_ACTIVE: 2,
    ScanIntensity.HIGH_RISK: 3,
}


@dataclass(frozen=True)
class Operation:
    target_id: uuid.UUID
    kind: OperationKind


def derive_effective_intensity(op: Operation) -> ScanIntensity:
    return OPERATION_INTENSITY[op.kind]


def compute_operation_digest(
    engagement_id: uuid.UUID, op: Operation, effective_intensity: ScanIntensity
) -> bytes:
    """SHA-256 over the canonical operation subject. The API and worker both
    recompute this from the pending scan and require equality against an
    approval's stored digest, so an approval can't be paired with swapped
    execution fields (DATABASE_SCHEMA §4)."""
    payload = json.dumps(
        {
            "engagement_id": str(engagement_id),
            "target_id": str(op.target_id),
            "kind": op.kind.value,
            "effective_intensity": effective_intensity.value,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).digest()


# ── Typed failures ───────────────────────────────────────────────────────────
class ScopeError(Exception):
    """Base for every authorization denial. `reason` is a stable machine code
    the caller writes into the audit event (outcome='blocked')."""

    reason = "scope_error"


class EngagementInactive(ScopeError):
    reason = "engagement_inactive"


class ROENotAccepted(ScopeError):
    reason = "roe_not_accepted"


class ROEStale(ScopeError):
    reason = "roe_stale"


class ROETermsMismatch(ScopeError):
    reason = "roe_terms_mismatch"


class OutsideTestWindow(ScopeError):
    reason = "outside_test_window"


class ScopeViolation(ScopeError):
    reason = "scope_violation"


class IntensityNotAuthorized(ScopeError):
    reason = "intensity_not_authorized"


class HighRiskNotApproved(ScopeError):
    reason = "high_risk_not_approved"


class SSRFBlocked(ScopeError):
    reason = "ssrf_ip_blocked"


@dataclass(frozen=True)
class ExecutionAuthorization:
    """Immutable proof of a granted operation — persisted as the execution
    envelope and re-verified in the worker (ARCHITECTURE §5.2)."""

    engagement_id: uuid.UUID
    target_id: uuid.UUID
    effective_intensity: ScanIntensity
    operation_digest: bytes
    roe_ack_id: uuid.UUID
    approval_id: uuid.UUID | None
    authorized_at: datetime


# ── Target ↔ scope matching ──────────────────────────────────────────────────
def _target_host_and_url(primary_value: str) -> tuple[str | None, str | None]:
    parsed = urlparse(primary_value.strip())
    if parsed.scheme and parsed.netloc:
        host = parsed.hostname.lower() if parsed.hostname else None
        return host, primary_value.strip()
    # Bare host / IP (no scheme).
    return primary_value.strip().lower() or None, None


def _url_prefix_match(target_url: str, base: str) -> bool:
    t, b = urlparse(target_url), urlparse(base)
    if t.scheme.lower() != b.scheme.lower():
        return False
    if (t.hostname or "").lower() != (b.hostname or "").lower() or t.port != b.port:
        return False
    base_path = b.path.rstrip("/")
    return t.path == b.path or t.path.startswith(base_path + "/") or base_path == ""


def _scope_matches(item: ScopeItem, host: str | None, url: str | None) -> bool:
    value = item.value
    if item.matcher_type == ScopeMatcher.DOMAIN:
        if host is None:
            return False
        if value.startswith("*."):
            return host == value[2:] or host.endswith(value[1:])
        return host == value
    if item.matcher_type == ScopeMatcher.IP_CIDR:
        if host is None:
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            # host→IP resolution is deferred to M2 (TM-1); a literal IP is
            # required to match a CIDR here. Fail closed (no match).
            return False
        return ip in ipaddress.ip_network(value, strict=False)
    if item.matcher_type in (ScopeMatcher.URL, ScopeMatcher.API_BASE):
        return url is not None and _url_prefix_match(url, value)
    if item.matcher_type == ScopeMatcher.REPO:
        return url is not None and (url == value or url.startswith(value))
    return False


def _check_scope(target: Target, scope_items: list[ScopeItem]) -> None:
    host, url = _target_host_and_url(target.primary_value)
    allow = [s for s in scope_items if s.kind == ScopeKind.ALLOW]
    deny = [s for s in scope_items if s.kind == ScopeKind.DENY]
    # Blocklist wins: a deny match blocks even if an allow also matches.
    if any(_scope_matches(d, host, url) for d in deny):
        raise ScopeViolation("target matches an out-of-scope (deny) rule")
    if not any(_scope_matches(a, host, url) for a in allow):
        raise ScopeViolation("target matches no in-scope (allow) rule")


# ── SSRF-precursor: host→resolved-IP scope check (M1-SEC3, TM-1 partial) ──────
# A target hostname can resolve (or be rebound) to an internal address — the
# classic SSRF pivot. We resolve the host and block any resolved IP in a
# dangerous range (loopback, link-local incl. 169.254.169.254 cloud metadata,
# RFC-1918/unique-local private, reserved, multicast, unspecified) unless an
# ip_cidr ALLOW rule explicitly puts it in scope; a matching ip_cidr DENY always
# blocks. `resolve` is injected (host → list[str]) so this stays pure and
# testable; the worker/API supply a real DNS resolver.


def is_dangerous_ip(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _ip_cidr_values(scope_items: list[ScopeItem], kind: ScopeKind) -> list[str]:
    return [
        s.value for s in scope_items if s.kind == kind and s.matcher_type == ScopeMatcher.IP_CIDR
    ]


def assert_resolved_ip_in_scope(
    target: Target,
    scope_items: list[ScopeItem],
    *,
    resolve: "Resolver",
) -> None:
    """Resolve the target host and raise SSRFBlocked if any resolved IP is out
    of scope: a dangerous internal address not explicitly allowed, or one that
    matches an ip_cidr deny rule. No-op for targets without a resolvable host
    (e.g. an uploaded archive's object key)."""
    host, _ = _target_host_and_url(target.primary_value)
    if host is None:
        return
    allow_cidrs = _ip_cidr_values(scope_items, ScopeKind.ALLOW)
    deny_cidrs = _ip_cidr_values(scope_items, ScopeKind.DENY)
    for ip_str in resolve(host):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFBlocked(f"resolver returned a non-IP value: {ip_str!r}") from None
        if any(ip in ipaddress.ip_network(c, strict=False) for c in deny_cidrs):
            raise SSRFBlocked(f"resolved IP {ip} matches an out-of-scope (deny) rule")
        if is_dangerous_ip(ip):
            explicitly_allowed = any(
                ip in ipaddress.ip_network(c, strict=False) for c in allow_cidrs
            )
            if not explicitly_allowed:
                raise SSRFBlocked(
                    f"resolved IP {ip} is in a blocked range "
                    "(loopback/link-local/metadata/private) and not explicitly in scope"
                )


def _check_high_risk_approval(
    engagement: Engagement,
    target: Target,
    roe_ack: ROEAcknowledgement,
    operation_digest: bytes,
    approval: ApprovalGate | None,
    now: datetime,
    policy_version: str | None,
) -> uuid.UUID:
    if approval is None:
        raise HighRiskNotApproved("high-risk operation requires an approval gate")
    checks = (
        approval.status == ApprovalStatus.APPROVED,
        approval.revoked_at is None,
        now < approval.expires_at,
        approval.engagement_id == engagement.id,
        approval.target_id == target.id,
        approval.roe_ack_id == roe_ack.id,
        approval.operation_digest == operation_digest,
        policy_version is None or approval.policy_version == policy_version,
    )
    if not all(checks):
        raise HighRiskNotApproved("no valid approval matches this exact operation")
    return approval.id


def authorize_operation(
    *,
    engagement: Engagement,
    target: Target,
    scope_items: list[ScopeItem],
    op: Operation,
    roe_ack: ROEAcknowledgement | None,
    now: datetime,
    approval: ApprovalGate | None = None,
    policy_version: str | None = None,
) -> ExecutionAuthorization:
    """Authorize one operation or raise a typed ScopeError. Checks, in order:
    engagement active → ROE accepted/current/terms-match → within test window →
    target in scope (deny wins) → effective intensity ≤ max → high-risk approved.
    """
    if engagement.status != EngagementStatus.ACTIVE:
        raise EngagementInactive(f"engagement status is {engagement.status.value}")

    if roe_ack is None or roe_ack.engagement_id != engagement.id:
        raise ROENotAccepted("no ROE acknowledgement for this engagement")

    # Terms mismatch is a more specific diagnosis than a general stale hash.
    if build_terms_snapshot(engagement) != roe_ack.terms_snapshot:
        raise ROETermsMismatch("engagement terms changed since ROE acceptance")
    _, _, _, current_hash = render_current_roe(engagement, scope_items)
    if current_hash != roe_ack.content_hash:
        raise ROEStale("scope or ROE text changed since acceptance")

    if (
        engagement.test_window_start is None
        or engagement.test_window_end is None
        or now < engagement.test_window_start
        or now > engagement.test_window_end
    ):
        raise OutsideTestWindow("now is outside the engagement test window")

    if target.engagement_id != engagement.id:
        raise ScopeViolation("target does not belong to this engagement")
    _check_scope(target, scope_items)

    effective = derive_effective_intensity(op)
    if INTENSITY_ORDER[effective] > INTENSITY_ORDER[engagement.max_intensity]:
        raise IntensityNotAuthorized(
            f"effective intensity {effective.value} exceeds max {engagement.max_intensity.value}"
        )

    digest = compute_operation_digest(engagement.id, op, effective)
    approval_id: uuid.UUID | None = None
    if effective == ScanIntensity.HIGH_RISK:
        approval_id = _check_high_risk_approval(
            engagement, target, roe_ack, digest, approval, now, policy_version
        )

    return ExecutionAuthorization(
        engagement_id=engagement.id,
        target_id=target.id,
        effective_intensity=effective,
        operation_digest=digest,
        roe_ack_id=roe_ack.id,
        approval_id=approval_id,
        authorized_at=now,
    )
