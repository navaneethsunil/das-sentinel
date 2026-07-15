"""M1-SEC3: scope host→resolved-IP SSRF-precursor check (TM-1 partial).

Pure given an injected resolver, so tested exhaustively here: a target whose
host resolves to an internal/metadata address is blocked unless an ip_cidr allow
rule explicitly puts it in scope, and a resolved IP matching an ip_cidr deny is
always blocked. Public IPs pass. (DNS-rebinding is why this runs at scan time
against the *resolved* IP, not just the hostname string.)"""

import ipaddress
import uuid

import pytest

from app.core.scope import SSRFBlocked, assert_resolved_ip_in_scope, is_dangerous_ip
from app.models.engagement import ScopeItem, ScopeKind, ScopeMatcher
from app.models.target import Target, TargetType


def _target(primary_value: str) -> Target:
    return Target(
        id=uuid.uuid4(),
        engagement_id=uuid.uuid4(),
        name="t",
        target_type=TargetType.WEB_APP,
        primary_value=primary_value,
    )


def _scope(kind: ScopeKind, value: str) -> ScopeItem:
    return ScopeItem(kind=kind, matcher_type=ScopeMatcher.IP_CIDR, value=value)


def _resolver(*ips: str):
    return lambda _host: list(ips)


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",  # loopback
        "169.254.169.254",  # cloud metadata (link-local)
        "10.1.2.3",  # RFC-1918
        "172.16.0.9",  # RFC-1918
        "192.168.1.10",  # RFC-1918
        "0.0.0.0",  # unspecified
        "::1",  # IPv6 loopback
        "fd00::1",  # IPv6 unique-local
    ],
)
def test_dangerous_ips_classified(ip: str) -> None:
    assert is_dangerous_ip(ipaddress.ip_address(ip)) is True


def test_public_ip_not_dangerous() -> None:
    assert is_dangerous_ip(ipaddress.ip_address("93.184.216.34")) is False


@pytest.mark.parametrize(
    "resolved",
    ["127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.0.1", "::1"],
)
def test_internal_resolution_blocked(resolved: str) -> None:
    target = _target("https://app.example.com")
    allow = [
        ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.DOMAIN, value="app.example.com")
    ]
    with pytest.raises(SSRFBlocked):
        assert_resolved_ip_in_scope(target, allow, resolve=_resolver(resolved))


def test_public_resolution_allowed() -> None:
    target = _target("https://app.example.com")
    allow = [
        ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.DOMAIN, value="app.example.com")
    ]
    assert_resolved_ip_in_scope(target, allow, resolve=_resolver("93.184.216.34"))  # no raise


def test_internal_ip_explicitly_in_scope_allowed() -> None:
    # An internal range can be legitimately in scope (e.g. an internal engagement).
    target = _target("https://internal.example.com")
    scope = [_scope(ScopeKind.ALLOW, "10.0.0.0/24")]
    assert_resolved_ip_in_scope(target, scope, resolve=_resolver("10.0.0.5"))  # no raise


def test_metadata_ip_not_covered_by_broad_allow_still_blocked() -> None:
    # Allowing 10.0.0.0/8 does not implicitly allow the 169.254 metadata IP.
    target = _target("https://app.example.com")
    scope = [_scope(ScopeKind.ALLOW, "10.0.0.0/8")]
    with pytest.raises(SSRFBlocked):
        assert_resolved_ip_in_scope(target, scope, resolve=_resolver("169.254.169.254"))


def test_deny_cidr_blocks_even_public_ip() -> None:
    target = _target("https://app.example.com")
    scope = [
        ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.DOMAIN, value="app.example.com"),
        _scope(ScopeKind.DENY, "93.184.216.0/24"),
    ]
    with pytest.raises(SSRFBlocked):
        assert_resolved_ip_in_scope(target, scope, resolve=_resolver("93.184.216.34"))


def test_multiple_ips_any_internal_blocks() -> None:
    # DNS returning several A records: one internal is enough to block.
    target = _target("https://app.example.com")
    allow = [
        ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.DOMAIN, value="app.example.com")
    ]
    with pytest.raises(SSRFBlocked):
        assert_resolved_ip_in_scope(target, allow, resolve=_resolver("93.184.216.34", "127.0.0.1"))


def test_non_ip_resolver_result_blocked() -> None:
    # A resolver returning garbage must fail closed, never pass through.
    target = _target("https://app.example.com")
    allow = [
        ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.DOMAIN, value="app.example.com")
    ]
    with pytest.raises(SSRFBlocked):
        assert_resolved_ip_in_scope(target, allow, resolve=_resolver("not-an-ip"))
