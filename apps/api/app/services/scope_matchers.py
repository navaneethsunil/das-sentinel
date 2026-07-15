"""Scope matcher validation + normalization (M1-B7).

Each scope_item's value must be well-formed for its matcher_type before it is
stored — a malformed allow/deny rule is a scope-enforcement hazard (a typo'd
CIDR that matches nothing, or a URL with no host). Pure and deterministic so
the scope-enforcement keystone (M1-B9) reuses the same normalization it will
match against. Raises ValueError on invalid input; returns the canonical form.
"""

import ipaddress
import re
from urllib.parse import urlparse

from app.models.engagement import ScopeMatcher

# DNS hostname, optional single leading "*." wildcard (e.g. *.example.com).
_HOSTNAME_RE = re.compile(
    r"^(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE
)
# scp-like git remote: git@host:org/repo(.git)
_SCP_GIT_RE = re.compile(r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+:[a-zA-Z0-9._/-]+$")

_HTTP_SCHEMES = frozenset({"http", "https"})
_REPO_SCHEMES = frozenset({"http", "https", "ssh", "git"})


def _validate_http_url(value: str, *, label: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme.lower() not in _HTTP_SCHEMES or not parsed.netloc:
        raise ValueError(f"{label} must be an absolute http(s) URL with a host")
    return value


def _validate_domain(value: str) -> str:
    host = value.lower()
    if not _HOSTNAME_RE.match(host):
        raise ValueError("domain must be a valid hostname (optionally '*.'-prefixed)")
    return host


def _validate_ip_cidr(value: str) -> str:
    try:
        # strict=False accepts a bare host (→ /32 or /128) and host bits set.
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid IP/CIDR: {exc}") from exc
    return str(network)


def _validate_repo(value: str) -> str:
    if _SCP_GIT_RE.match(value):
        return value
    parsed = urlparse(value)
    if parsed.scheme.lower() in _REPO_SCHEMES and parsed.netloc:
        return value
    raise ValueError("repo must be an http(s)/ssh/git URL or a git@host:path remote")


_VALIDATORS = {
    ScopeMatcher.URL: lambda v: _validate_http_url(v, label="url"),
    ScopeMatcher.API_BASE: lambda v: _validate_http_url(v, label="api_base"),
    ScopeMatcher.DOMAIN: _validate_domain,
    ScopeMatcher.IP_CIDR: _validate_ip_cidr,
    ScopeMatcher.REPO: _validate_repo,
}


def validate_matcher(matcher_type: ScopeMatcher, value: str) -> str:
    """Return the canonical value for a scope item, or raise ValueError."""
    stripped = value.strip()
    if not stripped:
        raise ValueError("scope value must not be empty")
    return _VALIDATORS[matcher_type](stripped)
