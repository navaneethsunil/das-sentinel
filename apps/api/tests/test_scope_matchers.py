"""M1-B7: scope matcher validation/normalization. Endpoint CRUD + org scoping
is verified live (scripts/verify_scope.py); here we pin the pure validator with
valid and invalid cases for every matcher type."""

import pytest

from app.models.engagement import ScopeMatcher
from app.services.scope_matchers import validate_matcher

M = ScopeMatcher


@pytest.mark.parametrize(
    ("matcher", "value", "expected"),
    [
        (M.URL, "https://app.example.com/login", "https://app.example.com/login"),
        (M.URL, "http://10.0.0.5:8080/api", "http://10.0.0.5:8080/api"),
        (M.API_BASE, "https://api.example.com/v2", "https://api.example.com/v2"),
        (M.DOMAIN, "App.Example.COM", "app.example.com"),
        (M.DOMAIN, "*.example.com", "*.example.com"),
        (M.IP_CIDR, "10.0.0.0/24", "10.0.0.0/24"),
        (M.IP_CIDR, "10.0.0.5", "10.0.0.5/32"),  # bare host → /32
        (M.IP_CIDR, "10.0.0.5/24", "10.0.0.0/24"),  # host bits normalized away
        (M.IP_CIDR, "2001:db8::/32", "2001:db8::/32"),
        (M.REPO, "https://github.com/org/repo.git", "https://github.com/org/repo.git"),
        (M.REPO, "git@github.com:org/repo.git", "git@github.com:org/repo.git"),
        (M.REPO, "ssh://git@host.example/org/repo", "ssh://git@host.example/org/repo"),
    ],
)
def test_valid_matchers_normalize(matcher: ScopeMatcher, value: str, expected: str) -> None:
    assert validate_matcher(matcher, value) == expected


@pytest.mark.parametrize(
    ("matcher", "value"),
    [
        (M.URL, "app.example.com"),  # no scheme
        (M.URL, "ftp://example.com"),  # wrong scheme
        (M.URL, "https://"),  # no host
        (M.API_BASE, "not a url"),
        (M.DOMAIN, "https://example.com"),  # scheme not allowed for domain
        (M.DOMAIN, "no_underscores.example.com"),
        (M.DOMAIN, "-bad.example.com"),
        (M.DOMAIN, "*.*.example.com"),  # only a single leading wildcard
        (M.IP_CIDR, "10.0.0.0/33"),  # invalid prefix
        (M.IP_CIDR, "not-an-ip"),
        (M.IP_CIDR, "999.1.1.1"),
        (M.REPO, "just-a-string"),
        (M.REPO, "ftp://example.com/repo"),  # scheme not allowed for repo
    ],
)
def test_invalid_matchers_raise(matcher: ScopeMatcher, value: str) -> None:
    with pytest.raises(ValueError):
        validate_matcher(matcher, value)


@pytest.mark.parametrize("matcher", list(ScopeMatcher))
def test_empty_value_rejected(matcher: ScopeMatcher) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        validate_matcher(matcher, "   ")
