"""M1-B3: RBAC matrix + route guard. The full principal resolution from a
session cookie is exercised live in M1-T2; here we pin the access matrix
(ARCHITECTURE §9) and the allow/deny behavior of require() — the
security-critical, deterministic core, with an explicit negative for every
role × capability cell."""

import uuid

import pytest
from fastapi import HTTPException

from app.core.deps import Capability, Principal, can, require
from app.models.identity import UserRole

A, T, RV, RO = UserRole.ADMIN, UserRole.TESTER, UserRole.REVIEWER, UserRole.READ_ONLY

# Independent restatement of ARCHITECTURE §9 — if CAPABILITY_ROLES drifts from
# the documented matrix, this table catches it (allowed roles per capability).
EXPECTED_ALLOWED: dict[Capability, set[UserRole]] = {
    Capability.MANAGE_USERS: {A},
    Capability.MANAGE_ENGAGEMENTS: {A, T},
    Capability.ACCEPT_ROE: {A, T},
    Capability.LAUNCH_SCANS: {A, T},
    Capability.APPROVE_HIGH_RISK: {A, RV},
    Capability.VALIDATE_FINDINGS: {A, T, RV},
    Capability.EXPORT_REPORTS: {A, T, RV},
    Capability.VIEW_AUDIT: {A, RV},
    Capability.VIEW: {A, T, RV, RO},
}

ALL_ROLES = [A, T, RV, RO]


def _principal(role: UserRole) -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        role=role,
        session_id=uuid.uuid4(),
    )


@pytest.mark.parametrize("capability", list(Capability))
@pytest.mark.parametrize("role", ALL_ROLES)
def test_can_matches_documented_matrix(role: UserRole, capability: Capability) -> None:
    assert can(role, capability) is (role in EXPECTED_ALLOWED[capability])


def test_every_capability_is_in_the_matrix() -> None:
    # A capability with no matrix row would KeyError at request time — catch it here.
    assert set(EXPECTED_ALLOWED) == set(Capability)


def test_read_only_can_only_view() -> None:
    granted = [c for c in Capability if can(RO, c)]
    assert granted == [Capability.VIEW]


def test_admin_has_every_capability() -> None:
    assert all(can(A, c) for c in Capability)


class TestRequireGuard:
    @pytest.mark.parametrize("capability", list(Capability))
    @pytest.mark.parametrize("role", ALL_ROLES)
    async def test_guard_allows_and_denies_per_matrix(
        self, role: UserRole, capability: Capability
    ) -> None:
        guard = require(capability)
        principal = _principal(role)
        if role in EXPECTED_ALLOWED[capability]:
            assert await guard(principal=principal) is principal
        else:
            with pytest.raises(HTTPException) as exc:
                await guard(principal=principal)
            assert exc.value.status_code == 403

    async def test_denied_error_names_role_and_capability(self) -> None:
        guard = require(Capability.MANAGE_USERS)
        with pytest.raises(HTTPException) as exc:
            await guard(principal=_principal(RO))
        assert "read_only" in exc.value.detail
        assert "manage_users" in exc.value.detail
