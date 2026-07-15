"""Request dependencies: principal resolution + RBAC guards (M1-B3).

Routes declare intent as a *capability* (`require(Capability.MANAGE_USERS)`),
not a raw role set — so the ARCHITECTURE §9 matrix lives in exactly one place
(CAPABILITY_ROLES) and a route can't drift from it. Resolution fails closed:
no/invalid/expired session → 401; authenticated-but-unauthorized → 403.
"""

import enum
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.config import Settings, get_settings
from app.core.db import get_db
from app.core.security import PasswordService
from app.core.sessions import SessionService, utcnow
from app.models.identity import User, UserRole


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    organization_id: uuid.UUID
    role: UserRole
    session_id: uuid.UUID


class Capability(enum.Enum):
    MANAGE_USERS = "manage_users"
    MANAGE_ENGAGEMENTS = "manage_engagements"
    ACCEPT_ROE = "accept_roe"
    LAUNCH_SCANS = "launch_scans"
    APPROVE_HIGH_RISK = "approve_high_risk"
    VALIDATE_FINDINGS = "validate_findings"
    EXPORT_REPORTS = "export_reports"
    VIEW = "view"


# ARCHITECTURE §9 RBAC matrix — the single source of truth. Any route guard
# resolves through here; changing an access rule means changing this table only.
CAPABILITY_ROLES: dict[Capability, frozenset[UserRole]] = {
    Capability.MANAGE_USERS: frozenset({UserRole.ADMIN}),
    Capability.MANAGE_ENGAGEMENTS: frozenset({UserRole.ADMIN, UserRole.TESTER}),
    Capability.ACCEPT_ROE: frozenset({UserRole.ADMIN, UserRole.TESTER}),
    Capability.LAUNCH_SCANS: frozenset({UserRole.ADMIN, UserRole.TESTER}),
    Capability.APPROVE_HIGH_RISK: frozenset({UserRole.ADMIN, UserRole.REVIEWER}),
    Capability.VALIDATE_FINDINGS: frozenset({UserRole.ADMIN, UserRole.TESTER, UserRole.REVIEWER}),
    Capability.EXPORT_REPORTS: frozenset({UserRole.ADMIN, UserRole.TESTER, UserRole.REVIEWER}),
    Capability.VIEW: frozenset(
        {UserRole.ADMIN, UserRole.TESTER, UserRole.REVIEWER, UserRole.READ_ONLY}
    ),
}


def can(role: UserRole, capability: Capability) -> bool:
    return role in CAPABILITY_ROLES[capability]


def get_cache(request: Request) -> Redis:
    return request.app.state.valkey


def get_password_service(settings: Settings = Depends(get_settings)) -> PasswordService:
    return PasswordService(settings.password_hash_scheme)


def get_audit_service(db: AsyncSession = Depends(get_db)) -> AuditService:
    """Audit writer bound to the request transaction — domain events commit
    atomically with the action they record."""
    return AuditService(db)


def get_session_service(
    db: AsyncSession = Depends(get_db),
    cache: Redis = Depends(get_cache),
    settings: Settings = Depends(get_settings),
) -> SessionService:
    return SessionService(db, cache, settings)


async def get_principal(
    request: Request,
    db: AsyncSession = Depends(get_db),
    svc: SessionService = Depends(get_session_service),
    settings: Settings = Depends(get_settings),
) -> Principal:
    """Resolve the caller from the session cookie. 401 on any failure."""
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise _unauthenticated()
    validated = await svc.validate_session(token, now=utcnow())
    if validated is None:
        raise _unauthenticated()
    organization_id = (
        await db.execute(select(User.organization_id).where(User.id == validated.user_id))
    ).scalar_one_or_none()
    if organization_id is None:
        raise _unauthenticated()
    principal = Principal(
        user_id=validated.user_id,
        organization_id=organization_id,
        role=validated.role,
        session_id=validated.session_id,
    )
    # Stamp for the audit middleware (it runs outside the DI graph).
    request.state.principal = principal
    return principal


def require(capability: Capability) -> Callable[[Principal], Awaitable[Principal]]:
    """Route dependency: allow only roles holding `capability`, else 403."""

    async def guard(principal: Principal = Depends(get_principal)) -> Principal:
        if not can(principal.role, capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role {principal.role.value!r} lacks capability {capability.value!r}",
            )
        return principal

    # Discoverable so a test can prove every domain route is guarded (M1-T2).
    guard._required_capability = capability  # type: ignore[attr-defined]
    return guard


def _unauthenticated() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="authentication required",
    )
