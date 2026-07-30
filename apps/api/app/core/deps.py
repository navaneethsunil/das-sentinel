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
from app.core.mfa import MfaService
from app.core.password_policy import PasswordBreachChecker, get_breach_checker
from app.core.ratelimit import LoginRateLimiter, UserRateLimiter
from app.core.security import PasswordService
from app.core.sessions import SessionService, utcnow
from app.models.identity import User, UserRole

# Read methods bypass the per-user throttle (see get_principal).
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    organization_id: uuid.UUID
    role: UserRole
    session_id: uuid.UUID


class Capability(enum.Enum):
    MANAGE_USERS = "manage_users"
    MANAGE_ENGAGEMENTS = "manage_engagements"
    MANAGE_CREDENTIALS = "manage_credentials"
    ACCEPT_ROE = "accept_roe"
    LAUNCH_SCANS = "launch_scans"
    APPROVE_HIGH_RISK = "approve_high_risk"
    VALIDATE_FINDINGS = "validate_findings"
    EXPORT_REPORTS = "export_reports"
    VIEW_AUDIT = "view_audit"
    VIEW = "view"


# ARCHITECTURE §9 RBAC matrix — the single source of truth. Any route guard
# resolves through here; changing an access rule means changing this table only.
CAPABILITY_ROLES: dict[Capability, frozenset[UserRole]] = {
    Capability.MANAGE_USERS: frozenset({UserRole.ADMIN}),
    Capability.MANAGE_ENGAGEMENTS: frozenset({UserRole.ADMIN, UserRole.TESTER}),
    # Managing credentials (create/delete the secrets targets reference) is a
    # privileged action — the people who set up engagements/targets, not viewers.
    Capability.MANAGE_CREDENTIALS: frozenset({UserRole.ADMIN, UserRole.TESTER}),
    Capability.ACCEPT_ROE: frozenset({UserRole.ADMIN, UserRole.TESTER}),
    Capability.LAUNCH_SCANS: frozenset({UserRole.ADMIN, UserRole.TESTER}),
    Capability.APPROVE_HIGH_RISK: frozenset({UserRole.ADMIN, UserRole.REVIEWER}),
    Capability.VALIDATE_FINDINGS: frozenset({UserRole.ADMIN, UserRole.TESTER, UserRole.REVIEWER}),
    Capability.EXPORT_REPORTS: frozenset({UserRole.ADMIN, UserRole.TESTER, UserRole.REVIEWER}),
    # Audit review is an oversight function (MVP_TASKS M1-F5): admins and
    # reviewers read it; testers see their own actions reflected elsewhere.
    Capability.VIEW_AUDIT: frozenset({UserRole.ADMIN, UserRole.REVIEWER}),
    Capability.VIEW: frozenset(
        {UserRole.ADMIN, UserRole.TESTER, UserRole.REVIEWER, UserRole.READ_ONLY}
    ),
}


def can(role: UserRole, capability: Capability) -> bool:
    return role in CAPABILITY_ROLES[capability]


def get_cache(request: Request) -> Redis:
    return request.app.state.valkey


def get_evidence_store(request: Request):
    """The S3 evidence store from app.state (M2-B1). Untyped return to avoid a
    core→storage import at module load; callers annotate as needed."""
    return request.app.state.evidence_store


def get_llm_service(request: Request, settings: Settings = Depends(get_settings)):
    """The LLM provider facade (M2-B2). Built on first use and cached on
    app.state — the vendor SDK is imported lazily here, never at API startup, so
    a deployment that makes no LLM call never loads it. Untyped return to keep
    core free of an app.llm import at module load."""
    svc = getattr(request.app.state, "llm_service", None)
    if svc is None:
        from app.llm import create_llm_service

        svc = create_llm_service(settings)
        request.app.state.llm_service = svc
    return svc


def get_password_service(settings: Settings = Depends(get_settings)) -> PasswordService:
    return PasswordService(settings.password_hash_scheme)


def get_password_breach_checker(
    settings: Settings = Depends(get_settings),
) -> PasswordBreachChecker:
    return get_breach_checker(settings.breached_password_list_path)


def get_mfa_service(settings: Settings = Depends(get_settings)) -> MfaService:
    key = settings.mfa_secret_encryption_key
    return MfaService(
        key.get_secret_value() if key else None,
        issuer=settings.mfa_issuer,
        allow_dev_key=settings.das_env != "prod",
    )


def get_credential_cipher(settings: Settings = Depends(get_settings)):
    """Credential-store cipher (untyped return to keep core free of an app.services
    import at module load; callers annotate). Dev fallback key outside prod; prod
    with no key fails closed at use time — a deployment that never uses credentials
    still boots."""
    from app.services.credentials import CredentialCipher

    key = settings.credential_encryption_key
    return CredentialCipher(
        key.get_secret_value() if key else None,
        allow_dev_key=settings.das_env != "prod",
    )


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


def get_login_rate_limiter(
    cache: Redis = Depends(get_cache),
    settings: Settings = Depends(get_settings),
) -> LoginRateLimiter:
    return LoginRateLimiter(cache, settings)


async def get_principal(
    request: Request,
    db: AsyncSession = Depends(get_db),
    svc: SessionService = Depends(get_session_service),
    cache: Redis = Depends(get_cache),
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
    # Per-user anti-automation throttle on state-changing requests only. Reads
    # (GET/HEAD/OPTIONS) are exempt: they're cheap and already auth+scope-gated,
    # and the SPA fires bursts of RSC-prefetch GETs that a blanket cap would trip.
    # The abusable surface (launches, mutations) is what this bounds.
    if request.method not in _SAFE_METHODS and not await UserRateLimiter(
        cache, settings
    ).within_budget(principal.user_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many requests",
            headers={"Retry-After": str(settings.api_rate_limit_window_seconds)},
        )
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
