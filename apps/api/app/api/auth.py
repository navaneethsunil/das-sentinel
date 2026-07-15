"""Authentication endpoints (M1-SEC2) — login/logout/me over opaque sessions.

Login failure is one generic 401 whatever the cause (unknown email, wrong
password, deactivated account), and an unknown email still burns a full hash
verification — neither the response nor its timing enumerates accounts.
Successful login regenerates the session id (fixation defense, M1-B2) and
mints the CSRF double-submit cookie (core/csrf.py). Failed attempts are
audited on an independent session because the request transaction rolls back
with the 401.
"""

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.config import Settings, get_settings
from app.core.csrf import generate_csrf_token
from app.core.deps import (
    Principal,
    get_audit_service,
    get_db,
    get_password_service,
    get_principal,
    get_session_service,
)
from app.core.security import PasswordService
from app.core.sessions import (
    SessionService,
    clear_csrf_cookie,
    clear_session_cookie,
    set_csrf_cookie,
    set_session_cookie,
    utcnow,
)
from app.models.audit import AuditOutcome
from app.models.identity import User
from app.schemas.auth import LoginRequest, LoginResponse, LogoutAllResponse
from app.schemas.users import UserOut

router = APIRouter(prefix="/auth", tags=["auth"])

# One throwaway hash per scheme so unknown-email logins cost the same as a
# real verification (no timing-based account enumeration).
_DUMMY_HASHES: dict[str, str] = {}


def _dummy_hash(passwords: PasswordService) -> str:
    if passwords.scheme not in _DUMMY_HASHES:
        _DUMMY_HASHES[passwords.scheme] = passwords.hash(secrets.token_urlsafe(32))
    return _DUMMY_HASHES[passwords.scheme]


def _bad_credentials() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid email or password",
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    passwords: PasswordService = Depends(get_password_service),
    sessions: SessionService = Depends(get_session_service),
    audit: AuditService = Depends(get_audit_service),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    ip_address = request.client.host if request.client else None
    # Email is unique per organization; single-org MVP, so take the oldest
    # active match deterministically (multi-org login is an SSO-era concern).
    user = (
        await db.execute(
            select(User)
            .where(User.email == body.email, User.is_active.is_(True))
            .order_by(User.created_at)
            .limit(1)
        )
    ).scalar_one_or_none()

    if user is None:
        passwords.verify(body.password.get_secret_value(), _dummy_hash(passwords))
        raise _bad_credentials()

    if not passwords.verify(body.password.get_secret_value(), user.password_hash):
        # Own session: the request transaction rolls back with the 401, but the
        # failed attempt must still be recorded (same pattern as the middleware).
        sessionmaker = request.app.state.db_sessionmaker
        async with sessionmaker() as audit_db:
            await AuditService(audit_db).log(
                organization_id=user.organization_id,
                actor_user_id=user.id,
                action="auth.login_failed",
                object_type="user",
                object_id=user.id,
                outcome=AuditOutcome.FAILURE,
                ip_address=ip_address,
            )
            await audit_db.commit()
        raise _bad_credentials()

    now = utcnow()
    token = await sessions.regenerate_on_login(
        request.cookies.get(settings.session_cookie_name),
        user.id,
        user.role,
        now=now,
        ip_address=ip_address,
        user_agent=request.headers.get("user-agent"),
    )
    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash(body.password.get_secret_value())
    user.last_login_at = now
    await db.flush()

    csrf_token = generate_csrf_token()
    set_session_cookie(response, token, settings)
    set_csrf_cookie(response, csrf_token, settings)

    await audit.log(
        organization_id=user.organization_id,
        actor_user_id=user.id,
        action="auth.login",
        object_type="user",
        object_id=user.id,
        ip_address=ip_address,
    )
    return LoginResponse(user=UserOut.model_validate(user), csrf_token=csrf_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    principal: Principal = Depends(get_principal),
    sessions: SessionService = Depends(get_session_service),
    audit: AuditService = Depends(get_audit_service),
    settings: Settings = Depends(get_settings),
) -> None:
    token = request.cookies.get(settings.session_cookie_name)
    if token:
        await sessions.revoke_session(token, now=utcnow())
    clear_session_cookie(response, settings)
    clear_csrf_cookie(response, settings)
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="auth.logout",
        object_type="session",
        object_id=principal.session_id,
        ip_address=request.client.host if request.client else None,
    )


@router.post("/logout-all", response_model=LogoutAllResponse)
async def logout_all(
    request: Request,
    response: Response,
    principal: Principal = Depends(get_principal),
    sessions: SessionService = Depends(get_session_service),
    audit: AuditService = Depends(get_audit_service),
    settings: Settings = Depends(get_settings),
) -> LogoutAllResponse:
    """Kill-all-my-sessions, current one included — the caller re-authenticates."""
    revoked = await sessions.revoke_all_for_user(principal.user_id, now=utcnow())
    clear_session_cookie(response, settings)
    clear_csrf_cookie(response, settings)
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="auth.logout_all",
        object_type="user",
        object_id=principal.user_id,
        detail={"revoked_sessions": revoked},
        ip_address=request.client.host if request.client else None,
    )
    return LogoutAllResponse(revoked_sessions=revoked)


@router.get("/me", response_model=UserOut)
async def me(
    principal: Principal = Depends(get_principal),
    db: AsyncSession = Depends(get_db),
) -> User:
    return (await db.execute(select(User).where(User.id == principal.user_id))).scalar_one()
