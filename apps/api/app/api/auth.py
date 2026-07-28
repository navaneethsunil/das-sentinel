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
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.config import Settings, get_settings
from app.core.csrf import generate_csrf_token
from app.core.deps import (
    Principal,
    get_audit_service,
    get_db,
    get_login_rate_limiter,
    get_mfa_service,
    get_password_service,
    get_principal,
    get_session_service,
)
from app.core.mfa import MfaError, MfaService
from app.core.ratelimit import LoginRateLimiter
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
from app.models.identity import MfaRecoveryCode, User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    LogoutAllResponse,
    MfaCodeRequest,
    MfaEnrollResponse,
    MfaRecoveryCodesResponse,
)
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


def _too_many_attempts(retry_after: int) -> HTTPException:
    # Generic 429 — deliberately identical whichever counter tripped, so it
    # never confirms an account exists (no enumeration oracle).
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="too many login attempts; try again later",
        headers={"Retry-After": str(retry_after)},
    )


def _rate_limit_unavailable() -> HTTPException:
    # Fail-closed: the anti-brute-force decision could not be made.
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="login temporarily unavailable",
    )


async def _consume_recovery_code(
    db: AsyncSession, user_id: object, code: str, now: datetime, mfa: MfaService
) -> bool:
    """Single-statement atomic consume (same pattern as approval consume): the
    WHERE used_at IS NULL row-locks so two concurrent logins can't reuse a code."""
    result = await db.execute(
        update(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.user_id == user_id,
            MfaRecoveryCode.code_hash == mfa.hash_recovery_code(code),
            MfaRecoveryCode.used_at.is_(None),
        )
        .values(used_at=now)
    )
    return result.rowcount == 1


async def _second_factor_ok(
    db: AsyncSession, user: User, code: str, now: datetime, mfa: MfaService
) -> bool:
    """A 6-digit value is tried as TOTP; anything else as a single-use recovery
    code. A corrupt/undecryptable stored secret fails closed."""
    if code.isdigit():
        try:
            return mfa.verify_totp(mfa.decrypt_secret(user.mfa_secret or ""), code)
        except MfaError:
            return False
    return await _consume_recovery_code(db, user.id, code, now, mfa)


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    passwords: PasswordService = Depends(get_password_service),
    sessions: SessionService = Depends(get_session_service),
    audit: AuditService = Depends(get_audit_service),
    rate_limiter: LoginRateLimiter = Depends(get_login_rate_limiter),
    mfa: MfaService = Depends(get_mfa_service),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    ip_address = request.client.host if request.client else None

    # Anti-brute-force gate (SEC-DEBT-1) — BEFORE any credential work, so a
    # throttled caller can neither keep burning Argon2id verifications nor
    # learn anything from the response.
    try:
        decision = await rate_limiter.check(ip_address, body.email)
    except Exception as exc:  # store unreachable → fail closed, not open
        raise _rate_limit_unavailable() from exc
    if decision.blocked:
        raise _too_many_attempts(decision.retry_after_seconds)

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
        await rate_limiter.register_failure(ip_address, body.email)
        raise _bad_credentials()

    if not passwords.verify(body.password.get_secret_value(), user.password_hash):
        await rate_limiter.register_failure(ip_address, body.email)
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

    # Second factor (SEC-DEBT-2). Password is correct but the account carries a
    # confirmed TOTP secret → require a valid code before minting a session. A
    # failed code is a real brute-force attempt, so it burns the rate limiter and
    # is audited; a missing code is a benign "prompt me" and does neither.
    if user.mfa_enabled:
        code = body.mfa_code.get_secret_value().strip() if body.mfa_code else ""
        if not code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "mfa_required"},
            )
        if not await _second_factor_ok(db, user, code, now, mfa):
            await rate_limiter.register_failure(ip_address, body.email)
            sessionmaker = request.app.state.db_sessionmaker
            async with sessionmaker() as audit_db:
                await AuditService(audit_db).log(
                    organization_id=user.organization_id,
                    actor_user_id=user.id,
                    action="auth.mfa_failed",
                    object_type="user",
                    object_id=user.id,
                    outcome=AuditOutcome.FAILURE,
                    ip_address=ip_address,
                )
                await audit_db.commit()
            raise _bad_credentials()

    # Correct credentials: clear this account's failure counter so a legitimate
    # user who mistyped recovers at once (per-IP counter is left to keep gating
    # a spraying source).
    await rate_limiter.reset_account(body.email)
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


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
async def mfa_enroll(
    request: Request,
    principal: Principal = Depends(get_principal),
    db: AsyncSession = Depends(get_db),
    mfa: MfaService = Depends(get_mfa_service),
    audit: AuditService = Depends(get_audit_service),
) -> MfaEnrollResponse:
    """Start enrollment: store a *pending* encrypted secret (mfa_enabled stays
    false until /confirm). The secret + provisioning URI are shown once here."""
    user = (await db.execute(select(User).where(User.id == principal.user_id))).scalar_one()
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA already enabled; disable it first")
    secret = mfa.new_secret()
    user.mfa_secret = mfa.encrypt_secret(secret)
    user.mfa_confirmed_at = None
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="auth.mfa_enroll_started",
        object_type="user",
        object_id=principal.user_id,
        ip_address=request.client.host if request.client else None,
    )
    return MfaEnrollResponse(
        secret=secret, provisioning_uri=mfa.provisioning_uri(secret, user.email)
    )


@router.post("/mfa/confirm", response_model=MfaRecoveryCodesResponse)
async def mfa_confirm(
    body: MfaCodeRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: AsyncSession = Depends(get_db),
    mfa: MfaService = Depends(get_mfa_service),
    audit: AuditService = Depends(get_audit_service),
) -> MfaRecoveryCodesResponse:
    """Prove possession of the pending secret with a live TOTP, then activate MFA
    and issue single-use recovery codes (returned once; only hashes stored)."""
    user = (await db.execute(select(User).where(User.id == principal.user_id))).scalar_one()
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA already enabled")
    if not user.mfa_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "no MFA enrollment in progress")
    code = body.code.get_secret_value().strip()
    if not (code.isdigit() and mfa.verify_totp(mfa.decrypt_secret(user.mfa_secret), code)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")

    user.mfa_enabled = True
    user.mfa_confirmed_at = utcnow()
    await db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    codes = mfa.new_recovery_codes()
    for c in codes:
        db.add(MfaRecoveryCode(user_id=user.id, code_hash=mfa.hash_recovery_code(c)))
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="auth.mfa_enabled",
        object_type="user",
        object_id=principal.user_id,
        ip_address=request.client.host if request.client else None,
    )
    return MfaRecoveryCodesResponse(recovery_codes=codes)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(
    body: MfaCodeRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: AsyncSession = Depends(get_db),
    mfa: MfaService = Depends(get_mfa_service),
    audit: AuditService = Depends(get_audit_service),
) -> None:
    """Self-disable, gated by a valid second factor (TOTP or a recovery code, so
    a lost device can still be recovered from). Clears the secret + all codes."""
    user = (await db.execute(select(User).where(User.id == principal.user_id))).scalar_one()
    if not user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA not enabled")
    code = body.code.get_secret_value().strip()
    if not await _second_factor_ok(db, user, code, utcnow(), mfa):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_confirmed_at = None
    await db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="auth.mfa_disabled",
        object_type="user",
        object_id=principal.user_id,
        ip_address=request.client.host if request.client else None,
    )
