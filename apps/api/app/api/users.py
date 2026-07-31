"""User management endpoints (M1-B4) — Admin only.

Every route is guarded by require(Capability.MANAGE_USERS) and scoped to the
caller's organization: a user in another org is 404, never 403-with-data
(no cross-org existence leak — the M1 IDOR/BOLA gate). Role change and password
change revoke all of the target's sessions (privilege change ⇒ forced re-auth,
ARCHITECTURE §13); deactivation revokes them too. Admins cannot deactivate or
demote themselves — avoids last-admin lockout.
"""

import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import (
    Capability,
    Principal,
    get_db,
    get_password_service,
    get_session_service,
    require,
)
from app.core.security import PasswordService
from app.core.sessions import SessionService, utcnow
from app.models.identity import MfaRecoveryCode, User
from app.schemas.users import (
    RoleUpdate,
    TempPasswordOut,
    UserCreate,
    UserCreateOut,
    UserOut,
)

router = APIRouter(prefix="/users", tags=["users"])


def _generate_temp_password() -> str:
    """A high-entropy one-time password. token_urlsafe(18) → 24 chars, well
    over the 12-char floor and never in a breach list (random)."""
    return secrets.token_urlsafe(18)


async def _get_org_user(db: AsyncSession, user_id: uuid.UUID, org_id: uuid.UUID) -> User:
    """Fetch a user within the caller's org, or 404 (no cross-org leak)."""
    user = (
        await db.execute(select(User).where(User.id == user_id, User.organization_id == org_id))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    return user


@router.post("", response_model=UserCreateOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    principal: Principal = Depends(require(Capability.MANAGE_USERS)),
    db: AsyncSession = Depends(get_db),
    passwords: PasswordService = Depends(get_password_service),
) -> UserCreateOut:
    temp_password = _generate_temp_password()
    user = User(
        organization_id=principal.organization_id,
        email=body.email,
        display_name=body.display_name,
        role=body.role,
        password_hash=passwords.hash(temp_password),
        is_active=True,
        must_change_password=True,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as exc:
        # UNIQUE (organization_id, email) — citext, so case-insensitive.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="email already exists"
        ) from exc
    await db.refresh(user)
    return UserCreateOut(user=UserOut.model_validate(user), temporary_password=temp_password)


@router.get("", response_model=list[UserOut])
async def list_users(
    principal: Principal = Depends(require(Capability.MANAGE_USERS)),
    db: AsyncSession = Depends(get_db),
) -> list[User]:
    result = await db.execute(
        select(User)
        .where(User.organization_id == principal.organization_id)
        .order_by(User.created_at)
    )
    return list(result.scalars().all())


@router.post("/{user_id}/deactivate", response_model=UserOut)
async def deactivate_user(
    user_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.MANAGE_USERS)),
    db: AsyncSession = Depends(get_db),
    sessions: SessionService = Depends(get_session_service),
) -> User:
    if user_id == principal.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="cannot deactivate your own account"
        )
    user = await _get_org_user(db, user_id, principal.organization_id)
    user.is_active = False
    await db.flush()
    await sessions.revoke_all_for_user(user.id, now=utcnow())
    await db.refresh(user)
    return user


@router.patch("/{user_id}/role", response_model=UserOut)
async def set_user_role(
    user_id: uuid.UUID,
    body: RoleUpdate,
    principal: Principal = Depends(require(Capability.MANAGE_USERS)),
    db: AsyncSession = Depends(get_db),
    sessions: SessionService = Depends(get_session_service),
) -> User:
    if user_id == principal.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="cannot change your own role"
        )
    user = await _get_org_user(db, user_id, principal.organization_id)
    user.role = body.role
    await db.flush()
    # Privilege change ⇒ force re-auth so the new role takes effect everywhere.
    await sessions.revoke_all_for_user(user.id, now=utcnow())
    await db.refresh(user)
    return user


@router.post("/{user_id}/reset-password", response_model=TempPasswordOut)
async def reset_user_password(
    user_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.MANAGE_USERS)),
    db: AsyncSession = Depends(get_db),
    passwords: PasswordService = Depends(get_password_service),
    sessions: SessionService = Depends(get_session_service),
) -> TempPasswordOut:
    """Mint a fresh one-time password for a user (the 'regenerate' action):
    forces a change on next login and revokes every current session. The new
    password is returned once and never stored in the clear."""
    user = await _get_org_user(db, user_id, principal.organization_id)
    temp_password = _generate_temp_password()
    user.password_hash = passwords.hash(temp_password)
    user.must_change_password = True
    await db.flush()
    # Password change revokes every session (including the target's current one).
    await sessions.revoke_all_for_user(user.id, now=utcnow())
    return TempPasswordOut(temporary_password=temp_password)


@router.post("/{user_id}/reset-mfa", response_model=UserOut)
async def reset_user_mfa(
    user_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.MANAGE_USERS)),
    db: AsyncSession = Depends(get_db),
    sessions: SessionService = Depends(get_session_service),
) -> User:
    """Admin lockout recovery for a user who lost both device and recovery codes.
    Clears MFA and revokes sessions (forced re-auth). Audited by the middleware."""
    user = await _get_org_user(db, user_id, principal.organization_id)
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_confirmed_at = None
    await db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    await db.flush()
    await sessions.revoke_all_for_user(user.id, now=utcnow())
    await db.refresh(user)
    return user
