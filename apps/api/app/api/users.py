"""User management endpoints (M1-B4) — Admin only.

Every route is guarded by require(Capability.MANAGE_USERS) and scoped to the
caller's organization: a user in another org is 404, never 403-with-data
(no cross-org existence leak — the M1 IDOR/BOLA gate). Role change and password
change revoke all of the target's sessions (privilege change ⇒ forced re-auth,
ARCHITECTURE §13); deactivation revokes them too. Admins cannot deactivate or
demote themselves — avoids last-admin lockout.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
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
from app.models.identity import User
from app.schemas.users import PasswordChange, RoleUpdate, UserCreate, UserOut

router = APIRouter(prefix="/users", tags=["users"])


async def _get_org_user(db: AsyncSession, user_id: uuid.UUID, org_id: uuid.UUID) -> User:
    """Fetch a user within the caller's org, or 404 (no cross-org leak)."""
    user = (
        await db.execute(select(User).where(User.id == user_id, User.organization_id == org_id))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    return user


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    principal: Principal = Depends(require(Capability.MANAGE_USERS)),
    db: AsyncSession = Depends(get_db),
    passwords: PasswordService = Depends(get_password_service),
) -> User:
    user = User(
        organization_id=principal.organization_id,
        email=body.email,
        display_name=body.display_name,
        role=body.role,
        password_hash=passwords.hash(body.password.get_secret_value()),
        is_active=True,
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
    return user


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


@router.post("/{user_id}/password", response_model=UserOut)
async def change_user_password(
    user_id: uuid.UUID,
    body: PasswordChange,
    principal: Principal = Depends(require(Capability.MANAGE_USERS)),
    db: AsyncSession = Depends(get_db),
    passwords: PasswordService = Depends(get_password_service),
    sessions: SessionService = Depends(get_session_service),
) -> User:
    user = await _get_org_user(db, user_id, principal.organization_id)
    user.password_hash = passwords.hash(body.password.get_secret_value())
    await db.flush()
    # Password change revokes every session (including the target's current one).
    await sessions.revoke_all_for_user(user.id, now=utcnow())
    await db.refresh(user)
    return user
