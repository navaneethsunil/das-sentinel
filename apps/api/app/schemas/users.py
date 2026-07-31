"""User-management schemas (M1-B4).

Passwords arrive as SecretStr so they never render in logs, error reprs, or
the OpenAPI schema; UserOut deliberately omits password_hash.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.identity import UserRole

# OWASP ASVS: allow long passphrases; enforce a floor, cap to bound hashing cost.
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256


class UserCreate(BaseModel):
    # No password field: the server mints a one-time temporary password and
    # forces the user to set their own on first login.
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=200)
    role: UserRole = UserRole.READ_ONLY


class RoleUpdate(BaseModel):
    role: UserRole


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    email: str
    display_name: str
    phone: str | None
    role: UserRole
    is_active: bool
    mfa_enabled: bool
    must_change_password: bool
    last_login_at: datetime | None
    created_at: datetime


class UserCreateOut(BaseModel):
    # The temporary password is shown to the admin exactly once (never stored
    # in the clear); the user must change it on first login.
    user: UserOut
    temporary_password: str


class TempPasswordOut(BaseModel):
    temporary_password: str
