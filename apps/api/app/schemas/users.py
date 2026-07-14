"""User-management schemas (M1-B4).

Passwords arrive as SecretStr so they never render in logs, error reprs, or
the OpenAPI schema; UserOut deliberately omits password_hash.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr

from app.models.identity import UserRole

# OWASP ASVS: allow long passphrases; enforce a floor, cap to bound hashing cost.
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256


class UserCreate(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=200)
    role: UserRole = UserRole.READ_ONLY
    password: SecretStr = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


class RoleUpdate(BaseModel):
    role: UserRole


class PasswordChange(BaseModel):
    password: SecretStr = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    email: str
    display_name: str
    role: UserRole
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime
