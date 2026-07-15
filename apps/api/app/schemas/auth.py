"""Authentication schemas (M1-SEC2).

Login enforces only the length *cap* (bounds hashing cost), not the
creation-time minimum: existing credentials must keep working, and a 422-vs-401
split on length would leak which validation rule fired.
"""

from pydantic import BaseModel, EmailStr, Field, SecretStr

from app.schemas.users import MAX_PASSWORD_LENGTH, UserOut


class LoginRequest(BaseModel):
    email: EmailStr
    password: SecretStr = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class LoginResponse(BaseModel):
    user: UserOut
    # Also set as a cookie; returned in the body so the SPA can start echoing
    # it in the CSRF header without a cookie read.
    csrf_token: str


class LogoutAllResponse(BaseModel):
    revoked_sessions: int
