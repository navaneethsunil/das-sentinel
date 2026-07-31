"""Authentication schemas (M1-SEC2).

Login enforces only the length *cap* (bounds hashing cost), not the
creation-time minimum: existing credentials must keep working, and a 422-vs-401
split on length would leak which validation rule fired.
"""

from pydantic import BaseModel, EmailStr, Field, SecretStr

from app.schemas.users import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, UserOut


class LoginRequest(BaseModel):
    email: EmailStr
    password: SecretStr = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    # Second factor (TOTP code or a recovery code), sent only when the account
    # has MFA enabled. A first login attempt without it gets a 401 {code:
    # mfa_required} so the SPA knows to prompt.
    mfa_code: SecretStr | None = Field(default=None, max_length=64)


class LoginResponse(BaseModel):
    user: UserOut
    # Also set as a cookie; returned in the body so the SPA can start echoing
    # it in the CSRF header without a cookie read.
    csrf_token: str


class LogoutAllResponse(BaseModel):
    revoked_sessions: int


class SelfProfileUpdate(BaseModel):
    # Every field optional — a PATCH updates only what's sent.
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    email: EmailStr | None = None
    phone: str | None = Field(default=None, max_length=50)


class SelfPasswordChange(BaseModel):
    # current_password is required for a normal change; it may be omitted only
    # when the account is in forced-change mode (already proved the temporary
    # password by authenticating this session). The router enforces that rule.
    current_password: SecretStr | None = Field(default=None, max_length=MAX_PASSWORD_LENGTH)
    new_password: SecretStr = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


class MfaCodeRequest(BaseModel):
    code: SecretStr = Field(min_length=1, max_length=64)


class MfaEnrollResponse(BaseModel):
    # Shown once so the user can add the authenticator (QR from the URI, or the
    # secret typed manually). Not persisted in the clear anywhere.
    secret: str
    provisioning_uri: str


class MfaRecoveryCodesResponse(BaseModel):
    # Returned once at confirm time; only their hashes are stored.
    recovery_codes: list[str]
