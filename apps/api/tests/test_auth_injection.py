"""M1-SEC5 (CI-safe half): SQL-injection defense at the auth input boundary.

The database layer is parameterized SQLAlchemy 2.0 (`select(User).where(
User.email == body.email)`) — user input is bound, never string-built — so
injection is prevented by construction. This test pins the *first* line of
defense: the login schema's `EmailStr` rejects classic SQLi payloads before
they ever reach a query, and the password field, while free-form, is a
`SecretStr` that is only ever fed to the hash verifier, never to SQL.

The end-to-end proof (payloads hitting the real DB return 401/422, never 200
or 500, and never leak rows) is in scripts/verify_login_ratelimit.py.
"""

import pytest
from pydantic import ValidationError

from app.schemas.auth import LoginRequest

SQLI_EMAILS = [
    "admin@example.com' OR '1'='1",
    "' OR 1=1 --",
    "admin@example.com'; DROP TABLE users; --",
    'admin@example.com" UNION SELECT password_hash FROM users --',
    "admin@example.com' OR sleep(5)--",
]


@pytest.mark.parametrize("email", SQLI_EMAILS)
def test_sqli_email_rejected_before_any_query(email: str) -> None:
    # EmailStr validation fires at the schema, so the payload never reaches the
    # DB — the request is a 422, not an auth attempt.
    with pytest.raises(ValidationError):
        LoginRequest(email=email, password="whatever")  # noqa: S106 - inert test value


def test_sqli_in_password_is_accepted_as_opaque_secret() -> None:
    # The password is free-form on purpose (any credential must be allowed),
    # but it only ever reaches the Argon2id verifier — never a SQL string.
    req = LoginRequest(
        email="real.user@example.com",
        password="' OR '1'='1' --",  # noqa: S106 - inert test value
    )
    assert req.password.get_secret_value() == "' OR '1'='1' --"


def test_login_response_model_never_exposes_password_hash() -> None:
    # Belt-and-suspenders on info disclosure: UserOut has no password_hash
    # field, so it cannot be serialized into any login/me response.
    from app.schemas.users import UserOut

    assert "password_hash" not in UserOut.model_fields
