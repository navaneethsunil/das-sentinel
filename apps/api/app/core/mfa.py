"""MFA / TOTP helpers (SEC-DEBT-2).

TOTP verification (RFC 6238) is delegated to pyotp rather than hand-rolled —
getting the time-window and drift handling right is exactly the "don't pick the
flimsier algorithm" case. The TOTP secret is a *reversible* authenticator secret,
so it is Fernet-encrypted at rest (never in the clear on an L3 auth surface).
Recovery codes are high-entropy, so SHA-256 storage is correct (same reasoning
as the session token hash) — no slow KDF needed.
"""

import base64
import hashlib
import secrets

import pyotp
from cryptography.fernet import Fernet, InvalidToken

# Fixed dev fallback key (a valid 32-byte Fernet key). Deliberately NOT in
# .env.example, so it can never be copied into a prod deployment by accident.
_DEV_FERNET_KEY = base64.urlsafe_b64encode(b"das-sentinel-dev-mfa-key-32bytes")

RECOVERY_CODE_COUNT = 10


class MfaError(Exception):
    """MFA could not be performed (no/invalid encryption key, corrupt secret)."""


class MfaService:
    def __init__(self, encryption_key: str | None, *, issuer: str, allow_dev_key: bool):
        if encryption_key:
            self._key: bytes | str | None = encryption_key
        elif allow_dev_key:
            self._key = _DEV_FERNET_KEY
        else:
            # prod with MFA in use but no key configured → fail closed at use time
            self._key = None
        self._issuer = issuer

    @property
    def _fernet(self) -> Fernet:
        if self._key is None:
            raise MfaError("MFA_SECRET_ENCRYPTION_KEY must be set to use MFA in production")
        try:
            return Fernet(self._key)
        except (ValueError, TypeError) as exc:
            raise MfaError("MFA_SECRET_ENCRYPTION_KEY is not a valid Fernet key") from exc

    def new_secret(self) -> str:
        return pyotp.random_base32()

    def encrypt_secret(self, secret: str) -> str:
        return self._fernet.encrypt(secret.encode()).decode()

    def decrypt_secret(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:
            raise MfaError("stored MFA secret could not be decrypted") from exc

    def provisioning_uri(self, secret: str, account: str) -> str:
        return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=self._issuer)

    def verify_totp(self, secret: str, code: str) -> bool:
        # valid_window=1 tolerates one 30s step of clock drift each way (RFC 6238).
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)

    def new_recovery_codes(self, n: int = RECOVERY_CODE_COUNT) -> list[str]:
        return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(n)]

    @staticmethod
    def hash_recovery_code(code: str) -> bytes:
        return hashlib.sha256(code.strip().encode()).digest()
