"""Password hashing service (M1-B1).

Argon2id with OWASP's first-choice parameters (19 MiB, t=2, p=1) is the
default. PBKDF2-HMAC-SHA256 (600k iterations) is the FIPS fallback, selected
via PASSWORD_HASH_SCHEME if the compliance gate flips (CLAUDE.md §3, ROADMAP).

Stored hashes are self-describing PHC-style strings, so verification dispatches
on the hash itself, not on the active scheme — after a scheme flip, existing
rows keep verifying and `needs_rehash()` flags them for transparent upgrade on
the next successful login. Verification of malformed/unknown hashes returns
False (fail closed), never raises.
"""

import base64
import hashlib
import hmac
import secrets
from typing import Literal

from argon2 import PasswordHasher as Argon2Hasher
from argon2 import exceptions as argon2_exc

PasswordScheme = Literal["argon2id", "pbkdf2_sha256"]

# OWASP Password Storage Cheat Sheet first-choice Argon2id parameters.
ARGON2_MEMORY_KIB = 19_456  # 19 MiB
ARGON2_TIME_COST = 2
ARGON2_PARALLELISM = 1

# OWASP floor for PBKDF2-HMAC-SHA256.
PBKDF2_ITERATIONS = 600_000
PBKDF2_SALT_BYTES = 16
PBKDF2_PREFIX = "$pbkdf2-sha256$"

_argon2 = Argon2Hasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_KIB,
    parallelism=ARGON2_PARALLELISM,
)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii").rstrip("=")


def _unb64(encoded: str) -> bytes:
    return base64.b64decode(encoded + "=" * (-len(encoded) % 4))


def _pbkdf2_hash(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{PBKDF2_PREFIX}{iterations}${_b64(salt)}${_b64(digest)}"


def _pbkdf2_verify(password: str, stored_hash: str) -> bool:
    try:
        iterations_s, salt_s, digest_s = stored_hash.removeprefix(PBKDF2_PREFIX).split("$")
        iterations = int(iterations_s)
        salt, expected = _unb64(salt_s), _unb64(digest_s)
    except (ValueError, TypeError):
        return False  # malformed hash — deny, never raise (TM-14)
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return hmac.compare_digest(actual, expected)


def _pbkdf2_iterations(stored_hash: str) -> int | None:
    try:
        return int(stored_hash.removeprefix(PBKDF2_PREFIX).split("$")[0])
    except (ValueError, IndexError):
        return None


class PasswordService:
    """Hash with the configured scheme; verify against whatever a row holds."""

    def __init__(self, scheme: PasswordScheme) -> None:
        if scheme not in ("argon2id", "pbkdf2_sha256"):
            raise ValueError(f"unknown password hash scheme: {scheme!r}")
        self.scheme: PasswordScheme = scheme

    def hash(self, password: str) -> str:
        if self.scheme == "argon2id":
            return _argon2.hash(password)
        return _pbkdf2_hash(password)

    def verify(self, password: str, stored_hash: str) -> bool:
        if stored_hash.startswith("$argon2id$"):
            try:
                return _argon2.verify(stored_hash, password)
            except argon2_exc.Argon2Error:
                return False  # mismatch or malformed — deny, never raise (TM-14)
        if stored_hash.startswith(PBKDF2_PREFIX):
            return _pbkdf2_verify(password, stored_hash)
        return False  # unknown format — deny

    def needs_rehash(self, stored_hash: str) -> bool:
        """True when the row should be re-hashed on next successful login:
        the stored scheme differs from the active one, or its parameters are
        below the current floor."""
        if self.scheme == "argon2id":
            if not stored_hash.startswith("$argon2id$"):
                return True
            try:
                return _argon2.check_needs_rehash(stored_hash)
            except argon2_exc.InvalidHashError:
                return True
        if not stored_hash.startswith(PBKDF2_PREFIX):
            return True
        iterations = _pbkdf2_iterations(stored_hash)
        return iterations is None or iterations < PBKDF2_ITERATIONS
