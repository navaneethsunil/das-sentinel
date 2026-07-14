"""M1-B1: password hashing service — both schemes, cross-scheme verification,
rehash-on-scheme-flip, and fail-closed handling of malformed hashes (TM-14)."""

import pytest

from app.core.config import Settings
from app.core.security import (
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    PBKDF2_ITERATIONS,
    PasswordService,
    _pbkdf2_hash,
)

PASSWORD = "correct horse battery staple"  # noqa: S105


@pytest.fixture()
def argon2_service() -> PasswordService:
    return PasswordService("argon2id")


@pytest.fixture()
def pbkdf2_service() -> PasswordService:
    return PasswordService("pbkdf2_sha256")


class TestArgon2id:
    def test_roundtrip(self, argon2_service: PasswordService) -> None:
        hashed = argon2_service.hash(PASSWORD)
        assert argon2_service.verify(PASSWORD, hashed)

    def test_wrong_password_rejected(self, argon2_service: PasswordService) -> None:
        hashed = argon2_service.hash(PASSWORD)
        assert not argon2_service.verify("wrong password", hashed)

    def test_owasp_parameters_encoded(self, argon2_service: PasswordService) -> None:
        hashed = argon2_service.hash(PASSWORD)
        assert hashed.startswith("$argon2id$")
        assert f"m={ARGON2_MEMORY_KIB},t={ARGON2_TIME_COST},p={ARGON2_PARALLELISM}" in hashed

    def test_salted(self, argon2_service: PasswordService) -> None:
        assert argon2_service.hash(PASSWORD) != argon2_service.hash(PASSWORD)

    def test_fresh_hash_needs_no_rehash(self, argon2_service: PasswordService) -> None:
        assert not argon2_service.needs_rehash(argon2_service.hash(PASSWORD))

    def test_unicode_password(self, argon2_service: PasswordService) -> None:
        hashed = argon2_service.hash("pässwörd-🔑")
        assert argon2_service.verify("pässwörd-🔑", hashed)


class TestPBKDF2:
    def test_roundtrip(self, pbkdf2_service: PasswordService) -> None:
        hashed = pbkdf2_service.hash(PASSWORD)
        assert hashed.startswith(f"$pbkdf2-sha256${PBKDF2_ITERATIONS}$")
        assert pbkdf2_service.verify(PASSWORD, hashed)

    def test_wrong_password_rejected(self, pbkdf2_service: PasswordService) -> None:
        hashed = pbkdf2_service.hash(PASSWORD)
        assert not pbkdf2_service.verify("wrong password", hashed)

    def test_salted(self, pbkdf2_service: PasswordService) -> None:
        assert pbkdf2_service.hash(PASSWORD) != pbkdf2_service.hash(PASSWORD)

    def test_below_iteration_floor_needs_rehash(self, pbkdf2_service: PasswordService) -> None:
        weak = _pbkdf2_hash(PASSWORD, iterations=100_000)
        assert pbkdf2_service.verify(PASSWORD, weak)  # still verifies...
        assert pbkdf2_service.needs_rehash(weak)  # ...but is flagged for upgrade


class TestSchemeFlip:
    """The FIPS gate: flip the scheme, old rows keep working and get flagged."""

    def test_argon2_service_verifies_pbkdf2_rows(
        self, argon2_service: PasswordService, pbkdf2_service: PasswordService
    ) -> None:
        old = pbkdf2_service.hash(PASSWORD)
        assert argon2_service.verify(PASSWORD, old)
        assert argon2_service.needs_rehash(old)

    def test_pbkdf2_service_verifies_argon2_rows(
        self, argon2_service: PasswordService, pbkdf2_service: PasswordService
    ) -> None:
        old = argon2_service.hash(PASSWORD)
        assert pbkdf2_service.verify(PASSWORD, old)
        assert pbkdf2_service.needs_rehash(old)


class TestFailClosed:
    """Malformed/unknown hashes deny and never raise (TM-14)."""

    @pytest.mark.parametrize(
        "bad_hash",
        [
            "",
            "plaintext-or-garbage",
            "$argon2id$corrupted",
            "$pbkdf2-sha256$not-an-int$salt$digest",
            "$pbkdf2-sha256$600000$only-one-part",
            "$md5$whatever",  # unknown scheme prefix
        ],
    )
    def test_verify_denies_malformed(self, argon2_service: PasswordService, bad_hash: str) -> None:
        assert not argon2_service.verify(PASSWORD, bad_hash)

    def test_malformed_hash_needs_rehash(self, argon2_service: PasswordService) -> None:
        assert argon2_service.needs_rehash("$argon2id$corrupted")

    def test_unknown_scheme_rejected_loudly(self) -> None:
        with pytest.raises(ValueError, match="unknown password hash scheme"):
            PasswordService("md5")  # type: ignore[arg-type]


def test_settings_carry_scheme(env: dict[str, str]) -> None:
    assert Settings().password_hash_scheme == "argon2id"  # noqa: S105 — scheme name, not a secret
