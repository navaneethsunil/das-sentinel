"""MFA service unit tests (SEC-DEBT-2) — pure logic; DB-backed login/enroll flow
is exercised end-to-end by scripts/verify_mfa.py."""

import pyotp
import pytest

from app.core.mfa import RECOVERY_CODE_COUNT, MfaError, MfaService


def _svc() -> MfaService:
    return MfaService(None, issuer="DAS Sentinel", allow_dev_key=True)


def test_secret_encrypt_decrypt_round_trip():
    svc = _svc()
    secret = svc.new_secret()
    enc = svc.encrypt_secret(secret)
    assert enc != secret  # ciphertext, not plaintext at rest
    assert svc.decrypt_secret(enc) == secret


def test_totp_accepts_live_code_rejects_wrong():
    svc = _svc()
    secret = svc.new_secret()
    live = pyotp.TOTP(secret).now()
    assert svc.verify_totp(secret, live)
    wrong = "000000" if live != "000000" else "111111"
    assert not svc.verify_totp(secret, wrong)


def test_recovery_codes_unique_and_stably_hashed():
    svc = _svc()
    codes = svc.new_recovery_codes()
    assert len(set(codes)) == RECOVERY_CODE_COUNT
    assert svc.hash_recovery_code(codes[0]) == svc.hash_recovery_code(f" {codes[0]} ")  # trims
    assert svc.hash_recovery_code(codes[0]) != svc.hash_recovery_code(codes[1])


def test_prod_without_key_fails_closed():
    svc = MfaService(None, issuer="x", allow_dev_key=False)
    with pytest.raises(MfaError):
        svc.encrypt_secret("whatever")


def test_invalid_key_fails_closed():
    svc = MfaService("not-a-valid-fernet-key", issuer="x", allow_dev_key=False)
    with pytest.raises(MfaError):
        svc.encrypt_secret("whatever")


def test_undecryptable_secret_raises():
    svc = _svc()
    with pytest.raises(MfaError):
        svc.decrypt_secret("garbage-not-a-token")
