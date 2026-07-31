"""Managed credential store — CI-safe unit tests (no network, no DB).

Covers the cipher (encrypt/decrypt + fail-closed key handling), the write-only
schema projection (no secret ever leaves), and the reference resolver + composition
(cred: resolves and decrypts; malformed/unknown/foreign refs fail closed).
"""

import uuid
from datetime import UTC, datetime

import pytest

import app.services.credentials as cred
from app.models.credential import Credential
from app.schemas.credentials import CredentialOut
from app.services.credentials import (
    CredentialCipher,
    CredentialCryptoError,
    CredentialRefError,
    compose_secret_resolver,
    resolve_auth_config_credentials,
    resolve_credential_ref,
)


def _cipher() -> CredentialCipher:
    return CredentialCipher(None, allow_dev_key=True)


# ── cipher ───────────────────────────────────────────────────────────────────


def test_cipher_roundtrip() -> None:
    c = _cipher()
    token = c.encrypt("sk-live-super-secret")
    assert token != "sk-live-super-secret"  # not stored in the clear
    assert c.decrypt(token) == "sk-live-super-secret"


def test_cipher_rejects_garbage_token() -> None:
    with pytest.raises(CredentialCryptoError):
        _cipher().decrypt("not-a-valid-fernet-token")


def test_cipher_fails_closed_without_key_in_prod() -> None:
    prod_like = CredentialCipher(None, allow_dev_key=False)  # no key, prod
    with pytest.raises(CredentialCryptoError, match="must be set"):
        prod_like.encrypt("x")


# ── schema: secret is write-only ──────────────────────────────────────────────


def test_credential_out_never_exposes_secret() -> None:
    c = Credential(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        name="prod-api-key",
        description="Prod API key",
        secret_encrypted="gAAAA-ciphertext",
        created_by=uuid.uuid4(),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    out = CredentialOut.from_model(c)
    dumped = out.model_dump()
    assert "secret" not in dumped
    assert "secret_encrypted" not in dumped
    assert out.reference == f"cred:{c.id}"


# ── resolver ───────────────────────────────────────────────────────────────────


class _FakeSession:
    """Returns a preset credential (or None) for get_org_credential's query."""


def _patch_lookup(monkeypatch, credential: Credential | None) -> None:
    async def fake_get(_db, _org, _cid):
        return credential

    monkeypatch.setattr(cred, "get_org_credential", fake_get)


def _stored(cipher: CredentialCipher, secret: str, org_id: uuid.UUID) -> Credential:
    return Credential(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="k",
        description=None,
        secret_encrypted=cipher.encrypt(secret),
    )


async def test_resolve_ref_happy_path_decrypts(monkeypatch) -> None:
    c = _cipher()
    org = uuid.uuid4()
    stored = _stored(c, "resolved-secret", org)
    _patch_lookup(monkeypatch, stored)
    ref = f"cred:{stored.id}"
    got = await resolve_credential_ref(_FakeSession(), c, organization_id=org, ref=ref)
    assert got == "resolved-secret"


async def test_resolve_ref_rejects_non_cred_scheme() -> None:
    with pytest.raises(CredentialRefError):
        await resolve_credential_ref(
            _FakeSession(), _cipher(), organization_id=uuid.uuid4(), ref="env:FOO"
        )


async def test_resolve_ref_rejects_malformed_uuid() -> None:
    with pytest.raises(CredentialRefError, match="malformed"):
        await resolve_credential_ref(
            _FakeSession(), _cipher(), organization_id=uuid.uuid4(), ref="cred:not-a-uuid"
        )


async def test_resolve_ref_fails_closed_on_unknown_or_foreign(monkeypatch) -> None:
    _patch_lookup(monkeypatch, None)  # not in this org / deleted
    with pytest.raises(CredentialRefError, match="does not resolve"):
        await resolve_credential_ref(
            _FakeSession(),
            _cipher(),
            organization_id=uuid.uuid4(),
            ref=f"cred:{uuid.uuid4()}",
        )


async def test_resolve_auth_config_finds_nested_refs(monkeypatch) -> None:
    c = _cipher()
    org = uuid.uuid4()
    stored = _stored(c, "nested-secret", org)
    _patch_lookup(monkeypatch, stored)
    auth_config = {"headers": [{"value_ref": f"cred:{stored.id}"}], "other": "env:X"}
    resolved = await resolve_auth_config_credentials(
        _FakeSession(), c, auth_config, organization_id=org
    )
    assert resolved == {f"cred:{stored.id}": "nested-secret"}  # env:X is not a cred ref


def test_compose_resolver_prefers_cred_map_then_delegates() -> None:
    resolver = compose_secret_resolver({"cred:abc": "from-vault"}, base=lambda ref: f"env:{ref}")
    assert resolver("cred:abc") == "from-vault"
    assert resolver("env:OTHER") == "env:env:OTHER"  # delegated to base
