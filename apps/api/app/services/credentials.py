"""Managed credential store — a hardened, in-app secret vault (TR-23).

Analysts create a named secret ONCE (the credential), and everywhere a secret is
needed they store a `cred:<id>` REFERENCE instead of the plaintext. The secret is
Fernet-encrypted at rest and WRITE-ONLY: no code path returns it to a client; it is
decrypted only in-memory at scan time to build a request header. This module owns
both the CRUD and the reference resolver.

Design (OWASP Secrets Management Cheat Sheet):
  * Encrypted at rest with a key held SEPARATELY from the ciphertext DB (the key
    comes from Settings.credential_encryption_key — SOPS/mounted secret, never the
    same store). Dev fallback key outside prod; prod fails closed with no key.
  * Least privilege + audit are enforced at the router (MANAGE_CREDENTIALS + audit
    events on create/delete/use).
  * The reference is provider-agnostic: `cred:<id>` resolves here, `env:<VAR>` in
    the connector — so the SAME reference can later be backed by an external
    secrets manager (`vault:…`) without touching callers. Envelope encryption /
    external KMS is the documented upgrade behind this same abstraction.
"""

import base64
import uuid
from collections.abc import Callable, Iterator
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.credential import Credential

CRED_REF_PREFIX = "cred:"
# A valid 32-byte Fernet key for dev/test only. Deliberately NOT in .env.example,
# so it can never be copied into a prod deployment by accident (mirrors MfaService).
_DEV_FERNET_KEY = base64.urlsafe_b64encode(b"das-sentinel-dev-cred-key-32byte")


class CredentialError(Exception):
    """Base for credential-store failures."""


class CredentialCryptoError(CredentialError):
    """No/invalid encryption key, or a stored secret that will not decrypt."""


class CredentialRefError(CredentialError):
    """A `cred:` reference does not resolve to a live credential in this org
    (unknown id, wrong org, or deleted) — fail closed; a scan never proceeds with
    an unresolved credential."""


class CredentialCipher:
    """Fernet encrypt/decrypt with the same key-handling contract as MfaService:
    a real key in prod, a fixed dev key outside prod, fail-closed when neither."""

    def __init__(self, encryption_key: str | None, *, allow_dev_key: bool) -> None:
        if encryption_key:
            self._key: bytes | str | None = encryption_key
        elif allow_dev_key:
            self._key = _DEV_FERNET_KEY
        else:
            self._key = None  # prod + no key → fail at use time, not at boot

    @property
    def _fernet(self) -> Fernet:
        if self._key is None:
            raise CredentialCryptoError(
                "CREDENTIAL_ENCRYPTION_KEY must be set to use the credential store in production"
            )
        try:
            return Fernet(self._key)
        except (ValueError, TypeError) as exc:
            raise CredentialCryptoError(
                "CREDENTIAL_ENCRYPTION_KEY is not a valid Fernet key"
            ) from exc

    def encrypt(self, secret: str) -> str:
        return self._fernet.encrypt(secret.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:
            raise CredentialCryptoError("stored credential secret could not be decrypted") from exc


async def create_credential(
    db: AsyncSession,
    cipher: CredentialCipher,
    *,
    organization_id: uuid.UUID,
    name: str,
    description: str | None,
    secret: str,
    created_by: uuid.UUID | None,
) -> Credential:
    """Encrypt + persist a new credential (flushed into the caller's transaction).
    The plaintext `secret` is consumed here and never stored or returned."""
    row = Credential(
        organization_id=organization_id,
        name=name,
        description=description,
        secret_encrypted=cipher.encrypt(secret),
        created_by=created_by,
    )
    db.add(row)
    await db.flush()
    return row


async def list_credentials(db: AsyncSession, organization_id: uuid.UUID) -> list[Credential]:
    """Live credentials for the org, newest first. Metadata only — the caller's
    schema omits the secret; this never decrypts."""
    return list(
        (
            await db.execute(
                select(Credential)
                .where(
                    Credential.organization_id == organization_id,
                    Credential.deleted_at.is_(None),
                )
                .order_by(Credential.created_at.desc())
            )
        )
        .scalars()
        .all()
    )


async def get_org_credential(
    db: AsyncSession, organization_id: uuid.UUID, credential_id: uuid.UUID
) -> Credential | None:
    """Fetch a live credential within the caller's org, or None (router → 404, no
    cross-org existence leak)."""
    return (
        await db.execute(
            select(Credential).where(
                Credential.id == credential_id,
                Credential.organization_id == organization_id,
                Credential.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()


async def resolve_credential_ref(
    db: AsyncSession, cipher: CredentialCipher, *, organization_id: uuid.UUID, ref: str
) -> str:
    """Resolve a `cred:<id>` reference to its plaintext secret (in-memory only),
    scoped to the org. Fail closed on a malformed/unknown/foreign/deleted ref."""
    if not isinstance(ref, str) or not ref.startswith(CRED_REF_PREFIX):
        raise CredentialRefError(f"not a credential reference: {ref!r}")
    raw = ref[len(CRED_REF_PREFIX) :]
    try:
        credential_id = uuid.UUID(raw)
    except ValueError as exc:
        raise CredentialRefError(f"malformed credential reference {ref!r}") from exc
    row = await get_org_credential(db, organization_id, credential_id)
    if row is None:
        raise CredentialRefError(
            f"credential reference {ref!r} does not resolve to a live credential in this org"
        )
    return cipher.decrypt(row.secret_encrypted)


def _iter_cred_refs(node: Any) -> Iterator[str]:
    """Every `cred:<id>` string value anywhere in a (nested) auth_config."""
    if isinstance(node, dict):
        for value in node.values():
            yield from _iter_cred_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_cred_refs(item)
    elif isinstance(node, str) and node.startswith(CRED_REF_PREFIX):
        yield node


async def resolve_auth_config_credentials(
    db: AsyncSession,
    cipher: CredentialCipher,
    auth_config: dict[str, Any] | None,
    *,
    organization_id: uuid.UUID,
) -> dict[str, str]:
    """Pre-resolve every `cred:` reference in an auth_config to its plaintext, once,
    inside the (async) worker session. Returns {ref: secret} for the sync connector
    resolver to look up — so the connector never needs DB/decrypt access itself."""
    out: dict[str, str] = {}
    for ref in set(_iter_cred_refs(auth_config)):
        out[ref] = await resolve_credential_ref(
            db, cipher, organization_id=organization_id, ref=ref
        )
    return out


def compose_secret_resolver(
    cred_map: dict[str, str], base: Callable[[str], str]
) -> Callable[[str], str]:
    """A connector secret resolver that returns a pre-resolved `cred:` secret, else
    delegates to `base` (the env resolver). A no-op wrapper when cred_map is empty,
    so non-credential targets behave exactly as before."""

    def _resolve(ref: str) -> str:
        if ref in cred_map:
            return cred_map[ref]
        return base(ref)

    return _resolve
