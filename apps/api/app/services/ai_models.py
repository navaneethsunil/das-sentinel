"""AI model registry — register a provider once, then reference it everywhere.

CRUD over `ai_models` plus a *credential-and-model check* run before a model is
registered, so a bad API key or an un-pulled Ollama model is caught here instead of
mid-scan. The check deliberately calls the provider's metadata endpoint (Anthropic
`GET /v1/models/{id}`, Ollama `POST /api/show`) — it sends NO prompt, so it is not
model egress and needs no engagement/redaction gate (CLAUDE.md §2.7).

The API key is encrypted with the credential store's cipher (`CredentialCipher`) and
is write-only: it is decrypted only in `app.llm.registry` to build an adapter.
"""

import uuid
from urllib.parse import urlsplit, urlunsplit

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.sessions import utcnow
from app.models.ai_model import AIModel
from app.services.credentials import CredentialCipher

_VERIFY_TIMEOUT_S = 10.0
# Loopback typed by an operator means the Docker host, not the API container.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})  # noqa: S104 - compared, not bound
_HOST_GATEWAY = "host.docker.internal"

_ANTHROPIC_API = "https://api.anthropic.com"
_ANTHROPIC_VERSION = "2023-06-01"


class AIModelError(Exception):
    """Base for registry failures."""


class AIModelVerificationError(AIModelError):
    """The provider rejected the key or does not have that model. The provider's
    response body is never included — only what the operator needs to fix it."""


class AIModelUnreachableError(AIModelVerificationError):
    """Nothing answered at the endpoint at all. Distinct from a provider that
    answered and said no, so that when several candidate endpoints are tried the
    answer ("no such model") wins over the silence."""


async def list_models(db: AsyncSession, organization_id: uuid.UUID) -> list[AIModel]:
    return list(
        (
            await db.execute(
                select(AIModel)
                .where(
                    AIModel.organization_id == organization_id,
                    AIModel.deleted_at.is_(None),
                )
                .order_by(AIModel.is_default.desc(), AIModel.name)
            )
        )
        .scalars()
        .all()
    )


async def get_org_model(
    db: AsyncSession, organization_id: uuid.UUID, model_id: uuid.UUID
) -> AIModel | None:
    """A live registered model in this org, or None (routers map None → 404, so a
    model in another org is never distinguishable from a missing one)."""
    return (
        await db.execute(
            select(AIModel).where(
                AIModel.id == model_id,
                AIModel.organization_id == organization_id,
                AIModel.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()


async def get_default_model(db: AsyncSession, organization_id: uuid.UUID) -> AIModel | None:
    return (
        await db.execute(
            select(AIModel).where(
                AIModel.organization_id == organization_id,
                AIModel.is_default.is_(True),
                AIModel.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()


def normalize_base_url(base_url: str) -> str:
    """Accept only an absolute http(s) origin for a local provider — the URL becomes
    an outbound request the platform makes, so a `file:`/`gopher:` scheme or a bare
    host is rejected at the boundary rather than handed to the HTTP client."""
    parts = urlsplit(base_url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise AIModelVerificationError(
            "the endpoint must be an absolute http:// or https:// URL, e.g. http://localhost:11434"
        )
    return base_url.strip().rstrip("/")


def endpoint_candidates(base_url: str) -> list[str]:
    """The endpoints to try for a local provider, in order.

    An operator who types `localhost:11434` means "the machine I administer". The
    API runs in a container, where loopback is the *container*, so that address can
    never be the operator's Ollama — the Docker host alias is tried as well and the
    one that answers is what gets stored. Outside a container the first candidate
    wins and nothing changes. No new reach: the host is already addressable by name
    in this admin-only field."""
    parts = urlsplit(base_url)
    if (parts.hostname or "").lower() not in _LOOPBACK_HOSTS:
        return [base_url]
    port = f":{parts.port}" if parts.port else ""
    gateway = urlunsplit((parts.scheme, f"{_HOST_GATEWAY}{port}", parts.path, "", ""))
    return [base_url, gateway.rstrip("/")]


async def verify_provider(
    *, provider: str, model_id: str, api_key: str | None, base_url: str | None
) -> None:
    """Prove the key/endpoint works and the model exists, without sending a prompt.
    Raises AIModelVerificationError with an operator-actionable message."""
    if provider == "anthropic":
        url = f"{_ANTHROPIC_API}/v1/models/{model_id}"
        headers = {"x-api-key": api_key or "", "anthropic-version": _ANTHROPIC_VERSION}
    elif provider == "ollama":
        url = f"{base_url}/api/show"
        headers = {}
    else:
        raise AIModelVerificationError(f"unsupported provider {provider!r}")

    try:
        async with httpx.AsyncClient(timeout=_VERIFY_TIMEOUT_S) as client:
            response = (
                await client.get(url, headers=headers)
                if provider == "anthropic"
                else await client.post(url, json={"model": model_id})
            )
    except httpx.HTTPError as exc:
        raise AIModelUnreachableError(
            f"could not reach the provider ({type(exc).__name__}) — check the endpoint"
        ) from exc

    if response.status_code in (401, 403):
        raise AIModelVerificationError("the provider rejected the API key")
    if response.status_code == 404:
        raise AIModelVerificationError(
            f"the provider does not have a model named {model_id!r} "
            "(for Ollama, pull it first: ollama pull <model>)"
        )
    if response.status_code >= 400:
        raise AIModelVerificationError(
            f"the provider returned HTTP {response.status_code} while checking the model"
        )


async def create_model(
    db: AsyncSession,
    cipher: CredentialCipher,
    *,
    organization_id: uuid.UUID,
    name: str,
    provider: str,
    model_id: str,
    api_key: str | None,
    base_url: str | None,
    make_default: bool,
    created_by: uuid.UUID | None,
) -> AIModel:
    """Register a model. The caller commits."""
    if provider == "ollama":
        if not base_url:
            raise AIModelVerificationError("a local model needs its Ollama endpoint URL")
        base_url = normalize_base_url(base_url)
        api_key = None
    elif provider == "anthropic":
        if not api_key:
            raise AIModelVerificationError("a hosted model needs an API key")
        base_url = None
    base_url = await _verified_endpoint(
        provider=provider, model_id=model_id, api_key=api_key, base_url=base_url
    )

    # First model registered becomes the default, so a fresh install works without
    # a second click.
    is_default = make_default or (await get_default_model(db, organization_id)) is None
    if is_default:
        await _clear_default(db, organization_id)

    row = AIModel(
        organization_id=organization_id,
        name=name,
        provider=provider,
        model_id=model_id,
        base_url=base_url,
        api_key_encrypted=cipher.encrypt(api_key) if api_key else None,
        is_default=is_default,
        created_by=created_by,
    )
    db.add(row)
    return row


async def _verified_endpoint(
    *, provider: str, model_id: str, api_key: str | None, base_url: str | None
) -> str | None:
    """Verify the model against the provider and return the endpoint that answered.
    Fail-closed: nothing is registered unless one candidate verifies."""
    candidates: list[str | None] = list(endpoint_candidates(base_url)) if base_url else [None]
    errors: list[AIModelVerificationError] = []
    for candidate in candidates:
        try:
            await verify_provider(
                provider=provider, model_id=model_id, api_key=api_key, base_url=candidate
            )
        except AIModelVerificationError as exc:
            errors.append(exc)
            continue
        return candidate

    # A provider that answered and refused is the useful message; pure silence from
    # every candidate is a reachability problem, reported with what was tried.
    answered = next((e for e in errors if not isinstance(e, AIModelUnreachableError)), None)
    if answered is not None:
        raise answered
    if len(candidates) > 1:
        raise AIModelUnreachableError(
            f"could not reach Ollama at {' or '.join(str(c) for c in candidates)} — "
            "is it running, and listening on an address the API container can reach "
            "(OLLAMA_HOST=0.0.0.0 ollama serve)?"
        ) from errors[0]
    raise errors[0]


async def set_default(db: AsyncSession, organization_id: uuid.UUID, row: AIModel) -> None:
    await _clear_default(db, organization_id)
    await db.execute(
        update(AIModel).where(AIModel.id == row.id).values(is_default=True, updated_at=utcnow())
    )


async def soft_delete(db: AsyncSession, row: AIModel) -> None:
    await db.execute(
        update(AIModel)
        .where(AIModel.id == row.id)
        .values(deleted_at=utcnow(), is_default=False, updated_at=utcnow())
    )


async def _clear_default(db: AsyncSession, organization_id: uuid.UUID) -> None:
    """Runs before setting a new default — the partial unique index allows only one
    live default per org, and statements in a transaction apply in order."""
    await db.execute(
        update(AIModel)
        .where(AIModel.organization_id == organization_id, AIModel.is_default.is_(True))
        .values(is_default=False, updated_at=utcnow())
    )
