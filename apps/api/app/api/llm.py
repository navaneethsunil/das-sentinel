"""AI model endpoints — the registry an admin fills in once, plus the env fallback.

Reads are VIEW-guarded (any authenticated role may see which model is active);
registering, defaulting, and removing a model are MANAGE_AI_MODELS (admin only) and
audited. The provider API key is write-only: it is accepted on create, encrypted,
and never returned by any route (§5 secrets, §7 LLM rules).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.config import Settings, get_settings
from app.core.deps import (
    Capability,
    Principal,
    get_audit_service,
    get_credential_cipher,
    get_db,
    require,
)
from app.models.ai_model import AIModel
from app.models.engagement import Engagement
from app.schemas.llm import (
    HOSTED_PROVIDERS,
    AIModelCreate,
    AIModelOut,
    LlmModels,
    LlmStatusOut,
)
from app.services.ai_models import (
    AIModelVerificationError,
    create_model,
    get_org_model,
    list_models,
    set_default,
    soft_delete,
)
from app.services.credentials import CredentialCipher

router = APIRouter(prefix="/llm", tags=["llm"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/status", response_model=LlmStatusOut)
async def llm_status(
    _principal: Principal = Depends(require(Capability.VIEW)),
    settings: Settings = Depends(get_settings),
) -> LlmStatusOut:
    """The environment-configured fallback provider — what analysis runs on when no
    AI model is registered. `GET /llm/models` is the registry an operator manages."""
    provider = settings.llm_provider
    endpoint = {
        "anthropic": "Anthropic API",
        "ollama": settings.ollama_base_url,
        "vllm": settings.vllm_base_url,
    }.get(provider)
    return LlmStatusOut(
        provider=provider,
        hosted=provider in HOSTED_PROVIDERS,
        endpoint=endpoint,
        models=LlmModels(
            default=settings.llm_model_default,
            triage=settings.llm_model_triage,
            classifier=settings.llm_model_classifier,
        ),
    )


@router.get("/models", response_model=list[AIModelOut])
async def list_ai_models(
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[AIModelOut]:
    return [AIModelOut.from_model(m) for m in await list_models(db, principal.organization_id)]


@router.post("/models", response_model=AIModelOut, status_code=status.HTTP_201_CREATED)
async def create_ai_model(
    body: AIModelCreate,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_AI_MODELS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    cipher: CredentialCipher = Depends(get_credential_cipher),
) -> AIModelOut:
    try:
        row = await create_model(
            db,
            cipher,
            organization_id=principal.organization_id,
            name=body.name,
            provider=body.provider,
            model_id=body.model_id,
            api_key=body.api_key.get_secret_value() if body.api_key else None,
            base_url=body.base_url,
            make_default=body.make_default,
            created_by=principal.user_id,
        )
        await db.flush()
    except AIModelVerificationError as exc:
        # The provider said no (bad key, unknown/un-pulled model, unreachable
        # endpoint) — surfaced loud so it is fixed now, not mid-scan.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="an AI model with this name already exists",
        ) from exc
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="ai_model.registered",
        object_type="ai_model",
        object_id=row.id,
        detail={  # never the key
            "name": row.name,
            "provider": row.provider,
            "model_id": row.model_id,
            "base_url": row.base_url,
            "is_default": row.is_default,
        },
        ip_address=_client_ip(request),
    )
    await db.commit()
    await db.refresh(row)
    return AIModelOut.from_model(row)


@router.post("/models/{ai_model_id}/default", response_model=AIModelOut)
async def make_default(
    ai_model_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_AI_MODELS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> AIModelOut:
    row = await _require_model(db, principal.organization_id, ai_model_id)
    await set_default(db, principal.organization_id, row)
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="ai_model.default_changed",
        object_type="ai_model",
        object_id=row.id,
        detail={"name": row.name},
        ip_address=_client_ip(request),
    )
    await db.commit()
    await db.refresh(row)
    return AIModelOut.from_model(row)


@router.delete("/models/{ai_model_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ai_model(
    ai_model_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_AI_MODELS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> None:
    row = await _require_model(db, principal.organization_id, ai_model_id)
    # An engagement pinned to this model would break at its next analysis call
    # (the resolver fails loud rather than silently swapping providers), so refuse
    # the removal while one still points here.
    still_used = await db.scalar(
        select(
            exists().where(
                Engagement.ai_model_id == row.id,
                Engagement.deleted_at.is_(None),
            )
        )
    )
    if still_used:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="an engagement still uses this AI model — point it at another model first",
        )
    await soft_delete(db, row)
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="ai_model.removed",
        object_type="ai_model",
        object_id=row.id,
        detail={"name": row.name},
        ip_address=_client_ip(request),
    )
    await db.commit()


async def _require_model(
    db: AsyncSession, organization_id: uuid.UUID, ai_model_id: uuid.UUID
) -> AIModel:
    row = await get_org_model(db, organization_id, ai_model_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI model not found")
    return row
