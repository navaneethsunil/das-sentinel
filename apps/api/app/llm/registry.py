"""Resolve which provider adapter a call runs on, from the AI model registry.

Precedence, per call:

  1. the engagement's pinned registered model (`engagements.ai_model_id`),
  2. the organization's default registered model,
  3. the environment fallback (`LLM_PROVIDER` + friends) for deployments that
     configure the provider in `.env` and never open the UI.

A model pinned to an engagement that has since been deleted **fails loud** — it is
never silently swapped for another provider, because the operator chose that model
deliberately (a local model, say, on a sensitive engagement).

Adapters hold a provider client, so they are cached per (row id, updated_at): an
edited row builds a fresh adapter and the stale one is closed.
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.llm.base import LLMBackendError, LLMClient
from app.models.ai_model import AIModel
from app.models.engagement import Engagement
from app.services.ai_models import get_default_model, get_org_model
from app.services.credentials import CredentialCipher

_ENV_KEY = "env"


class AIModelRegistry:
    def __init__(self, cipher: CredentialCipher, settings: Settings) -> None:
        self._cipher = cipher
        self._settings = settings
        self._adapters: dict[str, tuple[object, LLMClient]] = {}

    async def resolve(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        engagement: Engagement | None,
    ) -> tuple[LLMClient, str]:
        """The adapter to use and its default model id."""
        row = await self._row_for(session, organization_id, engagement)
        if row is None:
            adapter = await self._cached(_ENV_KEY, None, self._build_env)
            return adapter, self._settings.llm_model_default
        adapter = await self._cached(str(row.id), row.updated_at, lambda: self._build(row))
        return adapter, row.model_id

    async def _row_for(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        engagement: Engagement | None,
    ) -> AIModel | None:
        if engagement is not None and engagement.ai_model_id is not None:
            row = await get_org_model(session, organization_id, engagement.ai_model_id)
            if row is None:
                raise LLMBackendError(
                    "the AI model pinned to this engagement no longer exists — "
                    "pick a registered model under System → AI models"
                )
            return row
        return await get_default_model(session, organization_id)

    async def _cached(self, key: str, version: object, build) -> LLMClient:
        cached = self._adapters.get(key)
        if cached is not None:
            if cached[0] == version:
                return cached[1]
            await cached[1].aclose()  # row edited — drop the stale client
        adapter = build()
        self._adapters[key] = (version, adapter)
        return adapter

    def _build(self, row: AIModel) -> LLMClient:
        if row.provider == "anthropic":
            from app.llm.anthropic_adapter import AnthropicAdapter

            if row.api_key_encrypted is None:
                raise LLMBackendError(f"registered model {row.name!r} has no API key stored")
            return AnthropicAdapter(
                api_key=self._cipher.decrypt(row.api_key_encrypted),
                fallback_model=row.model_id,
            )
        if row.provider == "ollama":
            from app.llm.ollama_adapter import OllamaAdapter

            if row.base_url is None:
                raise LLMBackendError(f"registered model {row.name!r} has no endpoint stored")
            return OllamaAdapter(base_url=row.base_url)
        raise LLMBackendError(
            f"registered model {row.name!r} has unknown provider {row.provider!r}"
        )

    def _build_env(self) -> LLMClient:
        from app.llm import build_adapter

        try:
            return build_adapter(self._settings)
        except (ValueError, NotImplementedError) as exc:
            raise LLMBackendError(
                "no AI model is configured — add one under System → AI models"
            ) from exc

    async def aclose(self) -> None:
        for _version, adapter in self._adapters.values():
            await adapter.aclose()
        self._adapters.clear()
