"""AI model schemas — the registry (register once, engagements reference it) plus
the environment-fallback status view.

No secret ever appears in a response: the API key is write-only (create-only,
`SecretStr`), and the out-model carries only operator-visible facts — provider,
model id, endpoint, whether egress is hosted (off-box) or local (on-box).
"""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, model_validator

from app.models.ai_model import AIModel

# Only hosted (off-box) providers are subject to redaction + hosted_models_allowed.
HOSTED_PROVIDERS = frozenset({"anthropic"})

AIProvider = Literal["anthropic", "ollama"]


class LlmModels(BaseModel):
    default: str
    triage: str
    classifier: str


class LlmStatusOut(BaseModel):
    provider: str  # anthropic | ollama | vllm
    hosted: bool  # true = off-box egress (redaction + per-engagement gate apply)
    endpoint: str | None  # provider host / base URL (no credentials)
    models: LlmModels


class AIModelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    provider: AIProvider
    model_id: str = Field(min_length=1, max_length=200)
    # Hosted providers only — encrypted at rest, never returned.
    api_key: SecretStr | None = None
    # Local providers only, e.g. http://localhost:11434.
    base_url: str | None = Field(default=None, max_length=500)
    make_default: bool = False

    @model_validator(mode="after")
    def _require_provider_config(self) -> "AIModelCreate":
        if self.provider == "anthropic" and not self.api_key:
            raise ValueError("api_key is required for a hosted provider")
        if self.provider == "ollama" and not self.base_url:
            raise ValueError("base_url is required for a local provider")
        return self


class AIModelOut(BaseModel):
    id: uuid.UUID
    name: str
    provider: str
    model_id: str
    base_url: str | None
    hosted: bool
    is_default: bool
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, m: AIModel) -> "AIModelOut":
        return cls(
            id=m.id,
            name=m.name,
            provider=m.provider,
            model_id=m.model_id,
            base_url=m.base_url,
            hosted=m.provider in HOSTED_PROVIDERS,
            is_default=m.is_default,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )
