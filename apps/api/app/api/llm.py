"""Active-LLM status endpoint — which AI model is in use right now.

Read-only, VIEW-guarded. Reports the configured provider + model names + whether
egress is hosted or local, so operators/reviewers can see what AI is active. It
reads Settings only and never touches the API key (§5 secrets, §7 LLM rules).
`hosted` is derived from the provider (only Anthropic is off-box; Ollama and vLLM
are local), matching each adapter's own `hosted` flag.
"""

from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.core.deps import Capability, Principal, require
from app.schemas.llm import LlmModels, LlmStatusOut

router = APIRouter(prefix="/llm", tags=["llm"])

_HOSTED_PROVIDERS = frozenset({"anthropic"})


@router.get("/status", response_model=LlmStatusOut)
async def llm_status(
    _principal: Principal = Depends(require(Capability.VIEW)),
    settings: Settings = Depends(get_settings),
) -> LlmStatusOut:
    provider = settings.llm_provider
    hosted = provider in _HOSTED_PROVIDERS
    endpoint = {
        "anthropic": "Anthropic API",
        "ollama": settings.ollama_base_url,
        "vllm": settings.vllm_base_url,
    }.get(provider)
    return LlmStatusOut(
        provider=provider,
        hosted=hosted,
        endpoint=endpoint,
        models=LlmModels(
            default=settings.llm_model_default,
            triage=settings.llm_model_triage,
            classifier=settings.llm_model_classifier,
        ),
    )
