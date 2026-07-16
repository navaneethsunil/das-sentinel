"""LLM provider abstraction (M2-B2, CLAUDE.md §7, TRD TR-16).

All model calls go through `LLMService`, which owns the hosted-egress gate,
redaction-before-egress, and the `llm_interactions` audit record. Provider
adapters (Anthropic hosted, Ollama local) implement the `LLMClient` contract and
are built by `build_adapter` from Settings — imported lazily so the API process
never pulls a vendor SDK at startup when no LLM call is made.
"""

from app.llm.base import (
    HostedModelNotAllowedError,
    LLMBackendError,
    LLMClient,
    LLMError,
    LLMMessage,
    LLMRequest,
    LLMResult,
    LLMUsage,
    RedactionFailedError,
)
from app.llm.redaction import Redactor, RegexRedactor, redact_messages
from app.llm.service import LLMService

__all__ = [
    "HostedModelNotAllowedError",
    "LLMBackendError",
    "LLMClient",
    "LLMError",
    "LLMMessage",
    "LLMRequest",
    "LLMResult",
    "LLMService",
    "LLMUsage",
    "RedactionFailedError",
    "Redactor",
    "RegexRedactor",
    "build_adapter",
    "create_llm_service",
    "redact_messages",
]


def build_adapter(settings) -> LLMClient:
    """Construct the provider adapter selected by Settings.llm_provider. Fails
    loud if the backend for that provider is not configured."""
    settings.require_llm_backend()
    provider = settings.llm_provider
    if provider == "anthropic":
        from app.llm.anthropic_adapter import AnthropicAdapter

        return AnthropicAdapter(
            api_key=settings.anthropic_api_key.get_secret_value(),
            fallback_model=settings.llm_model_default,
        )
    if provider == "ollama":
        from app.llm.ollama_adapter import OllamaAdapter

        return OllamaAdapter(base_url=settings.ollama_base_url)
    if provider == "vllm":
        # vLLM (GPU-backed, air-gapped) drops in behind the same interface; its
        # adapter lands with the GPU deployment work, not the MVP.
        raise NotImplementedError("vLLM adapter not yet implemented")
    raise ValueError(f"unknown LLM provider {provider!r}")


def create_llm_service(settings) -> LLMService:
    return LLMService(build_adapter(settings), RegexRedactor(), settings)
