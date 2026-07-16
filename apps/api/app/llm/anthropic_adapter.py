"""Anthropic Claude adapter — the default hosted backend (M2-B2, CLAUDE.md §7).

Uses only current Claude params: adaptive thinking, `output_config.effort`, and
strict structured output via `output_config.format`. It does NOT send
`budget_tokens`, `temperature`, or `top_p` (those 400 on current models), nor
date-suffixed model ids.

Fable 5 is avoided as a default (its cyber-content classifier can refuse
security-adjacent prompts — a real false-positive risk for a pentest tool). If a
caller does select a Fable/Mythos model, this adapter attaches a server-side
`fallbacks` entry to `claude-opus-4-8` so a refusal is transparently re-served
rather than failing the job (CLAUDE.md §3, §7).

`anthropic` is imported at module load, so this module is imported lazily (via
build_adapter / the local import in the worker task) and never at API startup.
"""

import json
from typing import Any

from anthropic import AsyncAnthropic

from app.llm.base import LLMBackendError, LLMRequest, LLMResult, LLMUsage

_FABLE_FALLBACK_BETA = "server-side-fallback-2026-06-01"
_DEFAULT_FALLBACK_MODEL = "claude-opus-4-8"


def _is_fable(model: str) -> bool:
    return model.startswith("claude-fable") or model.startswith("claude-mythos")


def _extract_text(content: list[Any]) -> str:
    return "".join(block.text for block in content if getattr(block, "type", None) == "text")


class AnthropicAdapter:
    provider = "anthropic"
    hosted = True

    def __init__(self, *, api_key: str, fallback_model: str = _DEFAULT_FALLBACK_MODEL) -> None:
        self._client = AsyncAnthropic(api_key=api_key)
        # A Fable model can't fall back to itself; pin to Opus if misconfigured.
        self._fallback_model = (
            _DEFAULT_FALLBACK_MODEL if _is_fable(fallback_model) else fallback_model
        )

    async def complete(self, request: LLMRequest) -> LLMResult:
        output_config: dict[str, Any] = {"effort": request.effort}
        if request.output_schema is not None:
            output_config["format"] = {
                "type": "json_schema",
                "schema": request.output_schema,
            }
        kwargs: dict[str, Any] = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "output_config": output_config,
        }
        if request.system is not None:
            kwargs["system"] = request.system

        try:
            if _is_fable(request.model):
                # Thinking is always on for Fable — omit the param; add fallbacks.
                response = await self._client.beta.messages.create(
                    betas=[_FABLE_FALLBACK_BETA],
                    fallbacks=[{"model": self._fallback_model}],
                    **kwargs,
                )
            else:
                response = await self._client.messages.create(
                    thinking={"type": "adaptive"}, **kwargs
                )
        except Exception as exc:  # network, auth, request-shape — surface loud
            raise LLMBackendError(f"anthropic call failed: {exc}") from exc

        if response.stop_reason == "refusal":
            raise LLMBackendError(
                "anthropic declined the request (stop_reason=refusal); "
                "retry on a fallback model or revise the prompt"
            )

        text = _extract_text(response.content)
        structured = None
        if request.output_schema is not None and text:
            try:
                structured = json.loads(text)
            except json.JSONDecodeError as exc:
                raise LLMBackendError(f"structured output was not valid JSON: {exc}") from exc

        return LLMResult(
            text=text,
            model=response.model,
            provider=self.provider,
            usage=LLMUsage(
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            ),
            structured=structured,
            stop_reason=response.stop_reason,
        )

    async def aclose(self) -> None:
        await self._client.close()
