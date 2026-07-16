"""Ollama adapter — the local (on-box / air-gapped dev) backend (M2-B2).

`hosted = False`, so the redaction and `hosted_models_allowed` gates in the
facade do not apply to it: an engagement that forbids hosted models can still
run analysis against a local model. The base URL is operator-configured
(OLLAMA_BASE_URL); the platform still routes this traffic through the engagement
egress shaper (M2-SEC1) at run time.

Structured output uses Ollama's `format` field (a JSON Schema); `effort` has no
analog locally and is ignored.
"""

import json
from typing import Any

import httpx

from app.llm.base import LLMBackendError, LLMRequest, LLMResult, LLMUsage

_TIMEOUT_S = 300.0


class OllamaAdapter:
    provider = "ollama"
    hosted = False

    def __init__(self, *, base_url: str) -> None:
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=_TIMEOUT_S)

    async def complete(self, request: LLMRequest) -> LLMResult:
        messages: list[dict[str, str]] = []
        if request.system is not None:
            messages.append({"role": "system", "content": request.system})
        messages.extend({"role": m.role, "content": m.content} for m in request.messages)

        payload: dict[str, Any] = {
            "model": request.model,
            "messages": messages,
            "stream": False,
            "options": {"num_predict": request.max_tokens},
        }
        if request.output_schema is not None:
            payload["format"] = request.output_schema

        try:
            response = await self._client.post("/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            raise LLMBackendError(f"ollama call failed: {exc}") from exc

        text = data.get("message", {}).get("content", "")
        structured = None
        if request.output_schema is not None and text:
            try:
                structured = json.loads(text)
            except json.JSONDecodeError as exc:
                raise LLMBackendError(f"structured output was not valid JSON: {exc}") from exc

        return LLMResult(
            text=text,
            model=data.get("model", request.model),
            provider=self.provider,
            usage=LLMUsage(
                input_tokens=data.get("prompt_eval_count"),
                output_tokens=data.get("eval_count"),
            ),
            structured=structured,
            stop_reason=data.get("done_reason"),
        )

    async def aclose(self) -> None:
        await self._client.aclose()
