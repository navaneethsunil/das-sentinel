"""LLM provider abstraction — the shared contract (M2-B2, CLAUDE.md §7, TRD TR-16).

Every model call in the platform goes through this interface, never a vendor SDK
in a router or service. Adapters (Anthropic hosted, Ollama local) implement
`LLMClient`; the `LLMService` facade (service.py) is what callers use — it owns
the safety gates (hosted_models_allowed, redaction-before-egress) and the
audit record (`llm_interactions`). The adapter itself trusts nothing and enforces
nothing about scope; it only translates a normalized request into a provider call.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


class LLMError(Exception):
    """Base for every failure in the LLM layer."""


class HostedModelNotAllowedError(LLMError):
    """A hosted (off-box) model was requested for an engagement whose
    `hosted_models_allowed` flag is false, or with no engagement context at all.
    Fail-closed: hosted egress is denied unless explicitly permitted (§2.7)."""


class RedactionFailedError(LLMError):
    """The redaction pass raised or could not complete before a hosted call.
    Egress is blocked — a hosted call is never made when redaction is not
    provably applied (TR-16.2, fail-closed / TM-14)."""


class LLMBackendError(LLMError):
    """The provider call itself failed (network, auth, refusal, malformed
    response). Surfaced loud as a job failure — never swallowed (CLAUDE.md §5)."""


# Roles we send to a chat model. System guidance travels in the request's
# `system` field, not as a message, so the model treats it as instruction and
# everything in `messages` as data (TM-4: input is data, not instructions).
Role = str  # "user" | "assistant"


@dataclass(frozen=True)
class LLMMessage:
    role: Role
    content: str


@dataclass(frozen=True)
class LLMUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass(frozen=True)
class LLMRequest:
    """A provider-neutral completion request. `output_schema`, when set, asks the
    adapter for strict structured output (JSON Schema) — the suites and triage
    (M2-B4/B5, M4) require structured-output-only so model text can never be
    interpreted as an instruction or action (TM-4)."""

    model: str
    messages: list[LLMMessage]
    system: str | None = None
    output_schema: dict[str, Any] | None = None
    max_tokens: int = 4096
    effort: str = "high"


@dataclass(frozen=True)
class LLMResult:
    text: str
    model: str
    provider: str
    usage: LLMUsage = field(default_factory=LLMUsage)
    structured: dict[str, Any] | None = None
    stop_reason: str | None = None


@runtime_checkable
class LLMClient(Protocol):
    """A single provider backend. `hosted` decides whether the redaction and
    `hosted_models_allowed` gates apply — it is the property the facade reads,
    not the provider name, so a future on-prem hosted model is classified
    correctly."""

    provider: str
    hosted: bool

    async def complete(self, request: LLMRequest) -> LLMResult: ...

    async def aclose(self) -> None: ...
