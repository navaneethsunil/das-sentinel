"""Active-LLM status schema — what model the platform is using right now.

Reveals NO secrets (never the API key), only the operator-visible facts: the
provider, whether it is hosted (off-box egress) or local (on-box), its endpoint
host, and the model names in use per role.
"""

from pydantic import BaseModel


class LlmModels(BaseModel):
    default: str
    triage: str
    classifier: str


class LlmStatusOut(BaseModel):
    provider: str  # anthropic | ollama | vllm
    hosted: bool  # true = off-box egress (redaction + per-engagement gate apply)
    endpoint: str | None  # provider host / base URL (no credentials)
    models: LlmModels
