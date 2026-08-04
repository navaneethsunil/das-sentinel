# LLM usage rules

> Moved out of the root `CLAUDE.md` §7 so it loads only when working on LLM code.
> The invariants it depends on stay in the root file (§2.6 the LLM is never the source of truth,
> §2.7 redaction before egress, §2.9 findings are labeled by status).

- All model calls go through the provider abstraction (`app/llm`), never a vendor SDK directly in a router or service. Roll a thin adapter if we only ever need Claude + one local backend; use **LiteLLM** if we need many providers.
- **The AI model registry (`ai_models`) is the source of truth for provider + model + credentials, not env vars.** An admin registers a model once in the UI (System → AI models); `app/llm/registry.py` resolves per call in this order: the engagement's pinned model → the org default → the `LLM_*` environment fallback. Provider API keys live encrypted in that table (credential-store cipher) and are write-only. A deliberate exception to "all config via environment variables" (root §5) — do not reintroduce env-only provider selection, and keep `hosted` a property of the *resolved* adapter so the §2.7 gate cannot be sidestepped by registering a hosted model.
- Default provider is Anthropic Claude (`claude-opus-4-8` default, `claude-sonnet-5` for high-volume triage, `claude-haiku-4-5` for classification). **Ollama** covers local/dev; **vLLM** covers GPU-backed air-gapped servers.
- Use current Claude params only: `thinking: {type: "adaptive"}`, structured output via strict tool use / `output_config.format`. Do **not** use `budget_tokens`, `temperature`, `top_p`, or date-suffixed model IDs — they 400. Avoid Fable 5 as default (cyber-content refusal risk for pentest prompts); if used, set the `fallbacks` param to `claude-opus-4-8`.
- **Redaction layer runs before any hosted call.** If `hosted_models_allowed` is false for the engagement, hosted providers are unavailable and only local models may be used.
- Prompt templates live in versioned files under `app/llm/prompts/`, not inline strings.
- Track tokens and cost per interaction; persist LLM interactions for audit.
- LLM output is **draft analysis**. It must reference supplied evidence and is stored with an `ai-generated` label until a human validates it. Never let the model set final CVSS or mark a finding "fixed."
