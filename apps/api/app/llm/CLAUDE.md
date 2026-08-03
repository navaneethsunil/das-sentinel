# LLM usage rules

> Moved out of the root `CLAUDE.md` §7 so it loads only when working on LLM code.
> The invariants it depends on stay in the root file (§2.6 the LLM is never the source of truth,
> §2.7 redaction before egress, §2.9 findings are labeled by status).

- All model calls go through the provider abstraction (`app/llm`), never a vendor SDK directly in a router or service. Roll a thin adapter if we only ever need Claude + one local backend; use **LiteLLM** if we need many providers.
- Default provider is Anthropic Claude (`claude-opus-4-8` default, `claude-sonnet-5` for high-volume triage, `claude-haiku-4-5` for classification). **Ollama** covers local/dev; **vLLM** covers GPU-backed air-gapped servers.
- Use current Claude params only: `thinking: {type: "adaptive"}`, structured output via strict tool use / `output_config.format`. Do **not** use `budget_tokens`, `temperature`, `top_p`, or date-suffixed model IDs — they 400. Avoid Fable 5 as default (cyber-content refusal risk for pentest prompts); if used, set the `fallbacks` param to `claude-opus-4-8`.
- **Redaction layer runs before any hosted call.** If `hosted_models_allowed` is false for the engagement, hosted providers are unavailable and only local models may be used.
- Prompt templates live in versioned files under `app/llm/prompts/`, not inline strings.
- Track tokens and cost per interaction; persist LLM interactions for audit.
- LLM output is **draft analysis**. It must reference supplied evidence and is stored with an `ai-generated` label until a human validates it. Never let the model set final CVSS or mark a finding "fixed."
