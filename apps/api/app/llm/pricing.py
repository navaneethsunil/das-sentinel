"""Per-model cost estimation for the `llm_interactions.cost_usd` audit field
(M2-B2, TR-16.5). Also the basis for the per-engagement token/cost ceiling
(M2-SEC4).

Prices are USD per 1M tokens (input, output), verified July 2026 against the
Claude model catalog. Cost is an *estimate* for tracking and budgeting, not a
billing source of truth — hosted providers bill authoritatively. Local models
(Ollama/vLLM) have no per-token charge, so their cost is recorded as 0.
"""

from decimal import Decimal

# (input $/1M, output $/1M). Kept small and explicit rather than fetched — an
# air-gapped deployment must price offline. Unknown models return None (logged
# by the caller) rather than a wrong number.
_PRICE_PER_MTOK: dict[str, tuple[str, str]] = {
    "claude-opus-4-8": ("5.00", "25.00"),
    "claude-opus-4-7": ("5.00", "25.00"),
    "claude-sonnet-5": ("3.00", "15.00"),
    "claude-haiku-4-5": ("1.00", "5.00"),
    "claude-fable-5": ("10.00", "50.00"),
}

_MILLION = Decimal(1_000_000)


def hosted_cost_usd(
    model: str, input_tokens: int | None, output_tokens: int | None
) -> Decimal | None:
    """Estimated USD cost of one hosted call. None when the model is unpriced or
    token counts are unavailable — never a fabricated figure."""
    price = _PRICE_PER_MTOK.get(model)
    if price is None or input_tokens is None or output_tokens is None:
        return None
    input_rate, output_rate = price
    cost = (Decimal(input_tokens) * Decimal(input_rate)) + (
        Decimal(output_tokens) * Decimal(output_rate)
    )
    # Numeric(12, 6) in the schema — quantize to six decimals.
    return (cost / _MILLION).quantize(Decimal("0.000001"))


def is_priced(model: str) -> bool:
    return model in _PRICE_PER_MTOK
