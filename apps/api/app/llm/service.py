"""LLMService — the one entry point every caller uses for a model call (M2-B2).

This is where the safety invariants live, so no router/service/worker can skip
them (TR-16.3/16.5, §2.7):

  1. Hosted gate — a hosted adapter is refused unless the engagement explicitly
     sets `hosted_models_allowed = true`. No engagement context ⇒ refused.
  2. Redaction before egress — for hosted calls, the prompt is scrubbed first;
     if redaction cannot complete, egress is BLOCKED (fail-closed).
  2b. Per-engagement budget ceiling — a call is refused before egress once the
     engagement's cumulative token/cost usage reaches a configured ceiling
     (M2-SEC4, TM-12, fail-closed).
  3. Audit — every call that reaches a model writes one `llm_interactions` row
     (provider, model, template id, was_redacted, hosted, tokens, cost), flushed
     into the caller's transaction so it commits atomically with their work.

The service holds a single adapter (chosen from Settings.llm_provider) and a
redactor. Local (non-hosted) adapters skip gates 1 and 2 by design — on-box
inference is not off-box egress.
"""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.llm import pricing
from app.llm.base import (
    HostedModelNotAllowedError,
    LLMBudgetExceededError,
    LLMClient,
    LLMMessage,
    LLMRequest,
    LLMResult,
    RedactionFailedError,
)
from app.llm.redaction import Redactor, redact_messages
from app.models.engagement import Engagement
from app.models.llm import LLMInteraction, LLMPurpose


class LLMService:
    def __init__(self, adapter: LLMClient, redactor: Redactor, settings: Settings) -> None:
        self._adapter = adapter
        self._redactor = redactor
        self._settings = settings

    @property
    def hosted(self) -> bool:
        return self._adapter.hosted

    async def complete(
        self,
        session: AsyncSession,
        *,
        organization_id: uuid.UUID,
        engagement: Engagement | None,
        purpose: LLMPurpose,
        messages: list[LLMMessage],
        system: str | None = None,
        model: str | None = None,
        output_schema: dict | None = None,
        max_tokens: int = 4096,
        effort: str = "high",
        prompt_template: str | None = None,
        ref_object_type: str | None = None,
        ref_object_id: uuid.UUID | None = None,
    ) -> tuple[LLMResult, LLMInteraction]:
        hosted = self._adapter.hosted

        # 1. Hosted gate (fail-closed): no engagement, or one that forbids hosted
        # models, means a hosted adapter may not run at all.
        if hosted and (engagement is None or not engagement.hosted_models_allowed):
            raise HostedModelNotAllowedError(
                "hosted models are not permitted for this engagement "
                "(hosted_models_allowed is false or no engagement context)"
            )

        # 1b. Per-engagement budget ceiling (M2-SEC4, TM-12), fail-closed and
        # BEFORE egress. If the engagement's cumulative LLM usage has already
        # reached a configured ceiling, the call is refused and no row is written —
        # a runaway suite cannot rack up unbounded model work or hosted spend. The
        # ceiling is per-engagement, so a call with no engagement context (already
        # limited to local models by the hosted gate) has no bucket to meter.
        if engagement is not None:
            await self._enforce_budget(session, engagement)

        # 2. Redaction before egress (hosted only). A failure blocks the call —
        # nothing leaves the box unless redaction provably ran.
        was_redacted = False
        send_system, send_messages = system, messages
        if hosted:
            try:
                send_system, send_messages, _labels = redact_messages(
                    self._redactor, system, messages
                )
            except Exception as exc:
                raise RedactionFailedError(
                    "redaction failed before a hosted call; egress blocked"
                ) from exc
            was_redacted = True

        model_id = model or self._settings.llm_model_default
        result = await self._adapter.complete(
            LLMRequest(
                model=model_id,
                messages=send_messages,
                system=send_system,
                output_schema=output_schema,
                max_tokens=max_tokens,
                effort=effort,
            )
        )

        # 3. Audit. Local calls have no per-token charge (cost 0); hosted calls
        # get an estimate, or None when the model is unpriced.
        cost = (
            pricing.hosted_cost_usd(
                result.model, result.usage.input_tokens, result.usage.output_tokens
            )
            if hosted
            else None
        )
        interaction = LLMInteraction(
            organization_id=organization_id,
            engagement_id=engagement.id if engagement is not None else None,
            purpose=purpose,
            provider=result.provider,
            model=result.model,
            prompt_template=prompt_template,
            was_redacted=was_redacted,
            hosted=hosted,
            input_tokens=result.usage.input_tokens,
            output_tokens=result.usage.output_tokens,
            cost_usd=cost,
            ref_object_type=ref_object_type,
            ref_object_id=ref_object_id,
        )
        session.add(interaction)
        await session.flush()
        return result, interaction

    async def _enforce_budget(self, session: AsyncSession, engagement: Engagement) -> None:
        """Refuse the call fail-closed if the engagement has reached its configured
        LLM token or cost ceiling (M2-SEC4, TM-12). Usage is the running sum of the
        engagement's `llm_interactions`; because per-call usage is only known after
        the provider responds, a ceiling is enforced against already-consumed usage
        — the call that crosses the line completes, every subsequent one is blocked.
        A ceiling <= 0 is disabled."""
        token_ceiling = self._settings.llm_max_tokens_per_engagement
        cost_ceiling = self._settings.llm_max_cost_usd_per_engagement
        if token_ceiling <= 0 and cost_ceiling <= 0:
            return

        used_tokens, used_cost = (
            await session.execute(
                select(
                    func.coalesce(
                        func.sum(LLMInteraction.input_tokens + LLMInteraction.output_tokens), 0
                    ),
                    func.coalesce(func.sum(LLMInteraction.cost_usd), 0),
                ).where(LLMInteraction.engagement_id == engagement.id)
            )
        ).one()

        if token_ceiling > 0 and int(used_tokens) >= token_ceiling:
            raise LLMBudgetExceededError(
                f"engagement {engagement.id} has reached its LLM token ceiling "
                f"({used_tokens} >= {token_ceiling}); egress blocked"
            )
        if cost_ceiling > 0 and float(used_cost) >= cost_ceiling:
            raise LLMBudgetExceededError(
                f"engagement {engagement.id} has reached its LLM cost ceiling "
                f"(${float(used_cost):.4f} >= ${cost_ceiling:.4f}); egress blocked"
            )

    async def aclose(self) -> None:
        await self._adapter.aclose()
