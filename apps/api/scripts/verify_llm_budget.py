"""Live verification of the M2-SEC4 per-engagement LLM budget ceiling (TM-12)
against a real Postgres, using a stub adapter in place of the network (the
security-critical logic — the fail-closed budget gate before egress and the
llm_interactions running total — needs no real egress). Run inside the compose
network (base api image, no PyRIT):

    docker compose up -d --build api
    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_llm_budget.py"

Each case seeds a fresh engagement, pre-loads real `llm_interactions` rows to a
known cumulative usage, then calls `LLMService.complete` through a stub adapter
and asserts against the REAL SUM query:

  - token ceiling reached  → LLMBudgetExceededError, NO egress, NO new row;
  - under the token ceiling → the call proceeds and one row is written;
  - hosted cost ceiling reached → blocked fail-closed (no egress, no row);
  - ceilings <= 0 (disabled) → the call proceeds regardless of prior usage.

Cleans up via the dev-superuser trigger bypass (llm_interactions is insert-only).
"""

import asyncio
import sys
from decimal import Decimal

from sqlalchemy import delete, func, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.llm import LLMService, RegexRedactor
from app.llm.base import (
    LLMBudgetExceededError,
    LLMMessage,
    LLMRequest,
    LLMResult,
    LLMUsage,
)
from app.models.engagement import Engagement
from app.models.identity import Organization, User
from app.models.llm import LLMInteraction, LLMPurpose

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


class StubAdapter:
    """Records the request it would have sent; returns a fixed result. `hosted`
    decides which upstream gates apply."""

    def __init__(self, hosted: bool) -> None:
        self.provider = "stub"
        self.hosted = hosted
        self.calls: list[LLMRequest] = []

    async def complete(self, request: LLMRequest) -> LLMResult:
        self.calls.append(request)
        return LLMResult(
            text="draft",
            model=request.model,
            provider=self.provider,
            usage=LLMUsage(input_tokens=5, output_tokens=5),
        )

    async def aclose(self) -> None:
        pass


async def _count(session, engagement_id) -> int:
    return (
        await session.execute(
            select(func.count())
            .select_from(LLMInteraction)
            .where(LLMInteraction.engagement_id == engagement_id)
        )
    ).scalar_one()


def _row(
    org_id, engagement_id, *, tokens: int, cost: Decimal | None, hosted: bool
) -> LLMInteraction:
    return LLMInteraction(
        organization_id=org_id,
        engagement_id=engagement_id,
        purpose=LLMPurpose.TRIAGE,
        provider="seed",
        model="seed-model",
        was_redacted=hosted,
        hosted=hosted,
        input_tokens=tokens,
        output_tokens=0,
        cost_usd=cost,
    )


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)

    org_id = None
    eng_ids: dict[str, object] = {}

    async with sessionmaker() as session:
        org = Organization(name="verify-budget-org")
        session.add(org)
        await session.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-budget@example.com",
            password_hash=pw.hash("verify-budget-throwaway"),
            display_name="Verify Budget",
        )
        session.add(user)
        await session.flush()
        for key in ("token_block", "token_allow", "cost_block", "disabled"):
            eng = Engagement(
                organization_id=org.id,
                name=f"budget-{key}",
                client_system_name="acme",
                hosted_models_allowed=True,
                created_by=user.id,
            )
            session.add(eng)
            await session.flush()
            eng_ids[key] = eng.id
        # Pre-load cumulative usage per engagement.
        session.add(_row(org_id, eng_ids["token_block"], tokens=100, cost=None, hosted=False))
        session.add(_row(org_id, eng_ids["token_allow"], tokens=99, cost=None, hosted=False))
        session.add(
            _row(org_id, eng_ids["cost_block"], tokens=10, cost=Decimal("1.50"), hosted=True)
        )
        session.add(
            _row(org_id, eng_ids["disabled"], tokens=10**9, cost=Decimal("999"), hosted=True)
        )
        await session.commit()

    async def load(session, engagement_id):
        return await session.get(Engagement, engagement_id)

    # 1. Token ceiling reached → blocked, no egress, no new row.
    async with sessionmaker() as session:
        eng_id = eng_ids["token_block"]
        svc = LLMService(
            StubAdapter(hosted=False),
            RegexRedactor(),
            settings.model_copy(
                update={
                    "llm_max_tokens_per_engagement": 100,
                    "llm_max_cost_usd_per_engagement": 0.0,
                }
            ),
        )
        adapter: StubAdapter = svc._adapter  # type: ignore[assignment]
        blocked = False
        try:
            await svc.complete(
                session,
                organization_id=org_id,
                engagement=await load(session, eng_id),
                purpose=LLMPurpose.TEST_GEN,
                messages=[LLMMessage(role="user", content="hi")],
            )
        except LLMBudgetExceededError:
            blocked = True
        await session.rollback()
        check("token ceiling reached blocks the call", blocked)
        check("token-block: no egress", adapter.calls == [])
    async with sessionmaker() as session:
        check(
            "token-block: no new interaction row",
            await _count(session, eng_ids["token_block"]) == 1,
        )

    # 2. Under the token ceiling → proceeds, one row written.
    async with sessionmaker() as session:
        eng_id = eng_ids["token_allow"]
        svc = LLMService(
            StubAdapter(hosted=False),
            RegexRedactor(),
            settings.model_copy(
                update={
                    "llm_max_tokens_per_engagement": 100,
                    "llm_max_cost_usd_per_engagement": 0.0,
                }
            ),
        )
        adapter = svc._adapter  # type: ignore[assignment]
        proceeded = True
        try:
            await svc.complete(
                session,
                organization_id=org_id,
                engagement=await load(session, eng_id),
                purpose=LLMPurpose.TEST_GEN,
                messages=[LLMMessage(role="user", content="hi")],
            )
        except LLMBudgetExceededError:
            proceeded = False
        await session.commit()
        check("under the token ceiling the call proceeds", proceeded)
        check("token-allow: egress happened", adapter.calls != [])
    async with sessionmaker() as session:
        check(
            "token-allow: one new interaction row",
            await _count(session, eng_ids["token_allow"]) == 2,
        )

    # 3. Hosted cost ceiling reached → blocked, no egress, no new row.
    async with sessionmaker() as session:
        eng_id = eng_ids["cost_block"]
        svc = LLMService(
            StubAdapter(hosted=True),
            RegexRedactor(),
            settings.model_copy(
                update={"llm_max_tokens_per_engagement": 0, "llm_max_cost_usd_per_engagement": 1.0}
            ),
        )
        adapter = svc._adapter  # type: ignore[assignment]
        blocked = False
        try:
            await svc.complete(
                session,
                organization_id=org_id,
                engagement=await load(session, eng_id),
                purpose=LLMPurpose.TRIAGE,
                messages=[LLMMessage(role="user", content="hi")],
            )
        except LLMBudgetExceededError:
            blocked = True
        await session.rollback()
        check("hosted cost ceiling reached blocks the call", blocked)
        check("cost-block: no egress", adapter.calls == [])
    async with sessionmaker() as session:
        check(
            "cost-block: no new interaction row", await _count(session, eng_ids["cost_block"]) == 1
        )

    # 4. Ceilings disabled (<= 0) → proceeds regardless of prior usage.
    async with sessionmaker() as session:
        eng_id = eng_ids["disabled"]
        svc = LLMService(
            StubAdapter(hosted=False),
            RegexRedactor(),
            settings.model_copy(
                update={"llm_max_tokens_per_engagement": 0, "llm_max_cost_usd_per_engagement": 0.0}
            ),
        )
        adapter = svc._adapter  # type: ignore[assignment]
        proceeded = True
        try:
            await svc.complete(
                session,
                organization_id=org_id,
                engagement=await load(session, eng_id),
                purpose=LLMPurpose.TEST_GEN,
                messages=[LLMMessage(role="user", content="hi")],
            )
        except LLMBudgetExceededError:
            proceeded = False
        await session.rollback()
        check("disabled ceilings do not block", proceeded)
        check("disabled: egress happened", adapter.calls != [])

    # ── cleanup (trigger bypass: llm_interactions is insert-only) ──
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        if org_id is not None:
            eng_subq = select(Engagement.id).where(Engagement.organization_id == org_id)
            await conn.execute(
                delete(LLMInteraction).where(LLMInteraction.engagement_id.in_(eng_subq))
            )
            await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
            await conn.execute(delete(User).where(User.organization_id == org_id))
            await conn.execute(delete(Organization).where(Organization.id == org_id))
    await engine.dispose()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
