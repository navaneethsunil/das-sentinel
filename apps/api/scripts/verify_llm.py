"""Live verification of the M2-B2 LLM layer against a real Postgres, using a
stub transport in place of the network (the security-critical logic — hosted
gate, redaction-before-egress, and the llm_interactions audit row — needs no
real egress). Run inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_llm.py"

Proves against a real DB + a real seeded engagement: hosted egress is blocked
when the engagement forbids it (and when there's no engagement); a redactor
failure blocks hosted egress fail-closed; an allowed hosted call redacts the
prompt before it reaches the adapter and writes an llm_interactions row
(hosted/was_redacted/cost/engagement_id); a local call persists with no
redaction and no cost; and the interaction row is insert-only (UPDATE denied by
trigger). A real provider round-trip is out of scope here (no API key in dev)
and is exercised once a key/Ollama is configured. Cleans up after itself.
"""

import asyncio
import sys

from sqlalchemy import delete, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.llm import LLMService, RegexRedactor
from app.llm.base import (
    HostedModelNotAllowedError,
    LLMMessage,
    LLMRequest,
    LLMResult,
    LLMUsage,
    RedactionFailedError,
)
from app.models.engagement import Engagement
from app.models.identity import Organization, User
from app.models.llm import LLMInteraction, LLMPurpose

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


class FakeAdapter:
    """Stub transport: records the request it would have sent, returns a fixed
    result. `hosted` decides which gates apply."""

    def __init__(self, hosted: bool) -> None:
        self.provider = "fake"
        self.hosted = hosted
        self.calls: list[LLMRequest] = []

    async def complete(self, request: LLMRequest) -> LLMResult:
        self.calls.append(request)
        return LLMResult(
            text="draft analysis",
            model=request.model,
            provider=self.provider,
            usage=LLMUsage(input_tokens=42, output_tokens=7),
        )

    async def aclose(self) -> None:
        pass


class ExplodingRedactor:
    def redact_text(self, text: str) -> tuple[str, list[str]]:
        raise RuntimeError("detector unavailable")


async def main() -> int:  # noqa: C901, PLR0915 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)

    org_id = None
    eng_allowed_id = None
    eng_denied_id = None
    email = "analyst" + "@example.com"

    # Seed org + user + two engagements (hosted allowed / denied).
    async with sessionmaker() as session:
        org = Organization(name="verify-llm-org")
        session.add(org)
        await session.flush()
        org_id = org.id
        password_service = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-llm@example.com",
            password_hash=password_service.hash("verify-llm-throwaway"),
            display_name="Verify LLM",
        )
        session.add(user)
        await session.flush()
        eng_allowed = Engagement(
            organization_id=org.id,
            name="hosted-allowed",
            client_system_name="acme",
            hosted_models_allowed=True,
            created_by=user.id,
        )
        eng_denied = Engagement(
            organization_id=org.id,
            name="hosted-denied",
            client_system_name="acme",
            hosted_models_allowed=False,
            created_by=user.id,
        )
        session.add_all([eng_allowed, eng_denied])
        await session.flush()
        eng_allowed_id = eng_allowed.id
        eng_denied_id = eng_denied.id
        await session.commit()

    async def load(session, engagement_id):
        return await session.get(Engagement, engagement_id)

    # 1. Hosted blocked when the engagement forbids hosted models.
    async with sessionmaker() as session:
        svc = LLMService(FakeAdapter(hosted=True), RegexRedactor(), settings)
        adapter: FakeAdapter = svc._adapter  # type: ignore[assignment]
        try:
            await svc.complete(
                session,
                organization_id=org_id,
                engagement=await load(session, eng_denied_id),
                purpose=LLMPurpose.TRIAGE,
                messages=[LLMMessage(role="user", content="hi")],
            )
            check("hosted blocked when engagement disallows", False)
        except HostedModelNotAllowedError:
            check("hosted blocked when engagement disallows", True)
        check("no egress on hosted-denied", adapter.calls == [])
        await session.rollback()

    # 2. Hosted blocked with no engagement context at all.
    async with sessionmaker() as session:
        svc = LLMService(FakeAdapter(hosted=True), RegexRedactor(), settings)
        try:
            await svc.complete(
                session,
                organization_id=org_id,
                engagement=None,
                purpose=LLMPurpose.TRIAGE,
                messages=[LLMMessage(role="user", content="hi")],
            )
            check("hosted blocked without engagement", False)
        except HostedModelNotAllowedError:
            check("hosted blocked without engagement", True)
        await session.rollback()

    # 3. Redactor failure blocks hosted egress (fail-closed).
    async with sessionmaker() as session:
        svc = LLMService(FakeAdapter(hosted=True), ExplodingRedactor(), settings)
        adapter = svc._adapter  # type: ignore[assignment]
        try:
            await svc.complete(
                session,
                organization_id=org_id,
                engagement=await load(session, eng_allowed_id),
                purpose=LLMPurpose.TRIAGE,
                messages=[LLMMessage(role="user", content="secret")],
            )
            check("redactor failure blocks egress", False)
        except RedactionFailedError:
            check("redactor failure blocks egress", True)
        check("no egress when redaction fails", adapter.calls == [])
        await session.rollback()

    # 4. Allowed hosted call: redacts before egress, persists an audit row.
    async with sessionmaker() as session:
        svc = LLMService(FakeAdapter(hosted=True), RegexRedactor(), settings)
        adapter = svc._adapter  # type: ignore[assignment]
        _result, interaction = await svc.complete(
            session,
            organization_id=org_id,
            engagement=await load(session, eng_allowed_id),
            purpose=LLMPurpose.TRIAGE,
            messages=[LLMMessage(role="user", content=f"triage {email}")],
            prompt_template="analysis_system@v1",
        )
        await session.commit()
        hosted_id = interaction.id
        check("redaction ran before egress", email not in adapter.calls[0].messages[0].content)

    async with sessionmaker() as session:
        row = await session.get(LLMInteraction, hosted_id)
        check("hosted interaction row persisted", row is not None)
        check("row: hosted=True", row.hosted is True)
        check("row: was_redacted=True", row.was_redacted is True)
        check("row: engagement bound", row.engagement_id == eng_allowed_id)
        check("row: cost estimated", row.cost_usd is not None)
        check("row: token counts recorded", row.input_tokens == 42 and row.output_tokens == 7)

    # 5. Local call: no engagement needed, no redaction, no cost.
    async with sessionmaker() as session:
        svc = LLMService(FakeAdapter(hosted=False), RegexRedactor(), settings)
        adapter = svc._adapter  # type: ignore[assignment]
        _result, interaction = await svc.complete(
            session,
            organization_id=org_id,
            engagement=None,
            purpose=LLMPurpose.TEST_GEN,
            messages=[LLMMessage(role="user", content=f"generate {email}")],
        )
        await session.commit()
        local_id = interaction.id
        check("local call sends prompt unredacted", email in adapter.calls[0].messages[0].content)

    async with sessionmaker() as session:
        row = await session.get(LLMInteraction, local_id)
        check("local row: hosted=False", row.hosted is False)
        check("local row: was_redacted=False", row.was_redacted is False)
        check("local row: cost None", row.cost_usd is None)

    # 6. Immutability: llm_interactions is insert-only (trigger).
    async with sessionmaker() as session:
        try:
            await session.execute(
                text("UPDATE llm_interactions SET hosted = false WHERE id = :i"),
                {"i": str(hosted_id)},
            )
            await session.commit()
            check("llm_interactions immutable (UPDATE denied)", False)
        except Exception:
            await session.rollback()
            check("llm_interactions immutable (UPDATE denied)", True)

    # cleanup (insert-only → dev-superuser trigger bypass)
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(LLMInteraction).where(LLMInteraction.organization_id == org_id))
        await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    await engine.dispose()

    # Confirm what we did NOT cover here, so it isn't mistaken for verified.
    print(
        "\nNOTE: real provider round-trip (Anthropic/Ollama) not exercised — "
        "no API key/local model in dev; covered when a backend is configured."
    )
    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(summary)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
