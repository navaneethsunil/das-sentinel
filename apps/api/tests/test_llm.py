"""LLM layer unit tests (M2-B2) — CI-safe: no network, no DB, no vendor SDK call.

Covers the redactor, pricing, the prompt loader, and the LLMService safety
gates (hosted_models_allowed, redaction-before-egress fail-closed, audit-row
persistence) using a fake adapter and a fake session. The DB-coupled and
real-provider paths are exercised live in scripts/verify_llm.py. The M2-T0 task
formalizes the hosted-blocked / redactor-fail negatives as release-blocking.

Secret-looking test inputs are assembled at runtime from fragments so no literal
secret ever lands in the committed file (keeps the Gitleaks gate clean).
"""

import uuid
from decimal import Decimal
from types import SimpleNamespace

import pytest

from app.llm import pricing
from app.llm.base import (
    HostedModelNotAllowedError,
    LLMMessage,
    LLMRequest,
    LLMResult,
    LLMUsage,
    RedactionFailedError,
)
from app.llm.prompts import PromptNotFoundError, load_prompt
from app.llm.redaction import RegexRedactor, redact_messages
from app.llm.service import LLMService
from app.models.llm import LLMPurpose


class _FakeAdapter:
    def __init__(self, hosted: bool) -> None:
        self.provider = "fake"
        self.hosted = hosted
        self.calls: list[LLMRequest] = []

    async def complete(self, request: LLMRequest) -> LLMResult:
        self.calls.append(request)
        return LLMResult(
            text="draft",
            model=request.model,
            provider=self.provider,
            usage=LLMUsage(input_tokens=10, output_tokens=20),
        )

    async def aclose(self) -> None:  # pragma: no cover - trivial
        pass


class _ExplodingRedactor:
    def redact_text(self, text: str) -> tuple[str, list[str]]:
        raise RuntimeError("detector unavailable")


class _FakeSession:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.flushed = False

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushed = True


def _settings() -> SimpleNamespace:
    return SimpleNamespace(llm_model_default="claude-opus-4-8")


def _engagement(*, hosted_allowed: bool) -> SimpleNamespace:
    return SimpleNamespace(id=uuid.uuid4(), hosted_models_allowed=hosted_allowed)


def _service(adapter: _FakeAdapter, redactor=None) -> LLMService:
    return LLMService(adapter, redactor or RegexRedactor(), _settings())


# ── Redaction ────────────────────────────────────────────────────────────────


def test_redactor_scrubs_high_confidence_identifiers() -> None:
    email = "alice" + "@example.com"
    ip = "10.0." + "12.34"
    aws = "AKIA" + "ABCDEFGHIJ234567"
    prefixed = "sk-" + "A1b2C3d4E5f6G7h8I9j0"
    jwt = "eyJ" + "abcABC012_-" + "." + "payLOAD0129_-" + "." + "sigNATURE0129_-"
    pem = (
        "-----BEGIN " + "PRIVATE KEY-----\nMIIB" + "fakebody01\n" + "-----END " + "PRIVATE KEY-----"
    )
    text = f"contact {email} at {ip} key {aws} tok {prefixed} jwt {jwt} {pem}"

    redacted, labels = RegexRedactor().redact_text(text)

    assert email not in redacted
    assert aws not in redacted
    assert prefixed not in redacted
    assert jwt not in redacted
    assert "PRIVATE KEY" not in redacted
    for expected in ("email", "ipv4", "aws_access_key", "prefixed_token", "jwt", "private_key"):
        assert expected in labels


def test_redactor_flags_high_entropy_tokens_but_spares_low_entropy() -> None:
    secret = "kJ8" + "xQ2wZ9pL4mN7bV5cR1tY6uH0"  # 27 chars, mixed → high entropy
    boring = "a" * 30  # long but zero entropy → not a secret
    redacted, labels = RegexRedactor().redact_text(f"{secret} and {boring}")
    assert secret not in redacted
    assert boring in redacted
    assert "high_entropy" in labels


def test_redactor_leaves_ordinary_prose_untouched() -> None:
    prose = "The scanner reported a reflected parameter on the login page."
    redacted, labels = RegexRedactor().redact_text(prose)
    assert redacted == prose
    assert labels == []


def test_redact_messages_scrubs_system_and_messages() -> None:
    email = "bob" + "@corp.example"
    new_system, new_messages, labels = redact_messages(
        RegexRedactor(),
        f"operator {email}",
        [LLMMessage(role="user", content=f"reply to {email}")],
    )
    assert email not in (new_system or "")
    assert email not in new_messages[0].content
    assert "email" in labels


# ── Pricing ──────────────────────────────────────────────────────────────────


def test_pricing_known_model() -> None:
    # opus 4.8: (10*5 + 20*25) / 1e6 = 550/1e6
    assert pricing.hosted_cost_usd("claude-opus-4-8", 10, 20) == Decimal("0.000550")


def test_pricing_unknown_model_or_missing_tokens_returns_none() -> None:
    assert pricing.hosted_cost_usd("some-local-model", 10, 20) is None
    assert pricing.hosted_cost_usd("claude-opus-4-8", None, 20) is None


# ── Prompt templates ───────────────────────────────────────────────────────────


def test_prompt_loader_returns_versioned_template() -> None:
    tpl = load_prompt("analysis_system")
    assert tpl.name == "analysis_system"
    assert tpl.version == 1
    assert tpl.template_id == "analysis_system@v1"
    assert "UNTRUSTED DATA" in tpl.body


def test_prompt_loader_missing_raises() -> None:
    with pytest.raises(PromptNotFoundError):
        load_prompt("does_not_exist")


# ── Service gates ──────────────────────────────────────────────────────────────


async def test_hosted_blocked_without_engagement() -> None:
    adapter = _FakeAdapter(hosted=True)
    session = _FakeSession()
    with pytest.raises(HostedModelNotAllowedError):
        await _service(adapter).complete(
            session,
            organization_id=uuid.uuid4(),
            engagement=None,
            purpose=LLMPurpose.TRIAGE,
            messages=[LLMMessage(role="user", content="hi")],
        )
    assert adapter.calls == []  # egress never happened
    assert session.added == []  # no interaction row


async def test_hosted_blocked_when_engagement_disallows() -> None:
    adapter = _FakeAdapter(hosted=True)
    session = _FakeSession()
    with pytest.raises(HostedModelNotAllowedError):
        await _service(adapter).complete(
            session,
            organization_id=uuid.uuid4(),
            engagement=_engagement(hosted_allowed=False),
            purpose=LLMPurpose.TRIAGE,
            messages=[LLMMessage(role="user", content="hi")],
        )
    assert adapter.calls == []


async def test_redactor_failure_blocks_hosted_egress() -> None:
    adapter = _FakeAdapter(hosted=True)
    session = _FakeSession()
    with pytest.raises(RedactionFailedError):
        await _service(adapter, _ExplodingRedactor()).complete(
            session,
            organization_id=uuid.uuid4(),
            engagement=_engagement(hosted_allowed=True),
            purpose=LLMPurpose.TRIAGE,
            messages=[LLMMessage(role="user", content="secret payload")],
        )
    assert adapter.calls == []  # fail-closed: nothing sent
    assert session.added == []


async def test_hosted_call_redacts_and_persists_interaction() -> None:
    adapter = _FakeAdapter(hosted=True)
    session = _FakeSession()
    org_id = uuid.uuid4()
    email = "carol" + "@example.org"
    result, interaction = await _service(adapter).complete(
        session,
        organization_id=org_id,
        engagement=_engagement(hosted_allowed=True),
        purpose=LLMPurpose.TRIAGE,
        messages=[LLMMessage(role="user", content=f"triage {email}")],
        prompt_template="analysis_system@v1",
    )
    # Redaction ran before the adapter saw the prompt.
    assert email not in adapter.calls[0].messages[0].content
    assert result.text == "draft"
    assert interaction.hosted is True
    assert interaction.was_redacted is True
    assert interaction.organization_id == org_id
    assert interaction.provider == "fake"
    assert interaction.input_tokens == 10
    assert interaction.cost_usd == pricing.hosted_cost_usd("claude-opus-4-8", 10, 20)
    assert session.added == [interaction]
    assert session.flushed is True


async def test_local_call_skips_gates_and_redaction() -> None:
    adapter = _FakeAdapter(hosted=False)
    session = _FakeSession()
    email = "dave" + "@example.net"
    _result, interaction = await _service(adapter).complete(
        session,
        organization_id=uuid.uuid4(),
        engagement=None,  # allowed for local
        purpose=LLMPurpose.TEST_GEN,
        messages=[LLMMessage(role="user", content=f"generate {email}")],
    )
    # Local (on-box) call: no engagement required, prompt sent as-is, no cost.
    assert email in adapter.calls[0].messages[0].content
    assert interaction.hosted is False
    assert interaction.was_redacted is False
    assert interaction.cost_usd is None
    assert interaction.engagement_id is None
