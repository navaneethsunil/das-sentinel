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
    LLMBackendError,
    LLMBudgetExceededError,
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


class _RefusingAdapter:
    """A provider that raises AFTER egress (refusal / parse error / network)."""

    def __init__(self, hosted: bool, exc: Exception) -> None:
        self.provider = "fake"
        self.hosted = hosted
        self.calls: list[LLMRequest] = []
        self._exc = exc

    async def complete(self, request: LLMRequest) -> LLMResult:
        self.calls.append(request)
        raise self._exc

    async def aclose(self) -> None:  # pragma: no cover - trivial
        pass


class _ExplodingRedactor:
    def redact_text(self, text: str) -> tuple[str, list[str]]:
        raise RuntimeError("detector unavailable")


class _FakeSession:
    def __init__(self, used: tuple[int, float] = (0, 0.0)) -> None:
        self.added: list[object] = []
        self.flushed = False
        self.commits = 0
        self._used = used  # (tokens, cost) the budget SUM query returns

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushed = True

    async def commit(self) -> None:
        self.commits += 1

    async def execute(self, _stmt: object) -> object:
        used = self._used
        return SimpleNamespace(one=lambda: used)


def _settings(*, max_tokens: int = 0, max_cost: float = 0.0) -> SimpleNamespace:
    # Budget ceilings default to disabled (<= 0) so the existing gate tests are
    # unaffected; the budget tests pass explicit ceilings.
    return SimpleNamespace(
        llm_model_default="claude-opus-4-8",
        llm_max_tokens_per_engagement=max_tokens,
        llm_max_cost_usd_per_engagement=max_cost,
    )


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


def test_redactor_removes_full_authorization_credential() -> None:
    # sec-8: the old `\S+` stopped at the first space, leaking the token after
    # the scheme. The whole credential must be gone. (Fake token split so the
    # secret scanner doesn't flag this fixture.)
    token = "abcDEF" + "1234567890" + "secretpart"
    redacted, labels = RegexRedactor().redact_text(f"Authorization: Bearer {token}")
    assert token not in redacted
    assert "Bearer" not in redacted
    assert "auth_header" in labels


def test_redactor_covers_cookies_secrets_dsn_ipv6_phone() -> None:
    # All fixture "secrets" are split with `+` so the repo secret scanner (which
    # correctly flags high-entropy literals) does not trip on this test.
    ck = "session=" + "abc123" + "def456"
    sck = "topsecret" + "value"
    xak = "9f8e7d6c" + "5b4a3210"
    pw = "hunter2" + "wontleak"
    cs = "aVeryShort" + "ButRealSecret"
    dbp = "db" + "pass"
    v6 = "2001:db8:85a3::8a2e:370:7334"
    ph1 = "+1555" + "1234567"
    ph2 = "555-123-4567"
    cases = {
        "cookie": (f"Cookie: {ck}; other=1", ck),
        "set_cookie": (f"Set-Cookie: __Host-das_session={sck}; Secure", sck),
        "x_api_key": (f"X-API-Key: {xak}", xak),
        "password": (f'password: "{pw}"', pw),
        "secret_assign": (f"client_secret={cs}", cs),
        "dsn": (f"postgres://dbuser:{dbp}@db.internal:5432/app", dbp),
        "ipv6": (f"connect to {v6} now", v6),
        "phone_e164": (f"call {ph1} for support", ph1),
        "phone_sep": (f"call {ph2} for support", ph2),
    }
    for name, (text, secret) in cases.items():
        redacted, _ = RegexRedactor().redact_text(text)
        assert secret not in redacted, f"{name}: secret survived redaction ({redacted!r})"


def test_redactor_does_not_redact_timestamps_as_ipv6() -> None:
    # A HH:MM:SS time must not be mistaken for an IPv6 address.
    text = "the scan started at 12:34:56 and finished at 13:00:01"
    redacted, labels = RegexRedactor().redact_text(text)
    assert redacted == text
    assert "ipv6" not in labels


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
    # sec-4: a durable pre-egress attempt row precedes the committed success row.
    assert [i.status for i in session.added] == ["attempt", "success"]
    assert session.added[-1] is interaction
    assert session.commits >= 2


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


# ── M2-SEC4: per-engagement LLM budget ceiling (TM-12) ───────────────────────


def _budget_service(adapter: _FakeAdapter, *, max_tokens: int = 0, max_cost: float = 0.0):
    return LLMService(adapter, RegexRedactor(), _settings(max_tokens=max_tokens, max_cost=max_cost))


async def test_budget_blocks_when_token_ceiling_reached() -> None:
    # Token ceiling bounds total work for ANY provider — proved with a local
    # adapter (no hosted gate involved). Prior usage already at the ceiling.
    adapter = _FakeAdapter(hosted=False)
    session = _FakeSession(used=(500, 0.0))
    with pytest.raises(LLMBudgetExceededError):
        await _budget_service(adapter, max_tokens=500).complete(
            session,
            organization_id=uuid.uuid4(),
            engagement=_engagement(hosted_allowed=True),
            purpose=LLMPurpose.TEST_GEN,
            messages=[LLMMessage(role="user", content="hi")],
        )
    assert adapter.calls == []  # blocked before egress
    assert session.added == []  # no interaction row written


async def test_budget_allows_when_under_ceiling() -> None:
    adapter = _FakeAdapter(hosted=False)
    session = _FakeSession(used=(499, 0.0))
    _result, interaction = await _budget_service(adapter, max_tokens=500).complete(
        session,
        organization_id=uuid.uuid4(),
        engagement=_engagement(hosted_allowed=True),
        purpose=LLMPurpose.TEST_GEN,
        messages=[LLMMessage(role="user", content="hi")],
    )
    assert adapter.calls != []  # under budget → egress happened
    assert [i.status for i in session.added] == ["attempt", "success"]
    assert session.added[-1] is interaction


async def test_budget_cost_ceiling_blocks_hosted() -> None:
    adapter = _FakeAdapter(hosted=True)
    session = _FakeSession(used=(0, 1.50))
    with pytest.raises(LLMBudgetExceededError):
        await _budget_service(adapter, max_cost=1.0).complete(
            session,
            organization_id=uuid.uuid4(),
            engagement=_engagement(hosted_allowed=True),
            purpose=LLMPurpose.TRIAGE,
            messages=[LLMMessage(role="user", content="hi")],
        )
    assert adapter.calls == []
    assert session.added == []


async def test_failed_hosted_call_leaves_durable_attempt_and_failure() -> None:
    # sec-4: a provider refusal/error AFTER egress must leave BOTH a durable
    # pre-egress attempt row and a committed failure outcome — the audit invariant
    # must not depend on the call succeeding.
    adapter = _RefusingAdapter(hosted=True, exc=LLMBackendError("provider refused"))
    session = _FakeSession()
    with pytest.raises(LLMBackendError):
        await _service(adapter).complete(
            session,
            organization_id=uuid.uuid4(),
            engagement=_engagement(hosted_allowed=True),
            purpose=LLMPurpose.TRIAGE,
            messages=[LLMMessage(role="user", content="please analyze this evidence")],
        )
    assert adapter.calls != []  # egress happened
    statuses = [i.status for i in session.added]
    assert statuses == ["attempt", "failure"]
    failure = session.added[-1]
    assert failure.error_category == "LLMBackendError"
    # The failure is metered so repeated failures cannot bypass the budget ceiling.
    assert failure.input_tokens > 0
    assert session.commits >= 2


async def test_failed_call_metered_for_budget() -> None:
    # The failure row carries an estimated cost so a hosted refusal still consumes
    # engagement budget.
    adapter = _RefusingAdapter(hosted=True, exc=LLMBackendError("boom"))
    session = _FakeSession()
    with pytest.raises(LLMBackendError):
        await _service(adapter).complete(
            session,
            organization_id=uuid.uuid4(),
            engagement=_engagement(hosted_allowed=True),
            purpose=LLMPurpose.TRIAGE,
            messages=[LLMMessage(role="user", content="x" * 400)],
        )
    failure = session.added[-1]
    assert failure.cost_usd is not None  # hosted failure carries an estimate


async def test_budget_disabled_when_ceilings_nonpositive() -> None:
    # Both ceilings <= 0 → the gate never even queries usage; the call proceeds
    # regardless of how much has been consumed.
    adapter = _FakeAdapter(hosted=False)
    session = _FakeSession(used=(10**9, 10**6))
    _result, interaction = await _budget_service(adapter, max_tokens=0, max_cost=0.0).complete(
        session,
        organization_id=uuid.uuid4(),
        engagement=_engagement(hosted_allowed=True),
        purpose=LLMPurpose.TEST_GEN,
        messages=[LLMMessage(role="user", content="hi")],
    )
    assert adapter.calls != []
    assert [i.status for i in session.added] == ["attempt", "success"]
    assert session.added[-1] is interaction
