"""AI model registry unit tests — CI-safe: no network, no DB, no real provider call.

Covers what the registry actually decides: the write-only projection of the API key,
provider-config validation, the endpoint-URL boundary, the resolution precedence
(engagement pin → org default → env fallback) including the fail-loud on a deleted
pinned model, adapter caching, and — the safety-critical one — that the hosted gate
keys off the *resolved* adapter, so registering a hosted model cannot slip past an
engagement whose `hosted_models_allowed` is false.
"""

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

import app.services.ai_models as svc
from app.llm.base import (
    HostedModelNotAllowedError,
    LLMBackendError,
    LLMMessage,
    LLMResult,
    LLMUsage,
)
from app.llm.redaction import RegexRedactor
from app.llm.registry import AIModelRegistry
from app.llm.service import LLMService
from app.models.ai_model import AIModel
from app.models.llm import LLMPurpose
from app.schemas.llm import AIModelCreate, AIModelOut
from app.services.credentials import CredentialCipher

ORG = uuid.uuid4()


def _cipher() -> CredentialCipher:
    return CredentialCipher(None, allow_dev_key=True)


def _row(
    *,
    provider: str = "ollama",
    model_id: str = "llama3.1:8b",
    base_url: str | None = "http://localhost:11434",
    api_key_encrypted: str | None = None,
    is_default: bool = True,
    updated_at: datetime | None = None,
) -> AIModel:
    return AIModel(
        id=uuid.uuid4(),
        organization_id=ORG,
        name=f"{provider}-model",
        provider=provider,
        model_id=model_id,
        base_url=base_url,
        api_key_encrypted=api_key_encrypted,
        is_default=is_default,
        created_at=datetime(2026, 8, 1, tzinfo=UTC),
        updated_at=updated_at or datetime(2026, 8, 1, tzinfo=UTC),
    )


class _FakeSession:
    """Answers the registry's single row lookup per resolve()."""

    def __init__(self, row: AIModel | None) -> None:
        self._row = row
        self.added: list[object] = []

    async def execute(self, _stmt: object) -> object:
        row = self._row
        return SimpleNamespace(scalar_one_or_none=lambda: row, one=lambda: (0, 0.0))

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        pass


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        llm_provider="anthropic",
        anthropic_api_key=None,
        llm_model_default="claude-opus-4-8",
        llm_max_tokens_per_engagement=0,
        llm_max_cost_usd_per_engagement=0.0,
        require_llm_backend=lambda: (_ for _ in ()).throw(ValueError("ANTHROPIC_API_KEY unset")),
    )


def _engagement(*, hosted_allowed: bool, ai_model_id: uuid.UUID | None) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(), hosted_models_allowed=hosted_allowed, ai_model_id=ai_model_id
    )


# ── the key is write-only ─────────────────────────────────────────────────────


def test_out_model_never_exposes_the_api_key() -> None:
    row = _row(provider="anthropic", base_url=None, api_key_encrypted="gAAAA-ciphertext")
    dumped = AIModelOut.from_model(row).model_dump()
    assert "api_key" not in dumped
    assert "api_key_encrypted" not in dumped
    assert dumped["hosted"] is True  # hosted providers are flagged for the UI


def test_local_model_is_not_flagged_hosted() -> None:
    assert AIModelOut.from_model(_row()).hosted is False


# ── provider config is validated at the edge ──────────────────────────────────


def test_hosted_provider_requires_a_key() -> None:
    with pytest.raises(ValueError, match="api_key is required"):
        AIModelCreate(name="claude", provider="anthropic", model_id="claude-opus-4-8")


def test_local_provider_requires_an_endpoint() -> None:
    with pytest.raises(ValueError, match="base_url is required"):
        AIModelCreate(name="local", provider="ollama", model_id="llama3.1:8b")


@pytest.mark.parametrize("bad", ["file:///etc/passwd", "localhost:11434", "gopher://x", ""])
def test_endpoint_must_be_an_absolute_http_url(bad: str) -> None:
    with pytest.raises(svc.AIModelVerificationError):
        svc.normalize_base_url(bad)


def test_endpoint_is_normalized() -> None:
    assert svc.normalize_base_url(" http://localhost:11434/ ") == "http://localhost:11434"


# ── a loopback endpoint means the Docker host, not the API container ───────────


@pytest.mark.parametrize(
    "typed",
    ["http://localhost:11434", "http://127.0.0.1:11434", "http://0.0.0.0:11434"],
)
def test_loopback_endpoint_also_tries_the_docker_host(typed: str) -> None:
    candidates = svc.endpoint_candidates(typed)
    assert candidates == [typed, "http://host.docker.internal:11434"]


def test_a_named_endpoint_is_tried_as_given() -> None:
    assert svc.endpoint_candidates("http://ollama:11434") == ["http://ollama:11434"]


async def test_localhost_falls_back_to_the_docker_host_and_stores_what_worked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bug an operator hits: Ollama runs on their machine, the API runs in a
    container, so the loopback they typed is refused and the host alias answers."""
    tried: list[str | None] = []

    async def fake_verify(*, provider: str, model_id: str, api_key, base_url) -> None:  # noqa: ANN001, ARG001
        tried.append(base_url)
        if base_url is not None and "host.docker.internal" not in base_url:
            raise svc.AIModelUnreachableError("could not reach the provider (ConnectError)")

    monkeypatch.setattr(svc, "verify_provider", fake_verify)
    row = await svc.create_model(
        _FakeSession(None),  # type: ignore[arg-type]
        _cipher(),
        organization_id=ORG,
        name="local",
        provider="ollama",
        model_id="qwen3.6:35b-a3b",
        api_key=None,
        base_url="http://localhost:11434",
        make_default=True,
        created_by=None,
    )
    assert tried == ["http://localhost:11434", "http://host.docker.internal:11434"]
    assert row.base_url == "http://host.docker.internal:11434"  # what actually answered


async def test_a_provider_that_answered_no_beats_the_silent_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With two candidates, the useful message is the provider's refusal, not the
    connection failure from the address that had nothing listening."""

    async def fake_verify(*, provider: str, model_id: str, api_key, base_url) -> None:  # noqa: ANN001, ARG001
        if base_url is not None and "host.docker.internal" in base_url:
            raise svc.AIModelVerificationError(
                f"the provider does not have a model named {model_id!r}"
            )
        raise svc.AIModelUnreachableError("could not reach the provider (ConnectError)")

    monkeypatch.setattr(svc, "verify_provider", fake_verify)
    with pytest.raises(svc.AIModelVerificationError, match="does not have a model named"):
        await svc.create_model(
            _FakeSession(None),  # type: ignore[arg-type]
            _cipher(),
            organization_id=ORG,
            name="local",
            provider="ollama",
            model_id="not-pulled",
            api_key=None,
            base_url="http://localhost:11434",
            make_default=True,
            created_by=None,
        )


async def test_nothing_listening_anywhere_reports_both_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_verify(**_kwargs: object) -> None:
        raise svc.AIModelUnreachableError("could not reach the provider (ConnectError)")

    monkeypatch.setattr(svc, "verify_provider", fake_verify)
    with pytest.raises(svc.AIModelUnreachableError, match="host.docker.internal"):
        await svc.create_model(
            _FakeSession(None),  # type: ignore[arg-type]
            _cipher(),
            organization_id=ORG,
            name="local",
            provider="ollama",
            model_id="llama3.1:8b",
            api_key=None,
            base_url="http://localhost:11434",
            make_default=True,
            created_by=None,
        )


# ── provider check maps failures to operator-actionable errors ─────────────────


def _stub_httpx(monkeypatch: pytest.MonkeyPatch, status_code: int) -> None:
    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_exc: object) -> None:
            return None

        async def get(self, *_a: object, **_kw: object) -> object:
            return SimpleNamespace(status_code=status_code)

        async def post(self, *_a: object, **_kw: object) -> object:
            return SimpleNamespace(status_code=status_code)

    monkeypatch.setattr(svc.httpx, "AsyncClient", _Client)


@pytest.mark.parametrize(
    ("status_code", "message"),
    [(401, "rejected the API key"), (404, "does not have a model named"), (500, "HTTP 500")],
)
async def test_verify_provider_surfaces_the_provider_refusal(
    monkeypatch: pytest.MonkeyPatch, status_code: int, message: str
) -> None:
    _stub_httpx(monkeypatch, status_code)
    with pytest.raises(svc.AIModelVerificationError, match=message):
        await svc.verify_provider(
            provider="anthropic", model_id="claude-opus-4-8", api_key="k", base_url=None
        )


async def test_verify_provider_accepts_a_working_local_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_httpx(monkeypatch, 200)
    await svc.verify_provider(
        provider="ollama",
        model_id="llama3.1:8b",
        api_key=None,
        base_url="http://localhost:11434",
    )


async def test_create_model_encrypts_the_key_and_defaults_the_first_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_httpx(monkeypatch, 200)
    session = _FakeSession(None)  # no existing default
    row = await svc.create_model(
        session,  # type: ignore[arg-type]
        _cipher(),
        organization_id=ORG,
        name="claude",
        provider="anthropic",
        model_id="claude-opus-4-8",
        api_key="sk-" + "test-key-value",
        base_url="http://ignored:1",  # hosted provider → dropped
        make_default=False,
        created_by=None,
    )
    assert row.api_key_encrypted is not None
    assert "test-key-value" not in row.api_key_encrypted
    assert _cipher().decrypt(row.api_key_encrypted) == "sk-" + "test-key-value"
    assert row.base_url is None
    assert row.is_default is True  # first registered model becomes the default


# ── resolution precedence ─────────────────────────────────────────────────────


async def test_resolves_the_org_default_when_the_engagement_pins_nothing() -> None:
    row = _row()
    registry = AIModelRegistry(_cipher(), _settings())
    adapter, model_id = await registry.resolve(
        _FakeSession(row),  # type: ignore[arg-type]
        ORG,
        _engagement(hosted_allowed=False, ai_model_id=None),
    )
    assert (adapter.provider, model_id) == ("ollama", "llama3.1:8b")
    await registry.aclose()


async def test_resolves_the_model_pinned_to_the_engagement() -> None:
    pinned = _row(model_id="mistral:7b", is_default=False)
    registry = AIModelRegistry(_cipher(), _settings())
    _adapter, model_id = await registry.resolve(
        _FakeSession(pinned),  # type: ignore[arg-type]
        ORG,
        _engagement(hosted_allowed=False, ai_model_id=pinned.id),
    )
    assert model_id == "mistral:7b"
    await registry.aclose()


async def test_a_deleted_pinned_model_fails_loud_instead_of_swapping_providers() -> None:
    registry = AIModelRegistry(_cipher(), _settings())
    with pytest.raises(LLMBackendError, match="no longer exists"):
        await registry.resolve(
            _FakeSession(None),  # type: ignore[arg-type]
            ORG,
            _engagement(hosted_allowed=True, ai_model_id=uuid.uuid4()),
        )


async def test_no_registered_model_and_no_env_provider_says_so() -> None:
    registry = AIModelRegistry(_cipher(), _settings())
    with pytest.raises(LLMBackendError, match="no AI model is configured"):
        await registry.resolve(_FakeSession(None), ORG, None)  # type: ignore[arg-type]


async def test_adapter_is_cached_per_row_version() -> None:
    row = _row()
    registry = AIModelRegistry(_cipher(), _settings())
    session = _FakeSession(row)
    first, _ = await registry.resolve(session, ORG, None)  # type: ignore[arg-type]
    again, _ = await registry.resolve(session, ORG, None)  # type: ignore[arg-type]
    assert again is first  # same row version → same provider client

    row.updated_at = datetime(2026, 8, 2, tzinfo=UTC)  # operator edited the model
    rebuilt, _ = await registry.resolve(session, ORG, None)  # type: ignore[arg-type]
    assert rebuilt is not first
    await registry.aclose()


# ── the hosted gate keys off the RESOLVED adapter ─────────────────────────────


class _RecordingAdapter:
    provider = "anthropic"
    hosted = True

    def __init__(self) -> None:
        self.calls: list[object] = []

    async def complete(self, request: object) -> LLMResult:
        self.calls.append(request)
        return LLMResult(
            text="draft",
            model=getattr(request, "model", "?"),
            provider=self.provider,
            usage=LLMUsage(input_tokens=1, output_tokens=1),
        )

    async def aclose(self) -> None:
        pass


class _StubRegistry:
    def __init__(self, adapter: object, model_id: str) -> None:
        self._adapter = adapter
        self._model_id = model_id

    async def resolve(self, _session, _org, _engagement):  # noqa: ANN001, ANN202
        return self._adapter, self._model_id

    async def aclose(self) -> None:
        pass


async def _complete(service: LLMService, engagement: object) -> LLMResult:
    result, _interaction = await service.complete(
        _FakeSession(None),  # type: ignore[arg-type]
        organization_id=ORG,
        engagement=engagement,  # type: ignore[arg-type]
        purpose=LLMPurpose.TRIAGE,
        messages=[LLMMessage(role="user", content="finding evidence")],
    )
    return result


async def test_registered_hosted_model_is_still_blocked_when_the_engagement_forbids_it() -> None:
    adapter = _RecordingAdapter()
    service = LLMService(
        None, RegexRedactor(), _settings(), registry=_StubRegistry(adapter, "claude-opus-4-8")
    )
    with pytest.raises(HostedModelNotAllowedError):
        await _complete(service, _engagement(hosted_allowed=False, ai_model_id=None))
    assert adapter.calls == []  # nothing left the box


async def test_the_registered_model_id_is_what_gets_called() -> None:
    adapter = _RecordingAdapter()
    service = LLMService(
        None, RegexRedactor(), _settings(), registry=_StubRegistry(adapter, "claude-sonnet-5")
    )
    result = await _complete(service, _engagement(hosted_allowed=True, ai_model_id=None))
    assert result.model == "claude-sonnet-5"  # registry model, not LLM_MODEL_DEFAULT
