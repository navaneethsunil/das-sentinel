"""HTTP LLM/chatbot target connector (M2-B6) — the real `SuiteTarget` seam.

The AI/LLM suites (M2-B4/B5) drive attacks against an LLM target through a
`SuiteTarget` (`send` single-shot + `open_conversation` multi-turn) / `RunnerTarget`
(`send`). Until now a mock stood in for that seam; this module is the real,
scope-validated connector that reaches a configured chatbot or LLM-wrapper endpoint
over HTTP.

Safety (CLAUDE.md §2, TM-1/TM-5):

  * **Scope-validated egress, every request.** Before each outbound call — and
    for every redirect hop — the endpoint is checked through the scope keystone
    (`app.core.scope.assert_egress_allowed`): the URL must match an in-scope allow
    rule (deny wins) AND its host must resolve to a non-dangerous, in-scope IP
    (SSRF/DNS-rebinding defense). Nothing here re-implements scope matching; the
    connector cannot reach a host the engagement did not authorize.
  * **Credential handling.** The target's auth credential is a *reference* in
    `auth_config` (TR-23, refs-only). It is resolved to a secret at build time via
    an injected resolver, held only in memory for the request header, and NEVER
    persisted (not in connector_config, not in the transcript evidence, not logged).
  * **Fail loud, never fail-open.** A transport/parse/config error raises
    `TargetConnectorError` — surfaced as a job/attempt failure, never swallowed
    into a fake-empty response (§5, TM-14).

The connector is NOT the adjudicator: it returns what the target said. The
deterministic detectors (app/suites/detectors.py) decide pass/fail from that
response — the LLM is never the judge (§2.6).
"""

import copy
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.egress import EgressGate
from app.core.scope import assert_egress_allowed
from app.models.engagement import ScopeItem
from app.models.target import Target, TargetType
from app.services.targets import validate_auth_config_references

# host → resolved IP strings. Injected so egress checks stay testable and the
# production DNS path is swappable (matches app.core.scope.Resolver).
DnsResolver = Callable[[str], list[str]]
# credential reference (e.g. "env:VAR", a vault path) → secret value. Injected so
# the connector never reads a secret store directly and tests need no real secret.
SecretResolver = Callable[[str], str]

_ALLOWED_CONFIG_KEYS = frozenset(
    {
        "method",
        "headers",
        "mode",
        "body_template",
        "messages_pointer",
        "prompt_pointer",
        "response_pointer",
        "auth_ref_key",
        "auth_header",
        "auth_scheme",
        "max_redirects",
        "timeout_seconds",
    }
)
_MODES = frozenset({"chat_messages", "single_prompt"})
_METHODS = frozenset({"POST", "GET"})
_MAX_REDIRECTS_CEILING = 5
_LLM_TARGET_TYPES = frozenset({TargetType.AI_CHATBOT, TargetType.LLM_API_WRAPPER})

# TM-8 (hostile parser): a target is untrusted "tool output". Bound how much of one
# response we will buffer so a hostile/compromised in-scope target cannot exhaust
# worker memory with a giant or never-ending body. A body over this fails safe as a
# TargetConnectorError (never an OOM). 8 MiB is orders of magnitude above any real
# chat-completion reply.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class TargetConnectorError(Exception):
    """The connector could not reach/parse the target, or was blocked from doing
    so. Surfaced loud as an attempt/job failure — never a silent empty response."""


class ConnectorConfigError(TargetConnectorError):
    """The target's connector_config is malformed (unknown key, bad type/value).
    Fail-closed: a half-understood transport shape is never used."""


# ── JSON pointer (RFC 6901-lite) ──────────────────────────────────────────────
def _unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _split_pointer(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise ConnectorConfigError(f"JSON pointer must start with '/': {pointer!r}")
    return [_unescape(tok) for tok in pointer[1:].split("/")]


def json_pointer_get(doc: Any, pointer: str) -> Any:
    """Read a value out of a parsed JSON document by pointer, or raise
    TargetConnectorError if the path is absent/mistyped (fail-safe: a target that
    doesn't answer in the configured shape is a failure, not a crash)."""
    node = doc
    for token in _split_pointer(pointer):
        if isinstance(node, dict):
            if token not in node:
                raise TargetConnectorError(f"response has no key {token!r} at pointer {pointer!r}")
            node = node[token]
        elif isinstance(node, list):
            try:
                idx = int(token)
            except ValueError:
                raise TargetConnectorError(
                    f"response pointer {pointer!r} indexed a list with non-int {token!r}"
                ) from None
            if not -len(node) <= idx < len(node):
                raise TargetConnectorError(f"response list index {idx} out of range ({pointer!r})")
            node = node[idx]
        else:
            raise TargetConnectorError(f"response pointer {pointer!r} descended into a scalar")
    return node


def parse_target_json(raw: bytes, *, max_bytes: int = MAX_RESPONSE_BYTES) -> Any:
    """Parse an untrusted target response body into JSON, failing safe (TM-8).

    Treats the bytes as hostile tool output: an oversized body is rejected, and a
    malformed, truncated, or pathologically nested document raises a
    `TargetConnectorError` — never an uncaught crash. `RecursionError` (deeply
    nested arrays/objects blowing the interpreter stack) is mapped to the same
    fail-safe error. Uses `json` only; never an unsafe deserializer (no
    `pickle`/`yaml.load`)."""
    if len(raw) > max_bytes:
        raise TargetConnectorError(f"target response exceeded {max_bytes} bytes")
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise TargetConnectorError("target response was not valid JSON") from exc


def _json_pointer_set(doc: dict[str, Any], pointer: str, value: Any) -> None:
    """Set a value into a request-body template by pointer, creating intermediate
    dicts as needed. Only dict traversal is supported (list slots in a template
    must be pre-shaped) — enough for chat-style bodies, and fail-closed otherwise."""
    tokens = _split_pointer(pointer)
    if not tokens:
        raise ConnectorConfigError("cannot set the whole body via an empty pointer")
    node: Any = doc
    for token in tokens[:-1]:
        if not isinstance(node, dict):
            raise ConnectorConfigError(f"body pointer {pointer!r} traverses a non-dict")
        node = node.setdefault(token, {})
    if not isinstance(node, dict):
        raise ConnectorConfigError(f"body pointer {pointer!r} traverses a non-dict")
    node[tokens[-1]] = value


# ── Connection config ─────────────────────────────────────────────────────────
def validate_connector_config(raw: dict[str, Any] | None) -> None:
    """Validate a target's connector_config shape. Raises ConnectorConfigError on
    an unknown key or a bad type/value (fail-closed). Used both at target-create
    time (schema) and connector-build time."""
    if raw is None:
        return
    if not isinstance(raw, dict):
        raise ConnectorConfigError("connector_config must be an object")
    unknown = set(raw) - _ALLOWED_CONFIG_KEYS
    if unknown:
        raise ConnectorConfigError(f"unknown connector_config key(s): {sorted(unknown)}")
    if "mode" in raw and raw["mode"] not in _MODES:
        raise ConnectorConfigError(f"mode must be one of {sorted(_MODES)}")
    if "method" in raw and str(raw["method"]).upper() not in _METHODS:
        raise ConnectorConfigError(f"method must be one of {sorted(_METHODS)}")
    if "headers" in raw and not isinstance(raw["headers"], dict):
        raise ConnectorConfigError("headers must be an object")
    if "body_template" in raw and not isinstance(raw["body_template"], dict):
        raise ConnectorConfigError("body_template must be an object")
    if "max_redirects" in raw:
        mr = raw["max_redirects"]
        if not isinstance(mr, int) or isinstance(mr, bool) or not 0 <= mr <= _MAX_REDIRECTS_CEILING:
            raise ConnectorConfigError(
                f"max_redirects must be an int in [0, {_MAX_REDIRECTS_CEILING}]"
            )
    if "timeout_seconds" in raw:
        ts = raw["timeout_seconds"]
        if not isinstance(ts, (int, float)) or isinstance(ts, bool) or ts <= 0:
            raise ConnectorConfigError("timeout_seconds must be a positive number")


@dataclass(frozen=True)
class TargetConnectionConfig:
    """How to reach one LLM target. Defaults describe an OpenAI-style
    chat-completions endpoint; every field is overridable per target."""

    endpoint: str
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    mode: str = "chat_messages"
    body_template: dict[str, Any] = field(default_factory=dict)
    messages_pointer: str = "/messages"
    prompt_pointer: str = "/prompt"
    response_pointer: str = "/choices/0/message/content"
    auth_ref_key: str = "api_key_ref"
    auth_header: str = "authorization"
    auth_scheme: str = "Bearer"
    max_redirects: int = 0
    timeout_seconds: float = 30.0

    @classmethod
    def from_target(cls, target: Target) -> "TargetConnectionConfig":
        raw = target.connector_config or {}
        validate_connector_config(raw)
        return cls(
            endpoint=target.primary_value,
            method=str(raw.get("method", "POST")).upper(),
            headers=dict(raw.get("headers", {})),
            mode=raw.get("mode", "chat_messages"),
            body_template=copy.deepcopy(raw.get("body_template", {})),
            messages_pointer=raw.get("messages_pointer", "/messages"),
            prompt_pointer=raw.get("prompt_pointer", "/prompt"),
            response_pointer=raw.get("response_pointer", "/choices/0/message/content"),
            auth_ref_key=raw.get("auth_ref_key", "api_key_ref"),
            auth_header=raw.get("auth_header", "authorization"),
            auth_scheme=raw.get("auth_scheme", "Bearer"),
            max_redirects=int(raw.get("max_redirects", 0)),
            timeout_seconds=float(raw.get("timeout_seconds", 30.0)),
        )

    def build_body(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        body = copy.deepcopy(self.body_template)
        if self.mode == "chat_messages":
            _json_pointer_set(body, self.messages_pointer, messages)
        else:  # single_prompt: send only the latest user turn
            _json_pointer_set(body, self.prompt_pointer, messages[-1]["content"])
        return body


# ── Egress guard ────────────────────────────────────────────────────────────
class TargetEgressGuard:
    """Wraps the scope keystone for per-request egress checks. Re-resolves DNS on
    every call (DNS-rebinding defense); raises ScopeError (ScopeViolation /
    SSRFBlocked) if the URL is not an authorized, safe destination."""

    def __init__(self, *, scope_items: list[ScopeItem], resolve: DnsResolver) -> None:
        self._scope_items = scope_items
        self._resolve = resolve

    def assert_allowed(self, url: str) -> None:
        assert_egress_allowed(url=url, scope_items=self._scope_items, resolve=self._resolve)

    async def aguard(self, url: str) -> None:
        """`EgressGate` seam. The bare guard only checks scope/SSRF; the M2-SEC1
        `EgressShaper` implements the same method and adds the aggregate rate
        ceiling. The connector calls whichever gate it was built with."""
        self.assert_allowed(url)


# ── DNS / secret resolvers (injected; production paths swap here) ─────────────
def system_dns_resolver(host: str) -> list[str]:
    import socket

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise TargetConnectorError(f"could not resolve target host {host!r}") from exc
    return sorted({info[4][0] for info in infos})


def env_secret_resolver(ref: Any) -> str:
    """Resolve an "env:<VAR>" reference to a secret from the environment. A real
    deployment swaps this for a secrets-manager/Vault lookup — the connector never
    reads a secret store directly."""
    prefix = "env:"
    if not isinstance(ref, str) or not ref.startswith(prefix):
        raise TargetConnectorError(f"unsupported auth reference {ref!r}; expected 'env:<VAR>'")
    value = os.environ.get(ref[len(prefix) :])
    if not value:
        raise TargetConnectorError(f"auth reference {ref!r} resolved to an empty/undefined secret")
    return value


# ── Connector ─────────────────────────────────────────────────────────────
class HttpLLMTargetConnector:
    """A scope-validated `SuiteTarget`/`RunnerTarget` over HTTP.

    `send` is the stateless single-shot seam (one user turn). `open_conversation`
    yields a stateful conversation that replays the accumulated history on each
    turn (standard chat-completions semantics), so multi-turn probes and the
    suite's per-turn cancellation work unchanged."""

    def __init__(
        self,
        *,
        config: TargetConnectionConfig,
        guard: EgressGate,
        auth_header_value: str | None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._config = config
        self._guard = guard
        self._auth_header_value = auth_header_value
        # follow_redirects=False: we follow manually so each hop is re-validated
        # through the egress guard (a target must never auto-redirect us off-scope).
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=config.timeout_seconds,
            transport=transport,
        )

    def _headers(self) -> dict[str, str]:
        headers = dict(self._config.headers)
        if self._auth_header_value is not None:
            headers[self._config.auth_header] = self._auth_header_value
        return headers

    async def _read_bounded(self, response: httpx.Response) -> bytes:
        """Stream a response body, aborting once it exceeds `MAX_RESPONSE_BYTES`
        (TM-8) so a giant or never-ending body can never be fully buffered into
        memory. The cap is read at call time so tests can lower it."""
        buf = bytearray()
        async for chunk in response.aiter_bytes():
            buf.extend(chunk)
            if len(buf) > MAX_RESPONSE_BYTES:
                raise TargetConnectorError(f"target response exceeded {MAX_RESPONSE_BYTES} bytes")
        return bytes(buf)

    async def _post(self, messages: list[dict[str, str]]) -> str:
        url = self._config.endpoint
        for _hop in range(self._config.max_redirects + 1):
            # Egress choke point at THIS url — before the request, every hop:
            # scope + SSRF (always) and, when the gate is the M2-SEC1 shaper, the
            # aggregate rate ceiling. A blocked hop raises before any request.
            await self._guard.aguard(url)
            try:
                # Stream so the body is read under a hard byte cap (TM-8), not
                # eagerly buffered. A connection reset / truncated / protocol
                # error mid-read surfaces as httpx.HTTPError below and fails safe.
                async with self._client.stream(
                    self._config.method,
                    url,
                    json=self._config.build_body(messages),
                    headers=self._headers(),
                ) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise TargetConnectorError("target redirect had no Location header")
                        url = str(httpx.URL(url).join(location))
                        continue
                    if response.status_code >= 400:  # noqa: PLR2004 — HTTP client-error floor
                        raise TargetConnectorError(f"target returned HTTP {response.status_code}")
                    raw = await self._read_bounded(response)
            except httpx.HTTPError as exc:
                raise TargetConnectorError(f"request to target failed: {exc}") from exc
            data = parse_target_json(raw)
            reply = json_pointer_get(data, self._config.response_pointer)
            if not isinstance(reply, str):
                raise TargetConnectorError(
                    f"target response at {self._config.response_pointer!r} was not a string"
                )
            return reply
        raise TargetConnectorError(f"target exceeded max redirects ({self._config.max_redirects})")

    async def send(self, prompt: str) -> str:
        return await self._post([{"role": "user", "content": prompt}])

    def open_conversation(self) -> "_HttpConversation":
        return _HttpConversation(self)

    async def aclose(self) -> None:
        await self._client.aclose()


class _HttpConversation:
    """Stateful multi-turn conversation: accumulates the transcript and replays
    the full history to the target on each turn."""

    def __init__(self, connector: HttpLLMTargetConnector) -> None:
        self._connector = connector
        self._messages: list[dict[str, str]] = []

    async def send(self, prompt: str) -> str:
        self._messages.append({"role": "user", "content": prompt})
        reply = await self._connector._post(self._messages)
        self._messages.append({"role": "assistant", "content": reply})
        return reply


def build_llm_target_connector(
    target: Target,
    scope_items: list[ScopeItem],
    *,
    resolve: DnsResolver = system_dns_resolver,
    secret_resolver: SecretResolver = env_secret_resolver,
    transport: httpx.BaseTransport | None = None,
    gate: EgressGate | None = None,
) -> HttpLLMTargetConnector:
    """Build a scope-validated connector for a chatbot/LLM-wrapper target. Refuses
    non-LLM target types and any auth_config that embeds a plaintext secret (TR-23);
    resolves the auth reference to an in-memory header value that is never persisted.

    `gate` is the egress choke point every request passes through. When omitted the
    connector uses a bare `TargetEgressGuard` (scope + SSRF only); a run supplies the
    M2-SEC1 `EgressShaper` to add the engagement's aggregate rate ceiling."""
    if target.target_type not in _LLM_TARGET_TYPES:
        raise TargetConnectorError(
            f"target type {target.target_type.value} is not an LLM/chatbot target"
        )
    # Defense in depth: auth_config is refs-only (also enforced at create time).
    try:
        validate_auth_config_references(target.auth_config)
    except ValueError as exc:
        raise TargetConnectorError(str(exc)) from exc

    config = TargetConnectionConfig.from_target(target)

    auth_header_value: str | None = None
    if target.auth_config and config.auth_ref_key in target.auth_config:
        secret = secret_resolver(target.auth_config[config.auth_ref_key])
        auth_header_value = (
            f"{config.auth_scheme} {secret}".strip() if config.auth_scheme else secret
        )

    egress_gate = gate or TargetEgressGuard(scope_items=scope_items, resolve=resolve)
    return HttpLLMTargetConnector(
        config=config,
        guard=egress_gate,
        auth_header_value=auth_header_value,
        transport=transport,
    )
