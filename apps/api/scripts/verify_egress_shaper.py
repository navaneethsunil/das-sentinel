"""Live verification for M2-SEC1 — engagement-aware egress shaper.

DB-free: exercises the real `EgressShaper` + `ValkeyEgressLimiter` + the real
`HttpLLMTargetConnector` over real HTTP/TCP to a local mock chatbot, backed by the
live Valkey the compose stack runs. No PyRIT, so this runs in the base `api` image.

Proves the two controls the one choke point owns:

  1. Default-deny reachability (TM-1), fail-closed with NO network egress:
       - an in-scope loopback target IS reachable (control);
       - a decoy internal service (host not in scope) is blocked;
       - a cloud-metadata-IP probe (name-in-scope host resolving to 169.254.169.254)
         is blocked by the resolved-IP SSRF re-check;
       - a configured provider endpoint is reachable even with an empty target scope.
  2. Aggregate rate ceiling: several concurrent "runs" (independent limiter
     instances, as separate worker processes would be) sharing one engagement key
     hold the observed outbound rate at ≤ the engagement's rate_limit_rps.
  3. Fail-closed: with the rate-limiter backend unreachable, egress is denied
     (EgressUnavailable), not waved through — and no request leaves the box.

Run (base api image; mount scripts + sandbox):
  docker compose up -d --build api           # brings up postgres/valkey/migrate too
  docker compose run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" -v "$PWD/sandbox:/app/sandbox:ro" \
    --entrypoint sh api -c \
    "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
       python scripts/verify_egress_shaper.py"
"""

import asyncio
import sys
import time
import uuid

from redis.asyncio import Redis

from app.connectors import build_llm_target_connector, system_dns_resolver
from app.core.config import get_settings
from app.core.egress import EgressShaper, EgressUnavailable, ValkeyEgressLimiter
from app.core.scope import ScopeError
from app.models.engagement import ScopeItem, ScopeKind, ScopeMatcher
from app.models.target import Target, TargetType

sys.path.insert(0, "/app/sandbox")
from mock_llm import serve_mock_llm  # noqa: E402

_PASSED = 0
_FAILED = 0


def check(label: str, ok: bool, extra: str = "") -> None:
    global _PASSED, _FAILED
    mark = "PASS" if ok else "FAIL"
    if ok:
        _PASSED += 1
    else:
        _FAILED += 1
    print(f"  [{mark}] {label}{(' — ' + extra) if extra else ''}")


def _scope(kind: ScopeKind, matcher: ScopeMatcher, value: str) -> ScopeItem:
    return ScopeItem(kind=kind, matcher_type=matcher, value=value)


def _chatbot(endpoint: str) -> Target:
    return Target(
        name="mock",
        target_type=TargetType.AI_CHATBOT,
        primary_value=endpoint,
        connector_config=None,
        auth_config=None,
    )


def _fixed_resolver(mapping: dict[str, list[str]]):
    def _resolve(host: str) -> list[str]:
        if host in mapping:
            return mapping[host]
        return system_dns_resolver(host)

    return _resolve


def _connector(target: Target, shaper: EgressShaper):
    # `gate=shaper` routes every request through the choke point; the positional
    # scope_items is unused when a gate is supplied.
    return build_llm_target_connector(target, [], gate=shaper)


def _max_in_window(times: list[float], window: float = 1.0) -> int:
    ordered = sorted(times)
    best = 0
    for i, start in enumerate(ordered):
        count = sum(1 for t in ordered[i:] if t < start + window)
        best = max(best, count)
    return best


async def main() -> None:
    settings = get_settings()
    cache: Redis = Redis.from_url(settings.cache_url)

    mock = serve_mock_llm()
    port = mock.endpoint.rsplit(":", 1)[1].split("/", 1)[0]
    loopback_scope = [_scope(ScopeKind.ALLOW, ScopeMatcher.IP_CIDR, "127.0.0.0/8")]

    try:
        # 1. Reachable in-scope loopback target (control) ──────────────────
        eng_a = uuid.uuid4()
        shaper_a = EgressShaper(
            engagement_id=eng_a,
            rate_limit_rps=50,
            scope_items=loopback_scope,
            resolve=system_dns_resolver,
            limiter=ValkeyEgressLimiter(cache),
        )
        conn_a = _connector(_chatbot(mock.endpoint), shaper_a)
        try:
            reply = await conn_a.send("hello canary")
        finally:
            await conn_a.aclose()
        check("in-scope loopback target reachable", bool(reply) and len(mock.request_times) == 1)

        # 2. Decoy internal service (host not in scope) blocked, no egress ──
        before = len(mock.request_times)
        decoy = _chatbot(f"http://decoy.internal:{port}/v1/chat/completions")
        shaper_decoy = EgressShaper(
            engagement_id=uuid.uuid4(),
            rate_limit_rps=50,
            scope_items=loopback_scope,  # only loopback is allowed
            # Resolves to the mock's IP — would reach it IF the host were in scope.
            resolve=_fixed_resolver({"decoy.internal": ["127.0.0.1"]}),
            limiter=ValkeyEgressLimiter(cache),
        )
        conn_decoy = _connector(decoy, shaper_decoy)
        blocked = False
        try:
            await conn_decoy.send("probe")
        except ScopeError:
            blocked = True
        finally:
            await conn_decoy.aclose()
        check(
            "decoy internal service blocked with no egress",
            blocked and len(mock.request_times) == before,
        )

        # 3. Cloud-metadata-IP probe blocked by resolved-IP SSRF re-check ───
        before = len(mock.request_times)
        meta = _chatbot(f"http://meta.example.com:{port}/v1/chat/completions")
        shaper_meta = EgressShaper(
            engagement_id=uuid.uuid4(),
            rate_limit_rps=50,
            scope_items=[
                *loopback_scope,
                _scope(ScopeKind.ALLOW, ScopeMatcher.DOMAIN, "meta.example.com"),  # name allowed
            ],
            # Name is in scope, but it resolves to the cloud-metadata IP.
            resolve=_fixed_resolver({"meta.example.com": ["169.254.169.254"]}),
            limiter=ValkeyEgressLimiter(cache),
        )
        conn_meta = _connector(meta, shaper_meta)
        blocked = False
        try:
            await conn_meta.send("probe")
        except ScopeError:
            blocked = True
        finally:
            await conn_meta.aclose()
        check(
            "cloud-metadata-IP probe blocked (SSRF re-check) with no egress",
            blocked and len(mock.request_times) == before,
        )

        # 4. Configured provider endpoint reachable with empty target scope ─
        before = len(mock.request_times)
        shaper_provider = EgressShaper(
            engagement_id=uuid.uuid4(),
            rate_limit_rps=50,
            scope_items=[],  # nothing is a target
            resolve=system_dns_resolver,
            limiter=ValkeyEgressLimiter(cache),
            provider_allowlist=frozenset({f"127.0.0.1:{port}"}),
        )
        conn_provider = _connector(_chatbot(mock.endpoint), shaper_provider)
        try:
            reply = await conn_provider.send("hello canary")
        finally:
            await conn_provider.aclose()
        check(
            "configured provider endpoint reachable despite empty target scope",
            bool(reply) and len(mock.request_times) == before + 1,
        )

        # 5. Aggregate rate ceiling across concurrent runs ──────────────────
        rps = 5
        runs = 3
        per_run = 8
        eng_rate = uuid.uuid4()
        await cache.delete(f"egress:rate:{eng_rate}")
        start_count = len(mock.request_times)

        async def one_run() -> None:
            # A separate limiter instance per run, as separate worker processes
            # would have — they share the aggregate ceiling only via the Valkey key.
            shaper = EgressShaper(
                engagement_id=eng_rate,
                rate_limit_rps=rps,
                scope_items=loopback_scope,
                resolve=system_dns_resolver,
                limiter=ValkeyEgressLimiter(cache),
            )
            conn = _connector(_chatbot(mock.endpoint), shaper)
            try:
                for _ in range(per_run):
                    await conn.send("rate canary")
            finally:
                await conn.aclose()

        t0 = time.time()
        await asyncio.gather(*(one_run() for _ in range(runs)))
        elapsed = time.time() - t0
        total = runs * per_run
        times = mock.request_times[start_count:]
        observed_peak = _max_in_window(times, 1.0)
        observed_rate = (len(times) - 1) / elapsed if elapsed > 0 else float("inf")

        check(
            f"all {total} requests egressed under the shaper",
            len(times) == total,
            f"saw {len(times)}",
        )
        check(
            f"observed peak ≤ ceiling+1 in any 1s window (rps={rps})",
            observed_peak <= rps + 1,
            f"peak={observed_peak}",
        )
        check(
            "aggregate observed rate ≤ ceiling (with tolerance)",
            observed_rate <= rps * 1.34,
            f"{observed_rate:.2f} rps over {elapsed:.2f}s",
        )
        check(
            "shaper actually throttled (elapsed near total/rps)",
            elapsed >= (total - 1) / rps * 0.7,
            f"elapsed={elapsed:.2f}s vs floor≈{(total - 1) / rps:.2f}s",
        )

        # 6. Fail-closed when the rate-limiter backend is unreachable ───────
        before = len(mock.request_times)
        dead_cache: Redis = Redis.from_url(
            f"redis://{settings.valkey_host}:6399/{settings.valkey_db_cache}"
        )
        shaper_dead = EgressShaper(
            engagement_id=uuid.uuid4(),
            rate_limit_rps=5,
            scope_items=loopback_scope,
            resolve=system_dns_resolver,
            limiter=ValkeyEgressLimiter(dead_cache),
        )
        conn_dead = _connector(_chatbot(mock.endpoint), shaper_dead)
        failed_closed = False
        try:
            await conn_dead.send("hello canary")
        except EgressUnavailable:
            failed_closed = True
        finally:
            await conn_dead.aclose()
            await dead_cache.aclose()
        check(
            "egress denied (fail-closed) when limiter backend is down, no egress",
            failed_closed and len(mock.request_times) == before,
        )
    finally:
        mock.close()
        await cache.aclose()

    print(f"\n{_PASSED} passed, {_FAILED} failed")
    if _FAILED:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
