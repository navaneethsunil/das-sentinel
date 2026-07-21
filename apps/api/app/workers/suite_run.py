"""Run the configured AI/LLM suites for one scan and persist findings (M2-T1).

This is the payload the execution owner launches for an LLM-suite scan — the wire
that turns a launched scan into evidence-backed findings. It reads the scan's
frozen envelope to learn which suites were authorized, builds the scope-validated
HTTP connector to the target (M2-B6), runs each suite on PyRIT (M2-B3/B4/B5) under
the owner's `CancelToken`, and turns each run's `SuiteResult` into `automated`,
OWASP-mapped findings with transcript evidence (services/findings.py). One
`test_runs` row records each suite's execution.

`build_suite_owner` wraps `run_llm_suites` into the in-process thunk
`InProcessOwner` launches, so orchestration and emergency stop (M2-W1/W2) treat an
in-process PyRIT suite exactly like a subprocess scanner: the owner hands the run
its `CancelToken`, so a stop trips the SAME token the suite checks between
prompts/turns — a run halted mid-suite finalizes `cancelled`, its completed work
committed, and is never reported `completed`.

PyRIT is imported lazily by the runner, so importing this module is safe in the
base image (API, CI); the suites only actually execute where PyRIT is installed —
the `redteam` worker image. In the base image a run fails loud with `RunnerError`
rather than degrading to a fake-empty result (§5, TM-14).
"""

import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.connectors import (
    DnsResolver,
    SecretResolver,
    build_llm_target_connector,
    env_secret_resolver,
    system_dns_resolver,
)
from app.core.config import get_settings
from app.core.egress import (
    EgressShaper,
    RateLimiter,
    ValkeyEgressLimiter,
    parse_provider_allowlist,
)
from app.core.sessions import utcnow
from app.models.engagement import Engagement, ScopeItem
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus, TestRun, TestSuite
from app.models.target import Target
from app.services.findings import create_findings_from_suite
from app.storage.evidence import BlobStore
from app.suites.base import SuiteResult
from app.suites.data_leakage import DataLeakageSuite
from app.suites.prompt_injection import PromptInjectionSuite
from app.workers.execution import CancelToken, InProcessOwner, RunOutcome

# One suite class per launchable test suite (schemas.scans._LAUNCHABLE_SUITES).
# agent_permission (M5) is intentionally absent — it is not runnable here yet.
_SUITE_CLASSES: dict[TestSuite, Callable[[], object]] = {
    TestSuite.PROMPT_INJECTION: PromptInjectionSuite,
    TestSuite.DATA_LEAKAGE: DataLeakageSuite,
}


class SuiteRunError(Exception):
    """A precondition the suite run cannot proceed past (missing scan/envelope, or
    an envelope naming a suite with no runner). Surfaced as a failed run."""


def suites_from_config(normalized_config: dict) -> list[TestSuite]:
    """Resolve the ordered, de-duplicated suites frozen in the execution envelope.
    Fails loud on an unknown or non-runnable suite — the worker never silently
    skips authorized work."""
    seen: set[TestSuite] = set()
    ordered: list[TestSuite] = []
    for raw in normalized_config.get("suites", []):
        try:
            suite = TestSuite(raw)
        except ValueError as exc:
            raise SuiteRunError(f"envelope names unknown suite {raw!r}") from exc
        if suite not in _SUITE_CLASSES:
            raise SuiteRunError(f"suite {suite.value} has no runner")
        if suite not in seen:
            seen.add(suite)
            ordered.append(suite)
    if not ordered:
        raise SuiteRunError("envelope configures no runnable suites")
    return ordered


async def run_llm_suites(
    sessionmaker: async_sessionmaker[AsyncSession],
    store: BlobStore,
    *,
    scan_id: uuid.UUID,
    now: datetime,
    cancel: CancelToken,
    resolve: DnsResolver = system_dns_resolver,
    secret_resolver: SecretResolver = env_secret_resolver,
    limiter: RateLimiter | None = None,
    provider_allowlist: frozenset[str] | None = None,
) -> RunOutcome:
    """Run every configured suite against the scan's target and persist findings.

    A completed run is `ok=True` regardless of how many attacks *succeeded* — a
    successful attack is a finding, not a run failure. A run the `CancelToken`
    halted mid-suite reports `ok=False, detail='cancelled'` so orchestration
    finalizes it `cancelled`.

    All target traffic routes through the engagement-aware `EgressShaper`
    (M2-SEC1): default-deny reachability + the engagement's aggregate
    `rate_limit_rps` ceiling shared across concurrent runs. `limiter` defaults to a
    `ValkeyEgressLimiter` (aggregate across worker processes); tests inject an
    in-process limiter."""
    settings = get_settings()
    if provider_allowlist is None:
        provider_allowlist = parse_provider_allowlist(settings.egress_provider_allowlist)
    # Load config + build the scope-validated connector. The target's transport
    # shape is snapshotted into the connector; the scope items are only read
    # lazily by the egress guard, so detach them (expunge) to keep them readable
    # after this session closes — the per-suite writes use fresh sessions.
    async with sessionmaker() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            raise SuiteRunError(f"scan {scan_id} missing")
        envelope = (
            await db.execute(
                select(ExecutionAuthorization).where(ExecutionAuthorization.scan_id == scan_id)
            )
        ).scalar_one_or_none()
        if envelope is None:
            raise SuiteRunError(f"execution envelope for scan {scan_id} missing")
        suites = suites_from_config(envelope.normalized_config)
        target = await db.get(Target, scan.target_id)
        if target is None:
            raise SuiteRunError(f"target {scan.target_id} missing")
        engagement = await db.get(Engagement, scan.engagement_id)
        if engagement is None:
            raise SuiteRunError(f"engagement {scan.engagement_id} missing")
        rate_limit_rps = engagement.rate_limit_rps
        scope_items = list(
            (
                await db.execute(
                    select(ScopeItem).where(ScopeItem.engagement_id == scan.engagement_id)
                )
            ).scalars()
        )
        engagement_id = scan.engagement_id
        db.expunge_all()

    # Build the egress limiter (owning a Valkey client only when one wasn't
    # injected). Fail-closed: a run cannot proceed without an enforceable ceiling.
    owned_cache: Redis | None = None
    if limiter is None:
        owned_cache = Redis.from_url(settings.cache_url)
        limiter = ValkeyEgressLimiter(owned_cache)
    shaper = EgressShaper(
        engagement_id=engagement_id,
        rate_limit_rps=rate_limit_rps,
        scope_items=scope_items,
        resolve=resolve,
        limiter=limiter,
        provider_allowlist=provider_allowlist,
    )
    connector = build_llm_target_connector(
        target, scope_items, resolve=resolve, secret_resolver=secret_resolver, gate=shaper
    )

    total_findings = 0
    cancelled = False
    try:
        for suite_enum in suites:
            if cancel.cancelled:
                cancelled = True
                break
            suite = _SUITE_CLASSES[suite_enum]()
            result = await suite.run(connector, cancel)  # type: ignore[attr-defined]
            total_findings += await _persist_suite_run(
                sessionmaker,
                store,
                scan_id=scan_id,
                engagement_id=engagement_id,
                suite_enum=suite_enum,
                result=result,
                now=now,
            )
            if result.cancelled:
                cancelled = True
                break
    finally:
        await connector.aclose()
        if owned_cache is not None:
            await owned_cache.aclose()

    if cancelled:
        return RunOutcome(ok=False, detail="cancelled")
    return RunOutcome(ok=True, detail=f"{total_findings} finding(s) across {len(suites)} suite(s)")


async def _persist_suite_run(
    sessionmaker: async_sessionmaker[AsyncSession],
    store: BlobStore,
    *,
    scan_id: uuid.UUID,
    engagement_id: uuid.UUID,
    suite_enum: TestSuite,
    result: SuiteResult,
    now: datetime,
) -> int:
    """Record one test_run and its findings in a single committed transaction.
    Returns the number of findings created/reused for the suite."""
    async with sessionmaker() as db:
        engagement = await db.get(Engagement, engagement_id)
        scan = await db.get(Scan, scan_id)
        target = await db.get(Target, scan.target_id)
        status = ScanStatus.CANCELLED if result.cancelled else ScanStatus.COMPLETED
        test_run = TestRun(
            scan_id=scan_id,
            suite=suite_enum,
            engine=result.engine,
            engine_version=result.engine_version,
            config={"bundle_id": result.bundle_id, "bundle_sha256": result.bundle_sha256},
            status=status,
            started_at=now,
            finished_at=now,
        )
        db.add(test_run)
        await db.flush()
        findings = await create_findings_from_suite(
            db,
            store,
            engagement=engagement,
            target=target,
            scan=scan,
            test_run=test_run,
            suite_result=result,
            now=now,
        )
        await db.commit()
        return len(findings)


def build_suite_owner(
    sessionmaker: async_sessionmaker[AsyncSession],
    store: BlobStore,
    *,
    scan_id: uuid.UUID,
    now: datetime | None = None,
    resolve: DnsResolver = system_dns_resolver,
    secret_resolver: SecretResolver = env_secret_resolver,
    limiter: RateLimiter | None = None,
    provider_allowlist: frozenset[str] | None = None,
) -> InProcessOwner:
    """The execution owner for an LLM-suite scan: an `InProcessOwner` that runs
    `run_llm_suites` under its cancel token. Orchestration launches it exactly like
    a subprocess scanner (M2-W1), and emergency stop (M2-W2) cancels it through the
    same token the suites check between prompts/turns. Target traffic is shaped by
    the engagement-aware egress choke point (M2-SEC1)."""
    stamp = now if now is not None else utcnow()

    def _run_fn(cancel: CancelToken) -> Awaitable[RunOutcome]:
        return run_llm_suites(
            sessionmaker,
            store,
            scan_id=scan_id,
            now=stamp,
            cancel=cancel,
            resolve=resolve,
            secret_resolver=secret_resolver,
            limiter=limiter,
            provider_allowlist=provider_allowlist,
        )

    return InProcessOwner(_run_fn)
