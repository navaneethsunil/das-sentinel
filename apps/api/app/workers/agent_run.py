"""Run the agent-permission suite for one scan and persist findings (M5 worker-wiring).

The agent sibling of workers/suite_run.py. It turns a launched agent-permission
scan into evidence-backed findings: read the frozen envelope, build the
scope-validated HTTP connector to the AI_AGENT target (M2-B6, now accepting
AI_AGENT), drive the attack corpus through it under the owner's `CancelToken`
(app/agent/suite.py), and persist each crossed boundary as an `automated`,
LLM06/ASI02-mapped finding with its monitored transcript as evidence.

Unlike the PyRIT suites this needs no special image — the harness is pure Python +
httpx, so it runs on the base worker (the default `celery` queue). The fake tools
and default policy are baked in (app/agent/harness.py). `build_agent_owner` wraps
the run into the same `InProcessOwner` orchestration launches for any run, so
emergency stop (§2.10/§6a) trips the SAME token the suite checks between probes and
turns: a halted run finalizes `cancelled`, its completed findings committed.
"""

import uuid
from collections.abc import Awaitable
from datetime import datetime

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agent.harness import AGENT_TOOLS_DESCRIPTION, build_sandbox_tools, default_agent_policy
from app.agent.suite import AgentPermissionSuiteResult, run_agent_permission_suite
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
from app.services.agent_findings import create_findings_from_agent_suite
from app.storage.evidence import BlobStore
from app.workers.execution import CancelToken, InProcessOwner, RunOutcome

_AGENT_SUITE = TestSuite.AGENT_PERMISSION.value


class AgentRunError(Exception):
    """A precondition the agent run cannot proceed past (missing scan/envelope, or
    an envelope that does not configure the agent-permission suite)."""


async def run_agent_permission_scan(
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
    """Drive the attack corpus against the scan's agent target and persist findings.

    A completed run is `ok=True` regardless of how many probes *succeeded* — a
    crossed boundary is a finding, not a run failure. A run the `CancelToken`
    halted mid-corpus reports `ok=False, detail='cancelled'`. All target traffic
    routes through the engagement-aware `EgressShaper` (scope/SSRF + aggregate
    rate ceiling), exactly like the LLM suites."""
    settings = get_settings()
    if provider_allowlist is None:
        provider_allowlist = parse_provider_allowlist(settings.egress_provider_allowlist)
    async with sessionmaker() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            raise AgentRunError(f"scan {scan_id} missing")
        envelope = (
            await db.execute(
                select(ExecutionAuthorization).where(ExecutionAuthorization.scan_id == scan_id)
            )
        ).scalar_one_or_none()
        if envelope is None:
            raise AgentRunError(f"execution envelope for scan {scan_id} missing")
        if _AGENT_SUITE not in (envelope.normalized_config.get("suites") or []):
            raise AgentRunError(f"scan {scan_id} envelope does not configure the agent suite")
        target = await db.get(Target, scan.target_id)
        if target is None:
            raise AgentRunError(f"target {scan.target_id} missing")
        engagement = await db.get(Engagement, scan.engagement_id)
        if engagement is None:
            raise AgentRunError(f"engagement {scan.engagement_id} missing")
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

    registry, _tools = build_sandbox_tools()
    try:
        # A fresh conversation per probe (the corpus expects no shared state); each
        # conversation replays its own history to the target via the connector. The
        # suite calls this factory once per probe to get that probe's send fn.
        result = await run_agent_permission_suite(
            lambda: connector.open_conversation().send,
            default_agent_policy(),
            registry,
            tools_description=AGENT_TOOLS_DESCRIPTION,
            cancel=lambda: cancel.cancelled,
        )
        findings = await _persist_agent_run(
            sessionmaker,
            store,
            scan_id=scan_id,
            engagement_id=engagement_id,
            result=result,
            now=now,
        )
    finally:
        await connector.aclose()
        if owned_cache is not None:
            await owned_cache.aclose()

    if result.cancelled:
        return RunOutcome(ok=False, detail="cancelled")
    probes = len(result.probe_results)
    return RunOutcome(ok=True, detail=f"{findings} finding(s) across {probes} probe(s)")


async def _persist_agent_run(
    sessionmaker: async_sessionmaker[AsyncSession],
    store: BlobStore,
    *,
    scan_id: uuid.UUID,
    engagement_id: uuid.UUID,
    result: AgentPermissionSuiteResult,
    now: datetime,
) -> int:
    """Record one test_run for the whole corpus and its findings in a single
    committed transaction. Returns the number of findings created/reused."""
    async with sessionmaker() as db:
        engagement = await db.get(Engagement, engagement_id)
        scan = await db.get(Scan, scan_id)
        target = await db.get(Target, scan.target_id)
        status = ScanStatus.CANCELLED if result.cancelled else ScanStatus.COMPLETED
        test_run = TestRun(
            scan_id=scan_id,
            suite=TestSuite.AGENT_PERMISSION,
            engine="bespoke",
            config={"corpus": "default", "probes": len(result.probe_results)},
            status=status,
            started_at=now,
            finished_at=now,
        )
        db.add(test_run)
        await db.flush()
        findings = await create_findings_from_agent_suite(
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


def build_agent_owner(
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
    """The execution owner for an agent-permission scan: an `InProcessOwner` that
    runs the corpus under its cancel token. Orchestration launches it exactly like
    a scanner or LLM suite, and emergency stop cancels it through the same token
    the suite checks between probes/turns."""
    stamp = now if now is not None else utcnow()

    def _run_fn(cancel: CancelToken) -> Awaitable[RunOutcome]:
        return run_agent_permission_scan(
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
