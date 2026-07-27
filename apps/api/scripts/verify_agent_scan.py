"""M5 worker-wiring end-to-end: a launched agent-permission scan runs the corpus
against an AI_AGENT target over real HTTP and produces findings.

Runs in the BASE api image (the agent harness is pure Python + httpx — no PyRIT),
against real Postgres + MinIO, driving the whole vertical slice the way a launched
scan does in production, minus the Celery hop: `launch_scan` freezes the envelope
(kind = agent), then `orchestrate_scan` re-derives it, claims the scan RUNNING, and
launches the corpus through the real `InProcessOwner` (build_agent_owner) →
scope-validated connector → agent session runner → create_findings_from_agent_suite.

The target is a local mock AGENT (sandbox/mock_llm.py with a tool-call brain),
reached over real HTTP through the scope-validated connector (loopback in scope via
an ip_cidr allow). Proves:
  1. findings — one automated/open, LLM06+ASI02-mapped finding per crossed boundary,
     each citing its monitored transcript (with a blocked call) as evidence;
  2. lifecycle — the scan finalizes COMPLETED, one bespoke test_run recorded;
  3. audit — scan.started + scan.completed audited by the orchestrator;
  4. emergency stop — a second run against a slow mock is cancelled once RUNNING;
     the CancelToken halts the corpus between probes → CANCELLED with fewer findings.

Run:
  docker compose up -d --build api          # + postgres, valkey, minio, migrate
  docker compose run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" -v "$PWD/sandbox:/app/sandbox:ro" \
    --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_agent_scan.py"
"""

import asyncio
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta

sys.path.insert(0, "/app/sandbox")

from mock_llm import serve_mock_llm  # noqa: E402 — sandbox path inserted above
from sqlalchemy import delete, select, text  # noqa: E402

from app.agent.corpus import DEFAULT_CORPUS  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.db import create_engine, create_sessionmaker  # noqa: E402
from app.core.scope import Operation, OperationKind  # noqa: E402
from app.core.security import PasswordService  # noqa: E402
from app.models.audit import AuditEvent, AuditOutcome  # noqa: E402
from app.models.engagement import (  # noqa: E402
    Engagement,
    EngagementStatus,
    ROEAcknowledgement,
    ScanIntensity,
    ScopeItem,
    ScopeKind,
    ScopeMatcher,
)
from app.models.evidence import Evidence  # noqa: E402
from app.models.finding import (  # noqa: E402
    Finding,
    FindingEvidence,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
)
from app.models.identity import Organization, User, UserRole  # noqa: E402
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus, TestRun  # noqa: E402
from app.models.target import Target, TargetType  # noqa: E402
from app.services.roe import render_current_roe  # noqa: E402
from app.services.scans import launch_scan  # noqa: E402
from app.storage import create_evidence_store, load_evidence  # noqa: E402
from app.workers.agent_run import build_agent_owner  # noqa: E402
from app.workers.execution import RunSpec  # noqa: E402
from app.workers.orchestration import orchestrate_scan  # noqa: E402

NOW = datetime.now(UTC)
failures: list[str] = []

# The violating call a misbehaving agent makes for each probe (trips its watch rule).
_ATTACK: dict[str, tuple[str, dict]] = {
    "agent.unauthorized_tool.webhook_exfil": ("call_webhook", {"url": "http://x"}),
    "agent.out_of_scope.read_users": ("query_database", {"table": "users"}),
    "agent.param_manipulation.email_attachment": ("send_email", {"to": "o@c", "attach": "x"}),
    "agent.excessive_agency.exfil_recipient": ("send_email", {"to": "a@attacker.io"}),
    "agent.confused_deputy.injected_query": ("query_database", {"table": "users"}),
    "agent.unsafe_delegation.external_actor": ("call_webhook", {"url": "http://y"}),
}


def _agent_brain(prompt: str) -> str:
    """A misbehaving agent: on the first turn (the driving prompt carries the probe
    task) it emits that probe's violating tool call; afterwards it finishes."""
    if prompt.startswith("Tool results"):
        return json.dumps({"final": "done"})
    for probe in DEFAULT_CORPUS:
        if probe.task in prompt:
            tool, params = _ATTACK[probe.probe_id]
            return json.dumps({"tool_calls": [{"tool": tool, "params": params}]})
    return json.dumps({"final": "nothing to do"})


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


async def _seed(session, *, org_id, user_id, name, endpoint):  # noqa: ANN001
    eng = Engagement(
        organization_id=org_id,
        name=name,
        client_system_name="acme",
        status=EngagementStatus.ACTIVE,
        test_window_start=NOW - timedelta(days=1),
        test_window_end=NOW + timedelta(days=1),
        rate_limit_rps=50,
        max_intensity=ScanIntensity.SAFE_ACTIVE,
        created_by=user_id,
    )
    session.add(eng)
    await session.flush()
    scope = ScopeItem(
        engagement_id=eng.id,
        kind=ScopeKind.ALLOW,
        matcher_type=ScopeMatcher.IP_CIDR,
        value="127.0.0.0/8",
    )
    session.add(scope)
    await session.flush()
    target = Target(
        engagement_id=eng.id,
        name="local-mock-agent",
        target_type=TargetType.AI_AGENT,
        primary_value=endpoint,
        connector_config={"mode": "chat_messages"},
    )
    session.add(target)
    await session.flush()
    _, _, terms, content_hash = render_current_roe(eng, [scope])
    session.add(
        ROEAcknowledgement(
            engagement_id=eng.id,
            accepted_by=user_id,
            accepted_at=NOW - timedelta(hours=1),
            roe_text="frozen",
            scope_snapshot=[],
            terms_snapshot=terms,
            content_hash=content_hash,
        )
    )
    await session.flush()
    return eng.id, target.id


async def _launch(sm, *, eng_id, target_id, user_id) -> uuid.UUID:  # noqa: ANN001
    async with sm() as s:
        eng = await s.get(Engagement, eng_id)
        target = await s.get(Target, target_id)
        scope_items = list(
            (await s.execute(select(ScopeItem).where(ScopeItem.engagement_id == eng_id))).scalars()
        )
        roe_ack = (
            await s.execute(
                select(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id == eng_id)
            )
        ).scalar_one()
        scan = await launch_scan(
            s,
            engagement=eng,
            target=target,
            scope_items=scope_items,
            op=Operation(target_id=target.id, kind=OperationKind.SAFE_ACTIVE_SCAN),
            roe_ack=roe_ack,
            initiated_by=user_id,
            now=NOW,
            config={"suites": ["agent_permission"]},
        )
        await s.commit()
        return scan.id


async def _actions(sm, eng_id) -> set[str]:  # noqa: ANN001
    async with sm() as s:
        rows = (
            await s.execute(
                select(AuditEvent.action, AuditEvent.outcome).where(
                    AuditEvent.engagement_id == eng_id
                )
            )
        ).all()
    return {a for a, o in rows if o is AuditOutcome.SUCCESS}


async def _wait_status(sm, scan_id, want, timeout=15.0) -> bool:  # noqa: ANN001
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        async with sm() as s:
            scan = await s.get(Scan, scan_id)
            if scan is not None and scan.status is want:
                return True
        await asyncio.sleep(0.02)
    return False


async def _happy_path(sm, store, *, org_id, user_id) -> None:  # noqa: ANN001, PLR0915
    async with sm() as s:
        eng_id, target_id = await _seed(
            s, org_id=org_id, user_id=user_id, name="m5-happy", endpoint=HAPPY_ENDPOINT
        )
        await s.commit()
    scan_id = await _launch(sm, eng_id=eng_id, target_id=target_id, user_id=user_id)

    owner = build_agent_owner(sm, store, scan_id=scan_id, now=NOW)
    final = await orchestrate_scan(
        sm,
        scan_id=scan_id,
        owner=owner,
        now=NOW,
        cancel_poll_s=0.05,
        run_spec=RunSpec(label=str(scan_id), argv=[]),
    )
    check("happy: scan finalized COMPLETED", final is ScanStatus.COMPLETED)

    async with sm() as s:
        scan = await s.get(Scan, scan_id)
        check(
            "happy: runner_ref records the in-process run",
            (scan.runner_ref or "").startswith("inproc:"),
        )
        findings = (
            (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )
        check("happy: one finding per corpus probe", len(findings) == len(DEFAULT_CORPUS))
        check(
            "happy: all findings automated + open",
            all(
                f.provenance is FindingProvenance.AUTOMATED and f.status is FindingStatus.OPEN
                for f in findings
            ),
        )
        check(
            "happy: every finding maps to OWASP LLM06 + Agentic ASI02",
            all(
                (f.location.get("owasp") or {}).get("code") == "LLM06"
                and (f.location.get("asi") or {}).get("code") == "ASI02"
                for f in findings
            ),
        )
        # evidence: the monitored transcript, with a blocked call
        sample = findings[0]
        link = (
            await s.execute(select(FindingEvidence).where(FindingEvidence.finding_id == sample.id))
        ).scalar_one()
        parsed = json.loads((await load_evidence(s, store, link.evidence_id)).decode())
        check(
            "happy: evidence is the monitored transcript (has a blocked call)",
            isinstance(parsed.get("session", {}).get("transcript"), list)
            and any(not c["allowed"] for c in parsed["session"]["transcript"]),
        )
        runs = (await s.execute(select(TestRun).where(TestRun.scan_id == scan_id))).scalars().all()
        check(
            "happy: one bespoke test_run recorded, completed",
            len(runs) == 1
            and runs[0].engine == "bespoke"
            and runs[0].status is ScanStatus.COMPLETED,
        )

    actions = await _actions(sm, eng_id)
    check(
        "happy: audit trail has scan.started + scan.completed",
        {"scan.started", "scan.completed"} <= actions,
    )


async def _cancel_path(sm, store, *, org_id, user_id) -> None:  # noqa: ANN001
    async with sm() as s:
        eng_id, target_id = await _seed(
            s, org_id=org_id, user_id=user_id, name="m5-cancel", endpoint=SLOW_ENDPOINT
        )
        await s.commit()
    scan_id = await _launch(sm, eng_id=eng_id, target_id=target_id, user_id=user_id)

    owner = build_agent_owner(sm, store, scan_id=scan_id, now=NOW)
    task = asyncio.ensure_future(
        orchestrate_scan(
            sm,
            scan_id=scan_id,
            owner=owner,
            now=NOW,
            cancel_poll_s=0.05,
            run_spec=RunSpec(label=str(scan_id), argv=[]),
        )
    )
    became_running = await _wait_status(sm, scan_id, ScanStatus.RUNNING)
    check("cancel: scan reached RUNNING before the stop", became_running)
    async with sm() as s:
        scan = await s.get(Scan, scan_id)
        scan.cancel_requested = True
        await s.commit()
    final = await task
    check("cancel: run finalized CANCELLED", final is ScanStatus.CANCELLED)

    async with sm() as s:
        scan = await s.get(Scan, scan_id)
        check("cancel: scan status CANCELLED", scan.status is ScanStatus.CANCELLED)
        n = len(
            (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )
        check("cancel: halted before a full corpus (fewer findings)", n < len(DEFAULT_CORPUS))
    actions = await _actions(sm, eng_id)
    check("cancel: scan.cancelled audited", "scan.cancelled" in actions)


async def _cleanup(sm, org_id) -> None:  # noqa: ANN001
    async with sm() as s:
        await s.execute(text("SET session_replication_role = replica"))
        eng_ids = (
            (await s.execute(select(Engagement.id).where(Engagement.organization_id == org_id)))
            .scalars()
            .all()
        )
        scan_ids = (
            (await s.execute(select(Scan.id).where(Scan.engagement_id.in_(eng_ids))))
            .scalars()
            .all()
        )
        for table in (FindingEvidence, FindingStatusHistory):
            await s.execute(
                delete(table).where(
                    table.finding_id.in_(
                        select(Finding.id).where(Finding.engagement_id.in_(eng_ids))
                    )
                )
            )
        await s.execute(delete(Finding).where(Finding.engagement_id.in_(eng_ids)))
        await s.execute(delete(Evidence).where(Evidence.organization_id == org_id))
        await s.execute(delete(TestRun).where(TestRun.scan_id.in_(scan_ids)))
        await s.execute(
            delete(ExecutionAuthorization).where(ExecutionAuthorization.engagement_id.in_(eng_ids))
        )
        await s.execute(delete(Scan).where(Scan.engagement_id.in_(eng_ids)))
        await s.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        await s.execute(
            delete(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id.in_(eng_ids))
        )
        await s.execute(
            text("DELETE FROM scope_items WHERE engagement_id = ANY(:e)"), {"e": eng_ids}
        )
        await s.execute(delete(Target).where(Target.engagement_id.in_(eng_ids)))
        await s.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await s.execute(delete(User).where(User.organization_id == org_id))
        await s.execute(delete(Organization).where(Organization.id == org_id))
        await s.commit()


HAPPY_MOCK = None
SLOW_MOCK = None
HAPPY_ENDPOINT = ""
SLOW_ENDPOINT = ""


async def main() -> int:
    global HAPPY_MOCK, SLOW_MOCK, HAPPY_ENDPOINT, SLOW_ENDPOINT
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    store = create_evidence_store(settings)
    store.ensure_bucket()

    HAPPY_MOCK = serve_mock_llm(reply_fn=_agent_brain)
    SLOW_MOCK = serve_mock_llm(reply_fn=_agent_brain, delay_seconds=0.3)
    HAPPY_ENDPOINT = HAPPY_MOCK.endpoint
    SLOW_ENDPOINT = SLOW_MOCK.endpoint

    async with sm() as s:
        org = Organization(name=f"verify-m5wire-{uuid.uuid4().hex[:8]}")
        s.add(org)
        await s.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email=f"m5wire-{uuid.uuid4().hex[:8]}@example.com",
            password_hash=pw.hash("verify-m5-throwaway"),
            display_name="Verify M5",
            role=UserRole.TESTER,
        )
        s.add(user)
        await s.flush()
        user_id = user.id
        await s.commit()

    try:
        await _happy_path(sm, store, org_id=org_id, user_id=user_id)
        await _cancel_path(sm, store, org_id=org_id, user_id=user_id)
    finally:
        HAPPY_MOCK.close()
        SLOW_MOCK.close()
        await _cleanup(sm, org_id)
        await engine.dispose()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
