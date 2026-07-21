"""M2-T1 end-to-end: a launched scan runs the AI/LLM suites and produces findings.

Runs INSIDE the `redteam` image (real PyRIT 0.14.0) against real Postgres + MinIO,
driving the WHOLE vertical slice the way a launched scan does in production, minus
the Celery hop: `launch_scan` freezes the envelope, then `orchestrate_scan`
re-derives it, claims the scan running, and launches the suites through the real
`InProcessOwner` (build_suite_owner) — connector → PyRIT → create_findings_from_suite.
The target is the deliberately-vulnerable local mock LLM in `sandbox/mock_llm.py`,
reached over real HTTP/TCP through the scope-validated connector (loopback is in
scope via an ip_cidr allow).

Proves the M2-T1 acceptance criteria:
  1. findings with evidence — 10 automated/open findings; each transcript blob
     re-verifies its SHA-256 and carries the concrete leaked/echoed canary;
  2. pass/fail — a forged system-instruction override is refused, so it is NOT a
     finding (the deterministic detector adjudicated it a PASS);
  3. OWASP mapping — findings span LLM01 (injection) + LLM02/05/07/08 (leakage);
  4. audit trail — scan.started and scan.completed are audited by the orchestrator;
  5. cancellable — a second run against a slow mock is emergency-stopped once
     RUNNING; the CancelToken halts the in-process suite and the scan finalizes
     CANCELLED (audited), with fewer than a full run's findings.
  + the target credential is injected as a request header and never appears in any
    stored transcript (TM-5).

Run:
  DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose --profile redteam build redteam-worker
  docker compose up -d postgres valkey minio migrate
  docker compose --profile redteam run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" -v "$PWD/sandbox:/app/sandbox:ro" \
    --entrypoint sh redteam-worker \
    -c "cd /app && PYTHONPATH=/app python scripts/verify_e2e_llm_scan.py"
"""

import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta

sys.path.insert(0, "/app/sandbox")

from mock_llm import serve_mock_llm  # noqa: E402 — sandbox path inserted above
from sqlalchemy import delete, select, text  # noqa: E402

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
from app.models.scan import (  # noqa: E402
    ExecutionAuthorization,
    Scan,
    ScanStatus,
    TestRun,
)
from app.models.target import Target, TargetType  # noqa: E402
from app.services.roe import render_current_roe  # noqa: E402
from app.services.scans import launch_scan  # noqa: E402
from app.storage import create_evidence_store, load_evidence  # noqa: E402
from app.workers.execution import RunSpec  # noqa: E402
from app.workers.orchestration import orchestrate_scan  # noqa: E402
from app.workers.suite_run import build_suite_owner  # noqa: E402

NOW = datetime.now(UTC)
_TARGET_KEY_ENV = "MOCK_E2E_KEY"
_TARGET_SECRET = "local-e2e-key-do-not-log"  # noqa: S105 — test fixture, not a real credential
_FORGED_OVERRIDE_PROBE = "pi.instruction-hierarchy.system-override"

failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


async def _seed(session, *, org_id, user_id, name, endpoint):  # noqa: ANN001
    """Create an active, in-window engagement with loopback in scope, an ROE
    accepted, and a mock-LLM target with an auth reference."""
    eng = Engagement(
        organization_id=org_id,
        name=name,
        client_system_name="acme",
        status=EngagementStatus.ACTIVE,
        test_window_start=NOW - timedelta(days=1),
        test_window_end=NOW + timedelta(days=1),
        rate_limit_rps=5,
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
        name="local-mock-chatbot",
        target_type=TargetType.AI_CHATBOT,
        primary_value=endpoint,
        auth_config={"api_key_ref": f"env:{_TARGET_KEY_ENV}"},
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
    """Run the real launch path (scope gate → frozen envelope) for both suites."""
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
            config={"suites": ["prompt_injection", "data_leakage"]},
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
    """Poll until the scan reaches `want` (or timeout)."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        async with sm() as s:
            scan = await s.get(Scan, scan_id)
            if scan is not None and scan.status is want:
                return True
        await asyncio.sleep(0.05)
    return False


async def _happy_path(sm, store, *, org_id, user_id) -> None:  # noqa: ANN001, PLR0915
    async with sm() as s:
        eng_id, target_id = await _seed(
            s, org_id=org_id, user_id=user_id, name="t1-happy", endpoint=HAPPY_ENDPOINT
        )
        await s.commit()
    scan_id = await _launch(sm, eng_id=eng_id, target_id=target_id, user_id=user_id)

    owner = build_suite_owner(sm, store, scan_id=scan_id, now=NOW)
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
        check("happy: 10 findings produced (4 injection + 6 leakage)", len(findings) == 10)
        check(
            "happy: all findings automated + open",
            all(
                f.provenance is FindingProvenance.AUTOMATED and f.status is FindingStatus.OPEN
                for f in findings
            ),
        )
        codes = {f.location.get("owasp", {}).get("code") for f in findings}
        check(
            "happy: OWASP mapping spans LLM01 + LLM02/05/07/08",
            codes == {"LLM01", "LLM02", "LLM05", "LLM07", "LLM08"},
        )
        rule_ids = {f.rule_id for f in findings}
        check(
            "happy: forged system-override adjudicated PASS (no finding)",
            _FORGED_OVERRIDE_PROBE not in rule_ids,
        )

        # evidence: hash re-verifies, carries a canary, never the credential
        canary_seen = False
        secret_leaked = False
        for f in findings:
            links = (
                (await s.execute(select(FindingEvidence).where(FindingEvidence.finding_id == f.id)))
                .scalars()
                .all()
            )
            for link in links:
                blob = (await load_evidence(s, store, link.evidence_id)).decode()
                if "canary-canary-" in blob:
                    canary_seen = True
                if _TARGET_SECRET in blob:
                    secret_leaked = True
        check("happy: transcript evidence carries the concrete canary", canary_seen)
        check("happy: target credential never in stored transcripts (TM-5)", not secret_leaked)

        runs = (await s.execute(select(TestRun).where(TestRun.scan_id == scan_id))).scalars().all()
        check("happy: two test_runs recorded", len(runs) == 2)
        check(
            "happy: test_runs on PyRIT 0.14.0, completed",
            all(
                r.engine == "pyrit"
                and r.engine_version == "0.14.0"
                and r.status is ScanStatus.COMPLETED
                for r in runs
            ),
        )

    actions = await _actions(sm, eng_id)
    check(
        "happy: audit trail has scan.started + scan.completed",
        {"scan.started", "scan.completed"} <= actions,
    )
    check(
        "happy: connector injected the resolved credential header (TM-5)",
        bool(HAPPY_MOCK.seen_auth)
        and all(a == f"Bearer {_TARGET_SECRET}" for a in HAPPY_MOCK.seen_auth),
    )


async def _cancel_path(sm, store, *, org_id, user_id) -> None:  # noqa: ANN001
    async with sm() as s:
        eng_id, target_id = await _seed(
            s, org_id=org_id, user_id=user_id, name="t1-cancel", endpoint=SLOW_ENDPOINT
        )
        await s.commit()
    scan_id = await _launch(sm, eng_id=eng_id, target_id=target_id, user_id=user_id)

    owner = build_suite_owner(sm, store, scan_id=scan_id, now=NOW)
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
    # Wait until the run is actually RUNNING (past the pre-launch cancel check),
    # then request the emergency stop — this exercises the mid-flight halt.
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
        check("cancel: halted before a full run (fewer than 10 findings)", n < 10)
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
    os.environ[_TARGET_KEY_ENV] = _TARGET_SECRET
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    store = create_evidence_store(settings)
    store.ensure_bucket()

    HAPPY_MOCK = serve_mock_llm()
    SLOW_MOCK = serve_mock_llm(delay_seconds=0.4)
    HAPPY_ENDPOINT = HAPPY_MOCK.endpoint
    SLOW_ENDPOINT = SLOW_MOCK.endpoint

    async with sm() as s:
        org = Organization(name="verify-t1-org")
        s.add(org)
        await s.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-t1@example.com",
            password_hash=pw.hash("verify-t1-throwaway"),
            display_name="Verify T1",
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
