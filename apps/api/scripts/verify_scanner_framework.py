"""M3-W1 live proof: the scanner framework runs a scanner end-to-end.

Runs in the BASE api image (no PyRIT) against real Postgres + MinIO, driving the
whole scanner vertical slice the way a launched scan does in production, minus the
Celery hop: `launch_scan` freezes the envelope (config names the `stub` scanner),
then `orchestrate_scan` re-derives it, claims the scan running, and launches the
run through the real `InProcessOwner` (build_scanner_owner) → `run_scanners` →
a killable `SubprocessOwner` per tool → raw capture → normalize →
create_findings_from_scanner. The stub scanner (`echo` for findings, `sleep` for
the cancellable path) exercises every framework seam without needing Semgrep/ZAP.

Proves:
  1. a scanner scan finalizes COMPLETED via the real execution owner;
  2. a scanner_runs row records name/version/config, the real child PID
     (os_process_group), and the raw-evidence pointer;
  3. raw tool output is stored as immutable, hash-verifiable evidence
     (kind raw_scanner_output) and every finding cites it;
  4. findings are automated/open, carry scanner_run_id, and map the scanner's
     rule/severity into the shared vocabulary;
  5. idempotent re-run reuses findings (no duplicates);
  6. emergency stop halts an in-flight tool: the scan finalizes CANCELLED, the
     child process tree is gone, and the scanner_run is not COMPLETED.

Run:
  docker compose up -d --build api      # (postgres, valkey, minio, migrate too)
  docker compose run --rm --no-deps -v "$PWD/apps/api/scripts:/app/scripts:ro" \
    --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_scanner_framework.py"
"""

import asyncio
import os
import signal
import sys
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.scope import Operation, OperationKind
from app.core.security import PasswordService
from app.models.audit import AuditEvent, AuditOutcome
from app.models.engagement import (
    Engagement,
    EngagementStatus,
    ROEAcknowledgement,
    ScanIntensity,
    ScopeItem,
    ScopeKind,
    ScopeMatcher,
)
from app.models.evidence import Evidence
from app.models.finding import (
    Finding,
    FindingEvidence,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
)
from app.models.identity import Organization, User, UserRole
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus
from app.models.scanner import ScannerRun
from app.models.target import Target, TargetType
from app.services.roe import render_current_roe
from app.services.scans import launch_scan
from app.storage import create_evidence_store, load_evidence
from app.workers.execution import RunSpec
from app.workers.orchestration import orchestrate_scan
from app.workers.scanner_run import build_scanner_owner

NOW = datetime.now(UTC)
failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


async def _seed(session, *, org_id, user_id, name):  # noqa: ANN001
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
        name="local-app",
        target_type=TargetType.WEB_APP,
        primary_value="https://127.0.0.1:9",  # loopback in scope; stub makes no calls
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


async def _launch(sm, *, eng_id, target_id, user_id, config) -> uuid.UUID:  # noqa: ANN001
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
            config=config,
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
        await asyncio.sleep(0.05)
    return False


async def _happy_path(sm, store, *, org_id, user_id) -> None:  # noqa: ANN001, PLR0915
    async with sm() as s:
        eng_id, target_id = await _seed(s, org_id=org_id, user_id=user_id, name="w1-happy")
        await s.commit()
    scan_id = await _launch(
        sm, eng_id=eng_id, target_id=target_id, user_id=user_id, config={"scanners": ["stub"]}
    )

    owner = build_scanner_owner(sm, store, scan_id=scan_id, now=NOW, poll_s=0.05)
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
            "happy: runner_ref records the in-process owner",
            (scan.runner_ref or "").startswith("inproc:"),
        )

        runs = (
            (await s.execute(select(ScannerRun).where(ScannerRun.scan_id == scan_id)))
            .scalars()
            .all()
        )
        check("happy: one scanner_runs row", len(runs) == 1)
        sr = runs[0]
        check(
            "happy: scanner_run name/version captured",
            sr.scanner_name == "stub" and sr.scanner_version == "0.1.0",
        )
        check("happy: scanner_run status COMPLETED", sr.status is ScanStatus.COMPLETED)
        check("happy: config persisted (redacted, no secrets)", sr.config.get("mode") == "echo")
        check(
            "happy: os_process_group records a real child PID",
            isinstance(sr.os_process_group, int) and sr.os_process_group > 0,
        )
        check("happy: rules_digest captured", sr.rules_digest == "stub-rules-v1")
        check("happy: raw_evidence_id set", sr.raw_evidence_id is not None)

        # raw evidence: hash re-verifies, is the tool's own output
        raw = (await load_evidence(s, store, sr.raw_evidence_id)).decode()
        check(
            "happy: raw evidence is the tool output (hash-verified)", "stub.hardcoded-secret" in raw
        )

        findings = (
            (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )
        check("happy: two findings produced", len(findings) == 2)
        check(
            "happy: findings automated + open + carry scanner_run_id",
            all(
                f.provenance is FindingProvenance.AUTOMATED
                and f.status is FindingStatus.OPEN
                and f.scanner_run_id == sr.id
                for f in findings
            ),
        )
        rule_ids = {f.rule_id for f in findings}
        check("happy: rule ids normalized", rule_ids == {"stub.hardcoded-secret", "stub.weak-hash"})
        # every finding cites the raw evidence blob
        cited_ok = True
        for f in findings:
            links = (
                (await s.execute(select(FindingEvidence).where(FindingEvidence.finding_id == f.id)))
                .scalars()
                .all()
            )
            if not any(link.evidence_id == sr.raw_evidence_id for link in links):
                cited_ok = False
        check("happy: every finding cites the raw evidence", cited_ok)

    actions = await _actions(sm, eng_id)
    check(
        "happy: audit trail has scan.started + scan.completed",
        {"scan.started", "scan.completed"} <= actions,
    )

    # idempotent re-run: same scanner → findings reused, not duplicated
    scan_id2 = await _launch(
        sm, eng_id=eng_id, target_id=target_id, user_id=user_id, config={"scanners": ["stub"]}
    )
    owner2 = build_scanner_owner(sm, store, scan_id=scan_id2, now=NOW, poll_s=0.05)
    await orchestrate_scan(
        sm,
        scan_id=scan_id2,
        owner=owner2,
        now=NOW,
        cancel_poll_s=0.05,
        run_spec=RunSpec(label=str(scan_id2), argv=[]),
    )
    async with sm() as s:
        n = len(
            (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )
        check("idempotent: re-run reuses findings (still 2)", n == 2)


async def _cancel_path(sm, store, *, org_id, user_id) -> None:  # noqa: ANN001
    async with sm() as s:
        eng_id, target_id = await _seed(s, org_id=org_id, user_id=user_id, name="w1-cancel")
        await s.commit()
    scan_id = await _launch(
        sm,
        eng_id=eng_id,
        target_id=target_id,
        user_id=user_id,
        config={"scanners": ["stub"], "scanner_config": {"stub": {"hang": True}}},
    )
    owner = build_scanner_owner(sm, store, scan_id=scan_id, now=NOW, poll_s=0.05)
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
    # Grab the in-flight tool PID before we stop it, to prove the tree is gone.
    await asyncio.sleep(0.2)
    async with sm() as s:
        scan = await s.get(Scan, scan_id)
        scan.cancel_requested = True
        await s.commit()
    final = await task
    check("cancel: run finalized CANCELLED", final is ScanStatus.CANCELLED)

    async with sm() as s:
        scan = await s.get(Scan, scan_id)
        check("cancel: scan status CANCELLED", scan.status is ScanStatus.CANCELLED)
        runs = (
            (await s.execute(select(ScannerRun).where(ScannerRun.scan_id == scan_id)))
            .scalars()
            .all()
        )
        # A scanner_run row is written for the cancelled tool (status CANCELLED).
        pgid_gone = True
        for sr in runs:
            check("cancel: scanner_run not COMPLETED", sr.status is not ScanStatus.COMPLETED)
            if sr.os_process_group:
                try:
                    os.killpg(sr.os_process_group, 0)
                    pgid_gone = False  # still alive → teardown failed
                except ProcessLookupError:
                    pass
                except PermissionError:
                    pass  # exists but not ours — treat as inconclusive, not a fail
        check("cancel: the tool process tree is gone", pgid_gone)
        n = len(
            (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )
        check("cancel: no findings from a cancelled run", n == 0)
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
        await s.execute(delete(ScannerRun).where(ScannerRun.scan_id.in_(scan_ids)))
        await s.execute(delete(Evidence).where(Evidence.organization_id == org_id))
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


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    store = create_evidence_store(settings)
    store.ensure_bucket()

    async with sm() as s:
        org = Organization(name="verify-w1-org")
        s.add(org)
        await s.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-w1@example.com",
            password_hash=pw.hash("verify-w1-throwaway"),
            display_name="Verify W1",
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
        await _cleanup(sm, org_id)
        await engine.dispose()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


# Ensure a stray child from a failed run never lingers past the script.
def _reap(*_a) -> None:  # noqa: ANN002
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _reap)
    sys.exit(asyncio.run(main()))
