"""T1 production-wiring live proof: a launched scan runs the REAL payload via
Celery routing to the tool-bearing worker (no /bin/true placeholder).

Runs in the base `api` image (it only enqueues + polls the DB). The running
`scanner-worker` (consuming the `scanners` queue) does the real semgrep work.

Scenario A (scanner routing → completion): set up an engagement + source_archive
  target with an uploaded archive, launch a scanner scan, enqueue it exactly as
  the API does — send_task("app.run_scan", queue="scanners") — and poll the DB
  until the scanner-worker runs it to COMPLETED with real findings.

Scenario B (redteam routing → isolation): launch an LLM-suite scan and enqueue it
  to the `redteam` queue (no redteam worker is up here). It must STAY QUEUED — the
  base/scanner workers consume other queues and never pick it up.

Run:
  DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose --profile scanners build scanner-worker
  docker compose up -d --build postgres valkey minio migrate api worker
  docker compose --profile scanners up -d scanner-worker
  docker compose run --rm --no-deps -v "$PWD/apps/api/scripts:/app/scripts:ro" \
    --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_t1_wiring.py"
"""

import asyncio
import io
import sys
import uuid
import zipfile
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.scope import Operation, OperationKind
from app.models.audit import AuditEvent
from app.models.engagement import (
    Engagement,
    EngagementStatus,
    ROEAcknowledgement,
    ScanIntensity,
    ScopeItem,
    ScopeKind,
    ScopeMatcher,
)
from app.models.evidence import Evidence, EvidenceKind
from app.models.finding import Finding, FindingEvidence, FindingStatusHistory
from app.models.identity import Organization, User, UserRole
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus
from app.models.scanner import ScannerRun
from app.models.target import Target, TargetType
from app.services.roe import render_current_roe
from app.services.scans import launch_scan
from app.storage import create_evidence_store, store_evidence
from app.workers.celery_app import celery_app

NOW = datetime.now(UTC)
failures: list[str] = []

VULN_PY = b"""\
import hashlib, subprocess


def weak(data, cmd):
    subprocess.run(cmd, shell=True)  # nosec - scan fodder, never executed
    return hashlib.md5(data).hexdigest()
"""


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app/vulnerable.py", VULN_PY)
    return buf.getvalue()


async def _seed(sm, store):  # noqa: ANN001
    org_id = uuid.uuid4()
    async with sm() as s:
        s.add(Organization(id=org_id, name=f"t1-org-{org_id.hex[:8]}"))
        user = User(
            organization_id=org_id,
            email=f"t1-{org_id.hex[:8]}@example.com",
            display_name="T1 Tester",
            password_hash="x",  # noqa: S106 - fixture user; it never authenticates
            role=UserRole.TESTER,
            is_active=True,
        )
        s.add(user)
        await s.flush()
        eng = Engagement(
            organization_id=org_id,
            name="T1 Wiring",
            client_system_name="t1",
            created_by=user.id,
            status=EngagementStatus.ACTIVE,
            test_window_start=NOW - timedelta(days=1),
            test_window_end=NOW + timedelta(days=1),
            rate_limit_rps=5,
            max_intensity=ScanIntensity.SAFE_ACTIVE,
            hosted_models_allowed=False,
        )
        s.add(eng)
        await s.flush()
        scope = [
            ScopeItem(
                engagement_id=eng.id,
                kind=ScopeKind.ALLOW,
                matcher_type=ScopeMatcher.DOMAIN,
                value="mock-llm.example.com",
            )
        ]
        s.add_all(scope)
        await s.flush()
        _, _, terms, content_hash = render_current_roe(eng, scope)
        s.add(
            ROEAcknowledgement(
                engagement_id=eng.id,
                accepted_by=user.id,
                accepted_at=NOW,
                roe_text="frozen",
                scope_snapshot=[],
                terms_snapshot=terms,
                content_hash=content_hash,
            )
        )
        evidence = await store_evidence(
            s,
            store,
            organization_id=org_id,
            content=_zip(),
            kind=EvidenceKind.SOURCE_ARCHIVE,
            content_type="application/zip",
        )
        archive_target = Target(
            engagement_id=eng.id,
            name="App source",
            target_type=TargetType.SOURCE_ARCHIVE,
            primary_value=evidence.object_key,
        )
        llm_target = Target(
            engagement_id=eng.id,
            name="Mock chatbot",
            target_type=TargetType.AI_CHATBOT,
            primary_value="https://mock-llm.example.com/v1/chat/completions",
            connector_config={"mode": "chat_messages"},
        )
        s.add_all([archive_target, llm_target])
        await s.commit()
        return {
            "org_id": org_id,
            "user_id": user.id,
            "eng_id": eng.id,
            "archive_target_id": archive_target.id,
            "llm_target_id": llm_target.id,
        }


async def _launch(sm, ctx, target_id, config):  # noqa: ANN001
    async with sm() as s:
        eng = await s.get(Engagement, ctx["eng_id"])
        target = await s.get(Target, target_id)
        scope_items = list(
            (
                await s.execute(select(ScopeItem).where(ScopeItem.engagement_id == ctx["eng_id"]))
            ).scalars()
        )
        roe_ack = (
            await s.execute(
                select(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id == ctx["eng_id"])
            )
        ).scalar_one()
        scan = await launch_scan(
            s,
            engagement=eng,
            target=target,
            scope_items=scope_items,
            op=Operation(target_id=target.id, kind=OperationKind.SAFE_ACTIVE_SCAN),
            roe_ack=roe_ack,
            initiated_by=ctx["user_id"],
            now=NOW,
            config=config,
        )
        await s.commit()
        return scan.id


async def _poll_status(sm, scan_id, want, timeout_s, interval_s=2.0):  # noqa: ANN001
    waited = 0.0
    while waited < timeout_s:
        async with sm() as s:
            scan = await s.get(Scan, scan_id)
            if scan.status is want:
                return scan.status
            if scan.status in (ScanStatus.FAILED, ScanStatus.CANCELLED, ScanStatus.COMPLETED):
                return scan.status  # terminal, won't change
        await asyncio.sleep(interval_s)
        waited += interval_s
    async with sm() as s:
        return (await s.get(Scan, scan_id)).status


async def _cleanup(sm, org_id):  # noqa: ANN001
    # Replica mode disables triggers AND FK enforcement, so delete order is free.
    async with sm() as s:
        await s.execute(text("SET session_replication_role = replica"))
        eng_ids = (
            (await s.execute(select(Engagement.id).where(Engagement.organization_id == org_id)))
            .scalars()
            .all()
        )
        if eng_ids:
            scan_ids = (
                (await s.execute(select(Scan.id).where(Scan.engagement_id.in_(eng_ids))))
                .scalars()
                .all()
            )
            finding_ids = (
                (await s.execute(select(Finding.id).where(Finding.engagement_id.in_(eng_ids))))
                .scalars()
                .all()
            )
            if finding_ids:
                await s.execute(
                    delete(FindingStatusHistory).where(
                        FindingStatusHistory.finding_id.in_(finding_ids)
                    )
                )
                await s.execute(
                    delete(FindingEvidence).where(FindingEvidence.finding_id.in_(finding_ids))
                )
            await s.execute(delete(Finding).where(Finding.engagement_id.in_(eng_ids)))
            if scan_ids:
                await s.execute(delete(ScannerRun).where(ScannerRun.scan_id.in_(scan_ids)))
                await s.execute(
                    delete(ExecutionAuthorization).where(
                        ExecutionAuthorization.scan_id.in_(scan_ids)
                    )
                )
            await s.execute(delete(Scan).where(Scan.engagement_id.in_(eng_ids)))
            await s.execute(delete(ScopeItem).where(ScopeItem.engagement_id.in_(eng_ids)))
            await s.execute(
                delete(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id.in_(eng_ids))
            )
            await s.execute(delete(Target).where(Target.engagement_id.in_(eng_ids)))
        await s.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        await s.execute(delete(Evidence).where(Evidence.organization_id == org_id))
        await s.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await s.execute(delete(User).where(User.organization_id == org_id))
        await s.execute(delete(Organization).where(Organization.id == org_id))
        await s.execute(text("SET session_replication_role = DEFAULT"))
        await s.commit()


async def main() -> int:
    settings = get_settings()
    store = create_evidence_store(settings)
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    ctx = await _seed(sm, store)
    try:
        # Scenario A: scanner scan routed to the scanners queue → real completion.
        scan_id = await _launch(sm, ctx, ctx["archive_target_id"], {"scanners": ["semgrep"]})
        async with sm() as s:
            check(
                "scanner scan starts QUEUED",
                (await s.get(Scan, scan_id)).status is ScanStatus.QUEUED,
            )
        celery_app.send_task("app.run_scan", args=[str(scan_id)], queue="scanners")
        status = await _poll_status(sm, scan_id, ScanStatus.COMPLETED, timeout_s=180)
        check(
            "scanner scan COMPLETED via the scanner-worker (real semgrep, not placeholder)",
            status is ScanStatus.COMPLETED,
        )
        async with sm() as s:
            sr = (
                await s.execute(select(ScannerRun).where(ScannerRun.scan_id == scan_id))
            ).scalar_one_or_none()
            check(
                "a semgrep scanner_run was recorded COMPLETED",
                sr is not None
                and sr.status is ScanStatus.COMPLETED
                and sr.scanner_name == "semgrep",
            )
            findings = (
                (await s.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
            )
            check("real findings produced (>=1)", len(findings) >= 1)

        # Scenario B: LLM-suite scan routed to redteam (no redteam worker) → stays QUEUED.
        llm_scan_id = await _launch(sm, ctx, ctx["llm_target_id"], {"suites": ["prompt_injection"]})
        celery_app.send_task("app.run_scan", args=[str(llm_scan_id)], queue="redteam")
        await asyncio.sleep(8)
        async with sm() as s:
            check(
                "LLM scan routed to redteam stays QUEUED (base/scanner workers do not grab it)",
                (await s.get(Scan, llm_scan_id)).status is ScanStatus.QUEUED,
            )
    finally:
        await _cleanup(sm, ctx["org_id"])
        await engine.dispose()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + '; '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
