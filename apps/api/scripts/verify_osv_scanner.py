"""M4 live proof: the OSV-Scanner adapter runs real osv-scanner end-to-end.

Runs INSIDE the `scanners` image (real osv-scanner 2.4.0) against real Postgres +
MinIO, driving a scanner scan the way a launched scan does: launch_scan freezes an
envelope naming the `osv-scanner` scanner with a source_path pointing at a fixture
tree this script writes at runtime (a requirements.txt pinning long-known-
vulnerable PyPI packages), orchestrate_scan re-derives + runs it through the real
InProcessOwner → run_scanners → a killable SubprocessOwner running the actual
`osv-scanner scan source --format json --recursive` → raw capture → normalize →
findings.

NETWORK: osv-scanner looks up advisories against osv.dev (the same egress the
project's CI SCA gate uses), so this live proof needs outbound network.

Proves:
  1. a real osv-scanner scan finalizes COMPLETED via the framework;
  2. the scanner_run records the real osv-scanner version + raw-evidence pointer;
  3. osv-scanner reported the vulnerable deps → automated/open findings carrying
     scanner_run_id + advisory (CVE/GHSA) rule ids + package/version location,
     each citing the raw evidence;
  4. severities map from the group CVSS (>=1 High/Critical among the picks);
  5. idempotent re-run reuses findings.

Run:
  DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose --profile scanners build scanner-worker
  docker compose up -d postgres valkey minio migrate
  docker compose --profile scanners run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" \
    --entrypoint sh scanner-worker \
    -c "cd /app && PYTHONPATH=/app python scripts/verify_osv_scanner.py"
"""

import asyncio
import json
import sys
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
    Severity,
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
REPO_URL = "https://github.com/acme/vulnerable-deps"
# Long-known-vulnerable PyPI pins (real CVEs in the OSV database, incl. a Critical).
_REQUIREMENTS = "PyYAML==5.3.1\nrequests==2.19.1\nurllib3==1.24.1\n"
failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


def _write_fixture() -> str:
    src = tempfile.mkdtemp(prefix="dass-vulndeps-")
    (Path(src) / "requirements.txt").write_text(_REQUIREMENTS)
    return src


async def _seed(session, *, org_id, user_id):  # noqa: ANN001
    eng = Engagement(
        organization_id=org_id,
        name="m4-osv",
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
        matcher_type=ScopeMatcher.REPO,
        value=REPO_URL,
    )
    session.add(scope)
    await session.flush()
    target = Target(
        engagement_id=eng.id,
        name="vulnerable-deps",
        target_type=TargetType.SOURCE_REPO,
        primary_value=REPO_URL,  # scope-matched identifier; scanned path is source_path
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


async def _launch(sm, *, eng_id, target_id, user_id, source_path) -> uuid.UUID:  # noqa: ANN001
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
            config={
                "scanners": ["osv-scanner"],
                "scanner_config": {"osv-scanner": {"source_path": source_path}},
            },
        )
        await s.commit()
        return scan.id


async def _orchestrate(sm, store, scan_id) -> ScanStatus:  # noqa: ANN001
    owner = build_scanner_owner(sm, store, scan_id=scan_id, now=NOW, poll_s=0.1)
    return await orchestrate_scan(
        sm,
        scan_id=scan_id,
        owner=owner,
        now=NOW,
        cancel_poll_s=0.1,
        run_spec=RunSpec(label=str(scan_id), argv=[]),
    )


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


async def _run(sm, store, *, org_id, user_id, source_path) -> None:  # noqa: ANN001, PLR0915
    async with sm() as s:
        eng_id, target_id = await _seed(s, org_id=org_id, user_id=user_id)
        await s.commit()
    scan_id = await _launch(
        sm, eng_id=eng_id, target_id=target_id, user_id=user_id, source_path=source_path
    )
    final = await _orchestrate(sm, store, scan_id)
    check("scan finalized COMPLETED", final is ScanStatus.COMPLETED)

    async with sm() as s:
        runs = (
            (await s.execute(select(ScannerRun).where(ScannerRun.scan_id == scan_id)))
            .scalars()
            .all()
        )
        check("one scanner_runs row", len(runs) == 1)
        sr = runs[0]
        check("scanner is osv-scanner", sr.scanner_name == "osv-scanner")
        check(
            "real osv-scanner version captured",
            bool(sr.scanner_version) and sr.scanner_version != "unknown",
        )
        check("scanner_run COMPLETED", sr.status is ScanStatus.COMPLETED)
        check("config records the online OSV database", "osv.dev" in str(sr.config.get("database")))
        check("raw_evidence_id set", sr.raw_evidence_id is not None)

        raw = (await load_evidence(s, store, sr.raw_evidence_id)).decode()
        parsed = json.loads(raw)
        check("raw evidence is osv-scanner JSON (has results)", "results" in parsed)

        findings = (
            (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )
        check("osv-scanner reported vulnerable deps (>=1 finding)", len(findings) >= 1)
        check(
            "findings automated + open + carry scanner_run_id",
            all(
                f.provenance is FindingProvenance.AUTOMATED
                and f.status is FindingStatus.OPEN
                and f.scanner_run_id == sr.id
                for f in findings
            ),
        )
        check(
            "findings carry advisory rule ids + package/version location",
            all(
                "-" in (f.rule_id or "")
                and f.location.get("package")
                and f.location.get("version")
                and f.location.get("ecosystem")
                for f in findings
            ),
        )
        check(
            "at least one High/Critical severity mapped from CVSS",
            any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings),
        )
        cited_ok = True
        for f in findings:
            links = (
                (await s.execute(select(FindingEvidence).where(FindingEvidence.finding_id == f.id)))
                .scalars()
                .all()
            )
            if not any(link.evidence_id == sr.raw_evidence_id for link in links):
                cited_ok = False
        check("every finding cites the raw evidence", cited_ok)
        first_count = len(findings)

    actions = await _actions(sm, eng_id)
    check(
        "audit trail has scan.started + scan.completed",
        {"scan.started", "scan.completed"} <= actions,
    )

    # idempotent re-run
    scan_id2 = await _launch(
        sm, eng_id=eng_id, target_id=target_id, user_id=user_id, source_path=source_path
    )
    await _orchestrate(sm, store, scan_id2)
    async with sm() as s:
        n = len(
            (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )
        check("idempotent: re-run reuses findings (count unchanged)", n == first_count)


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
        await s.execute(
            delete(FindingEvidence).where(
                FindingEvidence.finding_id.in_(
                    select(Finding.id).where(Finding.engagement_id.in_(eng_ids))
                )
            )
        )
        await s.execute(
            text(
                "DELETE FROM finding_status_history WHERE finding_id IN "
                "(SELECT id FROM findings WHERE engagement_id = ANY(:e))"
            ),
            {"e": eng_ids},
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
    source_path = _write_fixture()

    async with sm() as s:
        org = Organization(name="verify-osv-org")
        s.add(org)
        await s.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-osv@example.com",
            password_hash=pw.hash("verify-osv-throwaway"),
            display_name="Verify OSV",
            role=UserRole.TESTER,
        )
        s.add(user)
        await s.flush()
        user_id = user.id
        await s.commit()

    try:
        await _run(sm, store, org_id=org_id, user_id=user_id, source_path=source_path)
    finally:
        await _cleanup(sm, org_id)
        await engine.dispose()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
