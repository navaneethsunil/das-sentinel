"""M4 live proof: the Gitleaks adapter runs real gitleaks end-to-end.

Runs INSIDE the `scanners` image (real gitleaks 8.30.1) against real Postgres +
MinIO, driving a scanner scan the way a launched scan does: launch_scan freezes an
envelope naming the `gitleaks` scanner with a source_path pointing at a fixture
tree this script writes at runtime, orchestrate_scan re-derives + runs it through
the real InProcessOwner → run_scanners → a killable SubprocessOwner running the
actual `gitleaks dir --report-format json --redact` → raw capture → normalize →
findings.

The fixture's fake secret is assembled from string PARTS at runtime and written to
a /tmp file (never committed) so the repo's own gitleaks CI gate (full-history
scan) never sees a contiguous secret literal.

Proves:
  1. a real gitleaks scan finalizes COMPLETED via the framework;
  2. the scanner_run records the real gitleaks version + raw-evidence pointer, and
     config marks the run redacted;
  3. gitleaks found the planted secret → an automated/open HIGH finding carrying
     scanner_run_id + the gitleaks rule id, citing the raw evidence;
  4. the raw evidence is gitleaks' own JSON and the secret value is REDACTED in it
     (we detect, we do not harvest — §2.5);
  5. idempotent re-run reuses findings.

Run:
  DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose --profile scanners build scanner-worker
  docker compose up -d postgres valkey minio migrate
  docker compose --profile scanners run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" \
    --entrypoint sh scanner-worker \
    -c "cd /app && PYTHONPATH=/app python scripts/verify_gitleaks_scanner.py"
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
REPO_URL = "https://github.com/acme/leaky-sample"
# A fake GitHub PAT (gitleaks' github-pat rule detects it by pattern+entropy and,
# unlike the AWS docs "EXAMPLE" key, it is not allowlisted). Assembled from PARTS so
# no committed file (this script included) holds a contiguous secret the repo's own
# gitleaks CI gate would flag.
_FAKE_KEY = "ghp_" + "ABcd1234EFgh5678" + "IJkl9012MNop3456" + "QRst"
failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


def _write_fixture() -> str:
    """A throwaway source tree with a fake AWS key gitleaks' default ruleset flags.
    The key is built from parts so NO committed file (this script included) contains
    a contiguous secret the repo's own gitleaks CI gate would catch."""
    src = tempfile.mkdtemp(prefix="dass-leaky-")
    (Path(src) / "config.py").write_text(f'GITHUB_TOKEN = "{_FAKE_KEY}"\n')
    return src


async def _seed(session, *, org_id, user_id):  # noqa: ANN001
    eng = Engagement(
        organization_id=org_id,
        name="m4-gitleaks",
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
        name="leaky-sample",
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
                "scanners": ["gitleaks"],
                "scanner_config": {"gitleaks": {"source_path": source_path}},
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
        check("scanner is gitleaks", sr.scanner_name == "gitleaks")
        check(
            "real gitleaks version captured",
            bool(sr.scanner_version) and sr.scanner_version != "unknown",
        )
        check("scanner_run COMPLETED", sr.status is ScanStatus.COMPLETED)
        check("config records the run as redacted", sr.config.get("redacted") is True)
        check("raw_evidence_id set", sr.raw_evidence_id is not None)

        raw = (await load_evidence(s, store, sr.raw_evidence_id)).decode()
        parsed = json.loads(raw)
        check(
            "raw evidence is a gitleaks JSON array", isinstance(parsed, list) and len(parsed) >= 1
        )
        check(
            "raw evidence REDACTS the secret (detect, not harvest — §2.5)",
            all(entry.get("Secret") in ("REDACTED", "", None) for entry in parsed)
            and _FAKE_KEY not in raw,
        )

        findings = (
            (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )
        check("gitleaks found the planted secret (>=1 finding)", len(findings) >= 1)
        check(
            "findings automated + open + HIGH + carry scanner_run_id",
            all(
                f.provenance is FindingProvenance.AUTOMATED
                and f.status is FindingStatus.OPEN
                and f.severity.value == "high"
                and f.scanner_run_id == sr.id
                for f in findings
            ),
        )
        check(
            "findings carry a gitleaks rule id + file/line location",
            all(
                f.rule_id and f.location.get("file") and f.location.get("start_line")
                for f in findings
            ),
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
    source_path = _write_fixture()

    async with sm() as s:
        org = Organization(name="verify-gitleaks-org")
        s.add(org)
        await s.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-gitleaks@example.com",
            password_hash=pw.hash("verify-gitleaks-throwaway"),
            display_name="Verify Gitleaks",
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
