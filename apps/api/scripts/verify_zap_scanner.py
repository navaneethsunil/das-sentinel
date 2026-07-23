"""M3-W3 live proof: the ZAP adapter runs a real ZAP baseline scan end-to-end.

Runs against real Postgres + MinIO + a real digest-pinned ZAP daemon (the `zap`
compose service) scanning a deliberately-insecure web target (the `vuln-target`
service, sandbox/vuln_web.py). Drives a scanner scan the way a launched scan does:
launch_scan freezes an envelope naming the `zap` scanner, orchestrate_scan
re-derives + runs it through the real InProcessOwner → run_scanners → the
ApiScannerAdapter path → ZapScanner drives the ZAP API (access → spider → passive
drain → alerts) → normalize → findings.

Proves:
  1. a real ZAP scan finalizes COMPLETED via the framework (API-driven, no
     worker-side subprocess — os_process_group is NULL);
  2. the scanner_run records the real ZAP version + pinned image digest + the
     raw-evidence pointer;
  3. ZAP raised real passive alerts on the header-less target → automated/open
     findings carrying scanner_run_id + endpoint/method location, citing raw
     evidence (ZAP's own alerts JSON, hash-verified);
  4. the ZAP API key NEVER appears in scanner_runs.config or the raw evidence
     (TM-5 / TR-23);
  5. idempotent re-run reuses findings.

Run:
  docker compose --profile scanners up -d postgres valkey minio migrate zap vuln-target
  docker compose --profile scanners run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" \
    --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_zap_scanner.py"
"""

import asyncio
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta

import httpx
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
TARGET_URL = "http://vuln-target:8000"
failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


async def _wait_for_zap(settings) -> bool:  # noqa: ANN001
    """Poll the ZAP API until the daemon answers (it takes ~30s to boot)."""
    url = f"{settings.zap_api_url}/JSON/core/view/version/"
    params = {"apikey": settings.zap_api_key.get_secret_value()}
    async with httpx.AsyncClient(timeout=5.0) as c:
        for _ in range(60):
            try:
                r = await c.get(url, params=params)
                if r.status_code == 200 and "version" in r.json():
                    return True
            except (httpx.HTTPError, ValueError):
                pass
            await asyncio.sleep(2.0)
    return False


async def _seed(session, *, org_id, user_id):  # noqa: ANN001
    eng = Engagement(
        organization_id=org_id,
        name="w3-zap",
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
        matcher_type=ScopeMatcher.DOMAIN,
        value="vuln-target",
    )
    session.add(scope)
    await session.flush()
    target = Target(
        engagement_id=eng.id,
        name="vuln-web",
        target_type=TargetType.WEB_APP,
        primary_value=TARGET_URL,
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
            config={
                "scanners": ["zap"],
                "scanner_config": {"zap": {"spider_max_children": 3, "max_wait_s": 150}},
            },
        )
        await s.commit()
        return scan.id


async def _orchestrate(sm, store, scan_id) -> ScanStatus:  # noqa: ANN001
    owner = build_scanner_owner(sm, store, scan_id=scan_id, now=NOW, poll_s=0.5)
    return await orchestrate_scan(
        sm,
        scan_id=scan_id,
        owner=owner,
        now=NOW,
        cancel_poll_s=0.5,
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


async def _run(sm, store, *, org_id, user_id, api_key) -> None:  # noqa: ANN001, PLR0915
    async with sm() as s:
        eng_id, target_id = await _seed(s, org_id=org_id, user_id=user_id)
        await s.commit()
    scan_id = await _launch(sm, eng_id=eng_id, target_id=target_id, user_id=user_id)
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
        check("scanner is zap", sr.scanner_name == "zap")
        check("scanner_run COMPLETED", sr.status is ScanStatus.COMPLETED)
        check(
            "real ZAP version captured (from the live API)",
            bool(sr.scanner_version) and sr.scanner_version not in ("unknown", sr.image_digest),
        )
        check("pinned image digest recorded", (sr.image_digest or "").startswith("ghcr.io/zaproxy"))
        check(
            "config records zap_mode + base_url",
            sr.config.get("zap_mode") == "baseline" and bool(sr.config.get("base_url")),
        )
        check("API-driven: no worker-side process group", sr.os_process_group is None)
        check("raw_evidence_id set", sr.raw_evidence_id is not None)

        raw = (await load_evidence(s, store, sr.raw_evidence_id)).decode()
        check("raw evidence is ZAP alerts JSON (hash-verified)", "alerts" in json.loads(raw))

        # TM-5 / TR-23: the API key must never be persisted anywhere.
        check("API key NOT in scanner_run.config", api_key not in json.dumps(sr.config))
        check("API key NOT in raw evidence", api_key not in raw)

        findings = (
            (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )
        check("ZAP raised real passive alerts (>=1 finding)", len(findings) >= 1)
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
            "findings carry endpoint/method location + zap rule ids",
            all(f.location.get("url") and (f.rule_id or "").startswith("zap.") for f in findings),
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
    scan_id2 = await _launch(sm, eng_id=eng_id, target_id=target_id, user_id=user_id)
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
    api_key = settings.zap_api_key.get_secret_value()
    if not await _wait_for_zap(settings):
        print("FAIL: ZAP daemon did not become ready")
        return 1

    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    store = create_evidence_store(settings)
    store.ensure_bucket()

    async with sm() as s:
        org = Organization(name="verify-w3-org")
        s.add(org)
        await s.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-w3@example.com",
            password_hash=pw.hash("verify-w3-throwaway"),
            display_name="Verify W3",
            role=UserRole.TESTER,
        )
        s.add(user)
        await s.flush()
        user_id = user.id
        await s.commit()

    try:
        await _run(sm, store, org_id=org_id, user_id=user_id, api_key=api_key)
    finally:
        await _cleanup(sm, org_id)
        await engine.dispose()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
