"""M3-T1 live proof: both real scanners end-to-end against OWASP Juice Shop.

The canonical per-scanner acceptance test. Runs INSIDE the `scanners` image (real
semgrep + httpx) against real Postgres + MinIO + a real digest-pinned ZAP daemon
(`zap`) and a real digest-pinned OWASP Juice Shop container (`juice-shop`). The
SAST source is the Juice Shop backend extracted from that same pinned image by
sandbox/extract_juice_shop_source.sh (mounted at /app/sandbox/juice-shop-src).

Proves, for BOTH scanners driven the way a launched scan is (launch_scan → freeze
envelope → orchestrate_scan → build_scanner_owner → run_scanners):
  A. SAST — Semgrep scans the Juice Shop source → COMPLETED, real findings with
     file+line locations in the Juice Shop source, each citing hash-verified raw
     evidence; the engagement rate-limit is carried onto the scanner run.
  B. DAST — a ZAP baseline scans the running Juice Shop → COMPLETED, passive
     findings with endpoint locations citing raw evidence; the ZAP API key is
     NEVER persisted (TM-5/TR-23).
  C. SCOPE ENFORCEMENT — launching either scanner against an out-of-scope target
     is refused by the keystone (ScopeViolation), before any tool runs.
  D. RATE-LIMIT — the engagement's aggregate rate_limit_rps reaches the adapter
     (recorded on the scanner run).
  E. CANCELLABLE — a running Semgrep scan, cancelled mid-flight, finalizes
     CANCELLED and its process tree is confirmed gone (§2.10).

Run (from the repo root):
  sh sandbox/extract_juice_shop_source.sh
  DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose --profile scanners build scanner-worker
  docker compose --profile scanners up -d postgres valkey minio migrate zap juice-shop
  docker compose --profile scanners run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" -v "$PWD/sandbox:/app/sandbox:ro" \
    --entrypoint sh scanner-worker \
    -c "cd /app && PYTHONPATH=/app python scripts/verify_t1_scanners.py"
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
from app.core.scope import Operation, OperationKind, ScopeViolation
from app.core.security import PasswordService
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
JUICE_URL = "http://juice-shop:3000"
SAST_SOURCE = "/app/sandbox/juice-shop-src"
REPO_ID = "https://github.com/juice-shop/juice-shop"
RATE = 4
failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


async def _wait_for_zap(settings) -> bool:  # noqa: ANN001
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


async def _wait_for_juice_shop() -> bool:
    """Gate the DAST scan on the target's health — Juice Shop boots slowly."""
    async with httpx.AsyncClient(timeout=5.0) as c:
        for _ in range(90):
            try:
                r = await c.get(f"{JUICE_URL}/", follow_redirects=True)
                if r.status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
            await asyncio.sleep(2.0)
    return False


async def _seed(session, *, org_id, user_id):  # noqa: ANN001
    eng = Engagement(
        organization_id=org_id,
        name="t1-juice-shop",
        client_system_name="OWASP Juice Shop",
        status=EngagementStatus.ACTIVE,
        test_window_start=NOW - timedelta(days=1),
        test_window_end=NOW + timedelta(days=1),
        rate_limit_rps=RATE,
        max_intensity=ScanIntensity.SAFE_ACTIVE,
        created_by=user_id,
    )
    session.add(eng)
    await session.flush()
    scope = [
        ScopeItem(
            engagement_id=eng.id,
            kind=ScopeKind.ALLOW,
            matcher_type=ScopeMatcher.REPO,
            value=REPO_ID,
        ),
        ScopeItem(
            engagement_id=eng.id,
            kind=ScopeKind.ALLOW,
            matcher_type=ScopeMatcher.DOMAIN,
            value="juice-shop",
        ),
    ]
    session.add_all(scope)
    await session.flush()

    def _target(name, ttype, value):  # noqa: ANN001
        t = Target(engagement_id=eng.id, name=name, target_type=ttype, primary_value=value)
        session.add(t)
        return t

    sast = _target("juice-shop-src", TargetType.SOURCE_REPO, REPO_ID)
    dast = _target("juice-shop-web", TargetType.WEB_APP, JUICE_URL)
    # out-of-scope targets for the scope-enforcement checks
    oos_repo = _target("oos-repo", TargetType.SOURCE_REPO, "https://github.com/evil/oos-repo")
    oos_web = _target("oos-web", TargetType.WEB_APP, "http://not-in-scope.example.com")
    await session.flush()

    _, _, terms, content_hash = render_current_roe(eng, scope)
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
    return {
        "eng_id": eng.id,
        "sast": sast.id,
        "dast": dast.id,
        "oos_repo": oos_repo.id,
        "oos_web": oos_web.id,
    }


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


async def _orchestrate(sm, store, scan_id, *, poll_s=0.5) -> ScanStatus:  # noqa: ANN001
    owner = build_scanner_owner(sm, store, scan_id=scan_id, now=NOW, poll_s=poll_s)
    return await orchestrate_scan(
        sm,
        scan_id=scan_id,
        owner=owner,
        now=NOW,
        cancel_poll_s=poll_s,
        run_spec=RunSpec(label=str(scan_id), argv=[]),
    )


SAST_CONFIG = {"scanners": ["semgrep"], "scanner_config": {"semgrep": {"source_path": SAST_SOURCE}}}
DAST_CONFIG = {
    "scanners": ["zap"],
    "scanner_config": {"zap": {"spider_max_children": 3, "max_wait_s": 150}},
}


async def _scanner_run(sm, scan_id):  # noqa: ANN001
    async with sm() as s:
        return (
            (await s.execute(select(ScannerRun).where(ScannerRun.scan_id == scan_id)))
            .scalars()
            .first()
        )


async def _findings(sm, eng_id):  # noqa: ANN001
    async with sm() as s:
        return (
            (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )


async def _cites_raw(sm, finding_id, evidence_id) -> bool:  # noqa: ANN001
    async with sm() as s:
        links = (
            (
                await s.execute(
                    select(FindingEvidence).where(FindingEvidence.finding_id == finding_id)
                )
            )
            .scalars()
            .all()
        )
    return any(link.evidence_id == evidence_id for link in links)


async def _part_a_sast(sm, store, ctx, user_id) -> None:  # noqa: ANN001, PLR0915
    scan_id = await _launch(
        sm, eng_id=ctx["eng_id"], target_id=ctx["sast"], user_id=user_id, config=SAST_CONFIG
    )
    final = await _orchestrate(sm, store, scan_id)
    check("A: SAST scan finalized COMPLETED", final is ScanStatus.COMPLETED)
    sr = await _scanner_run(sm, scan_id)
    check("A: semgrep scanner_run COMPLETED", sr and sr.status is ScanStatus.COMPLETED)
    check("A: real semgrep version captured", bool(sr and sr.scanner_version))
    check(
        "A: bundle sha + source + license recorded (provenance)",
        bool(sr and sr.rules_digest)
        and bool((sr.config or {}).get("rules_source"))
        and bool((sr.config or {}).get("rules_license"))
        and (sr.config or {}).get("rules_sha256") == sr.rules_digest,
    )
    check(
        "D: engagement rate-limit carried onto the scanner run",
        sr and sr.config.get("rate_limit_rps") == RATE,
    )
    check("A: raw_evidence_id set", sr and sr.raw_evidence_id is not None)
    async with sm() as s:
        raw = (await load_evidence(s, store, sr.raw_evidence_id)).decode()
    check(
        "A: raw evidence is semgrep JSON (hash-verified, has results)", "results" in json.loads(raw)
    )

    findings = await _findings(sm, ctx["eng_id"])
    check("A: Semgrep found real issues in Juice Shop (>=1 finding)", len(findings) >= 1)
    check(
        "A: findings automated + open + carry scanner_run_id",
        all(
            f.provenance is FindingProvenance.AUTOMATED
            and f.status is FindingStatus.OPEN
            and f.scanner_run_id == sr.id
            for f in findings
        ),
    )
    check(
        "A: findings carry file+line locations",
        all(f.location.get("file") and f.location.get("start_line") for f in findings),
    )
    cited = all([await _cites_raw(sm, f.id, sr.raw_evidence_id) for f in findings])
    check("A: every finding cites the raw evidence", cited)


async def _part_b_dast(sm, store, ctx, user_id, api_key) -> None:  # noqa: ANN001, PLR0915
    before = {f.id for f in await _findings(sm, ctx["eng_id"])}
    scan_id = await _launch(
        sm, eng_id=ctx["eng_id"], target_id=ctx["dast"], user_id=user_id, config=DAST_CONFIG
    )
    final = await _orchestrate(sm, store, scan_id)
    check("B: DAST scan finalized COMPLETED", final is ScanStatus.COMPLETED)
    sr = await _scanner_run(sm, scan_id)
    check("B: zap scanner_run COMPLETED", sr and sr.status is ScanStatus.COMPLETED)
    check(
        "B: pinned ZAP image digest recorded", (sr.image_digest or "").startswith("ghcr.io/zaproxy")
    )
    check("B: API-driven (no worker process group)", sr and sr.os_process_group is None)
    async with sm() as s:
        raw = (await load_evidence(s, store, sr.raw_evidence_id)).decode()
    check("B: raw evidence is ZAP alerts JSON (hash-verified)", "alerts" in json.loads(raw))
    check("B: ZAP API key NOT in scanner_run.config", api_key not in json.dumps(sr.config))
    check("B: ZAP API key NOT in raw evidence", api_key not in raw)

    zap_findings = [f for f in await _findings(sm, ctx["eng_id"]) if f.id not in before]
    check("B: ZAP raised passive alerts (>=1 new finding)", len(zap_findings) >= 1)
    check(
        "B: ZAP findings carry endpoint/method location + zap rule ids",
        all(f.location.get("url") and (f.rule_id or "").startswith("zap.") for f in zap_findings),
    )


async def _part_c_scope(sm, ctx, user_id) -> None:  # noqa: ANN001
    for label, target_id, config in (
        ("out-of-scope repo (SAST)", ctx["oos_repo"], SAST_CONFIG),
        ("out-of-scope web host (DAST)", ctx["oos_web"], DAST_CONFIG),
    ):
        blocked = False
        try:
            await _launch(
                sm, eng_id=ctx["eng_id"], target_id=target_id, user_id=user_id, config=config
            )
        except ScopeViolation as exc:
            blocked = exc.reason == "scope_violation"
        check(f"C: {label} refused by the scope keystone (scope_violation)", blocked)


async def _part_e_cancellable(sm, store, ctx, user_id) -> None:  # noqa: ANN001
    scan_id = await _launch(
        sm, eng_id=ctx["eng_id"], target_id=ctx["sast"], user_id=user_id, config=SAST_CONFIG
    )
    owner = build_scanner_owner(sm, store, scan_id=scan_id, now=NOW, poll_s=0.2)
    task = asyncio.ensure_future(
        orchestrate_scan(
            sm,
            scan_id=scan_id,
            owner=owner,
            now=NOW,
            cancel_poll_s=0.1,
            run_spec=RunSpec(label=str(scan_id), argv=[]),
        )
    )
    # Wait until the scan is claimed RUNNING (the semgrep child launches right
    # after), then request cancellation mid-flight. The inner semgrep subprocess's
    # PID group lives in-memory during the run (the scanner_run row is persisted
    # only at the end), so we don't observe it via the DB — instead we rely on the
    # framework's verified teardown: orchestrate only returns CANCELLED after the
    # SubprocessOwner SIGTERM/SIGKILLs the tool's process group AND confirms it is
    # gone (otherwise it surfaces an ExecutionTeardownError, not CANCELLED).
    running = False
    for _ in range(400):
        await asyncio.sleep(0.05)
        async with sm() as s:
            if (await s.get(Scan, scan_id)).status is ScanStatus.RUNNING:
                running = True
                break
    check("E: scan reached RUNNING (semgrep launched)", running)

    await asyncio.sleep(0.5)  # let semgrep get mid-scan before we pull the plug
    async with sm() as s:
        (await s.get(Scan, scan_id)).cancel_requested = True
        await s.commit()
    final = await task
    check(
        "E: cancelled mid-run scan finalizes CANCELLED (teardown confirmed the process tree gone)",
        final is ScanStatus.CANCELLED,
    )

    async with sm() as s:
        cancelled_findings = (
            (await s.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
        )
    check("E: cancelled scan persisted no findings", len(cancelled_findings) == 0)


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
        fids = (
            (await s.execute(select(Finding.id).where(Finding.engagement_id.in_(eng_ids))))
            .scalars()
            .all()
        )
        for table in (FindingEvidence, FindingStatusHistory):
            await s.execute(delete(table).where(table.finding_id.in_(fids)))
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


async def main() -> int:  # noqa: PLR0915
    settings = get_settings()
    api_key = settings.zap_api_key.get_secret_value()
    if not await _wait_for_juice_shop():
        print("FAIL: Juice Shop did not become ready")
        return 1
    if not await _wait_for_zap(settings):
        print("FAIL: ZAP daemon did not become ready")
        return 1

    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    store = create_evidence_store(settings)
    store.ensure_bucket()

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
        async with sm() as s:
            ctx = await _seed(s, org_id=org_id, user_id=user_id)
            await s.commit()
        await _part_a_sast(sm, store, ctx, user_id)
        await _part_b_dast(sm, store, ctx, user_id, api_key)
        await _part_c_scope(sm, ctx, user_id)
        await _part_e_cancellable(sm, store, ctx, user_id)
    finally:
        await _cleanup(sm, org_id)
        await engine.dispose()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
