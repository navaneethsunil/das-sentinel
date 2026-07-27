"""M4 live proof: deterministic scan-plan generation against real Postgres.

Runs in the BASE api image. Seeds a WEB_APP target with recon findings (httpx
technologies + katana endpoints) and a COMPLETED httpx scanner_run, then calls
scan_plan_for_target and asserts the deterministic plan:

  - recon signals are read back (detected technologies, endpoint count);
  - the WEB_APP plan is recon-first then DAST (httpx, katana, nuclei, zap);
  - the already-run httpx scan is flagged already_run; the rest are not;
  - the nuclei rationale is refined by the recon signals;
  - a SOURCE target yields the SAST/SCA/secrets plan instead.

Run:
  docker compose up -d --build api          # + postgres, valkey, minio, migrate
  docker compose run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_scan_plan.py"
"""

import asyncio
import sys
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.models.engagement import Engagement, EngagementStatus, ScanIntensity
from app.models.finding import (
    Finding,
    FindingProvenance,
    FindingStatus,
    SarifLevel,
    Severity,
)
from app.models.identity import Organization, User, UserRole
from app.models.scan import Scan, ScanStatus
from app.models.scanner import ScannerRun
from app.models.target import Target, TargetType
from app.services.finding_hash import PF_FINGERPRINT, PF_SOURCE, compute_hash_code
from app.services.scan_plan import scan_plan_for_target

NOW = datetime.now(UTC)
failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


def _recon_finding(eng_id, tgt_id, *, source, rule_id, fp, location) -> Finding:  # noqa: ANN001
    return Finding(
        engagement_id=eng_id,
        target_id=tgt_id,
        rule_id=rule_id,
        title=rule_id,
        message=f"{source} {rule_id}",
        sarif_level=SarifLevel.NONE,
        location=location,
        severity=Severity.INFORMATIONAL,
        provenance=FindingProvenance.AUTOMATED,
        status=FindingStatus.OPEN,
        hash_code=compute_hash_code(eng_id, tgt_id, source, fp),
        partial_fingerprints={PF_SOURCE: source, PF_FINGERPRINT: fp},
        created_at=NOW,
        updated_at=NOW,
    )


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    pw = PasswordService(settings.password_hash_scheme)

    async with sm() as s:
        org = Organization(name=f"verify-scanplan-{uuid.uuid4().hex[:8]}")
        s.add(org)
        await s.flush()
        org_id = org.id
        user = User(
            organization_id=org.id,
            email=f"scanplan-{uuid.uuid4().hex[:8]}@example.com",
            password_hash=pw.hash("x-throwaway"),
            display_name="sp",
            role=UserRole.TESTER,
        )
        s.add(user)
        await s.flush()
        eng = Engagement(
            organization_id=org.id,
            created_by=user.id,
            name="m4-scanplan",
            client_system_name="acme",
            status=EngagementStatus.ACTIVE,
            test_window_start=NOW - timedelta(days=1),
            test_window_end=NOW + timedelta(days=1),
            rate_limit_rps=5,
            max_intensity=ScanIntensity.SAFE_ACTIVE,
        )
        s.add(eng)
        await s.flush()
        eng_id = eng.id
        web = Target(
            engagement_id=eng.id,
            name="web",
            target_type=TargetType.WEB_APP,
            primary_value="http://vuln-target:8000",
        )
        src = Target(
            engagement_id=eng.id,
            name="src",
            target_type=TargetType.SOURCE_REPO,
            primary_value="https://github.com/acme/repo",
        )
        s.add_all([web, src])
        await s.flush()

        # Recon findings on the WEB target: 2 techs (one duplicated), 3 endpoints.
        for tech in ("nginx", "PHP", "nginx"):
            s.add(
                _recon_finding(
                    eng_id,
                    web.id,
                    source="httpx",
                    rule_id="httpx-tech",
                    fp=f"tech:{tech}",
                    location={"technology": tech},
                )
            )
        for path in ("/", "/login", "/account"):
            s.add(
                _recon_finding(
                    eng_id,
                    web.id,
                    source="katana",
                    rule_id="katana-endpoint",
                    fp=f"GET:{path}",
                    location={"url": f"http://vuln-target:8000{path}"},
                )
            )
        s.add(
            _recon_finding(
                eng_id,
                web.id,
                source="httpx",
                rule_id="httpx-fingerprint",
                fp="fingerprint",
                location={"url": "http://vuln-target:8000", "webserver": "x"},
            )
        )
        await s.flush()

        # A COMPLETED httpx scan of the web target → httpx should read already_run.
        scan = Scan(
            engagement_id=eng.id,
            target_id=web.id,
            intensity=ScanIntensity.SAFE_ACTIVE,
            status=ScanStatus.COMPLETED,
            initiated_by=user.id,
        )
        s.add(scan)
        await s.flush()
        s.add(
            ScannerRun(
                scan_id=scan.id,
                scanner_name="httpx",
                scanner_version="v1.10.0",
                config={},
                status=ScanStatus.COMPLETED,
                started_at=NOW,
                finished_at=NOW,
            )
        )
        await s.flush()

        # ── WEB target plan ──
        plan = await scan_plan_for_target(s, eng_id, web)
        check("target_type is web_app", plan.target_type == "web_app")
        check(
            "detected technologies read back (sorted, deduped)",
            plan.detected_technologies == ["PHP", "nginx"],
        )
        check("endpoints_discovered counted", plan.endpoints_discovered == 3)
        scanners = [r.scanner for r in plan.recommendations]
        check("web plan is recon-first then DAST", scanners == ["httpx", "katana", "nuclei", "zap"])
        by = {r.scanner: r for r in plan.recommendations}
        check("completed httpx scan flagged already_run", by["httpx"].already_run is True)
        check(
            "not-yet-run scanners flagged not already_run",
            not by["katana"].already_run
            and not by["nuclei"].already_run
            and not by["zap"].already_run,
        )
        check(
            "nuclei rationale refined by recon signals",
            "3 endpoint(s) mapped by recon" in by["nuclei"].reason
            and "Recon detected: PHP, nginx" in by["nuclei"].reason,
        )

        # ── SOURCE target plan ──
        src_plan = await scan_plan_for_target(s, eng_id, src)
        check(
            "source plan is SAST/secrets/SCA",
            [r.scanner for r in src_plan.recommendations] == ["semgrep", "gitleaks", "osv-scanner"],
        )
        check(
            "source plan has no recon signals + nothing run",
            src_plan.endpoints_discovered == 0
            and src_plan.detected_technologies == []
            and all(not r.already_run for r in src_plan.recommendations),
        )

        # cleanup (findings/scanner_runs are insert-only via triggers).
        await s.execute(text("SET session_replication_role = replica"))
        await s.execute(
            text(
                "DELETE FROM finding_status_history WHERE finding_id IN "
                "(SELECT id FROM findings WHERE engagement_id = :e)"
            ),
            {"e": eng_id},
        )
        await s.execute(delete(Finding).where(Finding.engagement_id == eng_id))
        await s.execute(
            delete(ScannerRun).where(
                ScannerRun.scan_id.in_(select(Scan.id).where(Scan.engagement_id == eng_id))
            )
        )
        await s.execute(delete(Scan).where(Scan.engagement_id == eng_id))
        await s.execute(delete(Target).where(Target.engagement_id == eng_id))
        await s.execute(delete(Engagement).where(Engagement.id == eng_id))
        await s.execute(delete(User).where(User.organization_id == org_id))
        await s.execute(delete(Organization).where(Organization.id == org_id))
        await s.commit()

    await engine.dispose()
    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
