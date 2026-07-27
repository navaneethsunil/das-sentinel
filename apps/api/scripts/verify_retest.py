"""M4-B3 live proof: reimport/retest reconciliation against real Postgres.

Runs in the BASE api image against real Postgres (exercises the JSONB per-source
scoping and the retests insert-only trigger — the parts the infra-free unit test
in tests/test_retest.py can't cover). Seeds findings for one target and drives
reconcile_reimport directly:

  - an ACTIVE finding absent from a rescan auto-mitigates (open→mitigated), with an
    automated (changed_by NULL) finding_status_history row;
  - a MITIGATED finding that reappears auto-reopens (mitigated→open), audited;
  - a present ACTIVE finding is a no-op; automation never writes `fixed`;
  - a human FALSE_POSITIVE finding is never touched and gets no retest;
  - reconciliation is scoped by source: a different scanner's finding is untouched;
  - findings carrying a remediation get a `retests` row (resolved when absent,
    still_present when present) linked to the remediation + rescan;
  - the retests table is insert-only (UPDATE raises — TM-9).

Run:
  docker compose up -d --build api          # + postgres, valkey, migrate
  docker compose run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_retest.py"
"""

import asyncio
import sys
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.models.engagement import Engagement, EngagementStatus, ScanIntensity
from app.models.finding import (
    Finding,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
    SarifLevel,
    Severity,
)
from app.models.identity import Organization, User, UserRole
from app.models.remediation import Remediation, Retest, RetestResult
from app.models.scan import Scan, ScanStatus
from app.models.target import Target, TargetType
from app.services.finding_hash import PF_FINGERPRINT, PF_SOURCE, compute_hash_code
from app.services.retest import reconcile_reimport

NOW = datetime.now(UTC)
failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


def _finding(eng_id, tgt_id, *, source, fp, status) -> Finding:  # noqa: ANN001
    return Finding(
        engagement_id=eng_id,
        target_id=tgt_id,
        rule_id=fp,
        title=fp,
        message=f"{source} {fp}",
        sarif_level=SarifLevel.ERROR,
        location={"file": "pkg/x.py", "start_line": 1},
        severity=Severity.HIGH,
        provenance=FindingProvenance.AUTOMATED,
        status=status,
        hash_code=compute_hash_code(eng_id, tgt_id, source, fp),
        partial_fingerprints={PF_SOURCE: source, PF_FINGERPRINT: fp},
        created_at=NOW,
        updated_at=NOW,
    )


async def _latest_status(s, finding_id) -> FindingStatus:  # noqa: ANN001
    return (await s.get(Finding, finding_id)).status


async def _retest_count(s, finding_id) -> int:  # noqa: ANN001
    return (
        await s.execute(
            select(func.count()).select_from(Retest).where(Retest.finding_id == finding_id)
        )
    ).scalar_one()


async def main() -> None:
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)

    pw = PasswordService(settings.password_hash_scheme)
    async with sm() as s:
        org = Organization(name=f"verify-retest-{uuid.uuid4().hex[:8]}")
        s.add(org)
        await s.flush()
        tester = User(
            organization_id=org.id,
            email=f"tester-{uuid.uuid4().hex[:8]}@verify-retest.example.com",
            password_hash=pw.hash("x-throwaway"),
            display_name="tester",
            role=UserRole.TESTER,
        )
        s.add(tester)
        await s.flush()
        eng = Engagement(
            organization_id=org.id,
            created_by=tester.id,
            name="m4-b3-retest",
            client_system_name="acme",
            status=EngagementStatus.ACTIVE,
            test_window_start=NOW - timedelta(days=1),
            test_window_end=NOW + timedelta(days=1),
            rate_limit_rps=5,
            max_intensity=ScanIntensity.SAFE_ACTIVE,
        )
        s.add(eng)
        await s.flush()
        target = Target(
            engagement_id=eng.id,
            name="t",
            target_type=TargetType.SOURCE_ARCHIVE,
            primary_value="sha256/seed",
        )
        s.add(target)
        await s.flush()
        eng_id, org_id = eng.id, org.id  # plain values — survive commit/rollback expiry

        # semgrep population: f1 (present later), f2 (absent later), fp (human FP)
        f1 = _finding(
            eng.id, target.id, source="semgrep", fp="semgrep:a", status=FindingStatus.OPEN
        )
        f2 = _finding(
            eng.id, target.id, source="semgrep", fp="semgrep:b", status=FindingStatus.OPEN
        )
        fp = _finding(
            eng.id, target.id, source="semgrep", fp="semgrep:c", status=FindingStatus.FALSE_POSITIVE
        )
        # a different scanner's finding — must be untouched by a semgrep reconcile
        zap = _finding(eng.id, target.id, source="zap", fp="zap:z", status=FindingStatus.OPEN)
        s.add_all([f1, f2, fp, zap])
        await s.flush()
        for f in (f1, f2, fp, zap):
            s.add(Remediation(finding_id=f.id, guidance_text="fix it", is_ai_generated=True))
        await s.flush()

        def _scan() -> Scan:
            sc = Scan(
                engagement_id=eng.id,
                target_id=target.id,
                intensity=ScanIntensity.SAFE_ACTIVE,
                status=ScanStatus.COMPLETED,
                initiated_by=tester.id,
            )
            s.add(sc)
            return sc

        scan1, scan2 = _scan(), _scan()
        await s.flush()
        rescan1 = scan1.id
        # Round 1: only f1 observed. f2 + fp absent; zap out of source scope.
        await reconcile_reimport(
            s,
            engagement=eng,
            target=target,
            source="semgrep",
            observed_hashes={f1.hash_code},
            rescan_scan_id=rescan1,
            now=NOW,
        )
        check(
            "present active finding stays open",
            await _latest_status(s, f1.id) is FindingStatus.OPEN,
        )
        check(
            "absent active finding auto-mitigates",
            await _latest_status(s, f2.id) is FindingStatus.MITIGATED,
        )
        check(
            "human false_positive untouched",
            await _latest_status(s, fp.id) is FindingStatus.FALSE_POSITIVE,
        )
        check(
            "out-of-source finding untouched", await _latest_status(s, zap.id) is FindingStatus.OPEN
        )

        # Automated mitigate is audited with changed_by NULL.
        hist = (
            (
                await s.execute(
                    select(FindingStatusHistory).where(
                        FindingStatusHistory.finding_id == f2.id,
                        FindingStatusHistory.to_status == FindingStatus.MITIGATED,
                    )
                )
            )
            .scalars()
            .all()
        )
        check(
            "auto-mitigate writes one automated history row",
            len(hist) == 1
            and hist[0].changed_by is None
            and hist[0].from_status is FindingStatus.OPEN,
        )

        # Retests: f1 still_present, f2 resolved; FP excluded (human-terminal).
        r_f2 = (await s.execute(select(Retest).where(Retest.finding_id == f2.id))).scalars().all()
        check(
            "absent finding retest = resolved",
            len(r_f2) == 1 and r_f2[0].result is RetestResult.RESOLVED,
        )
        check(
            "resolved retest links a remediation",
            r_f2[0].remediation_id is not None and r_f2[0].rescan_scan_id == rescan1,
        )
        r_f1 = (await s.execute(select(Retest).where(Retest.finding_id == f1.id))).scalars().all()
        check(
            "present finding retest = still_present",
            len(r_f1) == 1 and r_f1[0].result is RetestResult.STILL_PRESENT,
        )
        check("false_positive gets no retest", await _retest_count(s, fp.id) == 0)

        # Round 2: f2 reappears → auto-reopen.
        rescan2 = scan2.id
        await reconcile_reimport(
            s,
            engagement=eng,
            target=target,
            source="semgrep",
            observed_hashes={f1.hash_code, f2.hash_code},
            rescan_scan_id=rescan2,
            now=NOW,
        )
        check(
            "reappearing mitigated finding auto-reopens",
            await _latest_status(s, f2.id) is FindingStatus.OPEN,
        )
        check("reopen recorded a second retest (still_present)", await _retest_count(s, f2.id) == 2)

        # Automation never writes `fixed` anywhere.
        fixed_rows = (
            await s.execute(
                select(func.count())
                .select_from(FindingStatusHistory)
                .where(
                    FindingStatusHistory.to_status == FindingStatus.FIXED,
                    FindingStatusHistory.changed_by.is_(None),
                )
            )
        ).scalar_one()
        check("no automated transition to fixed", fixed_rows == 0)

        await s.commit()

        # retests is insert-only (TM-9) — UPDATE must raise.
        blocked = False
        try:
            await s.execute(text("UPDATE retests SET result = 'inconclusive'"))
            await s.commit()
        except Exception:
            await s.rollback()
            blocked = True
        check("retests table rejects UPDATE (append-only)", blocked)

        # cleanup — bypass the append-only triggers (retests/history) for the
        # throwaway rows, then cascade the rest (handoff dev-cleanup pattern).
        await s.execute(text("SET session_replication_role = replica"))
        _child = "WHERE finding_id IN (SELECT id FROM findings WHERE engagement_id = :e)"
        for _sql in (
            text("DELETE FROM retests " + _child),  # noqa: S608 — literal table + bound param
            text("DELETE FROM finding_status_history " + _child),  # noqa: S608
            text("DELETE FROM remediations " + _child),  # noqa: S608
        ):
            await s.execute(_sql.bindparams(e=eng_id))
        await s.execute(text("DELETE FROM findings WHERE engagement_id = :e").bindparams(e=eng_id))
        await s.execute(text("DELETE FROM scans WHERE engagement_id = :e").bindparams(e=eng_id))
        await s.execute(text("DELETE FROM targets WHERE engagement_id = :e").bindparams(e=eng_id))
        await s.execute(text("DELETE FROM engagements WHERE id = :e").bindparams(e=eng_id))
        await s.execute(text("DELETE FROM users WHERE organization_id = :o").bindparams(o=org_id))
        await s.execute(text("DELETE FROM organizations WHERE id = :o").bindparams(o=org_id))
        await s.commit()

    await engine.dispose()
    if failures:
        print(f"\n{len(failures)} FAILURE(S): {failures}")
        sys.exit(1)
    print("\nALL PASS")


if __name__ == "__main__":
    asyncio.run(main())
