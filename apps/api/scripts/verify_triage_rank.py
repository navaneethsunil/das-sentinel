"""Live proof of M4-B2 deterministic triage (rank + group) against real Postgres.

Base api image (needs postgres/valkey/migrate):
    docker compose up -d --build api
    docker compose run --rm --no-deps -v "$PWD/apps/api/scripts:/app/scripts:ro" \
      --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_triage_rank.py"

Seeds canonical findings across severities/rules (+ a duplicate + real CVSS rows),
then runs `triage_overview` (the real DB path: canonical-only list + per-finding
current CVSS) and asserts the deterministic ranking and grouping.
"""

import asyncio
import sys
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.models.cvss import CvssScore
from app.models.engagement import Engagement, ScanIntensity
from app.models.finding import Finding, FindingProvenance, FindingStatus, Severity
from app.models.identity import Organization, User
from app.models.scan import Scan, ScanStatus
from app.models.target import Target, TargetType
from app.services.cvss import set_cvss_score
from app.services.triage_rank import triage_overview

NOW = datetime.now(UTC)
V31_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8; tiebreak within the HIGH band
failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)

    org_id = eng_id = None
    ids: dict[str, uuid.UUID] = {}
    async with sm() as s:
        org = Organization(name="verify-triage-rank-org")
        s.add(org)
        await s.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-triage-rank@example.com",
            password_hash=pw.hash("throwaway-triage-rank"),
            display_name="Verify TriageRank",
        )
        s.add(user)
        await s.flush()
        eng = Engagement(
            organization_id=org.id,
            name="triage-rank-eng",
            client_system_name="acme",
            max_intensity=ScanIntensity.SAFE_ACTIVE,
            created_by=user.id,
        )
        s.add(eng)
        await s.flush()
        eng_id = eng.id
        target = Target(
            engagement_id=eng.id,
            name="app",
            target_type=TargetType.WEB_APP,
            primary_value="https://app.example.com/",
        )
        s.add(target)
        await s.flush()
        scan = Scan(
            engagement_id=eng.id,
            target_id=target.id,
            status=ScanStatus.COMPLETED,
            intensity=ScanIntensity.SAFE_ACTIVE,
            initiated_by=user.id,
        )
        s.add(scan)
        await s.flush()

        def mk(name, sev, rule, age, dup_of=None):  # noqa: ANN001, ANN202
            f = Finding(
                engagement_id=eng.id,
                target_id=target.id,
                scan_id=scan.id,
                rule_id=rule,
                title=f"{rule} finding",
                message="m",
                severity=sev,
                provenance=FindingProvenance.AUTOMATED,
                status=FindingStatus.OPEN,
                hash_code=uuid.uuid4().bytes + uuid.uuid4().bytes,
                duplicate_of=dup_of,
                created_at=NOW - timedelta(seconds=age),
                updated_at=NOW,
            )
            s.add(f)
            return f

        crit = mk("crit", Severity.CRITICAL, "sqli", 10)
        high_scored = mk("high_scored", Severity.HIGH, "sqli", 20)
        high_unscored = mk("high_unscored", Severity.HIGH, "xss", 30)
        med = mk("med", Severity.MEDIUM, "xss", 40)
        await s.flush()
        dup = mk("dup", Severity.CRITICAL, "sqli", 5, dup_of=crit.id)  # excluded (canonical-only)
        await s.flush()
        ids = {
            "crit": crit.id,
            "high_scored": high_scored.id,
            "high_unscored": high_unscored.id,
            "med": med.id,
            "dup": dup.id,
        }
        # A real current CVSS row for the scored HIGH finding (tiebreak within band).
        await set_cvss_score(s, finding=high_scored, vector_string=V31_HIGH, scored_by=user.id)
        await s.commit()

    async with sm() as s:
        ranked, groups = await triage_overview(s, eng_id)

    ranked_ids = [r.finding_id for r in ranked]
    check("duplicate excluded (canonical only)", ids["dup"] not in ranked_ids)
    check("4 canonical findings ranked", len(ranked) == 4)
    check("CRITICAL ranks first", ranked[0].finding_id == ids["crit"])
    check(
        "within HIGH band, CVSS-scored ranks before unscored",
        ranked_ids.index(ids["high_scored"]) < ranked_ids.index(ids["high_unscored"]),
    )
    check("scored HIGH carries its CVSS base score", ranked[1].cvss_base_score == 9.8)
    check("MEDIUM ranks last", ranked[-1].finding_id == ids["med"])
    check("ranks are 1..4 dense", [r.rank for r in ranked] == [1, 2, 3, 4])

    by_key = {g.group_key: g for g in groups}
    check("grouped by rule_id (sqli, xss)", set(by_key) == {"sqli", "xss"})
    check(
        "sqli group is CRITICAL, 2 members, top_rank 1",
        by_key["sqli"].severity is Severity.CRITICAL
        and by_key["sqli"].count == 2
        and by_key["sqli"].top_rank == 1,
    )
    check("groups ordered by best member rank (sqli before xss)", groups[0].group_key == "sqli")

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        fids = (
            (await conn.execute(select(Finding.id).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )
        if fids:
            await conn.execute(delete(CvssScore).where(CvssScore.finding_id.in_(fids)))
        await conn.execute(delete(Finding).where(Finding.engagement_id == eng_id))
        await conn.execute(delete(Scan).where(Scan.engagement_id == eng_id))
        await conn.execute(delete(Target).where(Target.engagement_id == eng_id))
        await conn.execute(delete(Engagement).where(Engagement.id == eng_id))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    await engine.dispose()

    print(
        "\n"
        + ("ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures))
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
