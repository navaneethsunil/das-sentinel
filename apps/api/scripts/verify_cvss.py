"""M3-B3 live proof: CVSS scoring (compute/parse + override + history) over HTTP.

Runs in the BASE api image against real Postgres + Valkey. Seeds one finding for a
target, then drives the real endpoints:

  - GET  /engagements/{id}/findings/{fid}/cvss  → current=None, empty history
    before any score (VIEW may read);
  - POST .../cvss with a v4.0 vector → 201, base score + severity band derived by
    the `cvss` package, is_current, scored_by set, not a manual override;
  - POST again with a v3.1 vector → new current row; the prior current is
    superseded (DB shows exactly one is_current row, full history preserved);
  - POST a manual override without a justification → 422 (fail-closed); with a
    justification → 201 and the trimmed justification is stored;
  - negatives: malformed vector → 422; unsupported version (CVSS:3.0) → 422;
    read-only POST → 403; cross-org / unknown finding → 404;
  - finding.cvss_scored is audited.

Run:
  docker compose up -d --build api               # + postgres, valkey, migrate
  docker compose run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx python scripts/verify_cvss.py"
"""

import asyncio
import sys
from datetime import UTC, datetime, timedelta

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, func, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.audit import AuditEvent, AuditOutcome
from app.models.cvss import CvssScore
from app.models.engagement import Engagement, EngagementStatus, ScanIntensity
from app.models.finding import (
    Finding,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
    Severity,
)
from app.models.identity import Organization, Session, User, UserRole
from app.models.target import Target, TargetType

API_BASE = "http://api:8000"
NOW = datetime.now(UTC)
failures: list[str] = []

V40_CRITICAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
V31_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_LOW = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"  # base 3.7 / Low


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


async def _seed(sm, cache, settings):  # noqa: ANN001
    pw = PasswordService(settings.password_hash_scheme)
    async with sm() as s:
        org = Organization(name="verify-b3-org")
        other = Organization(name="verify-b3-other")
        s.add_all([org, other])
        await s.flush()

        def _user(org_id, email, role):  # noqa: ANN001
            return User(
                organization_id=org_id,
                email=email,
                password_hash=pw.hash("x-throwaway"),
                display_name=email.split("@")[0],
                role=role,
            )

        tester = _user(org.id, "tester@verify-b3.example.com", UserRole.TESTER)
        viewer = _user(org.id, "viewer@verify-b3.example.com", UserRole.READ_ONLY)
        outsider = _user(other.id, "outsider@verify-b3.example.com", UserRole.ADMIN)
        s.add_all([tester, viewer, outsider])
        await s.flush()

        eng = Engagement(
            organization_id=org.id,
            name="b3-cvss",
            client_system_name="acme",
            status=EngagementStatus.ACTIVE,
            test_window_start=NOW - timedelta(days=1),
            test_window_end=NOW + timedelta(days=1),
            rate_limit_rps=5,
            max_intensity=ScanIntensity.SAFE_ACTIVE,
            created_by=tester.id,
        )
        s.add(eng)
        await s.flush()
        target = Target(
            engagement_id=eng.id,
            name="src",
            target_type=TargetType.SOURCE_ARCHIVE,
            primary_value="sha256/seed",
        )
        s.add(target)
        await s.flush()
        finding = Finding(
            engagement_id=eng.id,
            target_id=target.id,
            rule_id="python.eval",
            title="eval",
            message="use of eval",
            severity=Severity.MEDIUM,
            provenance=FindingProvenance.AUTOMATED,
            status=FindingStatus.OPEN,
            hash_code=b"\x00" * 32,
            created_at=NOW,
            updated_at=NOW,
        )
        s.add(finding)
        await s.flush()
        s.add(
            FindingStatusHistory(
                finding_id=finding.id,
                from_status=None,
                to_status=FindingStatus.OPEN,
                reason="seeded",
                changed_at=NOW,
            )
        )

        svc = SessionService(s, cache, settings)
        toks = {
            "tester": await svc.create_session(tester.id, UserRole.TESTER, now=utcnow()),
            "viewer": await svc.create_session(viewer.id, UserRole.READ_ONLY, now=utcnow()),
            "outsider": await svc.create_session(outsider.id, UserRole.ADMIN, now=utcnow()),
        }
        await s.commit()
        return {
            "org_ids": [org.id, other.id],
            "eng_id": eng.id,
            "finding_id": finding.id,
            "tester_id": tester.id,
            "tokens": toks,
        }


async def _current_count(sm, finding_id) -> int:  # noqa: ANN001
    async with sm() as s:
        return (
            await s.execute(
                select(func.count())
                .select_from(CvssScore)
                .where(CvssScore.finding_id == finding_id, CvssScore.is_current.is_(True))
            )
        ).scalar_one()


async def _total_count(sm, finding_id) -> int:  # noqa: ANN001
    async with sm() as s:
        return (
            await s.execute(
                select(func.count())
                .select_from(CvssScore)
                .where(CvssScore.finding_id == finding_id)
            )
        ).scalar_one()


async def _run(ctx, settings, sm) -> None:  # noqa: ANN001, C901, PLR0915
    cn = settings.session_cookie_name
    eng_id = ctx["eng_id"]
    fid = ctx["finding_id"]
    base = f"/engagements/{eng_id}/findings/{fid}/cvss"
    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=30,
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        tester = {cn: ctx["tokens"]["tester"]}
        viewer = {cn: ctx["tokens"]["viewer"]}
        outsider = {cn: ctx["tokens"]["outsider"]}

        # unscored → current None, empty history (viewer may read)
        r = await http.get(base, cookies=viewer)
        b = r.json() if r.status_code == 200 else {}
        check("GET before scoring → 200", r.status_code == 200)
        check(
            "unscored: current=None, history empty", b.get("current") is None and b["history"] == []
        )

        # score with a v4.0 critical vector
        r = await http.post(base, cookies=tester, json={"vector_string": V40_CRITICAL})
        b = r.json() if r.status_code == 201 else {}
        check("POST v4.0 vector → 201", r.status_code == 201)
        check(
            "v4.0 base_score 10.0 / critical",
            b.get("base_score") == 10.0 and b.get("severity_band") == "critical",
        )
        check("v4.0 version v4_0", b.get("version") == "v4_0")
        check(
            "scored_by = tester, not a manual override, is_current",
            b.get("scored_by") == str(ctx["tester_id"])
            and b.get("is_manual_override") is False
            and b.get("is_current") is True,
        )

        r = await http.get(base, cookies=viewer)
        b = r.json()
        check(
            "history len 1 after first score",
            len(b["history"]) == 1 and b["current"]["base_score"] == 10.0,
        )

        # re-score with a v3.1 vector → supersedes
        r = await http.post(base, cookies=tester, json={"vector_string": V31_CRITICAL})
        check("POST v3.1 vector → 201", r.status_code == 201)
        r = await http.get(base, cookies=viewer)
        b = r.json()
        check(
            "history len 2, current now v3.1 (9.8)",
            len(b["history"]) == 2
            and b["current"]["version"] == "v3_1"
            and b["current"]["base_score"] == 9.8,
        )
        check("exactly one is_current row in DB", await _current_count(sm, fid) == 1)

        # manual override without justification → 422 (schema)
        r = await http.post(
            base, cookies=tester, json={"vector_string": V31_LOW, "is_manual_override": True}
        )
        check("manual override without justification → 422", r.status_code == 422)

        # manual override WITH justification → 201, trimmed and stored
        r = await http.post(
            base,
            cookies=tester,
            json={
                "vector_string": V31_LOW,
                "is_manual_override": True,
                "override_justification": "  analyst downgrade: not reachable  ",
            },
        )
        b = r.json() if r.status_code == 201 else {}
        check("manual override with justification → 201", r.status_code == 201)
        check(
            "override flagged + justification trimmed/stored",
            b.get("is_manual_override") is True
            and b.get("override_justification") == "analyst downgrade: not reachable",
        )
        check(
            "override current is Low (3.7)",
            b.get("base_score") == 3.7 and b.get("severity_band") == "low",
        )

        r = await http.get(base, cookies=viewer)
        check("history len 3 after override", len(r.json()["history"]) == 3)
        check(
            "still exactly one is_current, total history 3",
            await _current_count(sm, fid) == 1 and await _total_count(sm, fid) == 3,
        )

        # negatives
        r = await http.post(base, cookies=tester, json={"vector_string": "not-a-vector"})
        check("malformed vector → 422", r.status_code == 422)
        r = await http.post(
            base,
            cookies=tester,
            json={"vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        )
        check("unsupported version CVSS:3.0 → 422", r.status_code == 422)
        r = await http.post(base, cookies=viewer, json={"vector_string": V40_CRITICAL})
        check("read-only POST → 403", r.status_code == 403)
        r = await http.get(base, cookies=viewer)
        check("read-only GET → 200 (VIEW)", r.status_code == 200)

        # cross-org (outsider) + unknown finding
        r = await http.get(base, cookies=outsider)
        check("cross-org GET → 404", r.status_code == 404)
        r = await http.post(base, cookies=outsider, json={"vector_string": V40_CRITICAL})
        check("cross-org POST → 404", r.status_code == 404)
        unknown = f"/engagements/{eng_id}/findings/{ctx['org_ids'][0]}/cvss"
        r = await http.get(unknown, cookies=tester)
        check("unknown finding → 404", r.status_code == 404)

        # audit
        async with sm() as s:
            actions = {
                a
                for a, o in (
                    await s.execute(
                        select(AuditEvent.action, AuditEvent.outcome).where(
                            AuditEvent.engagement_id == eng_id
                        )
                    )
                ).all()
                if o is AuditOutcome.SUCCESS
            }
            check("finding.cvss_scored audited", "finding.cvss_scored" in actions)


async def _cleanup(sm, org_ids, tokens, cache) -> None:  # noqa: ANN001
    async with sm() as s:
        await s.execute(text("SET session_replication_role = replica"))
        eng_ids = (
            (await s.execute(select(Engagement.id).where(Engagement.organization_id.in_(org_ids))))
            .scalars()
            .all()
        )
        fids = (
            (await s.execute(select(Finding.id).where(Finding.engagement_id.in_(eng_ids))))
            .scalars()
            .all()
        )
        await s.execute(delete(CvssScore).where(CvssScore.finding_id.in_(fids)))
        await s.execute(
            delete(FindingStatusHistory).where(FindingStatusHistory.finding_id.in_(fids))
        )
        await s.execute(delete(Finding).where(Finding.engagement_id.in_(eng_ids)))
        await s.execute(delete(AuditEvent).where(AuditEvent.organization_id.in_(org_ids)))
        await s.execute(delete(Target).where(Target.engagement_id.in_(eng_ids)))
        await s.execute(delete(Engagement).where(Engagement.organization_id.in_(org_ids)))
        await s.execute(
            delete(Session).where(
                Session.user_id.in_(select(User.id).where(User.organization_id.in_(org_ids)))
            )
        )
        await s.execute(delete(User).where(User.organization_id.in_(org_ids)))
        await s.execute(delete(Organization).where(Organization.id.in_(org_ids)))
        await s.commit()
    for tok in tokens:
        await cache.delete(f"session:{hash_token(tok).hex()}")


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)

    ctx = await _seed(sm, cache, settings)
    try:
        await _run(ctx, settings, sm)
    finally:
        await _cleanup(sm, ctx["org_ids"], list(ctx["tokens"].values()), cache)
        await cache.aclose()
        await engine.dispose()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
