"""M3-B5 live proof: report generate → edit → export (POA&M CSV + Markdown) over HTTP.

Runs in the BASE api image against real Postgres, KB mounted. Seeds an engagement
with two findings — one OWASP-LLM finding scored (CVSS) + auto-mapped (compliance),
one whose title is a spreadsheet formula — then drives the endpoints:

  - POST /engagements/{id}/reports (poam)        → snapshot body carries weakness_id,
    CVSS, compliance mappings, affected asset, source of discovery;
  - GET list / GET detail;
  - PATCH the draft body (fill owner + summary);
  - POST .../export?format=csv                    → text/csv w/ the §15 header row,
    the CVSS + control-mapping cells, and the malicious title NEUTRALIZED ('=...);
  - POST .../export?format=markdown               → text/markdown w/ sections;
  - POST .../finalize                             → PATCH after finalize → 409;
    export still works;
  - negatives: read-only create/export → 403, read-only GET → 200; cross-org → 404;
  - DELETE (soft) → subsequent GET → 404;
  - report.generated/updated/finalized/exported/deleted audited.

Run:
  docker compose up -d --build api               # + postgres, valkey, migrate
  docker compose run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" \
    -v "$PWD/packages/compliance:/app/packages/compliance:ro" \
    --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
        python scripts/verify_reports.py"
"""

import asyncio
import csv
import io
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.audit import AuditEvent, AuditOutcome
from app.models.compliance import ComplianceControl, ComplianceFramework, FindingComplianceMapping
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
from app.models.report import Report, ReportFinding
from app.models.target import Target, TargetType
from app.services.compliance import auto_map_finding, seed_frameworks
from app.services.cvss import set_cvss_score

API_BASE = "http://api:8000"
NOW = datetime.now(UTC)
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"  # 10.0 critical
failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


def _finding(eng_id, tgt_id, *, rule_id, title, location, pf, hb) -> Finding:  # noqa: ANN001
    return Finding(
        engagement_id=eng_id,
        target_id=tgt_id,
        rule_id=rule_id,
        title=title,
        message=title,
        severity=Severity.HIGH,
        provenance=FindingProvenance.AUTOMATED,
        status=FindingStatus.OPEN,
        location=location,
        partial_fingerprints=pf,
        description="The model followed injected instructions.",
        recommendation="Add input/output guardrails.",
        hash_code=hb,
        created_at=NOW,
        updated_at=NOW,
    )


async def _seed(sm, cache, settings):  # noqa: ANN001
    pw = PasswordService(settings.password_hash_scheme)
    async with sm() as s:
        await seed_frameworks(s, Path(settings.compliance_kb_dir))
        org = Organization(name="verify-b5-org")
        other = Organization(name="verify-b5-other")
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

        tester = _user(org.id, "tester@verify-b5.example.com", UserRole.TESTER)
        viewer = _user(org.id, "viewer@verify-b5.example.com", UserRole.READ_ONLY)
        outsider = _user(other.id, "outsider@verify-b5.example.com", UserRole.ADMIN)
        s.add_all([tester, viewer, outsider])
        await s.flush()

        eng = Engagement(
            organization_id=org.id,
            name="b5-reports",
            client_system_name="Acme Portal",
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
            name="chatbot",
            target_type=TargetType.AI_CHATBOT,
            primary_value="https://chat.acme.example.com",
        )
        s.add(target)
        await s.flush()

        llm_f = _finding(
            eng.id,
            target.id,
            rule_id="pi.direct",
            title="Prompt Injection",
            location={
                "owasp": {
                    "framework": "OWASP-LLM-2025",
                    "code": "LLM01",
                    "title": "Prompt Injection",
                }
            },
            pf={"source": "prompt_injection", "fingerprint": "pi.direct:1"},
            hb=b"\x11" * 32,
        )
        evil_f = _finding(
            eng.id,
            target.id,
            rule_id="scan.evil",
            title="=HYPERLINK(evil)",  # CSV formula-injection probe
            location={"file": "x.py"},
            pf={"source": "semgrep", "fingerprint": "scan.evil:1"},
            hb=b"\x12" * 32,
        )
        s.add_all([llm_f, evil_f])
        await s.flush()
        for f in (llm_f, evil_f):
            s.add(
                FindingStatusHistory(
                    finding_id=f.id, from_status=None, to_status=FindingStatus.OPEN, changed_at=NOW
                )
            )
        # score + auto-map the LLM finding so the report body carries CVSS + mappings
        await set_cvss_score(s, finding=llm_f, vector_string=V40, scored_by=tester.id, now=utcnow())
        await auto_map_finding(s, llm_f)

        svc = SessionService(s, cache, settings)
        toks = {
            "tester": await svc.create_session(tester.id, UserRole.TESTER, now=utcnow()),
            "viewer": await svc.create_session(viewer.id, UserRole.READ_ONLY, now=utcnow()),
            "outsider": await svc.create_session(outsider.id, UserRole.ADMIN, now=utcnow()),
        }
        await s.commit()
        return {"org_ids": [org.id, other.id], "eng_id": eng.id, "tokens": toks}


async def _run(ctx, settings, sm) -> None:  # noqa: ANN001, C901, PLR0912, PLR0915
    cn = settings.session_cookie_name
    eng_id = ctx["eng_id"]
    base = f"/engagements/{eng_id}/reports"
    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=30,
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        tester = {cn: ctx["tokens"]["tester"]}
        viewer = {cn: ctx["tokens"]["viewer"]}
        outsider = {cn: ctx["tokens"]["outsider"]}

        # generate a POA&M report over all findings
        r = await http.post(
            base, cookies=tester, json={"report_type": "poam", "title": "Acme POA&M"}
        )
        b = r.json() if r.status_code == 201 else {}
        check("POST generate report → 201", r.status_code == 201)
        rid = b.get("id")
        entries = b.get("body", {}).get("findings", [])
        check("body snapshots both findings", len(entries) == 2)
        llm_entry = next((e for e in entries if e["title"] == "Prompt Injection"), {})
        check(
            "LLM entry carries CVSS 10.0 + LLM01 mapping + asset + source",
            llm_entry.get("cvss", {}).get("base_score") == 10.0
            and any(m["code"] == "LLM01" for m in llm_entry.get("mappings", []))
            and "chat.acme.example.com" in llm_entry.get("affected_asset", "")
            and llm_entry.get("source_of_discovery") == "prompt_injection",
        )
        check("weakness ids assigned", {e["weakness_id"] for e in entries} == {"W-001", "W-002"})

        # list + detail
        r = await http.get(base, cookies=viewer)
        check("list reports → 200 with 1", r.status_code == 200 and len(r.json()) == 1)
        r = await http.get(f"{base}/{rid}", cookies=viewer)
        check("detail → 200 draft", r.status_code == 200 and r.json()["status"] == "draft")

        # edit the draft body (fill owner + summary)
        edited = b["body"]
        edited["summary"] = "Executive summary here."
        edited["findings"][0]["responsible_owner"] = "Team Blue"
        r = await http.patch(f"{base}/{rid}", cookies=tester, json={"body": edited})
        check("PATCH edit draft body → 200", r.status_code == 200)

        # export CSV
        r = await http.post(f"{base}/{rid}/export?format=csv", cookies=tester)
        check(
            "export CSV → 200 text/csv",
            r.status_code == 200 and "text/csv" in r.headers["content-type"],
        )
        check(
            "CSV has attachment disposition",
            "attachment" in r.headers.get("content-disposition", ""),
        )
        rows = list(csv.reader(io.StringIO(r.text)))
        check(
            "CSV header is the POA&M field set", rows[0][0] == "Weakness ID" and len(rows[0]) == 13
        )
        cells = [c for row in rows[1:] for c in row]
        check(
            "CSV neutralizes the =HYPERLINK title ('=)",
            any(c.startswith("'=HYPERLINK") for c in cells),
        )
        check(
            "CSV carries CVSS + control mapping",
            any("10.0 (CVSS v4.0)" in c for c in cells) and any("LLM01" in c for c in cells),
        )

        # export Markdown
        r = await http.post(f"{base}/{rid}/export?format=markdown", cookies=tester)
        md = r.text
        check(
            "export MD → 200 text/markdown",
            r.status_code == 200 and "text/markdown" in r.headers["content-type"],
        )
        check(
            "MD has header + summary + finding + mapping",
            "# Acme POA&M" in md
            and "Executive summary here." in md
            and "### W-001 — Prompt Injection" in md
            and "**OWASP mapping:** LLM01" in md,
        )

        # finalize → edit refused, export still works
        r = await http.post(f"{base}/{rid}/finalize", cookies=tester)
        check("finalize → 200 final", r.status_code == 200 and r.json()["status"] == "final")
        r = await http.patch(f"{base}/{rid}", cookies=tester, json={"title": "nope"})
        check("PATCH after finalize → 409", r.status_code == 409)
        r = await http.post(f"{base}/{rid}/export?format=csv", cookies=tester)
        check("export after finalize still works → 200", r.status_code == 200)

        # RBAC + cross-org
        r = await http.post(base, cookies=viewer, json={"report_type": "poam", "title": "x"})
        check("read-only generate → 403", r.status_code == 403)
        r = await http.post(f"{base}/{rid}/export?format=csv", cookies=viewer)
        check("read-only export → 403", r.status_code == 403)
        r = await http.get(f"{base}/{rid}", cookies=viewer)
        check("read-only detail → 200", r.status_code == 200)
        r = await http.get(f"{base}/{rid}", cookies=outsider)
        check("cross-org detail → 404", r.status_code == 404)

        # soft delete
        r = await http.delete(f"{base}/{rid}", cookies=tester)
        check("delete → 204", r.status_code == 204)
        r = await http.get(f"{base}/{rid}", cookies=viewer)
        check("deleted report → 404", r.status_code == 404)

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
        for act in (
            "report.generated",
            "report.updated",
            "report.finalized",
            "report.exported",
            "report.deleted",
        ):
            check(f"{act} audited", act in actions)


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
        rids = (
            (await s.execute(select(Report.id).where(Report.engagement_id.in_(eng_ids))))
            .scalars()
            .all()
        )
        await s.execute(delete(ReportFinding).where(ReportFinding.report_id.in_(rids)))
        await s.execute(delete(Report).where(Report.engagement_id.in_(eng_ids)))
        await s.execute(delete(CvssScore).where(CvssScore.finding_id.in_(fids)))
        await s.execute(
            delete(FindingComplianceMapping).where(FindingComplianceMapping.finding_id.in_(fids))
        )
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
        await s.execute(delete(ComplianceControl))
        await s.execute(delete(ComplianceFramework))
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
