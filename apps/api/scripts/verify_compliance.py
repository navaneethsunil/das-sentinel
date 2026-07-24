"""M3-B4 live proof: compliance KB seed + auto/manual mapping over HTTP.

Runs in the BASE api image against real Postgres, with the KB mounted at
settings.compliance_kb_dir. Seeds the KB (idempotent), then drives the endpoints:

  - seed_frameworks loads all 6 frameworks / 75 controls; a re-seed is idempotent
    (DB row counts unchanged);
  - GET  /compliance/frameworks               → the catalog (VIEW);
  - POST .../findings/{fid}/compliance/auto-map on an OWASP-LLM-coded finding →
    creates exactly the owasp_llm_2025/LLM01 mapping (AUTOMATED); re-run is a
    no-op; a scanner finding with no structured ref maps nothing;
  - POST .../findings/{fid}/compliance {control_id} → manual VALIDATED mapping;
    unknown control → 422; DELETE removes it; DELETE missing → 404;
  - POST .../engagements/{id}/compliance/auto-map bulk-maps canonical findings;
  - negatives: read-only POST → 403 / GET → 200; cross-org finding → 404;
  - every mutation is audited.

Run:
  docker compose up -d --build api             # + postgres, valkey, migrate
  docker compose run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" \
    -v "$PWD/packages/compliance:/app/packages/compliance:ro" \
    --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
        python scripts/verify_compliance.py"
"""

import asyncio
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, func, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.audit import AuditEvent, AuditOutcome
from app.models.compliance import ComplianceControl, ComplianceFramework, FindingComplianceMapping
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
from app.services.compliance import seed_frameworks

API_BASE = "http://api:8000"
NOW = datetime.now(UTC)
failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


def _finding(eng_id, tgt_id, *, rule_id, location, hb) -> Finding:  # noqa: ANN001
    return Finding(
        engagement_id=eng_id,
        target_id=tgt_id,
        rule_id=rule_id,
        title=rule_id,
        message=rule_id,
        severity=Severity.HIGH,
        provenance=FindingProvenance.AUTOMATED,
        status=FindingStatus.OPEN,
        location=location,
        hash_code=hb,
        created_at=NOW,
        updated_at=NOW,
    )


async def _seed(sm, cache, settings):  # noqa: ANN001
    pw = PasswordService(settings.password_hash_scheme)
    async with sm() as s:
        org = Organization(name="verify-b4-org")
        other = Organization(name="verify-b4-other")
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

        tester = _user(org.id, "tester@verify-b4.example.com", UserRole.TESTER)
        viewer = _user(org.id, "viewer@verify-b4.example.com", UserRole.READ_ONLY)
        outsider = _user(other.id, "outsider@verify-b4.example.com", UserRole.ADMIN)
        s.add_all([tester, viewer, outsider])
        await s.flush()

        eng = Engagement(
            organization_id=org.id,
            name="b4-compliance",
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
            target_type=TargetType.AI_CHATBOT,
            primary_value="https://chat.acme.example.com",
        )
        s.add(target)
        await s.flush()
        llm_f = _finding(
            eng.id,
            target.id,
            rule_id="pi.direct",
            location={
                "owasp": {
                    "framework": "OWASP-LLM-2025",
                    "code": "LLM01",
                    "title": "Prompt Injection",
                },
                "technique": "direct",
                "suite": "prompt_injection",
            },
            hb=b"\x01" * 32,
        )
        scan_f = _finding(
            eng.id,
            target.id,
            rule_id="python.eval",
            location={"file": "x.py", "cwe": "CWE-95"},
            hb=b"\x02" * 32,
        )
        s.add_all([llm_f, scan_f])
        await s.flush()
        for f in (llm_f, scan_f):
            s.add(
                FindingStatusHistory(
                    finding_id=f.id, from_status=None, to_status=FindingStatus.OPEN, changed_at=NOW
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
            "llm_fid": llm_f.id,
            "scan_fid": scan_f.id,
            "tokens": toks,
        }


async def _count(sm, model) -> int:  # noqa: ANN001
    async with sm() as s:
        return (await s.execute(select(func.count()).select_from(model))).scalar_one()


async def _run(ctx, settings, sm) -> None:  # noqa: ANN001, C901, PLR0912, PLR0915
    cn = settings.session_cookie_name
    eng_id = ctx["eng_id"]
    llm_fid = ctx["llm_fid"]
    scan_fid = ctx["scan_fid"]

    # seed the KB, then re-seed → idempotent
    async with sm() as s:
        counts = await seed_frameworks(s, Path(settings.compliance_kb_dir))
        await s.commit()
    check("seed loaded 6 frameworks", counts["frameworks"] == 6)
    check("seed loaded 75 controls", counts["controls"] == 75)
    fw_after_first = await _count(sm, ComplianceFramework)
    ctrl_after_first = await _count(sm, ComplianceControl)
    async with sm() as s:
        await seed_frameworks(s, Path(settings.compliance_kb_dir))
        await s.commit()
    check(
        "re-seed idempotent (no duplicate framework/control rows)",
        await _count(sm, ComplianceFramework) == fw_after_first
        and await _count(sm, ComplianceControl) == ctrl_after_first,
    )

    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=30,
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        tester = {cn: ctx["tokens"]["tester"]}
        viewer = {cn: ctx["tokens"]["viewer"]}
        outsider = {cn: ctx["tokens"]["outsider"]}

        # catalog
        r = await http.get("/compliance/frameworks", cookies=viewer)
        cat = r.json() if r.status_code == 200 else []
        check("GET /compliance/frameworks → 200", r.status_code == 200)
        check("catalog has 6 frameworks", len(cat) == 6)
        llm_cat = next((f for f in cat if f["key"] == "owasp_llm_2025"), None)
        check(
            "owasp_llm_2025 has 10 controls in catalog", llm_cat and len(llm_cat["controls"]) == 10
        )

        llm_base = f"/engagements/{eng_id}/findings/{llm_fid}/compliance"
        scan_base = f"/engagements/{eng_id}/findings/{scan_fid}/compliance"

        # auto-map the LLM finding → owasp_llm_2025/LLM01
        r = await http.post(f"{llm_base}/auto-map", cookies=tester)
        b = r.json() if r.status_code == 200 else {}
        check("auto-map LLM finding → created 1", r.status_code == 200 and b.get("created") == 1)
        r = await http.get(llm_base, cookies=viewer)
        maps = r.json() if r.status_code == 200 else []
        check(
            "mapping is owasp_llm_2025/LLM01, mapped_by automated",
            len(maps) == 1
            and maps[0]["framework_key"] == "owasp_llm_2025"
            and maps[0]["code"] == "LLM01"
            and maps[0]["mapped_by"] == "automated",
        )
        # idempotent
        r = await http.post(f"{llm_base}/auto-map", cookies=tester)
        check("auto-map again → created 0 (idempotent)", r.json().get("created") == 0)

        # scanner finding has no structured ref → maps nothing
        r = await http.post(f"{scan_base}/auto-map", cookies=tester)
        check("auto-map scanner finding → created 0", r.json().get("created") == 0)

        # manual mapping: add a WSTG-ATHZ control
        async with sm() as s:
            wstg_ctrl_id = (
                await s.execute(
                    select(ComplianceControl.id)
                    .join(ComplianceFramework)
                    .where(
                        ComplianceFramework.key == "owasp_wstg_4_2",
                        ComplianceControl.code == "WSTG-ATHZ",
                    )
                )
            ).scalar_one()
        r = await http.post(llm_base, cookies=tester, json={"control_id": str(wstg_ctrl_id)})
        b = r.json() if r.status_code == 201 else []
        check("manual add mapping → 201", r.status_code == 201)
        check(
            "now 2 mappings incl a VALIDATED WSTG one",
            len(b) == 2
            and any(m["code"] == "WSTG-ATHZ" and m["mapped_by"] == "validated" for m in b),
        )
        # unknown control → 422
        r = await http.post(llm_base, cookies=tester, json={"control_id": str(ctx["org_ids"][0])})
        check("manual add unknown control → 422", r.status_code == 422)

        # delete the manual mapping
        r = await http.delete(f"{llm_base}/{wstg_ctrl_id}", cookies=tester)
        check("delete mapping → 204", r.status_code == 204)
        r = await http.get(llm_base, cookies=viewer)
        check("back to 1 mapping after delete", len(r.json()) == 1)
        r = await http.delete(f"{llm_base}/{wstg_ctrl_id}", cookies=tester)
        check("delete missing mapping → 404", r.status_code == 404)

        # bulk engagement auto-map (LLM01 already mapped → 0 new)
        r = await http.post(f"/engagements/{eng_id}/compliance/auto-map", cookies=tester)
        check(
            "bulk engagement auto-map → 200 created 0 (already mapped)",
            r.status_code == 200 and r.json().get("created") == 0,
        )

        # RBAC + cross-org
        r = await http.post(f"{llm_base}/auto-map", cookies=viewer)
        check("read-only auto-map → 403", r.status_code == 403)
        r = await http.get(llm_base, cookies=viewer)
        check("read-only GET mappings → 200", r.status_code == 200)
        r = await http.get(llm_base, cookies=outsider)
        check("cross-org GET → 404", r.status_code == 404)
        r = await http.post(f"{llm_base}/auto-map", cookies=outsider)
        check("cross-org auto-map → 404", r.status_code == 404)

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
            "finding.compliance_auto_mapped",
            "finding.compliance_mapped",
            "finding.compliance_unmapped",
            "engagement.compliance_auto_mapped",
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
        # KB is global reference data seeded by this run — remove it too.
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
