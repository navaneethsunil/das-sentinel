"""M3-B2 live proof: SARIF 2.1.0 export/import + reimport dedup over HTTP.

Runs in the BASE api image against real Postgres + MinIO. Seeds two automated
findings for a target, then drives the real endpoints:

  - GET  /engagements/{id}/findings/export-sarif  → a valid SARIF 2.1.0 log whose
    results embed the exact hash_code (VIEW may read);
  - POST /engagements/{id}/findings/import-sarif   (multipart) reimports that log →
    every result matches an existing finding by hash_code and is linked
    duplicate_of the original (created=0, duplicates=2); the canonical list is
    unchanged; the raw SARIF is stored once as cited evidence;
  - importing a FOREIGN log (no embedded hash) creates novel findings, and
    reimporting it dedups them (hash derived from source+fingerprint);
  - negatives: malformed/wrong-version SARIF → 422; read-only import → 403;
    cross-org target → 404.

Run:
  docker compose up -d --build api minio        # + postgres, valkey, migrate
  docker compose run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx python scripts/verify_sarif.py"
"""

import asyncio
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, func, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.audit import AuditEvent, AuditOutcome
from app.models.engagement import Engagement, EngagementStatus, ScanIntensity
from app.models.evidence import Evidence, EvidenceKind
from app.models.finding import (
    Finding,
    FindingEvidence,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
    SarifLevel,
    Severity,
)
from app.models.identity import Organization, Session, User, UserRole
from app.models.target import Target, TargetType
from app.services.finding_hash import PF_FINGERPRINT, PF_SOURCE, compute_hash_code
from app.storage import create_evidence_store

API_BASE = "http://api:8000"
NOW = datetime.now(UTC)
failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


def _finding(eng_id, tgt_id, *, rule_id, fingerprint, line) -> Finding:  # noqa: ANN001
    return Finding(
        engagement_id=eng_id,
        target_id=tgt_id,
        rule_id=rule_id,
        title=rule_id.rsplit(".", 1)[-1],
        message=f"{rule_id} at line {line}",
        sarif_level=SarifLevel.ERROR,
        location={"file": "pkg/vulnerable.py", "start_line": line},
        severity=Severity.HIGH,
        provenance=FindingProvenance.AUTOMATED,
        status=FindingStatus.OPEN,
        hash_code=compute_hash_code(eng_id, tgt_id, "semgrep", fingerprint),
        partial_fingerprints={PF_SOURCE: "semgrep", PF_FINGERPRINT: fingerprint},
        created_at=NOW,
        updated_at=NOW,
    )


def _foreign_sarif() -> bytes:
    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "acme-linter"}},
                "results": [
                    {
                        "ruleId": "ACME-001",
                        "level": "warning",
                        "message": {"text": "hardcoded path"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "svc/x.py"},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(log).encode()


async def _seed(sm, cache, settings):  # noqa: ANN001
    pw = PasswordService(settings.password_hash_scheme)
    async with sm() as s:
        org = Organization(name="verify-b2-org")
        other = Organization(name="verify-b2-other")
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

        tester = _user(org.id, "tester@verify-b2.example.com", UserRole.TESTER)
        viewer = _user(org.id, "viewer@verify-b2.example.com", UserRole.READ_ONLY)
        outsider = _user(other.id, "outsider@verify-b2.example.com", UserRole.ADMIN)
        s.add_all([tester, viewer, outsider])
        await s.flush()

        eng = Engagement(
            organization_id=org.id,
            name="b2-sarif",
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
        for rid, fp, line in (
            ("python.eval", "python.eval:pkg/vulnerable.py:24", 24),
            ("python.md5", "python.md5:pkg/vulnerable.py:29", 29),
        ):
            f = _finding(eng.id, target.id, rule_id=rid, fingerprint=fp, line=line)
            s.add(f)
            await s.flush()
            s.add(
                FindingStatusHistory(
                    finding_id=f.id,
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
            "target_id": target.id,
            "tokens": toks,
        }


async def _live_count(sm, eng_id) -> int:  # noqa: ANN001
    async with sm() as s:
        return (
            await s.execute(
                select(func.count())
                .select_from(Finding)
                .where(
                    Finding.engagement_id == eng_id,
                    Finding.deleted_at.is_(None),
                    Finding.duplicate_of.is_(None),
                )
            )
        ).scalar_one()


async def _run(ctx, settings, sm) -> None:  # noqa: ANN001, C901, PLR0915
    cn = settings.session_cookie_name
    eng_id = ctx["eng_id"]
    tid = ctx["target_id"]
    base = f"/engagements/{eng_id}/findings"
    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=30,
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        # export (viewer may read)
        r = await http.get(f"{base}/export-sarif", cookies={cn: ctx["tokens"]["viewer"]})
        check("export → 200", r.status_code == 200)
        log = r.json() if r.status_code == 200 else {}
        check("exported log is SARIF 2.1.0", log.get("version") == "2.1.0")
        results = log.get("runs", [{}])[0].get("results", [])
        check("export has both findings", len(results) == 2)
        check(
            "each result embeds dasHash + ruleId",
            all(
                res.get("ruleId") and res["partialFingerprints"].get("dasHash/v1")
                for res in results
            ),
        )
        sarif_bytes = json.dumps(log).encode()

        # reimport the DAS-exported log → all dedup to duplicate_of
        r = await http.post(
            f"{base}/import-sarif",
            cookies={cn: ctx["tokens"]["tester"]},
            data={"target_id": str(tid)},
            files={"file": ("export.sarif", sarif_bytes, "application/sarif+json")},
        )
        check("reimport exported log → 200", r.status_code == 200)
        body = r.json() if r.status_code == 200 else {}
        check(
            "reimport: created=0, duplicates=2",
            body.get("created") == 0 and body.get("duplicates") == 2,
        )

        # duplicate_of actually set + canonical list unchanged
        async with sm() as s:
            dups = (
                (
                    await s.execute(
                        select(Finding).where(
                            Finding.engagement_id == eng_id, Finding.duplicate_of.is_not(None)
                        )
                    )
                )
                .scalars()
                .all()
            )
            check(
                "2 duplicate rows created, each linked to a canonical original",
                len(dups) == 2 and all(d.duplicate_of for d in dups),
            )
            ev = await s.get(Evidence, uuid.UUID(body["evidence_id"]))
            check(
                "raw SARIF stored as evidence (application/sarif+json)",
                ev is not None
                and ev.kind is EvidenceKind.RAW_SCANNER_OUTPUT
                and ev.content_type == "application/sarif+json",
            )
            links = (
                (
                    await s.execute(
                        select(FindingEvidence).where(
                            FindingEvidence.finding_id.in_([d.id for d in dups])
                        )
                    )
                )
                .scalars()
                .all()
            )
            check(
                "imported findings cite the SARIF evidence",
                all(link.evidence_id == ev.id for link in links) and len(links) == 2,
            )
        check("canonical list still 2 (duplicates excluded)", await _live_count(sm, eng_id) == 2)

        r = await http.get(base, cookies={cn: ctx["tokens"]["viewer"]})
        check(
            "findings list endpoint excludes duplicates (len 2)",
            r.status_code == 200 and len(r.json()) == 2,
        )

        # foreign SARIF → novel finding created; reimport dedups it
        foreign = _foreign_sarif()
        r = await http.post(
            f"{base}/import-sarif",
            cookies={cn: ctx["tokens"]["tester"]},
            data={"target_id": str(tid)},
            files={"file": ("acme.sarif", foreign, "application/sarif+json")},
        )
        b1 = r.json() if r.status_code == 200 else {}
        check(
            "foreign import creates 1 novel finding",
            b1.get("created") == 1 and b1.get("duplicates") == 0,
        )
        check("canonical list now 3", await _live_count(sm, eng_id) == 3)
        r = await http.post(
            f"{base}/import-sarif",
            cookies={cn: ctx["tokens"]["tester"]},
            data={"target_id": str(tid)},
            files={"file": ("acme.sarif", foreign, "application/sarif+json")},
        )
        b2 = r.json() if r.status_code == 200 else {}
        check(
            "foreign reimport dedups (created=0, duplicates=1)",
            b2.get("created") == 0 and b2.get("duplicates") == 1,
        )
        check("canonical list still 3 after reimport", await _live_count(sm, eng_id) == 3)

        # negatives
        r = await http.post(
            f"{base}/import-sarif",
            cookies={cn: ctx["tokens"]["tester"]},
            data={"target_id": str(tid)},
            files={"file": ("bad.sarif", b"not json", "application/json")},
        )
        check("malformed SARIF → 422", r.status_code == 422)
        r = await http.post(
            f"{base}/import-sarif",
            cookies={cn: ctx["tokens"]["tester"]},
            data={"target_id": str(tid)},
            files={
                "file": (
                    "v1.sarif",
                    json.dumps({"version": "1.0.0", "runs": []}).encode(),
                    "application/json",
                )
            },
        )
        check("wrong SARIF version → 422", r.status_code == 422)
        r = await http.post(
            f"{base}/import-sarif",
            cookies={cn: ctx["tokens"]["viewer"]},
            data={"target_id": str(tid)},
            files={"file": ("export.sarif", sarif_bytes, "application/sarif+json")},
        )
        check("read-only import → 403", r.status_code == 403)
        r = await http.post(
            f"{base}/import-sarif",
            cookies={cn: ctx["tokens"]["outsider"]},
            data={"target_id": str(tid)},
            files={"file": ("export.sarif", sarif_bytes, "application/sarif+json")},
        )
        check("cross-org target → 404", r.status_code == 404)

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
            check("finding.sarif_imported audited", "finding.sarif_imported" in actions)


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
        for tbl in (FindingEvidence, FindingStatusHistory):
            await s.execute(delete(tbl).where(tbl.finding_id.in_(fids)))
        # null out duplicate_of self-refs before deleting findings
        await s.execute(
            delete(Finding).where(
                Finding.engagement_id.in_(eng_ids), Finding.duplicate_of.is_not(None)
            )
        )
        await s.execute(delete(Finding).where(Finding.engagement_id.in_(eng_ids)))
        await s.execute(delete(Evidence).where(Evidence.organization_id.in_(org_ids)))
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
    create_evidence_store(settings).ensure_bucket()

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
