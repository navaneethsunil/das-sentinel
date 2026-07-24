"""M3-B1 live proof: upload a source archive over HTTP, then SAST-scan it.

Runs INSIDE the `scanners` image (real semgrep) against real Postgres + MinIO,
with the base-image `api` service also up (it serves the upload endpoint). Two
parts:

  Part A (real HTTP → the `api` service): a Tester POSTs a zip to
    POST /engagements/{id}/targets/{tid}/source-archive → 200; the archive is
    stored as content-addressed evidence (kind source_archive), the target's
    primary_value becomes the object key, and target.source_archive_uploaded is
    audited. Abuse/authz negatives: a non-archive and a zip-slip archive are
    refused 422 (nothing stored); wrong target type 422; read-only 403; cross-org
    404.

  Part B (in-process, this container): launch a scanner scan of that target with
    NO source_path in the envelope → orchestrate_scan → run_scanners fetches the
    uploaded archive (hash-verified), SAFELY EXTRACTS it, hands the extracted tree
    to Semgrep → COMPLETED with real automated findings citing raw evidence. This
    proves the upload → extract → scan hand-off end to end.

Run:
  DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose --profile scanners build scanner-worker
  docker compose up -d --build postgres valkey minio migrate api
  docker compose --profile scanners run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" \
    --entrypoint sh scanner-worker \
    -c "cd /app && PYTHONPATH=/app python scripts/verify_source_archive.py"
"""

import asyncio
import io
import sys
import zipfile
from datetime import UTC, datetime, timedelta

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.scope import Operation, OperationKind
from app.core.security import PasswordService
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.audit import AuditEvent, AuditOutcome
from app.models.engagement import (
    Engagement,
    EngagementStatus,
    ROEAcknowledgement,
    ScanIntensity,
    ScopeItem,
)
from app.models.evidence import Evidence, EvidenceKind
from app.models.finding import (
    Finding,
    FindingEvidence,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
)
from app.models.identity import Organization, Session, User, UserRole
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus
from app.models.scanner import ScannerRun
from app.models.target import Target, TargetType
from app.services.roe import render_current_roe
from app.services.scans import launch_scan
from app.storage import create_evidence_store, load_evidence
from app.workers.execution import RunSpec
from app.workers.orchestration import orchestrate_scan
from app.workers.scanner_run import build_scanner_owner

API_BASE = "http://api:8000"
NOW = datetime.now(UTC)
failures: list[str] = []

# Deliberately-vulnerable source the vendored opengrep bundle flags. NO secret-
# shaped literals (Gitleaks block-on-any). Zipped and uploaded as the archive.
VULN_PY = b"""\
import hashlib, os, subprocess


def run(cmd):
    subprocess.run(cmd, shell=True, check=False)
    os.system(cmd)


def ev(expr):
    return eval(expr)


def digest(data):
    return hashlib.md5(data).hexdigest()
"""


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _zip_slip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../escape.py", b"pwned\n")
    return buf.getvalue()


async def _accept_roe(session, eng, scope_items, user_id) -> None:  # noqa: ANN001
    _, _, terms, content_hash = render_current_roe(eng, scope_items)
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


def _engagement(org_id, user_id) -> Engagement:  # noqa: ANN001
    return Engagement(
        organization_id=org_id,
        name="b1-source-archive",
        client_system_name="acme",
        status=EngagementStatus.ACTIVE,
        test_window_start=NOW - timedelta(days=1),
        test_window_end=NOW + timedelta(days=1),
        rate_limit_rps=5,
        max_intensity=ScanIntensity.SAFE_ACTIVE,
        created_by=user_id,
    )


async def _seed(sm, cache, settings):  # noqa: ANN001, C901
    pw = PasswordService(settings.password_hash_scheme)
    async with sm() as s:
        org = Organization(name="verify-b1-org")
        other = Organization(name="verify-b1-other")
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

        tester = _user(org.id, "tester@verify-b1.example.com", UserRole.TESTER)
        viewer = _user(org.id, "viewer@verify-b1.example.com", UserRole.READ_ONLY)
        outsider = _user(other.id, "outsider@verify-b1.example.com", UserRole.ADMIN)
        s.add_all([tester, viewer, outsider])
        await s.flush()

        eng = _engagement(org.id, tester.id)
        s.add(eng)
        await s.flush()
        await _accept_roe(s, eng, [], tester.id)

        archive_t = Target(
            engagement_id=eng.id,
            name="uploaded-src",
            target_type=TargetType.SOURCE_ARCHIVE,
            primary_value="pending-upload",
        )
        web_t = Target(
            engagement_id=eng.id,
            name="web",
            target_type=TargetType.WEB_APP,
            primary_value="https://app.example.com/",
        )
        s.add_all([archive_t, web_t])
        await s.flush()

        svc = SessionService(s, cache, settings)
        t_tok = await svc.create_session(tester.id, UserRole.TESTER, now=utcnow())
        v_tok = await svc.create_session(viewer.id, UserRole.READ_ONLY, now=utcnow())
        o_tok = await svc.create_session(outsider.id, UserRole.ADMIN, now=utcnow())
        await s.commit()
        return {
            "org_id": org.id,
            "other_org_id": other.id,
            "user_id": tester.id,
            "eng_id": eng.id,
            "archive_target_id": archive_t.id,
            "web_target_id": web_t.id,
            "tokens": {"tester": t_tok, "viewer": v_tok, "outsider": o_tok},
        }


async def _part_a_http(ctx, settings, sm, store) -> None:  # noqa: ANN001
    cn = settings.session_cookie_name
    eng_id = ctx["eng_id"]
    at = ctx["archive_target_id"]
    good = _zip({"pkg/vulnerable.py": VULN_PY})
    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=30,
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        base = f"/engagements/{eng_id}/targets/{at}/source-archive"

        # read-only cannot upload (RBAC)
        r = await http.post(
            base,
            cookies={cn: ctx["tokens"]["viewer"]},
            files={"file": ("src.zip", good, "application/zip")},
        )
        check("read-only upload → 403", r.status_code == 403)

        # cross-org target → 404 (no IDOR)
        r = await http.post(
            base,
            cookies={cn: ctx["tokens"]["outsider"]},
            files={"file": ("src.zip", good, "application/zip")},
        )
        check("cross-org upload → 404", r.status_code == 404)

        # wrong target type → 422
        r = await http.post(
            f"/engagements/{eng_id}/targets/{ctx['web_target_id']}/source-archive",
            cookies={cn: ctx["tokens"]["tester"]},
            files={"file": ("src.zip", good, "application/zip")},
        )
        check("upload to non-archive target → 422", r.status_code == 422)

        # non-archive bytes → 422, nothing stored
        r = await http.post(
            base,
            cookies={cn: ctx["tokens"]["tester"]},
            files={"file": ("x.zip", b"not an archive", "application/zip")},
        )
        check("non-archive upload → 422", r.status_code == 422)

        # zip-slip archive → 422, nothing stored
        r = await http.post(
            base,
            cookies={cn: ctx["tokens"]["tester"]},
            files={"file": ("evil.zip", _zip_slip(), "application/zip")},
        )
        check("zip-slip upload → 422", r.status_code == 422)

        # happy path
        r = await http.post(
            base,
            cookies={cn: ctx["tokens"]["tester"]},
            files={"file": ("src.zip", good, "application/zip")},
        )
        check("valid upload → 200", r.status_code == 200)
        body = r.json() if r.status_code == 200 else {}
        check(
            "response carries evidence_id + object_key",
            bool(body.get("evidence_id")) and bool(body.get("object_key")),
        )
        check("archive_format is zip", body.get("archive_format") == "zip")

    # DB assertions for the happy upload
    async with sm() as s:
        target = await s.get(Target, at)
        check(
            "target.primary_value now the object key",
            target.primary_value == body.get("object_key"),
        )
        ev = (
            await s.execute(select(Evidence).where(Evidence.object_key == target.primary_value))
        ).scalar_one_or_none()
        check(
            "evidence row stored kind=source_archive",
            ev is not None and ev.kind is EvidenceKind.SOURCE_ARCHIVE,
        )
        # blob round-trips + hash matches the response
        blob = await load_evidence(s, store, ev.id)
        check(
            "stored blob is the uploaded zip (hash-verified)", zipfile.is_zipfile(io.BytesIO(blob))
        )
        check(
            "response sha matches stored evidence",
            body.get("content_sha256") == ev.content_sha256.hex(),
        )
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
        check("target.source_archive_uploaded audited", "target.source_archive_uploaded" in actions)
        # abuse attempts stored no extra source_archive evidence
        n = len(
            (await s.execute(select(Evidence).where(Evidence.kind == EvidenceKind.SOURCE_ARCHIVE)))
            .scalars()
            .all()
        )
        check("exactly one source_archive stored (abuse uploads persisted nothing)", n == 1)


async def _part_b_scan(ctx, sm, store) -> None:  # noqa: ANN001
    eng_id = ctx["eng_id"]
    at = ctx["archive_target_id"]
    async with sm() as s:
        eng = await s.get(Engagement, eng_id)
        target = await s.get(Target, at)
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
            initiated_by=ctx["user_id"],
            now=NOW,
            # NO source_path — the worker must derive it from the uploaded archive.
            config={"scanners": ["semgrep"]},
        )
        await s.commit()
        scan_id = scan.id

    owner = build_scanner_owner(sm, store, scan_id=scan_id, now=NOW, poll_s=0.1)
    final = await orchestrate_scan(
        sm,
        scan_id=scan_id,
        owner=owner,
        now=NOW,
        cancel_poll_s=0.1,
        run_spec=RunSpec(label=str(scan_id), argv=[]),
    )
    check("scan of uploaded archive finalized COMPLETED", final is ScanStatus.COMPLETED)

    async with sm() as s:
        sr = (
            await s.execute(select(ScannerRun).where(ScannerRun.scan_id == scan_id))
        ).scalar_one_or_none()
        check(
            "one semgrep scanner_run, COMPLETED",
            sr is not None and sr.status is ScanStatus.COMPLETED,
        )
        findings = (
            (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
            .scalars()
            .all()
        )
        check("semgrep found issues in the extracted archive (>=1 finding)", len(findings) >= 1)
        check(
            "findings automated + open + cite the scanner_run",
            all(
                f.provenance is FindingProvenance.AUTOMATED
                and f.status is FindingStatus.OPEN
                and f.scanner_run_id == sr.id
                for f in findings
            ),
        )
        check(
            "finding file locations point inside the uploaded tree",
            any("vulnerable.py" in (f.location.get("file") or "") for f in findings),
        )
        cited = True
        for f in findings:
            links = (
                (await s.execute(select(FindingEvidence).where(FindingEvidence.finding_id == f.id)))
                .scalars()
                .all()
            )
            if not any(link.evidence_id == sr.raw_evidence_id for link in links):
                cited = False
        check("every finding cites the raw scanner evidence", cited)


async def _cleanup(sm, org_ids, cache, tokens) -> None:  # noqa: ANN001
    async with sm() as s:
        await s.execute(text("SET session_replication_role = replica"))
        eng_ids = (
            (await s.execute(select(Engagement.id).where(Engagement.organization_id.in_(org_ids))))
            .scalars()
            .all()
        )
        scan_ids = (
            (await s.execute(select(Scan.id).where(Scan.engagement_id.in_(eng_ids))))
            .scalars()
            .all()
        )
        for tbl in (FindingEvidence, FindingStatusHistory):
            await s.execute(
                delete(tbl).where(
                    tbl.finding_id.in_(select(Finding.id).where(Finding.engagement_id.in_(eng_ids)))
                )
            )
        await s.execute(delete(Finding).where(Finding.engagement_id.in_(eng_ids)))
        await s.execute(delete(ScannerRun).where(ScannerRun.scan_id.in_(scan_ids)))
        await s.execute(delete(Evidence).where(Evidence.organization_id.in_(org_ids)))
        await s.execute(
            delete(ExecutionAuthorization).where(ExecutionAuthorization.engagement_id.in_(eng_ids))
        )
        await s.execute(delete(Scan).where(Scan.engagement_id.in_(eng_ids)))
        await s.execute(delete(AuditEvent).where(AuditEvent.organization_id.in_(org_ids)))
        await s.execute(
            delete(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id.in_(eng_ids))
        )
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
    store = create_evidence_store(settings)
    store.ensure_bucket()

    ctx = await _seed(sm, cache, settings)
    try:
        await _part_a_http(ctx, settings, sm, store)
        await _part_b_scan(ctx, sm, store)
    finally:
        await _cleanup(
            sm, [ctx["org_id"], ctx["other_org_id"]], cache, list(ctx["tokens"].values())
        )
        await cache.aclose()
        await engine.dispose()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
