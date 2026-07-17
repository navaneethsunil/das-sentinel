"""Live verification of M2-W2 emergency stop. Run inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_emergency_stop.py"

Proves the two halves of emergency stop (§2.10):

  A. WORKER (the real safety guarantee): a scan whose run is a live, blocking
     child process reaches RUNNING with a real PID; requesting cancellation
     mid-flight makes the supervisor terminate the process group (SIGTERM→
     SIGKILL) and CONFIRM the tree is gone, mark the scan cancelled, and audit
     it. A single `await_completion` would otherwise block until the sleep ends.

  B. SIGNAL PATH (HTTP): POST …/scans/{id}/cancel sets `cancel_requested` and
     audits `scan.cancel_requested` — guarded by LAUNCH_SCANS (read-only denied),
     org/engagement-scoped (cross-org 404), idempotent, and 409 on a finished
     scan. GET …/scans/{id} reports live status.

Uses a real SubprocessOwner for (A). Cleans up via the dev-superuser bypass.
"""

import asyncio
import os
import shutil
import sys
import uuid
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
    ScopeKind,
    ScopeMatcher,
)
from app.models.identity import Organization, Session, User, UserRole
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus
from app.models.target import Target, TargetType
from app.services.roe import render_current_roe
from app.services.scans import launch_scan
from app.workers.execution import RunSpec, SubprocessOwner
from app.workers.orchestration import orchestrate_scan

API_BASE = "http://api:8000"
SLEEP = shutil.which("sleep") or "/bin/sleep"
NOW = datetime.now(UTC)
failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


def _pg_alive(pgid: int) -> bool:
    """True iff the process group still exists (signal 0 probes without killing)."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but not ours to signal
    return True


async def _seed_engagement(session, *, org_id, user_id):
    eng = Engagement(
        organization_id=org_id,
        name="estop-eng",
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
        value="app.example.com",
    )
    target = Target(
        engagement_id=eng.id,
        name="web",
        target_type=TargetType.WEB_APP,
        primary_value="https://app.example.com/",
    )
    session.add_all([scope, target])
    await session.flush()
    _, _, terms, content_hash = render_current_roe(eng, [scope])
    ack = ROEAcknowledgement(
        engagement_id=eng.id,
        accepted_by=user_id,
        accepted_at=NOW - timedelta(hours=1),
        roe_text="frozen",
        scope_snapshot=[],
        terms_snapshot=terms,
        content_hash=content_hash,
    )
    session.add(ack)
    await session.flush()
    return eng, target, ack


async def _launch_queued(session, *, eng, target, ack, user_id) -> uuid.UUID:
    scope_items = list(
        (
            await session.execute(select(ScopeItem).where(ScopeItem.engagement_id == eng.id))
        ).scalars()
    )
    scan = await launch_scan(
        session,
        engagement=eng,
        target=target,
        scope_items=scope_items,
        op=Operation(target_id=target.id, kind=OperationKind.SAFE_ACTIVE_SCAN),
        roe_ack=ack,
        initiated_by=user_id,
        now=NOW,
    )
    return scan.id


async def _audit_actions(session, scan_id) -> list[tuple[str, AuditOutcome]]:
    rows = (
        await session.execute(
            select(AuditEvent.action, AuditEvent.outcome).where(AuditEvent.object_id == scan_id)
        )
    ).all()
    return [(r[0], r[1]) for r in rows]


async def main() -> int:  # noqa: C901, PLR0912, PLR0915 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)
    tokens: list[str] = []
    pw = PasswordService(settings.password_hash_scheme)

    # ── seed org + users (tester can stop, viewer cannot; other org for 404) ──
    async with sm() as s:
        org = Organization(name="verify-estop-org")
        other = Organization(name="verify-estop-other")
        s.add_all([org, other])
        await s.flush()
        tester = User(
            organization_id=org.id,
            email="tester@verify-estop.example.com",
            password_hash=pw.hash("x-throwaway"),
            display_name="tester",
            role=UserRole.TESTER,
        )
        viewer = User(
            organization_id=org.id,
            email="viewer@verify-estop.example.com",
            password_hash=pw.hash("x-throwaway"),
            display_name="viewer",
            role=UserRole.READ_ONLY,
        )
        outsider = User(
            organization_id=other.id,
            email="admin@verify-estop-other.example.com",
            password_hash=pw.hash("x-throwaway"),
            display_name="outsider",
            role=UserRole.ADMIN,
        )
        s.add_all([tester, viewer, outsider])
        await s.flush()
        eng, target, ack = await _seed_engagement(s, org_id=org.id, user_id=tester.id)
        # (A) a scan we will run as a live blocking process and cancel mid-flight.
        mid_id = await _launch_queued(s, eng=eng, target=target, ack=ack, user_id=tester.id)
        # (B) an already-running scan for the HTTP signal-path checks.
        http_id = await _launch_queued(s, eng=eng, target=target, ack=ack, user_id=tester.id)
        (await s.get(Scan, http_id)).status = ScanStatus.RUNNING
        # (B) a finished scan → cancel must 409.
        done_id = await _launch_queued(s, eng=eng, target=target, ack=ack, user_id=tester.id)
        (await s.get(Scan, done_id)).status = ScanStatus.COMPLETED
        svc = SessionService(s, cache, settings)
        tester_token = await svc.create_session(tester.id, UserRole.TESTER, now=utcnow())
        viewer_token = await svc.create_session(viewer.id, UserRole.READ_ONLY, now=utcnow())
        outsider_token = await svc.create_session(outsider.id, UserRole.ADMIN, now=utcnow())
        tokens += [tester_token, viewer_token, outsider_token]
        await s.commit()
        org_id, other_id = org.id, other.id
        eng_id = eng.id
        user_ids = [tester.id, viewer.id, outsider.id]

    # ── Part A: worker mid-run emergency stop against a real child process ────
    owner = SubprocessOwner()
    spec = RunSpec(label=str(mid_id), argv=[SLEEP, "30"], env={}, timeout_s=120.0)
    task = asyncio.ensure_future(
        orchestrate_scan(sm, scan_id=mid_id, owner=owner, now=NOW, cancel_poll_s=0.1, run_spec=spec)
    )
    pgid: int | None = None
    for _ in range(200):  # up to ~10s for the run to reach RUNNING with a live pid
        await asyncio.sleep(0.05)
        async with sm() as s:
            row = await s.get(Scan, mid_id)
            if row.status is ScanStatus.RUNNING and row.runner_ref:
                pgid = int(row.runner_ref)
                break
    check("mid-run: scan reached RUNNING with a real pid", pgid is not None)
    check("mid-run: launched process group is alive", pgid is not None and _pg_alive(pgid))

    async with sm() as s:  # request emergency stop while the run is in flight
        (await s.get(Scan, mid_id)).cancel_requested = True
        await s.commit()

    status = await asyncio.wait_for(task, timeout=30)
    check("mid-run: orchestrate returned CANCELLED", status is ScanStatus.CANCELLED)
    check("mid-run: process group terminated (tree gone)", pgid is not None and not _pg_alive(pgid))
    async with sm() as s:
        row = await s.get(Scan, mid_id)
        check("mid-run: scan marked cancelled", row.status is ScanStatus.CANCELLED)
        check("mid-run: finished_at set", row.finished_at is not None)
        actions = await _audit_actions(s, mid_id)
        check(
            "mid-run: started + cancelled audited",
            ("scan.started", AuditOutcome.SUCCESS) in actions
            and ("scan.cancelled", AuditOutcome.SUCCESS) in actions,
        )

    # ── Part B: HTTP signal path ──────────────────────────────────────────────
    cn = settings.session_cookie_name
    base = f"/engagements/{eng_id}/scans"
    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=10,
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        # read-only cannot cancel (LAUNCH_SCANS is Admin/Tester)
        r = await http.post(f"{base}/{http_id}/cancel", cookies={cn: viewer_token})
        check("http: read-only cannot cancel (403)", r.status_code == 403)

        # GET status (VIEW) before cancel
        r = await http.get(f"{base}/{http_id}", cookies={cn: tester_token})
        check("http: get status 200", r.status_code == 200)
        check(
            "http: status running, not yet cancel-requested",
            r.status_code == 200
            and r.json()["status"] == "running"
            and r.json()["cancel_requested"] is False,
        )

        # tester cancels → 200, flag set in the response body
        r = await http.post(f"{base}/{http_id}/cancel", cookies={cn: tester_token})
        check(
            "http: tester cancel 200 + cancel_requested true",
            r.status_code == 200 and r.json()["cancel_requested"] is True,
        )

        # idempotent: a second cancel still succeeds
        r = await http.post(f"{base}/{http_id}/cancel", cookies={cn: tester_token})
        check("http: repeat cancel is idempotent (200)", r.status_code == 200)

        # finished scan → 409
        r = await http.post(f"{base}/{done_id}/cancel", cookies={cn: tester_token})
        check("http: cancel finished scan 409", r.status_code == 409)

        # cross-org → 404 (no leak)
        r = await http.post(f"{base}/{http_id}/cancel", cookies={cn: outsider_token})
        check("http: cross-org cancel 404", r.status_code == 404)

        # unknown scan id → 404
        r = await http.post(f"{base}/{uuid.uuid4()}/cancel", cookies={cn: tester_token})
        check("http: unknown scan 404", r.status_code == 404)

    async with sm() as s:
        row = await s.get(Scan, http_id)
        check("http: DB flag set after cancel", row.cancel_requested is True)
        actions = await _audit_actions(s, http_id)
        check(
            "http: scan.cancel_requested audited",
            ("scan.cancel_requested", AuditOutcome.SUCCESS) in actions,
        )

    # ── cleanup (insert-only tables → dev-superuser trigger bypass) ───────────
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(
            delete(AuditEvent).where(AuditEvent.organization_id.in_([org_id, other_id]))
        )
        await conn.execute(
            delete(ExecutionAuthorization).where(ExecutionAuthorization.engagement_id == eng_id)
        )
        await conn.execute(delete(Scan).where(Scan.engagement_id == eng_id))
        await conn.execute(
            delete(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id == eng_id)
        )
        await conn.execute(delete(ScopeItem).where(ScopeItem.engagement_id == eng_id))
        await conn.execute(delete(Target).where(Target.engagement_id == eng_id))
        await conn.execute(delete(Session).where(Session.user_id.in_(user_ids)))
        await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await conn.execute(delete(User).where(User.organization_id.in_([org_id, other_id])))
        await conn.execute(delete(Organization).where(Organization.id.in_([org_id, other_id])))
    for token in tokens:
        await cache.delete(f"session:{hash_token(token).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
