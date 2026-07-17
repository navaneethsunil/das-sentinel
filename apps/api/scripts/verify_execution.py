"""Live verification of the M2-W3 SubprocessOwner inside the worker container
(Linux), where the confinement actually applies. Run:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_execution.py"

Proves the container-level guarantees unit tests on a dev Mac cannot: the child
runs with NoNewPrivs=1 (no-new-privileges really set), inherits the resource
limits, sees none of the worker's ambient env, gets a private scratch dir that is
wiped on teardown, and a cancelled run's process tree is confirmed gone. Then it
runs a real scan end to end through orchestrate_scan + SubprocessOwner (real PID
recorded, completed, audited). Cleans up after itself.
"""

import asyncio
import os
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.scope import Operation, OperationKind
from app.core.security import PasswordService
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
from app.models.identity import Organization, User
from app.models.scan import Scan, ScanStatus
from app.models.target import Target, TargetType
from app.services.roe import render_current_roe
from app.services.scans import launch_scan
from app.workers.execution import RunSpec, SubprocessOwner
from app.workers.orchestration import orchestrate_scan

failures: list[str] = []
NOW = datetime.now(UTC)


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


def _spec(code: str, *, timeout_s: float = 30.0) -> RunSpec:
    return RunSpec(label="v", argv=[sys.executable, "-c", code], env={}, timeout_s=timeout_s)


async def _owner_checks() -> None:
    owner = SubprocessOwner()

    # no-new-privileges really applied (Linux /proc proof)
    nnp = (
        "import sys\n"
        "v=[l for l in open('/proc/self/status') if l.startswith('NoNewPrivs')]\n"
        "sys.exit(0 if v and v[0].split()[1]=='1' else 3)"
    )
    h = await owner.launch(_spec(nnp))
    out = await owner.await_completion(h)
    await owner.teardown(h)
    check("child runs with NoNewPrivs=1", out.ok)

    # resource limit inherited
    rl = (
        "import resource,sys\n"
        "soft,_=resource.getrlimit(resource.RLIMIT_NOFILE)\n"
        "sys.exit(0 if soft==256 else 3)"
    )
    h = await owner.launch(_spec(rl))
    out = await owner.await_completion(h)
    await owner.teardown(h)
    check("child inherits RLIMIT_NOFILE=256", out.ok)

    # ambient env excluded
    os.environ["DASS_LIVE_SENTINEL"] = "secret"
    ae = "import os,sys; sys.exit(3 if 'DASS_LIVE_SENTINEL' in os.environ else 0)"
    h = await owner.launch(_spec(ae))
    out = await owner.await_completion(h)
    await owner.teardown(h)
    check("child excludes ambient worker env", out.ok)

    # scratch dir created then wiped on teardown
    h = await owner.launch(_spec("import sys; sys.exit(0)"))
    scratch = owner._runs[h.runner_ref].scratch  # inspect private state for the proof
    check(
        "per-run scratch dir created (0700)",
        scratch.exists() and (scratch.stat().st_mode & 0o777) == 0o700,
    )
    await owner.await_completion(h)
    await owner.teardown(h)
    check("scratch dir wiped on teardown", not scratch.exists())

    # cancel then verified teardown → process tree gone
    h = await owner.launch(_spec("import time; time.sleep(30)"))
    pid = int(h.runner_ref)
    await owner.cancel(h)
    await owner.teardown(h)
    gone = False
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        gone = True
    check("cancelled run's process tree confirmed gone", gone)

    # timeout reported
    h = await owner.launch(_spec("import time; time.sleep(30)", timeout_s=0.2))
    out = await owner.await_completion(h)
    await owner.teardown(h)
    check("run timeout reported", (not out.ok) and "timeout" in (out.detail or ""))


async def _integration_check(sm, *, org_id, user_id) -> None:
    async with sm() as s:
        eng = Engagement(
            organization_id=org_id,
            name="w3-eng",
            client_system_name="acme",
            status=EngagementStatus.ACTIVE,
            test_window_start=NOW - timedelta(days=1),
            test_window_end=NOW + timedelta(days=1),
            rate_limit_rps=5,
            max_intensity=ScanIntensity.SAFE_ACTIVE,
            created_by=user_id,
        )
        s.add(eng)
        await s.flush()
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
        s.add_all([scope, target])
        await s.flush()
        _, _, terms, chash = render_current_roe(eng, [scope])
        ack = ROEAcknowledgement(
            engagement_id=eng.id,
            accepted_by=user_id,
            accepted_at=NOW - timedelta(hours=1),
            roe_text="frozen",
            scope_snapshot=[],
            terms_snapshot=terms,
            content_hash=chash,
        )
        s.add(ack)
        await s.flush()
        scan = await launch_scan(
            s,
            engagement=eng,
            target=target,
            scope_items=[scope],
            op=Operation(target_id=target.id, kind=OperationKind.SAFE_ACTIVE_SCAN),
            roe_ack=ack,
            initiated_by=user_id,
            now=NOW,
        )
        await s.commit()
        scan_id = scan.id

    status = await orchestrate_scan(sm, scan_id=scan_id, owner=SubprocessOwner(), now=NOW)
    check("integration: scan completed via SubprocessOwner", status is ScanStatus.COMPLETED)
    async with sm() as s:
        row = await s.get(Scan, scan_id)
        check("integration: runner_ref is a real PID", (row.runner_ref or "").isdigit())
        actions = (
            await s.execute(
                select(AuditEvent.action, AuditEvent.outcome).where(AuditEvent.object_id == scan_id)
            )
        ).all()
        check(
            "integration: start+complete audited",
            ("scan.started", AuditOutcome.SUCCESS) in actions
            and ("scan.completed", AuditOutcome.SUCCESS) in actions,
        )


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)

    await _owner_checks()

    async with sm() as s:
        org = Organization(name="verify-exec-org")
        s.add(org)
        await s.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-exec@example.com",
            password_hash=pw.hash("verify-exec-throwaway"),
            display_name="Verify Exec",
        )
        s.add(user)
        await s.flush()
        user_id = user.id
        await s.commit()

    await _integration_check(sm, org_id=org_id, user_id=user_id)

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        for model in (Scan, ScopeItem, ROEAcknowledgement, Target):
            await conn.execute(
                delete(model).where(
                    model.engagement_id.in_(
                        select(Engagement.id).where(Engagement.organization_id == org_id)
                    )
                )
            )
        # execution_authorizations references engagements too
        await conn.execute(
            text(
                "DELETE FROM execution_authorizations WHERE engagement_id IN "
                "(SELECT id FROM engagements WHERE organization_id = :o)"
            ),
            {"o": str(org_id)},
        )
        await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
