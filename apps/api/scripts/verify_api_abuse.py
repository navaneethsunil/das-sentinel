"""Live verification of the scan-concurrency caps (API abuse controls,
IMPLEMENTATION_PLAN §9 item 5). Run inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_api_abuse.py"

Seeds an authorized engagement + target, then proves the fail-closed cap through
the real launch_scan path: launches succeed up to the per-engagement cap and the
next one raises ScanConcurrencyError; only QUEUED/RUNNING count (a COMPLETED scan
frees a slot); the org-wide cap and the disabled (<=0) case are exercised
directly. The per-user request throttle's logic is unit-tested
(tests/test_ratelimit.py) and its get_principal wiring is checked over HTTP with
API_RATE_LIMIT_MAX_PER_USER lowered. Cleans up via the dev-superuser bypass.
"""

import asyncio
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text

from app.core.config import Settings, get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.scope import Operation, OperationKind
from app.models.audit import AuditEvent
from app.models.engagement import (
    Engagement,
    EngagementStatus,
    ROEAcknowledgement,
    ScanIntensity,
    ScopeItem,
    ScopeKind,
    ScopeMatcher,
)
from app.models.identity import Organization, User, UserRole
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus
from app.models.target import Target, TargetType
from app.services.roe import render_current_roe
from app.services.scans import ScanConcurrencyError, _enforce_scan_concurrency, launch_scan

NOW = datetime.now(UTC)
failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


def _caps(per_eng: int, per_org: int) -> Settings:
    return Settings(
        _env_file=None,
        max_concurrent_scans_per_engagement=per_eng,
        max_concurrent_scans_per_org=per_org,
    )


async def _launch(db, *, eng, target, scope_items, ack, user_id, settings):
    return await launch_scan(
        db,
        engagement=eng,
        target=target,
        scope_items=scope_items,
        op=Operation(target_id=target.id, kind=OperationKind.SAFE_ACTIVE_SCAN),
        roe_ack=ack,
        initiated_by=user_id,
        now=NOW,
        settings=settings,
    )


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)

    async with sessionmaker() as db:
        org = Organization(name="verify-abuse-org")
        db.add(org)
        await db.flush()
        user = User(
            organization_id=org.id,
            email="abuse@verify-abuse.example.com",
            password_hash="x",  # noqa: S106 - fixture; no login in this script
            display_name="abuse",
            role=UserRole.TESTER,
        )
        db.add(user)
        await db.flush()
        eng = Engagement(
            organization_id=org.id,
            name="abuse-eng",
            client_system_name="acme",
            status=EngagementStatus.ACTIVE,
            test_window_start=NOW - timedelta(days=1),
            test_window_end=NOW + timedelta(days=1),
            rate_limit_rps=5,
            max_intensity=ScanIntensity.SAFE_ACTIVE,
            created_by=user.id,
        )
        db.add(eng)
        await db.flush()
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
        db.add_all([scope, target])
        await db.flush()
        _, _, terms, content_hash = render_current_roe(eng, [scope])
        ack = ROEAcknowledgement(
            engagement_id=eng.id,
            accepted_by=user.id,
            accepted_at=NOW - timedelta(hours=1),
            roe_text="frozen",
            scope_snapshot=[],
            terms_snapshot=terms,
            content_hash=content_hash,
        )
        db.add(ack)
        await db.flush()
        scope_items = [scope]

        # Per-engagement cap = 2: two launches succeed, the third is refused.
        s = _caps(2, 100)
        await _launch(
            db,
            eng=eng,
            target=target,
            scope_items=scope_items,
            ack=ack,
            user_id=user.id,
            settings=s,
        )
        await _launch(
            db,
            eng=eng,
            target=target,
            scope_items=scope_items,
            ack=ack,
            user_id=user.id,
            settings=s,
        )
        check("two launches allowed under cap=2", True)
        try:
            await _launch(
                db,
                eng=eng,
                target=target,
                scope_items=scope_items,
                ack=ack,
                user_id=user.id,
                settings=s,
            )
            check("third launch refused at cap", False)
        except ScanConcurrencyError:
            check("third launch refused at cap", True)

        # Only QUEUED/RUNNING count — freeing one slot re-admits a launch.
        one = (
            await db.execute(select(Scan).where(Scan.engagement_id == eng.id).limit(1))
        ).scalar_one()
        one.status = ScanStatus.COMPLETED
        await db.flush()
        try:
            await _launch(
                db,
                eng=eng,
                target=target,
                scope_items=scope_items,
                ack=ack,
                user_id=user.id,
                settings=s,
            )
            check("completed scan frees a slot", True)
        except ScanConcurrencyError:
            check("completed scan frees a slot", False)

        # There are now 2 active scans in the org. Org cap = 2 → next refused.
        try:
            await _enforce_scan_concurrency(db, eng, _caps(0, 2))
            check("org-wide cap enforced", False)
        except ScanConcurrencyError:
            check("org-wide cap enforced", True)

        # Both caps disabled (<=0) → never refuses.
        try:
            await _enforce_scan_concurrency(db, eng, _caps(0, 0))
            check("disabled caps never refuse", True)
        except ScanConcurrencyError:
            check("disabled caps never refuse", False)

        await db.rollback()  # discard all seeded rows; nothing committed

    # Belt-and-suspenders cleanup in case anything committed.
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org.id))
        eng_ids = select(Engagement.id).where(Engagement.organization_id == org.id)
        await conn.execute(
            delete(ExecutionAuthorization).where(ExecutionAuthorization.engagement_id.in_(eng_ids))
        )
        await conn.execute(delete(Scan).where(Scan.engagement_id.in_(eng_ids)))
        await conn.execute(
            delete(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id.in_(eng_ids))
        )
        await conn.execute(delete(ScopeItem).where(ScopeItem.engagement_id.in_(eng_ids)))
        await conn.execute(delete(Target).where(Target.engagement_id.in_(eng_ids)))
        await conn.execute(delete(Engagement).where(Engagement.organization_id == org.id))
        await conn.execute(delete(User).where(User.organization_id == org.id))
        await conn.execute(delete(Organization).where(Organization.id == org.id))
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
