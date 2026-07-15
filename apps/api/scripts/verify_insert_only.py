"""M1-SEC4: prove roe_acknowledgements and audit_events are insert-only
(UPDATE/DELETE denied) — TM-9. Run inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_insert_only.py"

(evidence is the third insert-only table but arrives in M3.) Cleanup uses the
dev-superuser trigger bypass — the same bypass a production app role must NOT
have; that role-level REVOKE is the hardening complement to these triggers.
"""

import asyncio
import sys

from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.models.audit import AuditEvent, AuditOutcome
from app.models.engagement import Engagement, ROEAcknowledgement
from app.models.identity import Organization, User, UserRole

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def _denied(engine, sql: str, params: dict) -> bool:
    """True iff the statement is rejected by the DB (append-only trigger)."""
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params)
        return False
    except Exception:
        return True


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)

    async with sessionmaker() as db:
        org = Organization(name="insertonly-org")
        db.add(org)
        await db.flush()
        user = User(
            organization_id=org.id,
            email="io@insertonly.test",
            password_hash="x",  # noqa: S106
            display_name="io",
            role=UserRole.TESTER,
        )
        db.add(user)
        await db.flush()
        eng = Engagement(
            organization_id=org.id,
            created_by=user.id,
            name="io-eng",
            client_system_name="sys",
        )
        db.add(eng)
        await db.flush()
        roe = ROEAcknowledgement(
            engagement_id=eng.id,
            accepted_by=user.id,
            roe_text="frozen",
            scope_snapshot=[],
            terms_snapshot={},
            content_hash=b"\x00" * 32,
        )
        event = AuditEvent(
            organization_id=org.id,
            actor_user_id=user.id,
            action="test.seed",
            object_type="test",
            outcome=AuditOutcome.SUCCESS,
        )
        db.add_all([roe, event])
        await db.flush()
        await db.commit()
        org_id, eng_id, user_id = org.id, eng.id, user.id
        roe_id, event_id = roe.id, event.id

    check(
        "roe_acknowledgements UPDATE denied",
        await _denied(
            engine,
            "UPDATE roe_acknowledgements SET roe_text='tampered' WHERE id=:i",
            {"i": str(roe_id)},
        ),
    )
    check(
        "roe_acknowledgements DELETE denied",
        await _denied(engine, "DELETE FROM roe_acknowledgements WHERE id=:i", {"i": str(roe_id)}),
    )
    check(
        "audit_events UPDATE denied",
        await _denied(
            engine, "UPDATE audit_events SET action='tampered' WHERE id=:i", {"i": str(event_id)}
        ),
    )
    check(
        "audit_events DELETE denied",
        await _denied(engine, "DELETE FROM audit_events WHERE id=:i", {"i": str(event_id)}),
    )

    # rows survived intact
    async with sessionmaker() as db:
        roe_text = (
            await db.execute(
                select(ROEAcknowledgement.roe_text).where(ROEAcknowledgement.id == roe_id)
            )
        ).scalar_one_or_none()
        action = (
            await db.execute(select(AuditEvent.action).where(AuditEvent.id == event_id))
        ).scalar_one_or_none()
    check("roe row survived unchanged", roe_text == "frozen")
    check("audit row survived unchanged", action == "test.seed")

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        await conn.execute(
            delete(ROEAcknowledgement).where(ROEAcknowledgement.engagement_id == eng_id)
        )
        await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await conn.execute(delete(User).where(User.id == user_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
