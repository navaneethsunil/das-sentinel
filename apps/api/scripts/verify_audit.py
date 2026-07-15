"""Live verification of the M1-B5 audit middleware + append-only guarantee.
Run inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx python scripts/verify_audit.py"

Drives real requests and asserts the middleware records a success event for an
allowed state change, a BLOCKED event for a 403, nothing for a GET, and that
the row cannot be updated (append-only trigger, TM-9).

Cleanup deletes the throwaway rows via `session_replication_role = replica`,
which only the DEV superuser can do — the production app DB role cannot, so the
immutability guarantee this test relies on still holds where it matters.
"""

import asyncio
import sys

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.audit import AuditEvent, AuditOutcome
from app.models.identity import Organization, Session, User, UserRole

API_BASE = "http://api:8000"

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)
    tokens: list[str] = []

    async with sessionmaker() as db:
        org = Organization(name="verify-audit-org")
        db.add(org)
        await db.flush()
        admin = User(
            organization_id=org.id,
            email="admin@verify-audit.test",
            password_hash="x",  # noqa: S106 - fixture row
            display_name="admin",
            role=UserRole.ADMIN,
        )
        readonly = User(
            organization_id=org.id,
            email="ro@verify-audit.test",
            password_hash="x",  # noqa: S106
            display_name="ro",
            role=UserRole.READ_ONLY,
        )
        db.add_all([admin, readonly])
        await db.flush()
        svc = SessionService(db, cache, settings)
        now = utcnow()
        admin_token = await svc.create_session(admin.id, UserRole.ADMIN, now=now)
        ro_token = await svc.create_session(readonly.id, UserRole.READ_ONLY, now=now)
        tokens += [admin_token, ro_token]
        await db.commit()
        org_id, admin_id, ro_id = org.id, admin.id, readonly.id

    cn = settings.session_cookie_name
    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=10,
        # Double-submit CSRF (M1-SEC2): any matching cookie/header pair passes.
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        await http.post(
            "/users",
            json={
                "email": "made@verify-audit.example.com",
                "display_name": "made",
                "role": "read_only",
                "password": "correct horse battery staple",
            },
            cookies={cn: admin_token},
        )
        await http.post("/users", json={}, cookies={cn: ro_token})  # 403 (read-only)
        await http.get("/users", cookies={cn: admin_token})  # not state-changing

    async with sessionmaker() as db:
        events = (
            (
                await db.execute(
                    select(AuditEvent)
                    .where(AuditEvent.organization_id == org_id)
                    .order_by(AuditEvent.created_at)
                )
            )
            .scalars()
            .all()
        )

    by = [(e.action, e.actor_user_id, e.outcome) for e in events]
    check(
        "success event for allowed POST by admin",
        ("POST /users", admin_id, AuditOutcome.SUCCESS) in by,
    )
    check(
        "blocked event for 403 POST by read-only",
        ("POST /users", ro_id, AuditOutcome.BLOCKED) in by,
    )
    check("no audit event for GET", not any(a.startswith("GET") for a, _, _ in by))
    check("events carry the actor", all(actor is not None for _, actor, _ in by))

    # append-only: the row cannot be mutated (M1-D4 trigger)
    append_only_held = False
    if events:
        try:
            async with engine.begin() as conn:
                await conn.execute(
                    text("UPDATE audit_events SET action='tampered' WHERE id = :i"),
                    {"i": str(events[0].id)},
                )
        except Exception:
            append_only_held = True
    check("audit row is immutable (UPDATE denied)", append_only_held)

    # dev-only cleanup: bypass the immutability trigger to remove throwaway rows.
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        await conn.execute(delete(Session).where(Session.user_id.in_([admin_id, ro_id])))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    for token in tokens:
        await cache.delete(f"session:{hash_token(token).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
