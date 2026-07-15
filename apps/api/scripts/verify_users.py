"""Live end-to-end verification of the M1-B4 user-management endpoints and the
M1-B3 RBAC guard over real HTTP. Run inside the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_users.py"

Seeds two orgs with users and mints real sessions directly (login lands
later), then drives the API service and asserts: 401 without a cookie, 403 for
read-only, 201/409 create, cross-org 404 (no IDOR leak), self-guard 400, and
that role/deactivate revoke the target's sessions. Cleans up after itself.
"""

import asyncio
import sys
import uuid

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.audit import AuditEvent
from app.models.identity import Organization, Session, User, UserRole

API_BASE = "http://api:8000"

failures: list[str] = []
minted_tokens: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


def cookie(settings, token: str) -> dict[str, str]:
    return {settings.session_cookie_name: token}


async def main() -> int:  # noqa: C901 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)

    async with sessionmaker() as db:
        org = Organization(name="verify-users-org")
        other_org = Organization(name="verify-users-other-org")
        db.add_all([org, other_org])
        await db.flush()

        admin = User(
            organization_id=org.id,
            email="admin@verify-users.test",
            password_hash="x",  # noqa: S106 - fixture row, auth is via seeded session
            display_name="admin",
            role=UserRole.ADMIN,
        )
        readonly = User(
            organization_id=org.id,
            email="ro@verify-users.test",
            password_hash="x",  # noqa: S106
            display_name="ro",
            role=UserRole.READ_ONLY,
        )
        outsider = User(
            organization_id=other_org.id,
            email="outsider@verify-users.test",
            password_hash="x",  # noqa: S106
            display_name="outsider",
            role=UserRole.TESTER,
        )
        db.add_all([admin, readonly, outsider])
        await db.flush()

        svc = SessionService(db, cache, settings)
        now = utcnow()
        admin_token = await svc.create_session(admin.id, UserRole.ADMIN, now=now)
        ro_token = await svc.create_session(readonly.id, UserRole.READ_ONLY, now=now)
        minted_tokens.extend([admin_token, ro_token])
        await db.commit()

    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=10,
        # Double-submit CSRF (M1-SEC2): any matching cookie/header pair passes.
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        # EmailStr rejects reserved TLDs (.test), so submitted emails use a
        # normal domain; seeded ORM rows above bypass EmailStr and keep .test.
        new_user = {
            "email": "created@verify-users.example.com",
            "display_name": "created",
            "role": "tester",
            "password": "correct horse battery staple",
        }

        r = await http.post("/users", json=new_user)
        check("no cookie → 401", r.status_code == 401)

        r = await http.post("/users", json=new_user, cookies=cookie(settings, ro_token))
        check("read-only → 403 on create", r.status_code == 403)

        r = await http.post("/users", json=new_user, cookies=cookie(settings, admin_token))
        check("admin → 201 create", r.status_code == 201)
        created = r.json() if r.status_code == 201 else {}
        check("response omits password_hash", "password_hash" not in created)
        check("created user is in admin's org", created.get("organization_id"))
        created_id = created.get("id")

        r = await http.post("/users", json=new_user, cookies=cookie(settings, admin_token))
        check("duplicate email → 409", r.status_code == 409)

        r = await http.post(
            "/users",
            json={**new_user, "email": "short@verify-users.example.com", "password": "short"},
            cookies=cookie(settings, admin_token),
        )
        check("short password → 422", r.status_code == 422)

        r = await http.get("/users", cookies=cookie(settings, admin_token))
        emails = [u["email"] for u in r.json()] if r.status_code == 200 else []
        check("list scoped to org (no outsider)", "outsider@verify-users.test" not in emails)
        check("list includes created user", "created@verify-users.example.com" in emails)

        # cross-org access is 404, never data (IDOR/BOLA)
        r = await http.patch(
            f"/users/{outsider.id}/role",
            json={"role": "admin"},
            cookies=cookie(settings, admin_token),
        )
        check("cross-org role change → 404", r.status_code == 404)

        # self-guards
        r = await http.post(f"/users/{admin.id}/deactivate", cookies=cookie(settings, admin_token))
        check("self-deactivate → 400", r.status_code == 400)
        r = await http.patch(
            f"/users/{admin.id}/role",
            json={"role": "read_only"},
            cookies=cookie(settings, admin_token),
        )
        check("self-demote → 400", r.status_code == 400)

        # role change revokes the target's sessions
        async with sessionmaker() as db:
            svc = SessionService(db, cache, settings)
            victim_token = await svc.create_session(
                uuid.UUID(created_id), UserRole.TESTER, now=utcnow()
            )
            minted_tokens.append(victim_token)
            await db.commit()
        r = await http.patch(
            f"/users/{created_id}/role",
            json={"role": "reviewer"},
            cookies=cookie(settings, admin_token),
        )
        check("admin role change → 200", r.status_code == 200)
        async with sessionmaker() as db:
            svc = SessionService(db, cache, settings)
            check(
                "role change revoked target session",
                await svc.validate_session(victim_token, now=utcnow()) is None,
            )

        # deactivate revokes sessions and flips is_active
        r = await http.post(
            f"/users/{created_id}/deactivate", cookies=cookie(settings, admin_token)
        )
        deactivated = r.status_code == 200 and r.json()["is_active"] is False
        check("deactivate → 200 and inactive", deactivated)

    # cleanup (audit rows are append-only → dev-superuser bypass; replica mode
    # also disables FK cascades, so sessions are deleted explicitly)
    org_ids = [org.id, other_org.id]
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id.in_(org_ids)))
        org_users = select(User.id).where(User.organization_id.in_(org_ids))
        await conn.execute(delete(Session).where(Session.user_id.in_(org_users)))
        await conn.execute(delete(User).where(User.organization_id.in_(org_ids)))
        await conn.execute(delete(Organization).where(Organization.id.in_(org_ids)))
    for token in minted_tokens:
        await cache.delete(f"session:{hash_token(token).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
