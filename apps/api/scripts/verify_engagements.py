"""Live end-to-end verification of the M1-B6 engagement endpoints. Run inside
the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_engagements.py"

Asserts create/read/update, the draft→active→paused→closed machine (valid +
rejected transitions), RBAC (read-only 403, viewer can read), org scoping
(cross-org 404), soft-delete, and that a domain audit event is recorded for a
status change. Cleans up via the dev-superuser trigger bypass (audit rows are
append-only).
"""

import asyncio
import sys

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.audit import AuditEvent
from app.models.engagement import Engagement
from app.models.identity import Organization, Session, User, UserRole

API_BASE = "http://api:8000"
failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def main() -> int:  # noqa: C901 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)
    tokens: list[str] = []

    async with sessionmaker() as db:
        org = Organization(name="verify-eng-org")
        other = Organization(name="verify-eng-other")
        db.add_all([org, other])
        await db.flush()
        tester = User(
            organization_id=org.id,
            email="tester@verify-eng.test",
            password_hash="x",  # noqa: S106
            display_name="tester",
            role=UserRole.TESTER,
        )
        readonly = User(
            organization_id=org.id,
            email="ro@verify-eng.test",
            password_hash="x",  # noqa: S106
            display_name="ro",
            role=UserRole.READ_ONLY,
        )
        outsider = User(
            organization_id=other.id,
            email="outsider@verify-eng.test",
            password_hash="x",  # noqa: S106
            display_name="outsider",
            role=UserRole.TESTER,
        )
        db.add_all([tester, readonly, outsider])
        await db.flush()
        svc = SessionService(db, cache, settings)
        now = utcnow()
        tester_token = await svc.create_session(tester.id, UserRole.TESTER, now=now)
        ro_token = await svc.create_session(readonly.id, UserRole.READ_ONLY, now=now)
        out_token = await svc.create_session(outsider.id, UserRole.TESTER, now=now)
        tokens += [tester_token, ro_token, out_token]
        await db.commit()
        org_id, other_id = org.id, other.id
        user_ids = [tester.id, readonly.id, outsider.id]

    cn = settings.session_cookie_name
    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=10,
        # Double-submit CSRF (M1-SEC2): any matching cookie/header pair passes.
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        payload = {"name": "Acme Q3 pentest", "client_system_name": "acme-web"}

        r = await http.post("/engagements", json=payload, cookies={cn: ro_token})
        check("read-only cannot create (403)", r.status_code == 403)

        r = await http.post("/engagements", json=payload, cookies={cn: tester_token})
        check("tester creates engagement (201)", r.status_code == 201)
        eng = r.json() if r.status_code == 201 else {}
        eng_id = eng.get("id")
        check("new engagement starts draft", eng.get("status") == "draft")
        check(
            "defaults: safe_active, hosted off",
            eng.get("max_intensity") == "safe_active" and eng.get("hosted_models_allowed") is False,
        )

        # bad window rejected (422)
        r = await http.post(
            "/engagements",
            json={
                **payload,
                "test_window_start": "2026-08-02T00:00:00Z",
                "test_window_end": "2026-08-01T00:00:00Z",
            },
            cookies={cn: tester_token},
        )
        check("window end<=start rejected (422)", r.status_code == 422)

        # read-only CAN view
        r = await http.get(f"/engagements/{eng_id}", cookies={cn: ro_token})
        check("read-only can view engagement (200)", r.status_code == 200)

        # cross-org read is 404 (no IDOR leak)
        r = await http.get(f"/engagements/{eng_id}", cookies={cn: out_token})
        check("cross-org read → 404", r.status_code == 404)

        # update fields
        r = await http.patch(
            f"/engagements/{eng_id}",
            json={"rate_limit_rps": 20, "max_intensity": "authenticated_active"},
            cookies={cn: tester_token},
        )
        check(
            "update applies fields",
            r.status_code == 200
            and r.json()["rate_limit_rps"] == 20
            and r.json()["max_intensity"] == "authenticated_active",
        )

        # invalid transition draft→paused rejected (409)
        r = await http.post(
            f"/engagements/{eng_id}/status", json={"status": "paused"}, cookies={cn: tester_token}
        )
        check("invalid transition draft→paused → 409", r.status_code == 409)

        # valid path draft→active→paused→active→closed
        seq = ["active", "paused", "active", "closed"]
        ok = True
        for target in seq:
            r = await http.post(
                f"/engagements/{eng_id}/status",
                json={"status": target},
                cookies={cn: tester_token},
            )
            ok = ok and r.status_code == 200 and r.json()["status"] == target
        check("valid transition chain draft→active→paused→active→closed", ok)

        # closed is terminal: closed→active rejected
        r = await http.post(
            f"/engagements/{eng_id}/status", json={"status": "active"}, cookies={cn: tester_token}
        )
        check("closed is terminal (409)", r.status_code == 409)

        # create a second engagement to soft-delete + verify list scoping
        r = await http.post(
            "/engagements",
            json={"name": "temp", "client_system_name": "temp"},
            cookies={cn: tester_token},
        )
        temp_id = r.json()["id"]
        r = await http.delete(f"/engagements/{temp_id}", cookies={cn: tester_token})
        check("soft-delete returns 204", r.status_code == 204)
        r = await http.get("/engagements", cookies={cn: tester_token})
        listed = [e["id"] for e in r.json()]
        check("soft-deleted engagement excluded from list", temp_id not in listed)
        check("live engagement present in list", eng_id in listed)

    # audit: a status_changed domain event exists for the engagement
    async with sessionmaker() as db:
        actions = (
            (await db.execute(select(AuditEvent.action).where(AuditEvent.engagement_id == eng_id)))
            .scalars()
            .all()
        )
    check("status change recorded a domain audit event", "engagement.status_changed" in actions)
    check("engagement.created audit event present", "engagement.created" in actions)

    # cleanup (audit rows are append-only → dev-superuser trigger bypass)
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(
            delete(AuditEvent).where(AuditEvent.organization_id.in_([org_id, other_id]))
        )
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
