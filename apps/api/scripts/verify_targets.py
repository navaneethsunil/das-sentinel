"""Live end-to-end verification of the M1-B10 target endpoints. Run inside the
compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_targets.py"

Asserts RBAC, primary_value validation per type, auth_config references-only
(plaintext secret → 422, reference → ok), org scoping (cross-org engagement →
404), update + soft-delete, findings_by_severity rollup empty, and audit
events. Cleans up via the dev-superuser trigger bypass.
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
from app.models.target import Target

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
        org = Organization(name="verify-tgt-org")
        other = Organization(name="verify-tgt-other")
        db.add_all([org, other])
        await db.flush()
        tester = User(
            organization_id=org.id,
            email="tester@verify-tgt.test",
            password_hash="x",  # noqa: S106
            display_name="tester",
            role=UserRole.TESTER,
        )
        readonly = User(
            organization_id=org.id,
            email="ro@verify-tgt.test",
            password_hash="x",  # noqa: S106
            display_name="ro",
            role=UserRole.READ_ONLY,
        )
        db.add_all([tester, readonly])
        await db.flush()
        eng = Engagement(
            organization_id=org.id,
            created_by=tester.id,
            name="tgt-eng",
            client_system_name="sys",
        )
        other_eng = Engagement(
            organization_id=other.id,
            created_by=tester.id,  # arbitrary; different org
            name="other-eng",
            client_system_name="sys",
        )
        db.add_all([eng, other_eng])
        await db.flush()
        svc = SessionService(db, cache, settings)
        now = utcnow()
        tester_token = await svc.create_session(tester.id, UserRole.TESTER, now=now)
        ro_token = await svc.create_session(readonly.id, UserRole.READ_ONLY, now=now)
        tokens += [tester_token, ro_token]
        await db.commit()
        org_id, other_id = org.id, other.id
        eng_id, other_eng_id = eng.id, other_eng.id
        user_ids = [tester.id, readonly.id]

    cn = settings.session_cookie_name
    base = f"/engagements/{eng_id}/targets"
    async with httpx.AsyncClient(base_url=API_BASE, timeout=10) as http:
        web = {
            "name": "web",
            "target_type": "web_app",
            "primary_value": "https://app.example.com",
        }

        r = await http.post(base, json=web, cookies={cn: ro_token})
        check("read-only cannot create target (403)", r.status_code == 403)

        r = await http.post(base, json=web, cookies={cn: tester_token})
        check("create web_app target (201)", r.status_code == 201)
        check("findings_by_severity empty at M1", r.json().get("findings_by_severity") == {})
        target_id = r.json().get("id")

        # bad URL for a url-type target → 422
        r = await http.post(
            base,
            json={"name": "bad", "target_type": "web_app", "primary_value": "not-a-url"},
            cookies={cn: tester_token},
        )
        check("invalid primary_value for web_app → 422", r.status_code == 422)

        # source_repo accepts a repo URL
        r = await http.post(
            base,
            json={
                "name": "repo",
                "target_type": "source_repo",
                "primary_value": "https://github.com/acme/web.git",
            },
            cookies={cn: tester_token},
        )
        check("create source_repo target (201)", r.status_code == 201)

        # auth_config with a plaintext secret → 422
        r = await http.post(
            base,
            json={
                "name": "api",
                "target_type": "rest_api",
                "primary_value": "https://api.example.com",
                "auth_config": {"password": "hunter2"},
            },
            cookies={cn: tester_token},
        )
        check("auth_config plaintext secret rejected (422)", r.status_code == 422)

        # auth_config with a reference → ok
        r = await http.post(
            base,
            json={
                "name": "api2",
                "target_type": "rest_api",
                "primary_value": "https://api2.example.com",
                "auth_status": "configured",
                "auth_config": {"password_ref": "vault://kv/acme/api"},
            },
            cookies={cn: tester_token},
        )
        check("auth_config reference accepted (201)", r.status_code == 201)

        # read-only can list; scoped
        r = await http.get(base, cookies={cn: ro_token})
        check("read-only can list targets (200)", r.status_code == 200 and len(r.json()) == 3)

        # update: revalidate primary_value + change auth_status
        r = await http.patch(
            f"{base}/{target_id}",
            json={"primary_value": "https://app2.example.com", "auth_status": "verified"},
            cookies={cn: tester_token},
        )
        check(
            "update target (200)",
            r.status_code == 200 and r.json()["auth_status"] == "verified",
        )

        # update with plaintext secret rejected
        r = await http.patch(
            f"{base}/{target_id}",
            json={"auth_config": {"api_key": "sk-live"}},
            cookies={cn: tester_token},
        )
        check("update plaintext secret rejected (422)", r.status_code == 422)

        # cross-org engagement → 404
        r = await http.get(f"/engagements/{other_eng_id}/targets", cookies={cn: tester_token})
        check("cross-org engagement targets → 404", r.status_code == 404)

        # soft delete
        r = await http.delete(f"{base}/{target_id}", cookies={cn: tester_token})
        check("soft-delete target (204)", r.status_code == 204)
        r = await http.get(base, cookies={cn: tester_token})
        check("deleted target excluded from list", target_id not in [t["id"] for t in r.json()])

    async with sessionmaker() as db:
        actions = (
            (await db.execute(select(AuditEvent.action).where(AuditEvent.engagement_id == eng_id)))
            .scalars()
            .all()
        )
    check("target.created audited", "target.created" in actions)
    check("target.deleted audited", "target.deleted" in actions)

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(
            delete(AuditEvent).where(AuditEvent.organization_id.in_([org_id, other_id]))
        )
        await conn.execute(delete(Target).where(Target.engagement_id.in_([eng_id, other_eng_id])))
        await conn.execute(delete(Session).where(Session.user_id.in_(user_ids)))
        await conn.execute(
            delete(Engagement).where(Engagement.organization_id.in_([org_id, other_id]))
        )
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
