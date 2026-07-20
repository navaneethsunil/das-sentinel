"""Live verification of M2-F1 suite-launcher backend seam. Run inside compose:

    docker compose up -d --build api            # needs postgres, valkey, migrate
    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_scan_launch.py"

Drives the real POST /engagements/{id}/scans over HTTP and proves the launcher
vertical slice end to end:

  - a Tester launches an in-scope LLM target at safe-active → 201 queued, an
    immutable execution envelope is frozen, and `scan.launched` is audited;
  - the scope keystone GATES the launch (server-derived intensity, scope, ROE):
    over-intensity → 403 intensity_not_authorized; out-of-scope → 403
    scope_violation; ROE-not-accepted engagement → 403 roe_not_accepted, each
    with a `scan.blocked` audit row on an independent session;
  - a non-LLM target is refused pre-flight (422, connector build); empty suites
    → 422 (schema); read-only role → 403 (RBAC); cross-org / unknown → 404;
  - GET (list) returns the launched scans.

The worker is not required — the endpoint enqueues by task name and this script
asserts the queued row + envelope + audit. Cleans up via the dev-superuser bypass.
"""

import asyncio
import sys
import uuid
from datetime import UTC, datetime, timedelta

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
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
from app.models.scan import ExecutionAuthorization, Scan
from app.models.target import AuthStatus, Target, TargetType
from app.services.roe import render_current_roe

API_BASE = "http://api:8000"
NOW = datetime.now(UTC)
failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def _accept_roe(session, eng, scope_items, user_id) -> None:
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


def _engagement(org_id, user_id, name) -> Engagement:
    return Engagement(
        organization_id=org_id,
        name=name,
        client_system_name="acme",
        status=EngagementStatus.ACTIVE,
        test_window_start=NOW - timedelta(days=1),
        test_window_end=NOW + timedelta(days=1),
        rate_limit_rps=5,
        max_intensity=ScanIntensity.SAFE_ACTIVE,
        created_by=user_id,
    )


async def main() -> int:  # noqa: C901, PLR0912, PLR0915 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)
    tokens: list[str] = []
    pw = PasswordService(settings.password_hash_scheme)

    async with sm() as s:
        org = Organization(name="verify-launch-org")
        other = Organization(name="verify-launch-other")
        s.add_all([org, other])
        await s.flush()

        tester = User(
            organization_id=org.id,
            email="tester@verify-launch.example.com",
            password_hash=pw.hash("x-throwaway"),
            display_name="tester",
            role=UserRole.TESTER,
        )
        viewer = User(
            organization_id=org.id,
            email="viewer@verify-launch.example.com",
            password_hash=pw.hash("x-throwaway"),
            display_name="viewer",
            role=UserRole.READ_ONLY,
        )
        outsider = User(
            organization_id=other.id,
            email="admin@verify-launch-other.example.com",
            password_hash=pw.hash("x-throwaway"),
            display_name="outsider",
            role=UserRole.ADMIN,
        )
        s.add_all([tester, viewer, outsider])
        await s.flush()

        # Engagement with ROE accepted: in-scope LLM target, out-of-scope LLM
        # target, and a non-LLM target.
        eng = _engagement(org.id, tester.id, "launch-eng")
        s.add(eng)
        await s.flush()
        scope = ScopeItem(
            engagement_id=eng.id,
            kind=ScopeKind.ALLOW,
            matcher_type=ScopeMatcher.DOMAIN,
            value="mock-llm.example.com",
        )
        s.add(scope)
        await s.flush()
        llm = Target(
            engagement_id=eng.id,
            name="mock-chatbot",
            target_type=TargetType.AI_CHATBOT,
            primary_value="https://mock-llm.example.com/v1/chat/completions",
            auth_status=AuthStatus.NONE,
            connector_config={"mode": "chat_messages"},
        )
        offscope = Target(
            engagement_id=eng.id,
            name="offscope-chatbot",
            target_type=TargetType.LLM_API_WRAPPER,
            primary_value="https://evil.example.com/v1/chat/completions",
        )
        web = Target(
            engagement_id=eng.id,
            name="web",
            target_type=TargetType.WEB_APP,
            primary_value="https://mock-llm.example.com/",
        )
        s.add_all([llm, offscope, web])
        await s.flush()
        await _accept_roe(s, eng, [scope], tester.id)

        # A second engagement WITHOUT an accepted ROE (roe_not_accepted gate).
        noroe = _engagement(org.id, tester.id, "launch-noroe")
        s.add(noroe)
        await s.flush()
        noroe_scope = ScopeItem(
            engagement_id=noroe.id,
            kind=ScopeKind.ALLOW,
            matcher_type=ScopeMatcher.DOMAIN,
            value="mock-llm.example.com",
        )
        s.add(noroe_scope)
        await s.flush()
        noroe_llm = Target(
            engagement_id=noroe.id,
            name="mock-chatbot",
            target_type=TargetType.AI_CHATBOT,
            primary_value="https://mock-llm.example.com/v1/chat/completions",
        )
        s.add(noroe_llm)
        await s.flush()

        svc = SessionService(s, cache, settings)
        tester_token = await svc.create_session(tester.id, UserRole.TESTER, now=utcnow())
        viewer_token = await svc.create_session(viewer.id, UserRole.READ_ONLY, now=utcnow())
        outsider_token = await svc.create_session(outsider.id, UserRole.ADMIN, now=utcnow())
        tokens += [tester_token, viewer_token, outsider_token]
        await s.commit()

        org_id, other_id = org.id, other.id
        eng_id, noroe_id = eng.id, noroe.id
        llm_id, offscope_id, web_id = llm.id, offscope.id, web.id
        noroe_llm_id = noroe_llm.id
        user_ids = [tester.id, viewer.id, outsider.id]

    cn = settings.session_cookie_name
    base = f"/engagements/{eng_id}/scans"
    launched_ids: list[str] = []
    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=15,
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        # 1. valid launch (single suite, safe active) → 201 queued
        r = await http.post(
            base,
            cookies={cn: tester_token},
            json={"target_id": str(llm_id), "suites": ["prompt_injection"]},
        )
        check("launch: valid → 201", r.status_code == 201)
        if r.status_code == 201:
            body = r.json()
            launched_ids.append(body["id"])
            check("launch: status queued", body["status"] == "queued")
            check("launch: intensity safe_active", body["intensity"] == "safe_active")

        # 2. valid launch (both suites)
        r = await http.post(
            base,
            cookies={cn: tester_token},
            json={"target_id": str(llm_id), "suites": ["prompt_injection", "data_leakage"]},
        )
        check("launch: both suites → 201", r.status_code == 201)
        if r.status_code == 201:
            launched_ids.append(r.json()["id"])

        # 3. read-only cannot launch (LAUNCH_SCANS is Admin/Tester)
        r = await http.post(
            base,
            cookies={cn: viewer_token},
            json={"target_id": str(llm_id), "suites": ["prompt_injection"]},
        )
        check("launch: read-only → 403 (RBAC)", r.status_code == 403)

        # 4. over-intensity: authenticated_active > engagement max safe_active
        r = await http.post(
            base,
            cookies={cn: tester_token},
            json={
                "target_id": str(llm_id),
                "suites": ["prompt_injection"],
                "intensity": "authenticated_active",
            },
        )
        check(
            "launch: over-intensity → 403 intensity_not_authorized",
            r.status_code == 403 and r.json()["detail"] == "intensity_not_authorized",
        )

        # 5. out-of-scope LLM target → 403 scope_violation
        r = await http.post(
            base,
            cookies={cn: tester_token},
            json={"target_id": str(offscope_id), "suites": ["prompt_injection"]},
        )
        check(
            "launch: out-of-scope → 403 scope_violation",
            r.status_code == 403 and r.json()["detail"] == "scope_violation",
        )

        # 6. non-LLM target refused pre-flight (connector build) → 422
        r = await http.post(
            base,
            cookies={cn: tester_token},
            json={"target_id": str(web_id), "suites": ["prompt_injection"]},
        )
        check("launch: non-LLM target → 422", r.status_code == 422)

        # 7. empty suites → 422 (schema)
        r = await http.post(
            base, cookies={cn: tester_token}, json={"target_id": str(llm_id), "suites": []}
        )
        check("launch: empty suites → 422", r.status_code == 422)

        # 8. cross-org → 404 (no leak)
        r = await http.post(
            base,
            cookies={cn: outsider_token},
            json={"target_id": str(llm_id), "suites": ["prompt_injection"]},
        )
        check("launch: cross-org → 404", r.status_code == 404)

        # 9. unknown target id → 404
        r = await http.post(
            base,
            cookies={cn: tester_token},
            json={"target_id": str(uuid.uuid4()), "suites": ["prompt_injection"]},
        )
        check("launch: unknown target → 404", r.status_code == 404)

        # 10. ROE-not-accepted engagement → 403 roe_not_accepted
        r = await http.post(
            f"/engagements/{noroe_id}/scans",
            cookies={cn: tester_token},
            json={"target_id": str(noroe_llm_id), "suites": ["prompt_injection"]},
        )
        check(
            "launch: no ROE → 403 roe_not_accepted",
            r.status_code == 403 and r.json()["detail"] == "roe_not_accepted",
        )

        # 11. list scans returns the launched ones
        r = await http.get(base, cookies={cn: tester_token})
        listed = {s["id"] for s in r.json()} if r.status_code == 200 else set()
        check(
            "list: launched scans present",
            r.status_code == 200 and all(sid in listed for sid in launched_ids),
        )

    # ── DB assertions: envelope frozen + audit rows ──────────────────────────
    async with sm() as s:
        for sid in launched_ids:
            env = (
                await s.execute(
                    select(ExecutionAuthorization).where(
                        ExecutionAuthorization.scan_id == uuid.UUID(sid)
                    )
                )
            ).scalar_one_or_none()
            check(f"envelope frozen for scan {sid[:8]}", env is not None)
            if env is not None:
                check(
                    f"envelope carries suites+kind for {sid[:8]}",
                    "suites" in env.normalized_config and "kind" in env.normalized_config,
                )
        launched_audits = (
            await s.execute(
                select(AuditEvent.action, AuditEvent.outcome).where(
                    AuditEvent.engagement_id == eng_id, AuditEvent.action == "scan.launched"
                )
            )
        ).all()
        check("audit: scan.launched success recorded", len(launched_audits) >= len(launched_ids))
        blocked = (
            await s.execute(
                select(AuditEvent.detail).where(
                    AuditEvent.action == "scan.blocked",
                    AuditEvent.outcome == AuditOutcome.BLOCKED,
                    AuditEvent.engagement_id.in_([eng_id, noroe_id]),
                )
            )
        ).all()
        reasons = {row[0]["reason"] for row in blocked if row[0]}
        check(
            "audit: scan.blocked reasons recorded (independent session survives)",
            {"intensity_not_authorized", "scope_violation", "roe_not_accepted"} <= reasons,
        )

    # ── cleanup (insert-only tables → dev-superuser trigger bypass) ───────────
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(
            delete(AuditEvent).where(AuditEvent.organization_id.in_([org_id, other_id]))
        )
        await conn.execute(
            delete(ExecutionAuthorization).where(
                ExecutionAuthorization.engagement_id.in_([eng_id, noroe_id])
            )
        )
        await conn.execute(delete(Scan).where(Scan.engagement_id.in_([eng_id, noroe_id])))
        await conn.execute(
            delete(ROEAcknowledgement).where(
                ROEAcknowledgement.engagement_id.in_([eng_id, noroe_id])
            )
        )
        await conn.execute(delete(ScopeItem).where(ScopeItem.engagement_id.in_([eng_id, noroe_id])))
        await conn.execute(
            delete(Target).where(Target.id.in_([llm_id, offscope_id, web_id, noroe_llm_id]))
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
