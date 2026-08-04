"""Live end-to-end verification of the AI model registry. Run inside the compose
network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_ai_models.py"

Asserts: RBAC (admin-only writes, VIEW reads), that the provider is checked before a
model is saved (a fake endpoint that 404s the model is refused), that the API key is
never echoed back, first-model-becomes-default + make-default, engagement pinning
(including cross-org 404), refusal to remove a model an engagement still uses, and
the audit trail. A local stub stands in for Ollama so no real provider is called.
"""

import asyncio
import socket
import sys

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.sessions import SessionService, hash_token, utcnow
from app.models.ai_model import AIModel
from app.models.audit import AuditEvent
from app.models.engagement import Engagement
from app.models.identity import Organization, Session, User, UserRole

API_BASE = "http://api:8000"
STUB_PORT = 18434
STUB_MISSING_PORT = 18435
API_KEY = "sk-ant-" + "verify-ai-models-fake-key"
failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def _stub_ollama(port: int, status_line: str) -> asyncio.Server:
    """Minimal HTTP responder standing in for an Ollama daemon: `POST /api/show`
    answers with the given status, which is exactly what the registry checks. Bound
    on 0.0.0.0 because the *API container* is what calls it, not this process."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.read(1)  # enough to know a request arrived
            body = b'{"model":"stub"}'
            writer.write(
                f"HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
        finally:
            writer.close()

    return await asyncio.start_server(handle, "0.0.0.0", port)  # noqa: S104


async def main() -> int:  # noqa: C901 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)
    tokens: list[str] = []

    async with sessionmaker() as db:
        org = Organization(name="verify-aim-org")
        other = Organization(name="verify-aim-other")
        db.add_all([org, other])
        await db.flush()
        admin = User(
            organization_id=org.id,
            email="admin@verify-aim.test",
            password_hash="x",  # noqa: S106
            display_name="admin",
            role=UserRole.ADMIN,
        )
        tester = User(
            organization_id=org.id,
            email="tester@verify-aim.test",
            password_hash="x",  # noqa: S106
            display_name="tester",
            role=UserRole.TESTER,
        )
        outsider = User(
            organization_id=other.id,
            email="outsider@verify-aim.test",
            password_hash="x",  # noqa: S106
            display_name="outsider",
            role=UserRole.ADMIN,
        )
        db.add_all([admin, tester, outsider])
        await db.flush()
        svc = SessionService(db, cache, settings)
        now = utcnow()
        admin_token = await svc.create_session(admin.id, UserRole.ADMIN, now=now)
        tester_token = await svc.create_session(tester.id, UserRole.TESTER, now=now)
        out_token = await svc.create_session(outsider.id, UserRole.ADMIN, now=now)
        tokens += [admin_token, tester_token, out_token]
        await db.commit()
        org_id, other_id = org.id, other.id
        user_ids = [admin.id, tester.id, outsider.id]

    ok_stub = await _stub_ollama(STUB_PORT, "200 OK")
    missing_stub = await _stub_ollama(STUB_MISSING_PORT, "404 Not Found")
    # The API container resolves the stub by this container's address on the
    # compose network — its own 127.0.0.1 is not us.
    stub_host = socket.gethostbyname(socket.gethostname())

    cn = settings.session_cookie_name
    async with httpx.AsyncClient(
        base_url=API_BASE,
        timeout=15,
        cookies={settings.csrf_cookie_name: "verify-csrf"},
        headers={settings.csrf_header_name: "verify-csrf"},
    ) as http:
        local = {
            "name": "local-llama",
            "provider": "ollama",
            "model_id": "llama3.1:8b",
            "base_url": f"http://{stub_host}:{STUB_PORT}",
        }

        r = await http.post("/llm/models", json=local, cookies={cn: tester_token})
        check("tester cannot register a model (403)", r.status_code == 403)

        r = await http.post(
            "/llm/models",
            json={**local, "name": "unreachable", "base_url": "http://127.0.0.1:1"},
            cookies={cn: admin_token},
        )
        check("unreachable endpoint refused (400)", r.status_code == 400)

        r = await http.post(
            "/llm/models",
            json={
                **local,
                "name": "not-pulled",
                "base_url": f"http://{stub_host}:{STUB_MISSING_PORT}",
            },
            cookies={cn: admin_token},
        )
        check("model the provider does not have is refused (400)", r.status_code == 400)

        r = await http.post(
            "/llm/models",
            json={**local, "name": "bad-scheme", "base_url": "file:///etc/passwd"},
            cookies={cn: admin_token},
        )
        check("non-http endpoint refused (400)", r.status_code == 400)

        # A loopback endpoint an operator types cannot be the API container's own
        # loopback, so the Docker host alias is tried too — the refusal names both.
        r = await http.post(
            "/llm/models",
            json={**local, "name": "loopback", "base_url": f"http://localhost:{STUB_PORT}"},
            cookies={cn: admin_token},
        )
        check(
            "loopback endpoint is retried against the Docker host", "host.docker.internal" in r.text
        )

        r = await http.post("/llm/models", json=local, cookies={cn: admin_token})
        check("admin registers a local model (201)", r.status_code == 201)
        first = r.json() if r.status_code == 201 else {}
        check("first registered model becomes the default", first.get("is_default") is True)
        check("local model is not flagged hosted", first.get("hosted") is False)

        r = await http.post("/llm/models", json=local, cookies={cn: admin_token})
        check("duplicate name refused (409)", r.status_code == 409)

        r = await http.post(
            "/llm/models",
            json={
                "name": "hosted-claude",
                "provider": "anthropic",
                "model_id": "claude-opus-4-8",
                "api_key": API_KEY,
            },
            cookies={cn: admin_token},
        )
        # No valid key here by design: either Anthropic rejects it (401→400) or the
        # container has no egress (unreachable→400). Either way it must NOT save.
        check("hosted model with a bad key is not registered (400)", r.status_code == 400)
        check("the rejected key is not echoed back", API_KEY not in r.text)

        second = {**local, "name": "local-mistral", "model_id": "mistral:7b"}
        r = await http.post("/llm/models", json=second, cookies={cn: admin_token})
        second_id = r.json()["id"]
        check("second model registers, not default", r.json()["is_default"] is False)

        r = await http.get("/llm/models", cookies={cn: tester_token})
        listed = r.json()
        check("any signed-in role can read the registry", r.status_code == 200)
        check("both models listed", {m["id"] for m in listed} >= {first["id"], second_id})
        check("no key material in the listing", "api_key" not in r.text)

        r = await http.post(f"/llm/models/{second_id}/default", cookies={cn: admin_token})
        check("make-default moves the default", r.status_code == 200 and r.json()["is_default"])
        listed = (await http.get("/llm/models", cookies={cn: admin_token})).json()
        check(
            "exactly one default remains",
            sum(1 for m in listed if m["is_default"]) == 1,
        )

        r = await http.post(
            "/engagements",
            json={
                "name": "verify-aim engagement",
                "client_system_name": "aim",
                "ai_model_id": second_id,
            },
            cookies={cn: admin_token},
        )
        check("engagement pins a registered model (201)", r.status_code == 201)
        eng_id = r.json()["id"]
        check("engagement carries the pinned model", r.json()["ai_model_id"] == second_id)

        r = await http.post(
            "/engagements",
            json={
                "name": "cross-org pin",
                "client_system_name": "aim",
                "ai_model_id": second_id,
            },
            cookies={cn: out_token},
        )
        check("another org cannot pin our model (404)", r.status_code == 404)

        r = await http.delete(f"/llm/models/{second_id}", cookies={cn: admin_token})
        check("cannot remove a model an engagement uses (409)", r.status_code == 409)

        r = await http.patch(
            f"/engagements/{eng_id}", json={"ai_model_id": None}, cookies={cn: admin_token}
        )
        check("engagement can fall back to the org default", r.json()["ai_model_id"] is None)

        r = await http.delete(f"/llm/models/{second_id}", cookies={cn: admin_token})
        check("unpinned model removes (204)", r.status_code == 204)
        listed = (await http.get("/llm/models", cookies={cn: admin_token})).json()
        check("removed model is gone from the registry", second_id not in {m["id"] for m in listed})

        r = await http.delete(f"/llm/models/{second_id}", cookies={cn: admin_token})
        check("removing it twice is 404", r.status_code == 404)

    ok_stub.close()
    missing_stub.close()

    async with sessionmaker() as db:
        actions = (
            (
                await db.execute(
                    select(AuditEvent.action).where(AuditEvent.organization_id == org_id)
                )
            )
            .scalars()
            .all()
        )
        for action in ("ai_model.registered", "ai_model.default_changed", "ai_model.removed"):
            check(f"audit event {action} recorded", action in actions)
        stored = (
            (
                await db.execute(
                    select(AIModel.api_key_encrypted).where(AIModel.organization_id == org_id)
                )
            )
            .scalars()
            .all()
        )
        check("no plaintext key stored", all(k is None or not k.startswith("sk-") for k in stored))

    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(
            delete(AuditEvent).where(AuditEvent.organization_id.in_([org_id, other_id]))
        )
        await conn.execute(delete(Session).where(Session.user_id.in_(user_ids)))
        await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await conn.execute(delete(AIModel).where(AIModel.organization_id == org_id))
        await conn.execute(delete(User).where(User.organization_id.in_([org_id, other_id])))
        await conn.execute(delete(Organization).where(Organization.id.in_([org_id, other_id])))
    for token in tokens:
        await cache.delete(f"session:{hash_token(token).hex()}")
    await cache.aclose()
    await engine.dispose()

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
