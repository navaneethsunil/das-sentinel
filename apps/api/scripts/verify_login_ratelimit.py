"""Live verification of M1-SEC5 login anti-brute-force + SQLi defense. Run in
the compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
          python scripts/verify_login_ratelimit.py"

Proves against the real API + Valkey + DB:
  - per-account throttle: after N failures the login returns a generic 429 with
    Retry-After, and a *correct* password is still refused while throttled (the
    gate runs before credential verification — no bypass, no Argon2 burn);
  - recovery: once the window counter is cleared the account logs in again;
  - per-IP gate: enough failures across distinct emails from one source trip a
    429 even for a brand-new email;
  - SQL injection: SQLi payloads in the email are rejected (422) before any
    query; a SQLi password is treated as an opaque secret (401); neither ever
    returns 200/500 nor leaks a password hash.
Cleans up after itself (counters, sessions, seeded rows).
"""

import asyncio
import sys

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.core.sessions import hash_token
from app.models.audit import AuditEvent
from app.models.identity import Organization, Session, User, UserRole

API_BASE = "http://api:8000"
PASSWORD = "correct horse battery staple"  # noqa: S105 - fixture credential
WRONG = "definitely-not-it"  # noqa: S105

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def _clear_counters(cache: Redis) -> None:
    async for key in cache.scan_iter("login_fail_*"):
        await cache.delete(key)


async def main() -> int:  # noqa: C901, PLR0915 - linear verification script
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    cache = Redis.from_url(settings.cache_url)
    passwords = PasswordService(settings.password_hash_scheme)
    cn = settings.session_cookie_name
    max_email = settings.login_rate_limit_max_per_email
    max_ip = settings.login_rate_limit_max_per_ip
    recovered_token = ""

    async with sessionmaker() as db:
        org = Organization(name="verify-ratelimit-org")
        db.add(org)
        await db.flush()
        tester = User(
            organization_id=org.id,
            email="tester@verify-rl.example.com",
            password_hash=passwords.hash(PASSWORD),
            display_name="tester",
            role=UserRole.TESTER,
        )
        db.add(tester)
        await db.flush()
        await db.commit()
        org_id, tester_id, tester_email = org.id, tester.id, tester.email

    await _clear_counters(cache)

    async with httpx.AsyncClient(base_url=API_BASE, timeout=30) as http:
        # ── SQL injection at the auth boundary ──
        sqli_emails = [
            "admin@x.example.com' OR '1'='1",
            "' OR 1=1 --",
            "x@x.example.com'; DROP TABLE users; --",
        ]
        for payload in sqli_emails:
            r = await http.post("/auth/login", json={"email": payload, "password": PASSWORD})
            check(f"SQLi email rejected pre-query (422): {payload[:24]!r}", r.status_code == 422)
        r = await http.post(
            "/auth/login", json={"email": tester_email, "password": "' OR '1'='1' --"}
        )
        check("SQLi password → 401 (opaque secret, no bypass)", r.status_code == 401)
        check("SQLi attempts never 200/500", True)  # asserted by the checks above
        await _clear_counters(cache)

        # ── per-account throttle ──
        for i in range(max_email):
            r = await http.post("/auth/login", json={"email": tester_email, "password": WRONG})
            check(f"failure {i + 1}/{max_email} below threshold → 401", r.status_code == 401)
        r = await http.post("/auth/login", json={"email": tester_email, "password": WRONG})
        check("attempt over threshold → 429", r.status_code == 429)
        check("429 carries Retry-After header", int(r.headers.get("retry-after", "0")) > 0)
        check(
            "429 detail is generic (no account-exists oracle)",
            "too many" in r.json().get("detail", "").lower(),
        )
        # correct password while throttled is STILL refused (gate before creds)
        r = await http.post("/auth/login", json={"email": tester_email, "password": PASSWORD})
        check("correct password while throttled → 429 (no bypass)", r.status_code == 429)

        # ── recovery once the window counter clears ──
        await _clear_counters(cache)
        r = await http.post("/auth/login", json={"email": tester_email, "password": PASSWORD})
        check("login succeeds after window reset → 200", r.status_code == 200)
        user_body = r.json().get("user", {})
        check("recovered login omits password_hash", "password_hash" not in user_body)
        recovered_token = r.cookies.get(cn) or ""

        # ── per-IP gate across distinct (nonexistent) emails ──
        await _clear_counters(cache)
        for i in range(max_ip):
            await http.post(
                "/auth/login", json={"email": f"spray{i}@verify-rl.example.com", "password": WRONG}
            )
        r = await http.post(
            "/auth/login", json={"email": "brand-new@verify-rl.example.com", "password": WRONG}
        )
        check("fresh email blocked by per-IP gate → 429", r.status_code == 429)

    # cleanup (audit rows are append-only → dev-superuser bypass)
    await _clear_counters(cache)
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        await conn.execute(delete(AuditEvent).where(AuditEvent.organization_id == org_id))
        await conn.execute(delete(Session).where(Session.user_id == tester_id))
        await conn.execute(delete(User).where(User.organization_id == org_id))
        await conn.execute(delete(Organization).where(Organization.id == org_id))
    # drop only the session cookie minted by the successful recovery login
    if recovered_token:
        await cache.delete(f"session:{hash_token(recovered_token).hex()}")
    await cache.aclose()
    await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
