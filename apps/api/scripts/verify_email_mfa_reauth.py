"""Live regression guard for finding [12] — changing the login email and
enrolling MFA both require recent-authentication (current-password) proof, and
an email change revokes sibling sessions (CWE-306 / CWE-620).

    docker compose run --rm --no-deps -v "$PWD/apps/api/scripts:/app/scripts:ro" \
      --entrypoint sh api -c "cd /app && PYTHONPATH=/app uv run --no-sync --with httpx \
      python scripts/verify_email_mfa_reauth.py"
"""

import asyncio
import sys
import uuid

import httpx
from sqlalchemy import select, update

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.models.identity import Organization, User, UserRole

BASE = "http://api:8000"
PASSWORD = "verify-reauth-2026!"  # noqa: S105 - throwaway fixture credential
WRONG = "verify-reauth-wrong!"  # noqa: S105
DEADLINE = 15.0

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


def _auth(settings, login: httpx.Response) -> dict[str, str]:
    sc = login.cookies.get(settings.session_cookie_name) or ""
    cc = login.cookies.get(settings.csrf_cookie_name) or ""
    return {
        "Cookie": f"{settings.session_cookie_name}={sc}; {settings.csrf_cookie_name}={cc}",
        settings.csrf_header_name: cc,
    }


async def main() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    tag = uuid.uuid4().hex[:8]
    email = f"verify-reauth-{tag}@example.com"
    new_email = f"verify-reauth-{tag}-new@example.com"

    async with sessionmaker() as db:
        org = (await db.execute(select(Organization).limit(1))).scalar_one()
        user = User(
            organization_id=org.id,
            email=email,
            display_name="Verify Reauth",
            password_hash=PasswordService(settings.password_hash_scheme).hash(PASSWORD),
            role=UserRole.READ_ONLY,
        )
        db.add(user)
        await db.commit()
        user_id = user.id

    try:
        async with httpx.AsyncClient(base_url=BASE, timeout=DEADLINE) as client:
            login = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
            # A second session that the email change must later revoke.
            sibling = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
            check("login", login.status_code == 200)
            auth = _auth(settings, login)
            auth_sibling = _auth(settings, sibling)

            # --- Email change gate ---
            no_pw = await client.patch("/auth/me", json={"email": new_email}, headers=auth)
            check("email change without password is rejected (400)", no_pw.status_code == 400)

            wrong_pw = await client.patch(
                "/auth/me",
                json={"email": new_email, "current_password": WRONG},
                headers=auth,
            )
            check("email change with wrong password is rejected (400)", wrong_pw.status_code == 400)

            ok = await client.patch(
                "/auth/me",
                json={"email": new_email, "current_password": PASSWORD},
                headers=auth,
            )
            check("email change with correct password works (200)", ok.status_code == 200)
            check("response carries the new address", ok.json().get("email") == new_email)

            # Sibling session must be dead after the email change.
            sib_after = await client.get("/auth/me", headers=auth_sibling)
            check("sibling session revoked after email change (401)", sib_after.status_code == 401)

            # Non-security edits still need no password.
            fresh = await client.post(
                "/auth/login", json={"email": new_email, "password": PASSWORD}
            )
            auth2 = _auth(settings, fresh)
            phone_only = await client.patch(
                "/auth/me", json={"phone": "+1 555 0100"}, headers=auth2
            )
            check("phone-only edit needs no password (200)", phone_only.status_code == 200)

            # --- MFA enroll gate ---
            enroll_no_pw = await client.post("/auth/mfa/enroll", json={}, headers=auth2)
            check(
                "MFA enroll without password is rejected (422)",
                enroll_no_pw.status_code == 422,
            )
            enroll_wrong = await client.post(
                "/auth/mfa/enroll", json={"current_password": WRONG}, headers=auth2
            )
            check(
                "MFA enroll with wrong password is rejected (400)",
                enroll_wrong.status_code == 400,
            )
            enroll_ok = await client.post(
                "/auth/mfa/enroll", json={"current_password": PASSWORD}, headers=auth2
            )
            check("MFA enroll with correct password works (200)", enroll_ok.status_code == 200)
            check("enroll returns a secret", bool(enroll_ok.json().get("secret")))
    finally:
        async with sessionmaker() as db:
            await db.execute(update(User).where(User.id == user_id).values(is_active=False))
            await db.commit()
        await engine.dispose()

    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
