"""Idempotent e2e fixture: one org + one admin user with a known password for
the Playwright auth flow (apps/web/tests/e2e/auth.spec.ts), locally and in the
CI smoke job. Fixture-only credentials, not a secret. Run inside the compose
network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/seed_e2e_user.py"
"""

import asyncio

from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.models.identity import Organization, User, UserRole

E2E_ORG = "e2e-org"
E2E_EMAIL = "e2e-admin@dassentinel.example.com"
# Must match auth.spec.ts. noqa S105: shared Playwright fixture, not a credential.
E2E_PASSWORD = "e2e horse battery staple"  # noqa: S105


async def main() -> None:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    passwords = PasswordService(settings.password_hash_scheme)

    async with sessionmaker() as db:
        org = (
            await db.execute(select(Organization).where(Organization.name == E2E_ORG))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name=E2E_ORG)
            db.add(org)
            await db.flush()

        user = (
            await db.execute(
                select(User).where(User.organization_id == org.id, User.email == E2E_EMAIL)
            )
        ).scalar_one_or_none()
        if user is None:
            db.add(
                User(
                    organization_id=org.id,
                    email=E2E_EMAIL,
                    password_hash=passwords.hash(E2E_PASSWORD),
                    display_name="E2E Admin",
                    role=UserRole.ADMIN,
                )
            )
        else:
            # Re-seed converges to a known-good state whatever earlier runs did.
            user.password_hash = passwords.hash(E2E_PASSWORD)
            user.role = UserRole.ADMIN
            user.is_active = True
        await db.commit()

    await engine.dispose()
    print(f"seeded {E2E_EMAIL} (admin) in {E2E_ORG}")


if __name__ == "__main__":
    asyncio.run(main())
