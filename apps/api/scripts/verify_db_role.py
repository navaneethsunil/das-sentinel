"""Live verification of the least-privilege runtime DB role (SEC-DEBT-4). Run
inside the compose network AFTER migrations have provisioned the role
(POSTGRES_APP_PASSWORD set):

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_db_role.py"

Connects AS the app role (not the owner) and proves the privilege floor:
UPDATE/DELETE on every append-only table is denied at the privilege layer
(distinct from the trigger), while DML on a mutable table and reads on the
append-only tables still work — and the role is not a superuser. Every
statement uses WHERE false, so nothing is mutated; no seed or cleanup needed.
"""

import asyncio
import sys

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings

APPEND_ONLY = (
    "audit_events",
    "evidence",
    "execution_authorizations",
    "finding_status_history",
    "llm_interactions",
    "retests",
    "roe_acknowledgements",
)

failures: list[str] = []


def check(name: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}")
    if not condition:
        failures.append(name)


async def _runs(engine, sql: str) -> tuple[bool, str]:
    """Run one statement in its own transaction; return (succeeded, error text)."""
    try:
        async with engine.begin() as conn:
            await conn.execute(sa.text(sql))
        return True, ""
    except Exception as exc:  # noqa: BLE001 - classify by message below
        return False, str(exc)


def _is_denied(err: str) -> bool:
    return "permission denied" in err.lower() or "42501" in err


async def main() -> int:
    settings = get_settings()
    url = settings.app_role_database_url
    if url is None:
        print("SKIP: POSTGRES_APP_PASSWORD unset — app role not provisioned")
        return 0

    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            user, is_super = (
                await conn.execute(
                    sa.text(
                        "SELECT current_user, "
                        "(SELECT rolsuper FROM pg_roles WHERE rolname = current_user)"
                    )
                )
            ).one()
        check(f"connected as app role ({user})", user == settings.postgres_app_user)
        check("app role is NOT a superuser", is_super is False)

        # {t} is a fixed table name from APPEND_ONLY, never user input.
        for t in APPEND_ONLY:
            ok_read, _ = await _runs(engine, f"SELECT 1 FROM {t} LIMIT 1")  # noqa: S608
            check(f"{t}: SELECT allowed", ok_read)
            up_ok, up_err = await _runs(engine, f"UPDATE {t} SET id = id WHERE false")  # noqa: S608
            check(f"{t}: UPDATE denied by privilege", (not up_ok) and _is_denied(up_err))
            del_ok, del_err = await _runs(engine, f"DELETE FROM {t} WHERE false")  # noqa: S608
            check(f"{t}: DELETE denied by privilege", (not del_ok) and _is_denied(del_err))

        # A mutable table proves the role isn't merely read-only.
        mut_up, mut_err = await _runs(
            engine, "UPDATE sessions SET user_agent = user_agent WHERE false"
        )
        check("mutable table (sessions): UPDATE allowed", mut_up or not _is_denied(mut_err))
        mut_del, mdel_err = await _runs(engine, "DELETE FROM sessions WHERE false")
        check("mutable table (sessions): DELETE allowed", mut_del or not _is_denied(mdel_err))
    finally:
        await engine.dispose()

    summary = "ALL PASS" if not failures else f"{len(failures)} FAILURE(S): " + ", ".join(failures)
    print(f"\n{summary}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
