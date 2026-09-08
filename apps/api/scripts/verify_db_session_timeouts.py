"""Live verification of the API's DB session bounds (UAT DEF-004 follow-up).

    docker compose run --rm --no-deps -v "$PWD/apps/api/scripts:/app/scripts:ro" \
      --entrypoint sh api -c "cd /app && PYTHONPATH=/app uv run --no-sync \
      python scripts/verify_db_session_timeouts.py"

A request that leaves a transaction open, or waits forever on a row lock, must
not be able to block every other writer until someone terminates the backend by
hand. The API's engine therefore sets idle_in_transaction_session_timeout and
lock_timeout per connection; the Celery workers deliberately do NOT get them,
because scanner jobs hold legitimately long transactions and the app DB role is
shared with them (so a role-level ALTER ROLE would throttle those too).

Asserts: the API engine carries both bounds, a worker-style engine carries
neither, and Postgres really does terminate a connection that sits idle in a
transaction past the bound (proven with a deliberately tiny override).
"""

import asyncio
import sys

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {name}{f' — {detail}' if detail else ''}")
    if not condition:
        failures.append(name)


async def show(engine, guc: str) -> str:
    async with engine.connect() as conn:
        return (await conn.execute(text(f"SHOW {guc}"))).scalar_one()


async def main() -> int:
    settings = get_settings()

    api_engine = create_engine(settings, apply_session_timeouts=True)
    worker_engine = create_engine(settings)
    try:
        idle = await show(api_engine, "idle_in_transaction_session_timeout")
        lock = await show(api_engine, "lock_timeout")
        check("API connection bounds idle-in-transaction", idle not in ("0", "0ms"), f"= {idle}")
        check("API connection bounds lock waits", lock not in ("0", "0ms"), f"= {lock}")

        w_idle = await show(worker_engine, "idle_in_transaction_session_timeout")
        w_lock = await show(worker_engine, "lock_timeout")
        check(
            "worker connections stay unbounded (long scanner transactions)",
            w_idle in ("0", "0ms") and w_lock in ("0", "0ms"),
            f"idle={w_idle} lock={w_lock}",
        )
    finally:
        await api_engine.dispose()
        await worker_engine.dispose()

    # A bound is only worth anything if the server enforces it. Use a
    # deliberately tiny value so the proof takes a second rather than 30.
    fast = settings.model_copy(update={"db_idle_in_transaction_timeout_ms": 1000})
    fast_engine = create_engine(fast, apply_session_timeouts=True)
    try:
        sessionmaker = create_sessionmaker(fast_engine)
        async with sessionmaker() as db:
            pid = (await db.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            await asyncio.sleep(2.5)  # hold the transaction open, doing nothing
            async with fast_engine.connect() as probe:
                still_there = (
                    await probe.execute(
                        text("select count(*) from pg_stat_activity where pid = :pid"),
                        {"pid": pid},
                    )
                ).scalar_one()
            try:
                await db.execute(text("SELECT 1"))
                reusable = True
            except DBAPIError:
                reusable = False  # the server hung up, as it should
        check(
            "Postgres terminates a session left idle in a transaction",
            still_there == 0 and not reusable,
            f"backend {pid} gone={still_there == 0}, connection dead={not reusable}",
        )
    finally:
        await fast_engine.dispose()

    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
