"""Async DB engine + session dependency (M1-B2).

One engine/sessionmaker per app, created in the lifespan and stashed on
app.state; routers depend on `get_db` for a request-scoped AsyncSession that
commits on success and rolls back on error. All DB access goes through this
dependency (CLAUDE.md §5) — no module-level engine, so tests and workers can
supply their own.
"""

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings


def create_engine(settings: Settings, *, apply_session_timeouts: bool = False) -> AsyncEngine:
    """`apply_session_timeouts` bounds how long a connection may sit in an open
    transaction or wait for a lock (see Settings for why only the API opts in)."""
    connect_args: dict[str, object] = {}
    if apply_session_timeouts:
        server_settings = {
            key: str(value)
            for key, value in (
                ("idle_in_transaction_session_timeout", settings.db_idle_in_transaction_timeout_ms),
                ("lock_timeout", settings.db_lock_timeout_ms),
            )
            if value > 0
        }
        if server_settings:
            connect_args["server_settings"] = server_settings
    return create_async_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    sessionmaker: async_sessionmaker[AsyncSession] = request.app.state.db_sessionmaker
    async with sessionmaker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
