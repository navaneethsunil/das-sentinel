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


def create_engine(settings: Settings) -> AsyncEngine:
    return create_async_engine(settings.database_url, pool_pre_ping=True)


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
