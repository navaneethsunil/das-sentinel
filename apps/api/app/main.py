"""FastAPI app factory (M0-B1).

Run: `uvicorn app.main:create_app --factory`.

No CORSMiddleware on purpose: web and api share a single origin behind the
proxy (TR-4, same-origin); enabling CORS would only widen the attack surface.
"""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.api.engagements import router as engagements_router
from app.api.roe import router as roe_router
from app.api.scope import router as scope_router
from app.api.users import router as users_router
from app.core.audit import register_audit_middleware
from app.core.config import Settings, get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import setup_logging

logger = logging.getLogger(__name__)

# A hung backend must fail readiness, not hang it (fail closed).
READINESS_CHECK_TIMEOUT_S = 3.0


async def check_database(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))


async def check_valkey(client: Redis) -> None:
    await client.ping()


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    app.state.db_engine = create_engine(settings)
    app.state.db_sessionmaker = create_sessionmaker(app.state.db_engine)
    app.state.valkey = Redis.from_url(settings.cache_url)
    try:
        yield
    finally:
        await app.state.valkey.aclose()
        await app.state.db_engine.dispose()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    setup_logging(settings.log_level)

    app = FastAPI(
        title="DAS Sentinel API",
        root_path=settings.api_root_path,
        lifespan=_lifespan,
    )
    app.state.settings = settings

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness only — must not touch backends (a DB outage is not a reason
        to restart the API container)."""
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz(response: Response) -> dict[str, object]:
        checks = {
            "database": check_database(app.state.db_engine),
            "valkey": check_valkey(app.state.valkey),
        }
        results: dict[str, str] = {}
        for name, check in checks.items():
            try:
                await asyncio.wait_for(check, READINESS_CHECK_TIMEOUT_S)
                results[name] = "ok"
            except Exception:
                # Full detail goes to the log only: /api/readyz is reachable through
                # the single ingress, so no DSN/hostname detail leaves the process.
                logger.exception("readiness check failed: %s", name)
                results[name] = "unavailable"
        ready = all(state == "ok" for state in results.values())
        if not ready:
            response.status_code = 503
        return {"status": "ok" if ready else "unavailable", "checks": results}

    app.include_router(users_router)
    app.include_router(engagements_router)
    app.include_router(scope_router)
    app.include_router(roe_router)
    register_audit_middleware(app)

    return app
