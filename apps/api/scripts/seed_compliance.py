"""Seed the compliance KB (packages/compliance/*.json) into the DB (M3-B4).

Idempotent upsert of frameworks + controls — safe to re-run. This is a
deploy/operational step; the KB directory must be mounted (or baked) at
settings.compliance_kb_dir. Run inside the compose network with the KB mounted:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" \
      -v "$PWD/packages/compliance:/app/packages/compliance:ro" \
      --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/seed_compliance.py"
"""

import asyncio
from pathlib import Path

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.services.compliance import seed_frameworks


async def main() -> None:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    try:
        async with sessionmaker() as db:
            counts = await seed_frameworks(db, Path(settings.compliance_kb_dir))
            await db.commit()
        print(f"seeded {counts['frameworks']} frameworks, {counts['controls']} controls")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
