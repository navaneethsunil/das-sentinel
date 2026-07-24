"""Ensure the S3/MinIO evidence bucket exists (dev/CI bootstrap).

Bucket creation is intentionally not in the API startup path (network-free boot,
M2-B1); this one-shot bootstraps it for the dev stack and e2e flows that upload
evidence (e.g. the M3-B1 source-archive upload). Idempotent. Run inside the
compose network:

    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/ensure_bucket.py"
"""

from app.core.config import get_settings
from app.storage.evidence import create_evidence_store


def main() -> None:
    create_evidence_store(get_settings()).ensure_bucket()
    print("evidence bucket ready")


if __name__ == "__main__":
    main()
