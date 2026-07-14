# DAS Sentinel API/worker image (M0-B1).
# One image for both services: compose overrides the command for `worker` (M0-W1).
# Pinned base per CLAUDE.md §3 (Python 3.12+); digest-pin is a follow-up (TR-25).
FROM python:3.12-slim AS runtime

# uv pinned by minor version; digest-pin with the rest of TR-25.
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Non-root (ASVS/least-privilege).
RUN useradd --create-home --uid 10001 appuser

# Locked deps first (layer cache), app code after.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY app ./app
# Migrations ship in the same image: the one-shot `migrate` service (M0-D1) runs
# `alembic upgrade head` from it, so schema and code always deploy together.
COPY alembic.ini ./
COPY migrations ./migrations

USER appuser
ENV PATH="/app/.venv/bin:$PATH"

# Internal-network bind only: no host port is ever published for this service (TR-4);
# the Caddy proxy is the single ingress.
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]

# Dev-only Flower stage (M0-W1): the monitoring group adds flower==2.0.1 on top of
# the runtime deps, so Flower runs against the exact same Celery as the worker
# (air-gap friendly — no third-party flower image). Compose builds this target only
# for the dev-profile `flower` service; the default target stays `runtime`.
FROM runtime AS monitoring
USER root
RUN uv sync --frozen --no-dev --group monitoring
USER appuser
