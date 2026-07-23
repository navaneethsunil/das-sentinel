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

# Red-team engine stage (M2-B3): PyRIT + its heavy ML/redteam deps, installed from
# a SEPARATE hash-pinned bundle (requirements-redteam.txt) that is deliberately NOT
# in uv.lock. The block-on-High SCA gate runs osv-scanner against uv.lock, so
# keeping PyRIT out of the lock isolates its 107-package transitive blast radius
# from the base image and the base SCA/Trivy gates (SECURITY_DEVELOPMENT_PLAN §7).
# --require-hashes enforces the pin at install time (supply-chain integrity). The
# PyRIT-backed worker runs from this target; the default target stays `runtime`.
# HARDENING (tracked): a report-only SCA pass over this bundle in the redteam-image
# build (its deps are not yet in the base gate).
FROM runtime AS redteam
USER root
COPY requirements-redteam.txt ./
RUN uv pip install --python /app/.venv/bin/python --require-hashes \
        -r requirements-redteam.txt
USER appuser

# Scanner-engine stage (M3-W2): Semgrep CE + its transitive tree, installed from a
# SEPARATE hash-pinned bundle (requirements-scanners.txt) that is deliberately NOT
# in uv.lock — same isolation rationale as `redteam` above (keep the base uv.lock,
# base image, and base SCA/Trivy gates free of the scanner's blast radius,
# SECURITY_DEVELOPMENT_PLAN §7). The scanner-backed worker runs from this target;
# the default target stays `runtime`. The vendored, content-hashed rule bundle
# (security/semgrep-rules) is mounted read-only at runtime rather than baked here —
# it lives at the repo root (shared with the M0 CI self-scan gate) and the build
# context is apps/api; baking it into the image is a packaging/hardening seam.
# HARDENING (tracked): report-only SCA over this bundle at its image build; digest-
# pin the scanner image; bake + verify the rule bundle in the shipped image.
FROM runtime AS scanners
USER root
COPY requirements-scanners.txt ./
RUN uv pip install --python /app/.venv/bin/python --require-hashes \
        -r requirements-scanners.txt
USER appuser
