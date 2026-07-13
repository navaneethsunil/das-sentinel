# DAS Sentinel API/worker image — STUB (M0-I2).
# Real build (deps, app copy, uvicorn/celery entrypoints) lands in M0-B1 / M0-W1.
# Pinned base per CLAUDE.md §3 (Python 3.12+); digest-pin as a follow-up (TR-25).
FROM python:3.12-slim

WORKDIR /app

# Non-root by default (ASVS/least-privilege); real deps + code arrive in M0-B1.
RUN useradd --create-home --uid 10001 appuser
USER appuser

# Placeholder: keep the container alive so infra bring-up can be validated this chunk.
# M0-B1 replaces this with the FastAPI app; M0-W1 overrides the command for the worker.
CMD ["sleep", "infinity"]
