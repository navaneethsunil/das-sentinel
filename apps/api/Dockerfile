# DAS Sentinel API/worker image (M0-B1).
# One image for both services: compose overrides the command for `worker` (M0-W1).
# Digest-pinned base per CLAUDE.md §3 (never a mutable tag) — TR-25. Bump: re-pin
# via `docker buildx imagetools inspect --format '{{.Manifest.Digest}}' python:3.12-slim`.
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime

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
# Gitleaks (M4 next-wave secret scanner): pinned release, checksum-verified —
# same version + digest as the CI secrets gate (.github/workflows/security.yml).
# MIT; embeds its ruleset (version pins rules); runs fully offline on a source dir.
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/* \
    && gitleaks version
# OSV-Scanner (M4 next-wave SCA): pinned release, checksum-verified — same version
# + digest as the CI SCA gate. Apache-2.0; single static binary. Looks up the OSV
# database over the network by default (accepted egress, same as the CI gate).
ARG OSV_VERSION=2.4.0
ARG OSV_SHA256=15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL -o /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64" \
    && echo "${OSV_SHA256}  /usr/local/bin/osv-scanner" | sha256sum -c - \
    && chmod +x /usr/local/bin/osv-scanner \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/* \
    && osv-scanner --version
# Nuclei (M4 next-wave DAST): pinned release, checksum-verified (pinned by digest,
# CLAUDE.md §3). MIT. Its SAFE-ACTIVE template bundle is the vendored, content-
# hashed security/nuclei-templates dir, mounted read-only at runtime (never a
# floating registry pack, never -update-templates).
ARG NUCLEI_VERSION=3.11.0
ARG NUCLEI_SHA256=dc238d6040813e14fc30514dac5a2eb1b430c694f3ca99eee2a5097e55076283
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates unzip \
    && curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum -c - \
    && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && rm /tmp/nuclei.zip \
    && apt-get purge -y --auto-remove curl unzip \
    && rm -rf /var/lib/apt/lists/* \
    && nuclei -version -disable-update-check
# httpx (M4 recon: non-intrusive HTTP fingerprinting): pinned release, checksum-
# verified (pinned by digest, CLAUDE.md §3). MIT (projectdiscovery). Distinct from
# the Python httpx library used elsewhere in the app.
ARG HTTPX_VERSION=1.10.0
ARG HTTPX_SHA256=63eac4dcd6e5c9867c94765fdaaf66e7b4eeae3474a1f06e600e266a1c81a53e
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates unzip \
    && curl -fsSL -o /tmp/httpx.zip \
        "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" \
    && echo "${HTTPX_SHA256}  /tmp/httpx.zip" | sha256sum -c - \
    && unzip -o /tmp/httpx.zip httpx -d /usr/local/bin \
    # Rename to pdhttpx: the Python `httpx` library ships its own `httpx` CLI in the
    # venv, which shadows this binary on PATH — the adapter invokes `pdhttpx`.
    && mv /usr/local/bin/httpx /usr/local/bin/pdhttpx \
    && rm /tmp/httpx.zip \
    && apt-get purge -y --auto-remove curl unzip \
    && rm -rf /var/lib/apt/lists/* \
    && pdhttpx -version -disable-update-check
# Katana (M4 recon: bounded, in-scope endpoint-discovery crawler): pinned release,
# checksum-verified (pinned by digest, CLAUDE.md §3). MIT (projectdiscovery).
ARG KATANA_VERSION=1.6.1
ARG KATANA_SHA256=503754f1bd370c3ef287df6998e317baed2dd75bdd13ea64034f09b80ca393f3
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates unzip \
    && curl -fsSL -o /tmp/katana.zip \
        "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" \
    && echo "${KATANA_SHA256}  /tmp/katana.zip" | sha256sum -c - \
    && unzip -o /tmp/katana.zip katana -d /usr/local/bin \
    && rm /tmp/katana.zip \
    && apt-get purge -y --auto-remove curl unzip \
    && rm -rf /var/lib/apt/lists/* \
    && katana -version -disable-update-check
# testssl.sh (M4 recon: TLS/cipher/certificate assessment): pinned release,
# checksum-verified (pinned by digest, CLAUDE.md §3). GPLv2 — shelled out as an
# UNMODIFIED script (no linking/bundling). Uses its bundled openssl; needs bash +
# a few coreutils (procps/bsdmainutils/dnsutils), which stay resident.
ARG TESTSSL_VERSION=3.2.4
ARG TESTSSL_SHA256=98528f8a0ac07f1e226efaa8ead438247df8efcb8fee4e056a937ab82a305490
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates bash procps bsdmainutils dnsutils \
    && curl -fsSL -o /tmp/testssl.tgz \
        "https://github.com/drwetter/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz" \
    && echo "${TESTSSL_SHA256}  /tmp/testssl.tgz" | sha256sum -c - \
    && mkdir -p /opt/testssl \
    && tar -xzf /tmp/testssl.tgz -C /opt/testssl --strip-components=1 \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
    && rm /tmp/testssl.tgz \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/* \
    && testssl.sh --version
USER appuser
