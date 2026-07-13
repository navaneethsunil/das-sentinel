# DAS Sentinel

AI security testing and automated penetration-testing platform for **authorized defensive security
assessments** of web apps, APIs, source code, and AI/LLM applications. It turns an approved engagement
scope into evidence-backed, compliance-mapped, prioritized, report-ready findings.

> ⚠️ Use only against systems you are authorized to test. No scan runs without a saved engagement, a
> defined scope, and an accepted ROE. See the safety invariants in [`CLAUDE.md`](./CLAUDE.md) §2.

## Documentation

| Doc | Purpose |
|---|---|
| [`CLAUDE.md`](./CLAUDE.md) | Project rules, stack, safety invariants, repo layout |
| [`ai-security-testing-platform-build-brief.md`](./ai-security-testing-platform-build-brief.md) | Authoritative product/scope definition |
| [`ROADMAP.md`](./ROADMAP.md) | Milestones M0→M6, build order, decision gates |
| [`MVP_TASKS.md`](./MVP_TASKS.md) | Ordered, checkable task breakdown (M0→M3) |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) · [`TRD.md`](./TRD.md) · [`DATABASE_SCHEMA.md`](./DATABASE_SCHEMA.md) · [`BACKEND_SCHEMA.md`](./BACKEND_SCHEMA.md) · [`APPFLOW.md`](./APPFLOW.md) | System design |
| [`SECURITY_DEVELOPMENT_PLAN.md`](./SECURITY_DEVELOPMENT_PLAN.md) | Secure-SDLC for the platform itself |
| [`PRD.md`](./PRD.md) · [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md) | Requirements, sequencing |

## Repository layout

```
apps/
  web/                 # Next.js (App Router) frontend        — built in M0-F1
  api/                 # FastAPI backend
    app/               #   application package                — built in M0-B1
    migrations/        #   Alembic migrations                 — initialized in M0-D1
packages/
  compliance/          # OWASP/NIST mapping knowledge base
sandbox/               # mock vulnerable apps for safe testing
docker-compose.yml     # self-hosted, air-gap-friendly stack
Caddyfile              # reverse proxy (real routing lands in M0-I4)
```

## Local development (work in progress)

The stack runs via Docker Compose (single node, air-gap friendly):

```bash
docker compose up -d
```

> Current status: **M0 scaffolding**. Infrastructure services (`postgres`, `valkey`, `minio`,
> `proxy`) come up healthy today; the `api`/`web`/`worker` services are placeholders until
> M0-B1/W1/F1 land, and the full browser → proxy → api → db round-trip is the M0 exit gate.

Stack (see `CLAUDE.md §3`): Next.js + TypeScript · FastAPI (Python 3.12+) · Celery · PostgreSQL 17 ·
Valkey 8 · S3-compatible evidence store · Caddy · Node 24 LTS.
