# ARCHITECTURE.md — DAS Sentinel

> System architecture for the AI security testing and automated penetration-testing platform. Read alongside `CLAUDE.md` (rules), `ai-security-testing-platform-build-brief.md` (scope), and `DATABASE_SCHEMA.md` (data model). This document describes *how the system is put together and why*; it does not restate feature scope.

---

## 1. Architectural goals & constraints

The architecture is driven by five forces, in priority order:

1. **Safety is structural, not cosmetic.** Scope enforcement, ROE gating, and the high-risk approval gate live at the service layer where they cannot be bypassed by a crafted API call. The UI is the *last* line of defense, never the only one.
2. **Evidence integrity.** Raw scanner output is immutable, hashed, and stored separately from interpreted findings so it survives as defensible chain-of-custody evidence for federal reporting.
3. **Modularity of tools.** Scanners and LLM providers are pluggable behind stable interfaces; adding Nuclei or swapping Claude for a local model touches one adapter, not the orchestration core.
4. **Self-hostable / air-gap friendly.** Every dependency runs in Docker Compose on a single VM with no mandatory outbound internet. Hosted LLMs are opt-in per engagement.
5. **Auditability.** Every state-changing action and every scan produces an append-only audit event answering who / what / which target / when / what result.

Non-goals: multi-region HA, horizontal auto-scaling, and multi-tenant SaaS isolation are explicitly out of scope for the MVP (single-org, single-node). The schema keeps an `organization` boundary so this can grow later, but we do not build for it now.

---

## 2. System context (C4 level 1)

```
                        ┌─────────────────────────────────────────────┐
                        │                 Human users                  │
                        │  Admin · Security Tester · Reviewer · Read-only│
                        └───────────────────────┬─────────────────────┘
                                                 │ HTTPS (browser)
                                                 ▼
                        ┌─────────────────────────────────────────────┐
                        │              DAS Sentinel platform            │
                        │   (Docker Compose, single self-hosted node)   │
                        └───────┬───────────────────────────┬─────────┘
                                │                             │
              in-scope targets  │                             │  optional, per-engagement
              (only, validated) ▼                             ▼  (redacted, opt-in)
        ┌───────────────────────────────┐          ┌────────────────────────┐
        │  Targets under test           │          │  LLM providers          │
        │  • Web apps / REST / GraphQL  │          │  • Anthropic Claude (hosted)
        │  • Source repos / archives    │          │  • Ollama / vLLM (local) │
        │  • AI chatbot / LLM / agent   │          └────────────────────────┘
        └───────────────────────────────┘
```

The platform reaches **outward only to (a) authorized in-scope targets** and **(b) an LLM provider**. Target access is always scope-validated; LLM egress is redacted and only to hosted providers when the engagement allows it.

---

## 3. Container view (C4 level 2)

All containers run under one `docker-compose.yml`. Arrows show the primary call direction.

```
┌──────────────┐    HTTPS     ┌──────────────────────────────────────────────┐
│   Browser    │ ───────────▶ │  web (Next.js, App Router)                     │
│              │ ◀─────────── │  SSR/RSC + static assets                       │
└──────────────┘              └───────────────┬────────────────────────────────┘
                                     JSON / REST (same-origin, via reverse proxy)
                                               ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  reverse proxy (Caddy or nginx)  — TLS termination, routes / → web, /api → api │
└───────────────┬───────────────────────────────────────────────┬────────────┘
                ▼                                                 ▼
┌──────────────────────────────┐                   ┌──────────────────────────────┐
│  api (FastAPI)               │   enqueue jobs     │  worker (Celery)             │
│  • auth + sessions           │ ─────────────────▶ │  • scanner adapters          │
│  • engagement/scope/ROE      │   (Valkey broker)  │  • LLM jobs                  │
│  • scope-enforcement service │ ◀───────────────── │  • recon / triage            │
│  • findings, CVSS, reports   │   status/results   │  • runs tools in child procs │
│  • audit log (append-only)   │                    │    (killable process groups) │
└───────┬───────────┬──────────┘                    └───────┬───────────┬─────────┘
        │           │                                       │           │
        ▼           ▼                                       ▼           ▼
┌────────────┐ ┌────────────┐                        ┌────────────┐ ┌────────────┐
│ PostgreSQL │ │  Valkey    │                        │  MinIO     │ │ LLM provider│
│  17        │ │  8         │                        │ (S3-compat)│ │ (see §8)    │
│ structured │ │ cache +    │                        │ raw evidence│ └────────────┘
│ data       │ │ broker +   │                        │ blobs      │
│            │ │ sessions   │                        │ (immutable)│
└────────────┘ └────────────┘                        └────────────┘
```

**Container responsibilities**

| Container | Tech | Responsibility |
|---|---|---|
| `web` | Next.js (App Router) + TS + Tailwind + shadcn/ui | Dashboard UI. Talks only to `api` (same-origin through the proxy). No direct DB/broker access. |
| `reverse proxy` | Caddy (auto-TLS) or nginx | Single ingress. TLS, routing, security headers. `/` → web, `/api/*` → api. |
| `api` | FastAPI + Pydantic v2 | All business logic, authZ, scope enforcement, persistence, report generation. Enqueues jobs; never runs scanners in-process. |
| `worker` | Celery (Valkey broker) | Executes scanner/LLM/recon jobs in isolated killable child processes. Normalizes results. Reports status back. |
| `PostgreSQL 17` | Postgres | System of record for structured data (§7). |
| `Valkey 8` | Valkey | Job broker, cache, and session store — **separate logical DBs per role**; connect via the `redis://` URL scheme (Kombu has no `valkey://` transport). |
| `evidence store` | S3-compatible (production backend is a blocking gate — see §7) | Object-locked immutable store for raw evidence blobs. **The MinIO OSS repository was archived 2026-04-25 (https://github.com/minio/minio); the production backend is a blocking pre-go-live decision — see §7.** |
| LLM provider | Claude / Ollama / vLLM | Draft analysis only, on supplied evidence (§8). |

`scanner tools` (Semgrep CE, ZAP by Checkmarx, Nuclei, OSV-Scanner, Gitleaks, TruffleHog) are invoked by the worker as **subprocesses or sibling containers**, never linked into the app process. This keeps them isolated, version-pinned, killable, and swappable.

---

## 4. Backend component view (inside `api`)

```
app/
├── api/            HTTP routers — thin: validate input, call a service, shape response
├── core/           cross-cutting: config, security (hash/session), scope-enforcement, audit, deps
├── services/       business logic — the only place that mutates domain state
├── models/         SQLAlchemy ORM models
├── schemas/        Pydantic request/response models
├── scanners/       scanner adapters (see §6)
├── storage/        MinIO client — put/get raw evidence, hashing, object-lock
├── llm/            provider abstraction + adapters + versioned prompt templates (see §8)
├── workers/        Celery task definitions (thin wrappers over services/scanners)
└── reports/        exporters: CSV, Markdown (MVP); PDF/DOCX/JSON later
```

**Layering rule:** `api` (routers) → `services` → `models`/`storage`/`llm`. Routers never touch the ORM directly; services never build HTTP responses. This keeps the safety-critical logic (scope enforcement, audit) in `services`/`core` where every path — HTTP, worker, or future CLI — must pass through it.

**The scope-enforcement service is the architectural keystone.** It is a single module (`core/scope.py`) exposing one function that every active operation must call:

```
authorize_operation(engagement, target, op, roe_ack, now) -> ExecutionAuthorization
    op = typed/normalized config + SERVER-derived capabilities & effective intensity (not caller-declared)
    raises ScopeViolation | ROENotAccepted | ROEStale | ROETermsMismatch | OutsideTestWindow
         | IntensityNotAuthorized | HighRiskNotApproved | EngagementInactive
```

It is invoked in two places for defense in depth: (1) at request time in the service before a scan is enqueued (persisting the immutable `execution_authorization` envelope it returns), and (2) inside the worker immediately before the tool launches — the engagement/target/ROE/approval and the envelope are re-read from the DB and re-derived (recomputing `operation_digest`), never trusted from the job payload. The keystone also proves the run is **within the ROE test window** and that the engagement's live rate/intensity terms still **equal those accepted in the ROE**. Every raise is audit-logged as a blocked attempt.

---

## 5. Request & scan lifecycle

### 5.1 Authenticated request (opaque session)

```
Browser ──cookie(sid)──▶ proxy ──▶ api
   api: look up session row (Valkey cache → Postgres) → load user + role
        → RBAC check for the route → handle → audit event → response
   logout / "kill sessions" = delete session row(s) → immediate revocation
```

Session ID is a high-entropy random token in an `HttpOnly; Secure; SameSite=Strict` cookie. No JWT: revocation, forced logout, and full-session audit are first-class because state is server-side.

### 5.2 Launching a scan (the safety-critical path)

```
1. Tester selects engagement + target + scanner + intensity in the UI.
2. api → ScanService.create_scan():
     a. Load engagement; assert status active, ROE accepted.
     b. scope.authorize_operation(engagement, target, op, roe_ack, now)
          - typed/normalized op + SERVER-derived effective intensity (not caller-declared)
          - ROE terms (window/rate/max-intensity) equal the accepted roe_ack.terms_snapshot
          - now ∈ engagement test window
          - target matches an allowlist item and NO blocklist item (deny wins)
          - effective intensity ≤ engagement max intensity
          - if high-risk → valid approval whose operation_digest matches op
     c. Persist Scan(status=queued) + IMMUTABLE execution_authorization envelope
        (same txn) + audit "scan.queued".
     d. Enqueue Celery job with scan_id ONLY (envelope + scope re-verified in worker).
3. worker picks up job:
     a. Re-load scan + execution_authorization envelope + engagement/target/ROE/approval.
     b. RE-DERIVE from live DB, recompute operation_digest, RE-RUN authorize_operation;
        refuse on any divergence. For high-risk, ATOMICALLY consume the approval.
     c. ExecutionOwner launches Adapter.run()/PyRIT in a rootless per-run sandbox
        (dropped caps, scoped creds, egress via shaper); process/container id recorded.
     d. Timeout enforced; engagement rate limit enforced in aggregate at the egress shaper.
     e. Stream raw output → evidence store (hashed, object-locked). Store object key.
     f. Adapter.normalize(raw) → Finding rows (status=automated).
     g. ExecutionOwner verifies teardown (sandbox gone, transient creds revoked).
     h. Update scan status; audit "scan.completed" / "scan.failed".
4. Emergency stop: api sets scan.cancel_requested=true and signals the worker; worker
   terminates the recorded process group/container (SIGTERM→SIGKILL) AND confirms it is
   gone (in-process PyRIT halts via its CancelToken), verifies teardown, marks cancelled.
```

**If any gate in step 2a–2b fails, no job is enqueued and the attempt is audit-logged.** Default intensity is passive/safe-active; anything higher requires explicit selection plus (for high-risk) an approval record.

### 5.3 Scan intensity levels

| Level | Meaning | Gate |
|---|---|---|
| `passive` | No traffic to target beyond what's needed to read public metadata | Default, always allowed in-scope |
| `safe_active` | Non-destructive active checks (safe ZAP rules, Semgrep, template scans) | Allowed if engagement max ≥ safe_active |
| `authenticated_active` | Uses supplied test credentials against in-scope auth surface | Allowed if engagement max ≥ this level + creds configured |
| `high_risk` | Exploit validation, brute-force style, data-modifying payloads, large-scale crawl | **Blocked unless an ApprovalGate is approved by an Admin/Reviewer** |

---

## 6. Scanner orchestration

Every scanner implements the `ScannerAdapter` contract (defined in `CLAUDE.md §6`). Architecturally:

```
ScanService ──enqueue──▶ Celery task ──▶ ScannerAdapter
                                            │
        ┌───────────────────────────────────┼───────────────────────────────┐
        ▼                 ▼                  ▼                ▼                ▼
   Semgrep CE       ZAP by Checkmarx      Nuclei         OSV-Scanner       Gitleaks
   (subprocess)     (ZAP daemon +         (subprocess)   (subprocess)      (subprocess)
                     API over HTTP)
        │
        └─▶ RawResult ──▶ storage.put_evidence() ──▶ MinIO (hash, object-lock)
                     └──▶ normalize() ──▶ Finding[] ──▶ Postgres
```

Design points:

- **Raw ≠ normalized.** The raw artifact is written to MinIO first and never mutated; normalization reads from it. If we improve a normalizer later, we can re-normalize from preserved raw evidence.
- **Version & config captured** on every `ScannerRun` row (tool version string + the exact config/args used) for reproducibility and audit.
- **Uniform execution owner (containment, not just killability).** Every run — scanner **and** PyRIT suite — is launched by a single `ExecutionOwner` abstraction that provides a uniform launch/cancel/teardown contract. Process-group recording gives *lifecycle control* (kill), but killability is not *compromise containment*: a subprocess still inherits the worker's filesystem, credentials, syscalls, capabilities, and internal-network reach. So each run executes in a **rootless, per-run sandbox** (rootless container / user namespace) with: a **minimal, mostly read-only mount set** (only the run's inputs/outputs), **all Linux capabilities dropped** + `no-new-privileges` + a seccomp profile, **short-lived scoped credentials** for that one run (no ambient worker secrets), **egress only through the engagement-aware egress shaper** (default-deny; §anti-SSRF), and **verified teardown** (the owner confirms the sandbox and its process tree are gone and transient credentials revoked — teardown failure is surfaced, not assumed).
- **Confirmed cancellation.** Emergency stop terminates the run's process group / container (SIGTERM→SIGKILL) **and confirms** it stopped; PyRIT (embedded in-process) is given the same identity via the owner — either its own child owner or a fully propagated bounded cooperative-cancellation token checked between turns (see §6a / `TR-15.4`).
- **Aggregate egress shaping.** Per-engagement request rate is enforced at the **egress shaper** (a single choke point all run traffic is routed through), so the ceiling holds **across concurrent runs and inside opaque scanner processes/daemons** — not only inside one cooperative tool (see `TR-12.2`).
- **MVP scanners:** Semgrep CE (SAST) and ZAP by Checkmarx (DAST). **Next wave:** Nuclei (pin ≥ v3.8.0), OSV-Scanner v2 + pip-audit/npm audit, Gitleaks (default) + TruffleHog (verification, AGPL — shell out only). Adding one = drop a new adapter module + register it; orchestration is untouched.

**AI/LLM test suites** (prompt injection, data leakage, agent-permission) follow the same shape: a test-runner produces a transcript (prompt / response / expected / actual / pass-fail), the transcript is the evidence written to MinIO, and results normalize into the same `Finding` schema with an OWASP LLM mapping.

---

## 7. Data & evidence architecture

Two stores, split by role:

**PostgreSQL 17 — system of record (structured, queryable):**
- Users, organizations, engagements, scope items, targets, scans, scanner runs, findings, CVSS scores, compliance mappings, reports, audit events, LLM interactions, approval gates, sessions.
- JSONB is used only for *moderate-size structured* data (parsed finding attributes, normalized results) with GIN indexes — never for large raw blobs.

**Object evidence store (immutable blobs) — accessed only through an internal `storage/` S3 client:**
- Raw scanner output, captured HTTP responses, LLM test transcripts, uploaded source archives.
- Each object is content-hashed (SHA-256, stored as `bytea`); the hash + object key + size + content-type are stored on the related Postgres row. Object-lock/WORM in **compliance mode** (not governance mode) + retention policy give chain-of-custody integrity.
- Findings reference evidence by object key; the DB stays small and fast while evidence stays defensible.
- **Two-phase write is not transactional:** write the blob first, then commit metadata; run an orphan-sweep job for blobs whose metadata commit failed, and never delete a blob still under object-lock retention. Re-verify size + hash on read.

> ⚠️ **Backend decision required — blocking gate (verified July 2026).** The original plan named MinIO, but MinIO's open-source edition is **archived as of 2026-04-25** (repository https://github.com/minio/minio; console features moved to paid AIStor; no guaranteed security patches). **Evidence storage is not considered complete until the production backend is selected and its compliance-mode WORM is empirically verified** — the dev MinIO build ships the feature but does not satisfy the Definition of Done. Its WORM code still functions, but a new federal-compliance evidence store should not sit on unpatched, abandoned software. There is **no clean lightweight drop-in**: Ceph RGW has proven object-lock but is operationally heavy; SeaweedFS has an unresolved compliance-mode WORM-enforcement bug; Garage lacks object-lock; RustFS is unproven. **Decision (July 2026):** access all evidence storage through an S3-API abstraction (`storage/`) so the backend is swappable. For **local dev / MVP**, run the last-good MinIO OSS release (WORM code still functions) — it is a true S3 drop-in and unblocks development. The **production backend is an explicit pre-go-live decision** tracked in `ROADMAP.md` (candidates: Ceph RGW for proven enforced WORM, or re-evaluate SeaweedFS/RustFS once their object-lock enforcement is verified). Whatever backend ships to production, we will empirically test that a delete/overwrite under compliance-mode retention is actually *rejected* before trusting the WORM claim.

Rationale: large JSONB values trigger Postgres TOAST read-amplification and hit the 1 GB field ceiling; object storage is the correct home for large immutable artifacts and gives federal-grade evidence handling for free. Full entity model lives in `DATABASE_SCHEMA.md`.

---

## 8. LLM layer architecture

```
services (triage / remediation / report / test-gen)
        │  never calls a vendor SDK directly
        ▼
  llm/ provider abstraction  ──▶ redaction layer  ──▶ provider adapter
        │                              │                    ├─ Anthropic Claude (hosted)
        │                              │                    ├─ Ollama (local)
        │                              │                    └─ vLLM (local, GPU)
        ▼                              ▼
  versioned prompt templates     token/cost tracking + LLMInteraction audit row
```

- **Provider abstraction.** A thin internal interface; use **LiteLLM** only if we end up needing many providers. Default model `claude-opus-4-8` (workhorse), `claude-sonnet-5` (volume triage), `claude-haiku-4-5` (classification). Current Claude params only (`thinking: {type:"adaptive"}`, strict tool use for structured output). Avoid Fable 5 as default (cyber-content refusal risk on pentest prompts).
- **Redaction before egress.** A redaction pass runs before any *hosted* call. If the engagement's `hosted_models_allowed` flag is false, hosted adapters are unavailable and only local (Ollama/vLLM) models may run — this is how air-gapped/sensitive engagements are enforced at the architecture level.
- **Evidence-grounded, draft-only.** Every LLM call is given concrete evidence (scanner output, transcript, source snippet, captured response) and its output is stored with an `ai-generated` label and a link to the evidence it cited. The LLM never sets final CVSS or marks a finding fixed. Every interaction is persisted (prompt template version, tokens, cost, provider/model) for audit and cost tracking.

---

## 9. Safety & authorization architecture (cross-cutting)

> This section covers **product safety** (controls that stop the platform harming targets). The platform's **own application security** — anti-SSRF worker egress, cross-engagement access control, injection/upload/parser hardening, secret & supply-chain handling, and how each is security-tested every phase — is architected and gated in **`SECURITY_DEVELOPMENT_PLAN.md`** (threat model + per-phase 🛡 gates). Both are structural, not cosmetic.

Safety is enforced by components that sit in the request/worker path, not by UI conditionals:

| Control | Where it lives | How it's enforced |
|---|---|---|
| Engagement + scope + ROE required | `core/scope.py`, called by every scan service | Raises before any job is enqueued; re-checked in worker |
| Target allowlist / out-of-scope blocklist | `scope` items in DB, evaluated by scope service | Host/URL/CIDR match; blocklist wins over allowlist |
| Scan intensity tiers | Scan service + engagement max-intensity setting | Intensity ≤ engagement max; high-risk needs approval |
| High-risk approval gate | `ApprovalGate` entity + service | Scan blocked until an Admin/Reviewer approves; approval is audited |
| Rate limiting | Worker | Token-bucket per engagement setting, applied to outbound scan traffic |
| Emergency stop | api flag + worker signal handler | Terminates recorded process group/container **and confirms it is gone** (in-process PyRIT halts via CancelToken), verifies teardown, marks scan cancelled |
| RBAC | `core/deps.py` route dependencies | Admin / Tester / Reviewer / Read-only checked per route |
| Audit log | `core/audit.py` | Append-only events on every state change + every blocked attempt |
| Finding labeling | `Finding.status` enum | automated / ai-generated / validated / manually-overridden surfaced in UI |
| Signed ROE artifact | `core/roe.py` | Hash + snapshot of scope at acceptance time, immutable record |

**RBAC matrix (summary):**

| Capability | Admin | Tester | Reviewer | Read-only |
|---|---|---|---|---|
| Manage users/org settings | ✅ | — | — | — |
| Create/edit engagements & scope | ✅ | ✅ | — | — |
| Accept ROE | ✅ | ✅ | — | — |
| Launch passive/safe-active scans | ✅ | ✅ | — | — |
| Approve high-risk gate | ✅ | — | ✅ | — |
| Validate / override findings, set CVSS | ✅ | ✅ | ✅ | — |
| Generate/export reports | ✅ | ✅ | ✅ | — |
| View dashboards & findings | ✅ | ✅ | ✅ | ✅ |

---

## 10. Deployment architecture

```
docker-compose.yml  (single node — VM or on-prem, air-gap capable)
├── proxy      (Caddy/nginx, :443)         — only exposed port
├── web        (Next.js)                    — internal
├── api        (FastAPI/uvicorn)            — internal
├── worker     (Celery; scaled by replicas) — internal, outbound to in-scope targets
├── postgres   (17)                         — internal, named volume
├── valkey     (8)                          — internal, named volume
├── minio      (S3-compatible)              — internal, named volume
└── (scanner images pulled/pinned by digest for reproducibility)
```

- **Single ingress:** only the reverse proxy exposes a port (443). Everything else is on the internal Compose network.
- **Config & secrets:** all via env / `.env` (from `.env.example`) or a mounted secrets file; nothing hardcoded. API keys for hosted LLMs are optional and per-deployment.
- **Air-gap mode:** with `hosted_models_allowed=false` on every engagement and local models only, the platform needs zero outbound internet except to the in-scope targets themselves.
- **Scaling knob for MVP:** `worker` replica count. No k8s, no autoscaling — deferred (see `ROADMAP.md`).
- **Backups:** Postgres dump + MinIO bucket snapshot; evidence immutability is preserved by MinIO object-lock.
- **Migrations:** Alembic runs on `api` startup (guarded) or as a one-shot init container.

---

## 11. Key architectural decisions (ADR summary)

| # | Decision | Rationale | Alternative rejected |
|---|---|---|---|
| 1 | Next.js (App Router) frontend | User decision; richest ecosystem, room for future SSR pages | Vite SPA (simpler, smaller attack surface) — reconsidered, not chosen |
| 2 | FastAPI + Celery + Valkey | Python-native scanner/LLM ecosystem; async I/O fits orchestration | NestJS; Temporal (deferred — see §6a) |
| 3 | Postgres 17 + MinIO split | Keep DB small/fast; immutable, hash-verified evidence for federal chain-of-custody | Everything in JSONB (TOAST amplification, 1 GB cap) |
| 4 | Valkey over Redis | BSD-3 under Linux Foundation; avoids SSPL/AGPL friction for federal/air-gap | Redis 7 (licensing risk) |
| 5 | Opaque server-side sessions | Instant revocation, forced logout, clean audit — needed for a security tool | JWT (revocation/audit friction) |
| 6 | Scanner adapter pattern + subprocess isolation | Tools swappable, version-pinned, killable for emergency stop | In-process libraries (no isolation/kill) |
| 7 | LLM provider abstraction + redaction + local models | Air-gap support; draft-only, evidence-grounded analysis | Direct vendor SDK calls in services |
| 8 | Scope enforcement in a single service, checked twice | Cannot be bypassed by a crafted request; defense in depth | UI-only gating (unsafe) |

---

## 12. What this architecture deliberately defers

- Horizontal scaling / Kubernetes / multi-node HA.
- Multi-tenant SaaS isolation (org boundary exists in schema; enforcement is single-org for now).
- SSO (OIDC/SAML) — abstraction is in place; implementation is post-MVP.
- Temporal/Dramatiq migration for the worker — only if orchestration grows to multi-step resumable pipelines.
- PDF/DOCX/JSON export — MVP ships CSV + Markdown.

These are intentional. The guiding principle from the brief holds: **a working vertical slice over broad-but-shallow features.**

---

## 13. Implementation caveats & required mitigations (verified against current sources, July 2026)

Every item below was fact-checked against current documentation. These are binding implementation notes, not suggestions.

**Queue / broker (Celery + Valkey)**
- Connect using the **`redis://` URL scheme**, never `valkey://` — Kombu has no `valkey://` transport and will raise `No such transport: valkey`. Valkey is protocol-compatible over `redis-py`, so `redis://` works unchanged.
- Use **separate logical DBs** on the one Valkey instance for broker / result backend / cache / sessions (single-DB-for-everything is an anti-pattern). Set `result_expires` (or `ignore_result=True`) so `celery-task-meta-*` keys don't accumulate.

**Reverse proxy / ingress**
- Set FastAPI **`root_path="/api"`** when the proxy strips the prefix, so OpenAPI/docs URLs are correct.
- Ensure response **streaming isn't collapsed** into one delayed response so Next.js RSC/streaming works. `proxy_buffering off;` is an **nginx** directive — it does **not** exist in Caddy. In **Caddy**, streaming is controlled on the `reverse_proxy` directive: Caddy auto-detects common streaming content types, but to force immediate flushing set **`flush_interval -1`** inside the `reverse_proxy` block (a negative value flushes writes to the client immediately). Emitting `X-Accel-Buffering: no` from the app additionally disables buffering on nginx-family proxies. See the [Caddy `reverse_proxy` docs](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).
- Forward `X-Forwarded-Proto`/`X-Forwarded-Host` correctly, or App Router soft-navigation breaks behind the proxy.
- Air-gap: configure Caddy **`tls internal`** (built-in CA) or mount certs — never leave it defaulting to public Let's Encrypt, or TLS provisioning fails against unreachable ACME. Distribute the internal root CA to clients.

**Migrations**
- Prefer a **one-shot init/migration service** (runs `alembic upgrade head`, exits, gated by a DB healthcheck) over migrate-on-startup. If migrate-on-startup is used, keep `api` at a **single replica** — multiple replicas race on migrations.

**Deployment (single-node Compose)**
- **Mandatory:** `deploy.resources.limits` (hard CPU/memory caps, especially on `worker` — a runaway scan can starve Postgres/Valkey/MinIO), healthchecks + `depends_on: service_healthy`, restart policies, and a real backup strategy (pg_dump/WAL + evidence-store mirror). Single node = no HA; acceptable for single-org internal use, documented as such.

**Scanner execution**
- Subprocess kill pattern: `subprocess.Popen(..., start_new_session=True)`, record the PID, cancel with `os.killpg(os.getpgid(pid), SIGTERM)` then `SIGKILL`. Celery `revoke`/`terminate` signals the worker child, **not** the scanner grandchild — the process-group kill is required.
- Run worker containers with **`--init`** (or bake in tini/dumb-init) so re-parented scanner children are reaped and signals are forwarded (PID-1 zombie problem).
- **ZAP:** use the `zaproxy/zap-stable` image **pinned by digest** (`zaproxy/zap-stable@sha256:<digest>`, never the floating tag — the `owasp/zap2docker-*` names are also deprecated); the **API key is required by default** — treat it as runtime secret material injected at launch (`-config api.key=...` from a secret, sent on every call) and never persist it into the stored `scanner_runs.config`; size the JVM heap (`-Xmx`) and container memory — active scans are memory-hungry.
- **Output parsing:** Nuclei (`-jsonl`) and TruffleHog (`--json`) emit **JSON Lines** — parse line-by-line, not `json.load()`. Pin TruffleHog's current schema (avoid `--json-legacy`). Semgrep (`--json`), OSV-Scanner (`--format json`), Gitleaks (`--report-format json`) emit standard JSON.
- **Rate limiting:** the per-engagement token bucket is the **authoritative aggregate ceiling**, enforced at the **egress shaper** (the single choke point all run traffic is routed through) so it holds across concurrent runs and inside opaque scanner daemons — not just inside one cooperative tool. Pair it with the outer timeout (which triggers the process-group kill). Also set each tool's native throttle as a floor (Nuclei `-rl`/`-timeout`, ZAP scan-policy delay/threads).

**Sessions**
- Use the **`__Host-` cookie name prefix** (implies `Secure`, `Path=/`, no `Domain`), ≥64-bit entropy ID, `HttpOnly; Secure; SameSite=Strict`.
- **Regenerate the session ID on login / privilege change** (session-fixation defense) — the most common gap.
- Enforce **idle + absolute timeouts server-side** (high-value tool: idle ~5–15 min, absolute ~4–8 h).
- On revoke / logout / kill-all-sessions, **invalidate the Valkey cache entry (write-through), not just the Postgres row** — otherwise a cached session outlives revocation until TTL, defeating "instant" revocation. Keep cache TTL short as a backstop.
- Future OIDC/SAML: `SameSite=Strict` blocks the IdP cross-site return — plan a `SameSite=None; Secure` correlation cookie used only during the auth handshake, or ensure 302-redirect binding.

**LLM layer**
- If **LiteLLM** is adopted: treat it as untrusted-until-verified after the **March 2026 PyPI supply-chain backdoor** (v1.82.7/.8) — hash-pin installs (`--require-hashes`), pull from a vetted internal mirror, pin image digests, run network-segmented with least privilege (it holds provider keys), rotate handled credentials. Default remains a **thin in-house adapter** for Claude + one local backend (lower attack surface).
- **Redaction** (Presidio for PII + regex/entropy for secrets) is **defense-in-depth, not a guarantee** — detection is probabilistic. The `hosted_models_allowed=false` hard block is the real control for sensitive engagements. Redaction must **fail-closed** (block egress on redactor error/timeout) and log what it redacted.
- Local model **weights** carry their own licenses (runtime is permissive: Ollama MIT, vLLM Apache-2.0). Prefer **Apache-2.0 weights (Qwen3, Gemma)** over Llama's custom community license for federal use; record each model's license in the SBOM.

**Evidence store**
- See §7: the MinIO OSS repository is archived (2026-04-25, https://github.com/minio/minio) — access storage through the S3 abstraction and decide the production backend explicitly (a blocking pre-go-live gate); verify compliance-mode WORM is actually *enforced* (delete-before-expiry must be rejected) before trusting it, and before evidence storage counts as complete.
