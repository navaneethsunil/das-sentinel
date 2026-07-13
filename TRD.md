# TRD.md — DAS Sentinel

> **Technical Requirements Document.** Translates the PRD's functional/non-functional requirements into concrete, testable technical specifications: API contracts, component responsibilities, adapter interfaces, crypto/security specifics, observability, performance budgets, and test requirements. Pairs with `PRD.md` (the *what/why*) and `ARCHITECTURE.md` (system shape). Where a data structure is referenced, `DATABASE_SCHEMA.md` is authoritative. Requirement IDs here (**TR-n**) trace back to PRD **FR-n / NFR-n**.

| | |
|---|---|
| **Product** | DAS Sentinel |
| **Scope of this doc** | MVP (M1–M3) technical spec, with post-MVP interfaces stubbed where they shape MVP design |
| **Last updated** | 2026-07-06 |
| **Authoritative siblings** | ARCHITECTURE.md · DATABASE_SCHEMA.md · MVP_TASKS.md · CLAUDE.md · SECURITY_DEVELOPMENT_PLAN.md |

---

## 1. Technology baseline (normative)

| Concern | Requirement |
|---|---|
| Backend | Python 3.12+, FastAPI, Pydantic v2 (≥2.7), SQLAlchemy 2.x, Alembic |
| Workers | Celery, Valkey broker via the **`redis://`** URL scheme (Kombu has no `valkey://` transport), separate logical DBs for broker/backend/cache/session |
| Frontend | Next.js (App Router) + TypeScript (strict), Tailwind, shadcn/ui |
| Data | PostgreSQL 17; MinIO/S3-compatible object store for evidence (backend per `ROADMAP.md` gate) |
| Cache/queue/session | Valkey 8 |
| LLM | Provider abstraction (thin adapter default); Anthropic Claude hosted, Ollama/vLLM local |
| Ingress | Caddy/nginx reverse proxy, single `:443`, TLS (Caddy `tls internal` for air-gap) |
| Packaging | Docker Compose, single node; `--init` on worker containers |
| Auth | Local email/password (Argon2id / FIPS PBKDF2), opaque server-side sessions |

All version/currency and licensing caveats are in `CLAUDE.md §3`. This TRD does not restate them.

---

## 2. Service topology & responsibilities

Per `ARCHITECTURE.md §3`. Normative boundaries:

- **TR-1** The `api` service performs **all** authorization, scope enforcement, and persistence. It **must not** execute scanner tools in-process; it only enqueues jobs.
- **TR-2** The `worker` service executes scanner/LLM/test jobs via the **uniform execution owner** in **rootless, contained, killable per-run sandboxes** (TR-12.1); it **re-reads** the scan, the immutable `execution_authorization` envelope, and the engagement/target/ROE/approval from the DB, **re-derives and re-verifies the authorization** (recomputing `operation_digest`, TR-11.5) and **re-runs scope enforcement** before launching any tool (never trusts the job payload).
- **TR-3** The `web` service talks only to `api` over same-origin `/api/*`; it holds no DB/broker credentials.
- **TR-4** Only the reverse proxy exposes a network port. All inter-service traffic is on the internal Compose network.

---

## 3. API specification (MVP)

**Conventions**
- Base path `/api`; JSON over HTTPS; `application/json`.
- Auth via the opaque-session cookie (`__Host-…`). **CSRF: the primary defense is a synchronizer anti-CSRF token bound to the server-side session** (required on all state-changing routes), with `SameSite=Strict` + Origin/Referer verification as defense-in-depth. Per current OWASP guidance, SameSite alone is *not* sufficient (it doesn't cover sibling-subdomain/same-site risks) — see TR-22.1.
- Errors: RFC 9457 problem+json shape — `{ "type","title","status","detail","instance" }`.
- Timestamps ISO-8601 UTC. IDs are UUIDs. List endpoints support `?limit&cursor` keyset pagination.
- **TR-5** Every state-changing endpoint emits exactly one primary `audit_event` reflecting the outcome (success/blocked/failure).

**Standard error codes**

| HTTP | When |
|---|---|
| 400 | Malformed request / validation error |
| 401 | No / expired / revoked session |
| 403 | **Policy/authorization refusal** (RFC 9110 §15.5.4): RBAC denial, **target out of scope**, **ROE not accepted**, **high-risk not approved** |
| 409 | **Resource-state conflict** (§15.5.10): engagement not active (draft/paused/closed) |
| 422 | **Semantic payload validation** (§15.5.21): e.g., scan intensity exceeds the engagement maximum |
| 429 | Rate-limited |

Each 4xx carries an RFC 9457 `type` URI identifying the specific reason (e.g., `…/errors/scope-violation`) so clients branch on the cause, not just the status.

### 3.1 Auth & sessions (FR-24, NFR-5)
```
POST   /api/auth/login            {email,password} → sets __Host- session cookie; regenerates session id
POST   /api/auth/logout           → revokes current session (revoked_at, cache purge)
POST   /api/auth/logout-all       → revokes all sessions for the user
GET    /api/me                    → {id,email,display_name,role}
```
- **TR-6** On successful login, mint a new session row (new random token, store only SHA-256), set `__Host-` cookie `HttpOnly; Secure; SameSite=Strict; Path=/`. Any prior session for that browser is revoked (fixation defense).
- **TR-7** Every authenticated request validates the session against Valkey (cache) → Postgres (source of truth), rejecting if `revoked_at IS NOT NULL` or past `idle_expires_at`/`absolute_expires_at`. Sliding `idle` updates; `absolute` is a hard cap.

### 3.2 Engagements, scope, ROE, approvals (FR-1–FR-6)
```
GET/POST/PATCH   /api/engagements[/{id}]
GET/POST/DELETE  /api/engagements/{id}/scope-items
POST             /api/engagements/{id}/roe:accept   {roe_text_ack:true} → writes immutable roe_acknowledgement (hash+snapshot)
GET              /api/engagements/{id}/roe           → current acceptance + status
POST             /api/engagements/{id}/approvals     {target_id,action_type,intensity,config,justification} → approval_gate (pending); server computes+stores operation_digest, roe_ack_id, policy_version, mandatory expires_at
POST             /api/approvals/{id}:decide          {decision,reason,expires_at}   (Admin/Reviewer only)
POST             /api/approvals/{id}:revoke          {reason}   (Admin/Reviewer only; approved→revoked, effective immediately)
GET              /api/approvals/{id}                  → full state (status, subject digest, expiry, revocation, consumption)
```
- **TR-8** ROE acceptance computes `content_hash = SHA256(roe_text ‖ canonical_json(scope_snapshot) ‖ canonical_json(terms_snapshot))` and freezes both the scope snapshot **and the authorization-relevant terms** (`test_window_start/end`, `rate_limit_rps`, `max_intensity`). Editing scope **or any frozen term** after acceptance sets the engagement to require re-acceptance (a flag surfaced on scan attempts) — so the values enforced at run time are always provably equal to the values a human accepted.
- **TR-8.1 Approval state machine (TR-11.5 enforces it)** — `pending → approved → consumed`, or `→ denied / → expired / → revoked`. At request time the server binds the approval to an **immutable operation subject**: `operation_digest = SHA256(canonical_json(engagement_id, target_id, action_type, effective_intensity, typed_canonical_config, server_capabilities))`, plus `roe_ack_id` (current ROE acknowledgement) and `policy_version`. `expires_at` is **mandatory**. An approval is **single-use**: a scan claims it via an atomic conditional update (`approved → consumed` only if not expired/revoked), and the affected-row count is checked — 0 rows ⇒ refuse. Revocation takes effect immediately (checked at both enqueue and execution).

### 3.3 Targets (FR-7)
```
GET/POST/PATCH/DELETE  /api/engagements/{id}/targets[/{tid}]
POST                   /api/targets/{tid}/source-archive   (multipart) → evidence(kind=source_archive)
```

### 3.4 Scans (FR-8–FR-12, FR-22)
```
POST   /api/scans                 {engagement_id,target_id,scanner|suite,intensity,config} → 202 {scan_id}
GET    /api/scans/{id}            → status, runs, progress
POST   /api/scans/{id}:cancel     → emergency stop (sets cancel_requested; worker kills process group)
GET    /api/scans?engagement_id=  → list
```
- **TR-9** `POST /api/scans` runs the scope-enforcement gate (§4) **before** enqueueing. On block → the appropriate 4xx per the error table (403 scope/ROE/high-risk, 409 engagement-inactive, 422 intensity) + audit `blocked`, no job enqueued. On success → **202 Accepted**, persist `scan(status=queued)` **and, in the same transaction, an immutable `execution_authorization` envelope** (TR-9.1), then enqueue a Celery job carrying **only** `scan_id`.
- **TR-9.1 Execution-authorization envelope (immutable)** — when the gate passes, the server writes one `execution_authorizations` row (`DATABASE_SCHEMA.md §6`) freezing exactly what was authorized: `engagement_id`, `target_id`, `requested_by`, **server-derived `effective_intensity`** (from typed config classification, not the caller's declared value — see TR-11.6), typed/canonicalized/redacted `normalized_config`, `server_capabilities`, `roe_ack_id`, `policy_version`, bound `approval_gate_id` (high-risk only), the `operation_digest` over the canonical subject, and the authorized `test_window`. The ID-only job cannot carry authorization state, so the envelope is the reconstructable record. **The worker re-reads the envelope, re-derives every field from the live DB, and refuses to launch on any divergence** (TR-11.5). The envelope is insert-only (TR-19).

### 3.5 Findings, CVSS, mapping (FR-14–FR-16)
```
GET    /api/findings?engagement_id=&severity=&source=&status=   (keyset paginated)
GET    /api/findings/{id}
PATCH  /api/findings/{id}         {status?,is_false_positive?}  → validated transitions only
POST   /api/findings/{id}/cvss    {version,vector_string,manual_override?,justification?}
GET    /api/findings/{id}/evidence
POST   /api/findings:import-sarif (multipart SARIF 2.1.0) → normalized findings
GET    /api/findings/{id}/export-sarif
```
- **TR-10** A status transition to `confirmed`/`fixed` on a finding whose `provenance='ai_generated'` requires an authenticated Reviewer/Tester/Admin and writes a `finding_status_history` row; the service rejects the transition otherwise (enforces the provenance rule).

### 3.6 Reports (FR-19)
```
GET/POST/PATCH   /api/reports[/{id}]
POST             /api/reports/{id}/findings        {finding_ids[]}
GET              /api/reports/{id}/export?format=csv|md   → POA&M CSV | Markdown
```

### 3.7 Audit & LLM config (FR-21, FR-23)
```
GET    /api/audit?engagement_id=&actor=&outcome=      (Admin/Reviewer; read-only; append-only source)
GET/PATCH  /api/settings/llm                          (Admin) → provider/model/hosted defaults
```

---

## 4. Scope-enforcement engine (TR-11) 🔒

The keystone (`core/scope.py`). Single entry point, called by both `api` (pre-enqueue) and `worker` (pre-execute). It authorizes a **typed, server-normalized operation** — never the caller's raw declared intensity — and evaluates against the wall clock:

```
authorize_operation(engagement, target, op: NormalizedOperation, roe_ack, now) -> ExecutionAuthorization
  where NormalizedOperation = typed+canonicalized scanner/suite config + server-derived capabilities
  raises: EngagementInactive | ROENotAccepted | ROEStale | ROETermsMismatch
        | OutsideTestWindow | ScopeViolation | IntensityNotAuthorized | HighRiskNotApproved
```

- **TR-11.1** Order of checks: engagement active → ROE accepted (and not stale) → **ROE terms match** (engagement's live `test_window`/`rate_limit_rps`/`max_intensity` equal `roe_ack.terms_snapshot`; any drift ⇒ `ROETermsMismatch`, re-acceptance required) → **within test window** (`now ∈ [test_window_start, test_window_end]` when set; outside ⇒ `OutsideTestWindow`) → target matches an **allow** scope item → target matches **no deny** item (deny wins) → **`effective_intensity ≤ engagement.max_intensity`** → if `effective_intensity = high_risk`, a valid approval exists **and its `operation_digest` equals the digest recomputed from `op`** (TR-11.5).
- **TR-11.2** Matching semantics: `url` (scheme+host+path prefix), `domain` (host or subdomain), `ip_cidr` (address ∈ CIDR, resolve host→IP for URL/domain targets and check the resolved IP too), `api_base` (URL prefix), `repo` (normalized repo identity). Ambiguous/unresolvable → **fail closed** (treated as out of scope).
- **TR-11.3** Every raise writes an audit event with `outcome='blocked'` and the specific reason in `detail`.
- **TR-11.4** The function is pure/deterministic (all inputs — including `now` and `roe_ack` — passed in) and unit-tested with a negative-test matrix (see §11).
- **TR-11.5 Two-boundary verification** — at enqueue the API runs this and persists the resulting `ExecutionAuthorization` envelope (TR-9.1). Before launch the worker re-reads the envelope, **re-derives every field from the live DB** (engagement, target, ROE terms, current time, approval state), recomputes `operation_digest`, and refuses to launch on any divergence — the envelope is a record to verify against, never a trusted payload. For high-risk it also **atomically consumes** the bound approval (`approved → consumed`; 0-row update ⇒ refuse).
- **TR-11.6 Server-derived intensity (no caller trust)** — the effective intensity is **classified by the server from the typed, canonicalized operation config and server-derived capabilities**, not taken from the caller's declared field. Config is parsed into a typed model and capabilities resolved **before** policy evaluation; the caller-declared intensity is at most an upper-bound hint and a mismatch where the classified intensity exceeds it is a `422`.

---

## 5. Scanner adapter interface (TR-12)

Per `CLAUDE.md §6` / `ARCHITECTURE.md §6`. Every scanner implements:

```python
class ScannerAdapter(Protocol):
    name: str
    def version(self) -> str: ...
    def validate_prerequisites(self) -> None: ...           # tool present/reachable
    def build_command(self, target, config) -> Command: ...  # never runs on an unvalidated target
    def run(self, target, config, on_progress) -> RawResult: ...  # child process group; timeout+rate-limit
    def normalize(self, raw: RawResult) -> list[FindingDraft]: ...  # → shared Finding model (SARIF superset)
```

- **TR-12.1 Uniform execution owner — containment, kill & verified teardown** — scanners and PyRIT suites launch through one `ExecutionOwner` (`workers/execution.py`) with a uniform launch/cancel/teardown contract. Runs execute in a **rootless per-run sandbox** (rootless container / user namespace): minimal mostly-read-only mounts (only the run's inputs/outputs), **all capabilities dropped** + `no-new-privileges` + seccomp, **short-lived scoped credentials** for that run only (no ambient worker secrets), and **egress only via the engagement egress shaper** (TR-26.2/TR-12.2). Killability alone is not containment — the sandbox removes the worker's filesystem/credential/syscall/capability/internal-network authority from the tool. Record the process-group/container id on `scanner_runs.os_process_group`; cancellation sends `SIGTERM`→`SIGKILL` (`os.killpg`/container stop) **and confirms** the process tree is gone. **Teardown is verified** — the owner asserts the sandbox is destroyed and transient credentials revoked; teardown failure is a surfaced job error, never silently assumed. Worker containers run with `--init` (tini) for zombie reaping.
- **TR-12.2 Aggregate rate & timeout (egress shaper)** — the engagement's `rate_limit_rps` is the **authoritative aggregate ceiling**, enforced at an **engagement-aware egress shaper** (a forward-proxy/choke point all run traffic is routed through) so it holds **across concurrent runs and inside opaque scanner processes/daemons** (e.g., the ZAP daemon), not only inside one cooperative tool. The worker also applies an outer wall-clock timeout that triggers the kill path. Native tool throttles (Nuclei `-rl`, ZAP scan-policy delay) are set as a floor. A test asserts the **observed** aggregate outbound rate under concurrent runs stays ≤ the ceiling; if the shaper is unavailable, egress fails closed.
- **TR-12.3 Evidence split** — raw output is streamed to the object store first (hashed → `evidence` row), then `normalize()` reads from the raw artifact. Raw is never mutated.
- **TR-12.4 Version/config capture** — `scanner_runs.scanner_version` + `config` recorded on every run.

**MVP adapters**
- **TR-13 Semgrep CE** — invoke `semgrep --json --metrics=off` against a **vendored, content-hashed rule bundle** on a local path (never floating registry aliases like `p/owasp-top-ten`/`p/default`, which resolve to whatever the registry serves at run time and are non-reproducible and air-gap-hostile). The bundle's license must be cleared for our use (Semgrep-maintained rules ship under the Semgrep Rules License v1.0 — no redistribution in a competing/SaaS product; use OpenGrep/LGPL-compatible rules or an explicitly licensed set) and is recorded with its **SHA-256 digest + source + license** in `scanner_runs.config` and the SBOM. Map `results[]` → findings (rule_id, path+line into `location`, severity).
- **TR-14 ZAP by Checkmarx** — run the ZAP image **pinned by digest** (`zaproxy/zap-stable@sha256:<digest>`, never the floating `zaproxy/zap-stable` tag) in daemon mode; the API key is **runtime secret material** injected at launch (not persisted into `scanner_runs.config` — see `DATABASE_SCHEMA.md §6`); drive via the ZAP API; baseline (passive) for routine runs, active only at higher intensity; size JVM `-Xmx`; map alerts → findings (endpoint/method into `location`).

**Post-MVP adapters** (interfaces must not require change to add): Nuclei (JSONL), OSV-Scanner/pip-audit/npm audit, Gitleaks/TruffleHog (JSONL). Parsers must handle **JSON Lines** (parse per line) for Nuclei/TruffleHog.

---

## 6. AI/LLM test-runner interface (TR-15)

- **TR-15.1** A single `Runner` interface: `run(target, config, cancel: CancelToken) -> NormalizedResult`. **MVP implements PyRIT only** (native Python library, `github.com/microsoft/PyRIT`). Because PyRIT is embedded in the Celery worker with **no subprocess**, process-group signalling cannot selectively stop it, so the interface carries an explicit **cancellation handle**: the owner either runs the suite in a **dedicated child owner** (killable like a scanner) or PyRIT honours a **bounded cooperative `CancelToken` checked between every prompt/turn** so emergency stop takes effect within the TR-30 budget. garak (Python subprocess/JSONL) and promptfoo (Node.js CLI — requires Node 24 in the image) are post-MVP adapters behind the same interface.
- **TR-15.2** Each test produces a transcript (`prompt / response / expected / actual / pass-fail`) written to the object store as `evidence(kind=llm_transcript)`; findings normalize into the shared model with an OWASP LLM mapping and `provenance` in {`automated`,`ai_generated`}.
- **TR-15.3** Suites: prompt-injection (direct, multi-turn/Crescendo, indirect from seeded corpora, instruction-hierarchy, jailbreak, tool-call manipulation → LLM01); data-leakage (LLM02/05/07/08 + cross-tenant isolation, the last being bespoke).
- **TR-15.4** Test runs use the **same uniform execution owner** (TR-12.1) as scanners — rootless sandbox, scoped credentials, egress via the shaper, verified teardown — and the same confirmed-cancellation guarantee via the `CancelToken`/child-owner in TR-15.1. A test asserts an in-flight PyRIT suite actually halts on emergency stop.

---

## 7. LLM provider layer (TR-16, FR-21) 🔒

- **TR-16.1** All model calls go through `app/llm`; no vendor SDK is called directly from a router/service.
- **TR-16.2 Redaction gate (fail-closed)** — before any **hosted** call, run the redaction pass (PII via Presidio-class detection + secret/entropy scan). If the redactor errors or times out, **block egress** (do not send). Redaction is defense-in-depth, not the sole control.
- **TR-16.3 Hosted gate** — if `engagement.hosted_models_allowed = false`, hosted adapters are unavailable; only local (Ollama/vLLM) may run. Enforced in the abstraction, not the caller.
- **TR-16.4 Draft-only** — LLM output is stored `ai_generated`, must cite supplied evidence, and never sets final CVSS or a `confirmed`/`fixed` status.
- **TR-16.5 Logging** — every call writes `llm_interactions` with provider, model, prompt-template version, `was_redacted`, `hosted`, tokens, and `cost_usd`.
- **TR-16.6 Claude params** — use current params only (`thinking:{type:"adaptive"}`, strict tool use for structured output); no `budget_tokens`/`temperature`/date-suffixed IDs; avoid Fable-5 as default (cyber-refusal risk) or set `fallbacks`.

---

## 8. Data & evidence handling (NFR-2)

- **TR-17** Structured data in Postgres 17 per `DATABASE_SCHEMA.md`; large blobs never in JSONB.
- **TR-18** Evidence write is two-phase: blob → object store (compliance-mode object-lock, content-hash) **then** commit the `evidence` row (object_key, `content_sha256` as bytea, size, content-type, `retain_until`). An orphan-sweep job reconciles blobs whose metadata commit failed. Re-verify hash + size on read.
- **TR-19** Immutable tables (`evidence`, `roe_acknowledgements`, `execution_authorizations`, `audit_events`, `llm_interactions`, `cvss_scores`, `*_history`, `retests`) are insert-only; production DB role denies UPDATE/DELETE on them.
- **TR-20** Dedup: compute `hash_code = SHA256(defined field set)` on (re)import; a live finding with the same hash for the target links `duplicate_of` instead of inserting; `partial_fingerprints` supports cross-tool matching.

---

## 9. Security requirements (NFR-1, NFR-5)

- **TR-21 Password hashing** — Argon2id (OWASP params: ≥19 MiB, t=2, p=1) by default; **PBKDF2-HMAC-SHA-256 (≥600k)** where a FIPS 140-3-validated module is required. The choice is a startup config; must be fixed before first users (avoids rehash migration).
- **TR-22 Sessions** — opaque, server-side, hashed at rest (SHA-256 of a ≥128-bit random token); `__Host-` cookie; idle + absolute timeouts server-enforced; instant revocation via `revoked_at` + cache purge.
- **TR-22.1 CSRF** — primary defense is a **synchronizer token bound to the server-side session**, verified on every state-changing request (surfaced to the SPA via a readable token + custom request header, which also forces a CORS preflight cross-origin). `SameSite=Strict` and Origin/Referer verification are defense-in-depth, not the primary control. If SameSite-only is ever accepted for the same-origin single-proxy deployment, it must be a recorded, signed-off risk acceptance noting the sibling-subdomain caveat.
- **TR-23 Secrets** — no plaintext secrets in DB or code; `targets.auth_config` holds references to a secrets manager only; LLM keys via env/secrets file; `.env.example` placeholders only.
- **TR-24 Transport & headers** — TLS at the proxy; internal network isolated. Security headers at the proxy: **HSTS**, **CSP** (including **`frame-ancestors 'none'`** for clickjacking defense — obsoletes `X-Frame-Options`), **X-Content-Type-Options: nosniff**, **Referrer-Policy**, **Permissions-Policy** (disable unused features: camera/mic/geolocation/…), and **Cross-Origin-Opener-Policy: same-origin**. Do **not** emit `X-XSS-Protection` (deprecated; set `0` if present) or `Expect-CT`/HPKP; strip `Server`/`X-Powered-By`.
- **TR-25 Supply chain** — pin exact versions + hashes for Python (esp. any LLM-gateway dep); pin **all scanner container images by digest** (`…@sha256:<digest>`, not a mutable tag such as `zaproxy/zap-stable` or `:latest`); pin **scanner rule/signature bundles by content hash** (Semgrep rules, Nuclei templates) rather than pulling floating registry packs at run time; prefer a vetted internal mirror for air-gap. Digests/hashes are recorded per run for reproducibility.
- **TR-26 RBAC** — enforced as FastAPI route dependencies resolving the session→user→role, per the `ARCHITECTURE.md §9` matrix; default-deny. Every object query is additionally scoped to the caller's org/engagement (no cross-engagement IDOR/BOLA — OWASP A01:2025).
- **TR-26.1 Platform self-AppSec (normative)** — the platform is built to **OWASP ASVS 5.0** (target Level 2 app-wide, **Level 3** for auth/session/crypto/audit), **OWASP Top 10:2025**, and **NIST SSDF (SP 800-218/218A)**. The threat model, CI security pipeline, and per-phase 🛡 Security Gates are defined in **`SECURITY_DEVELOPMENT_PLAN.md`** and are release-gating, not advisory.
- **TR-26.2 Anti-SSRF worker egress (fail-closed)** — all run traffic is routed through the **engagement-aware egress shaper** (the single choke point that also enforces the aggregate rate ceiling, TR-12.2), which applies a **default-deny egress allowlist**: only in-scope target IPs and configured LLM/provider endpoints are reachable. Loopback, link-local, RFC-1918, and cloud-metadata (169.254.169.254) destinations are blocked unless explicitly in scope; the scope engine checks the **resolved** IP (`TR-11.2`); adapters limit and re-validate redirect hops. The per-run sandbox (TR-12.1) has no other network path, so an opaque or compromised tool cannot bypass the shaper. If the shaper is unavailable, egress fails closed. (Threat TM-1; a scan-launcher is an inherent SSRF amplifier — the scope allowlist alone is necessary but not sufficient.)
- **TR-26.3 Our-own-LLM injection defense** — input to *our* triage/remediation/report models (scanner output, captured target responses, uploaded code) is treated as untrusted **data, not instructions**; structured-output tool-use only; the LLM never sets scope, severity, status, or actions (reinforces `TR-16.4`); every evidence pointer the model cites is validated programmatically against the source record (unresolved ⇒ rejected). (Threat TM-4; OWASP LLM01 against us.)
- **TR-26.4 SBOM & provenance** — a **CycloneDX SBOM** (Syft) is generated per build from M0 for visibility; **artifact signing (Sigstore/cosign) + SLSA v1.0 provenance** are enforced at the Hardening gate for release artifacts (OWASP A03:2025). Bundled model-weight licenses are recorded in the SBOM.

---

## 10. Observability & performance

- **TR-27 Health** — `/healthz` (liveness) must **not** check external dependencies (a dependency outage must not trigger restart loops); `/readyz` checks DB + Valkey + object-store reachability. Worker liveness via Celery ping.
- **TR-28 Logging** — structured JSON logs; correlation id per request and per scan; scanner stderr captured into the run record on failure (never swallowed).
- **TR-29 Metrics** — task queue depth, scan durations, LLM tokens/cost per engagement; dev via Flower (pinned), prod path via celery-exporter + Prometheus (post-MVP).
- **TR-30 Performance budgets (MVP, single-org dataset)** — dashboard/list API p95 < 300 ms; scan enqueue < 500 ms; cancellation takes effect within ~5 s — process group killed and confirmed for subprocess/container runs, and the cooperative `CancelToken` observed within one prompt/turn for in-process PyRIT suites (TR-15.1); findings list paginated (keyset) to bound payloads.

---

## 11. Testing requirements (NFR-1)

- **TR-31 Safety negative tests (mandatory, gating)** — automated tests prove scope enforcement blocks: no engagement, no scope, ROE not accepted, ROE stale after scope change, **ROE-terms drift (rate_limit/max_intensity/test-window changed after acceptance)**, **execution outside the test window (before start, after end)**, out-of-scope target, deny-overrides-allow, resolved-IP out of scope, over-max-intensity, **intensity-escalation-via-config (caller declares a low intensity but the typed config classifies higher)**, high-risk-without-approval, **approval whose `operation_digest` doesn't match the scan**, **reuse of an already-consumed approval**, **use of an expired approval**, and **use of a revoked approval** — each asserting a `blocked` audit event and no job enqueued (and, for the worker boundary, no tool launched). Every check runs at **both** the API and worker boundaries.
- **TR-32 Auth/session tests** — fixation regeneration on login; immediate revocation across cache+DB; idle/absolute expiry; RBAC allow/deny per route per role.
- **TR-33 LLM gate tests** — hosted egress blocked when `hosted_models_allowed=false`; redactor failure → egress blocked (fail-closed); AI finding cannot reach confirmed/fixed without a human transition.
- **TR-34 Adapter tests** — Semgrep against a known-vulnerable repo (Juice Shop/BrokenCrystals source) and ZAP baseline against a running vulnerable container assert normalized findings + evidence + rate-limit respected + cancellable; SARIF import/export round-trip; dedup links `duplicate_of`.
- **TR-35 Export tests** — POA&M CSV has the required columns; Markdown report renders; CVSS history preserved on override.
- **TR-36 CI gate** — Ruff + ESLint/Prettier + TS strict + the above suites must pass; safety negative tests (TR-31) are release-blocking.
- **TR-37 CI security pipeline** — on every PR (per `SECURITY_DEVELOPMENT_PLAN.md §5`): SAST (Semgrep + Bandit), secret scanning (Gitleaks), SCA (pip-audit/npm audit/OSV-Scanner), container/IaC scan (Trivy), **DAST baseline (ZAP) against our own running app**, SBOM (Syft→CycloneDX), and CI/CD hardening (pinned action SHAs, least-privilege tokens, zizmor). Secret findings and safety negatives block from M0; other thresholds tighten per milestone (report-only → block-on-High → production-blocking). A scanner stage that errors is a failed stage (fail-closed), not skipped. All tool databases must be mirror-able offline (air-gap).
- **TR-38 Platform abuse-case / negative security tests (release-blocking)** — cross-engagement IDOR/BOLA (TM-3); **cross-engagement graph splicing — a scan whose target or approval_gate belongs to a different engagement is rejected at the API, in the worker re-check, AND by the composite FK/DDL (two-engagement negative test)** (TM-3); session fixation/instant-revoke/CSRF (TM-10, extends TR-32); SSRF/egress — target resolving to loopback/link-local/RFC-1918/metadata blocked, out-of-scope redirect blocked, decoy internal service unreachable (TM-1); our-own-LLM injection (TM-4); malicious upload — zip-bomb/zip-slip/symlink (TM-7); hostile-parser fuzz on SARIF/JSONL/transcripts (TM-8); deny-on-error at every security decision point (TM-14); **secret-material containment — a sentinel control secret (e.g., the ZAP API key) injected at launch must not appear in `scanner_runs.config`, logs, evidence blobs, error summaries, or any export** (TM-6). Catalog in `SECURITY_DEVELOPMENT_PLAN.md §8`.
- **TR-39 Dogfooding** — from M3, the platform's own Semgrep + ZAP adapters run against DAS Sentinel's own code/running app in CI; findings are triaged like any engagement's (`SECURITY_DEVELOPMENT_PLAN.md §4`).

---

## 12. Traceability (TR → PRD → brief)

| TRD | PRD | Brief module |
|---|---|---|
| TR-6/7/22, TR-26 | FR-24, NFR-5 | Safety & authorization controls (roles) |
| TR-8, TR-11 | FR-1–FR-6 | Engagement & scope management |
| TR-9, TR-12 | FR-11, FR-22 | Scanner orchestration; emergency stop |
| TR-13/14 | FR-11 | Semgrep; DAST |
| TR-15 | FR-8–FR-9 | Prompt-injection & data-leakage testing |
| TR-16 | FR-21 | LLM layer |
| TR-10, TR-20 | FR-14 | Automated findings normalization |
| TR-18/19 | NFR-2 | Raw evidence retention |
| TR-17, TR-20 | FR-14–FR-16 | Standards mapping, CVSS |
| TR-31…36 | NFR-1 | Safety acceptance criteria |
| TR-26.1…26.4, TR-37…39 | NFR-1, NFR-5 | Platform self-AppSec / secure SDLC (`SECURITY_DEVELOPMENT_PLAN.md`) |

---

## 13. Deferred technical decisions (gates)

Resolved before production, per `ROADMAP.md`: production evidence-store backend; Argon2id-vs-PBKDF2 (FIPS); worker engine (Celery vs Dramatiq/Temporal) only if orchestration grows; LiteLLM vs thin adapter when a 3rd provider is needed; SSO/OIDC.
