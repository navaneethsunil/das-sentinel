# MVP_TASKS.md — DAS Sentinel

> Concrete, ordered, checkable task breakdown for the **MVP critical path (M0 → M3)**. Scope, sequencing, and exit criteria come from `ROADMAP.md`; entities from `DATABASE_SCHEMA.md`; rules from `CLAUDE.md`. Post-MVP milestones (M4–M6) are tracked in `ROADMAP.md`, not here.

## How to use this file

- Tasks are grouped by milestone, then ordered by dependency. **Do them top-to-bottom within a milestone** unless a task is marked parallel-safe.
- Each task has an ID (`M1-B3` = Milestone 1, Backend, task 3), a **Definition of Done (DoD)**, and its blocking dependencies.
- Lanes: **B** = backend/API, **W** = worker, **F** = frontend, **D** = data/migrations, **I** = infra/devops, **T** = tests, **SEC** = platform application-security (see `SECURITY_DEVELOPMENT_PLAN.md`).
- 🔒 = safety-critical (must have negative tests). 🛡 = platform-AppSec task tied to a threat-model ID (`TM-n`) in `SECURITY_DEVELOPMENT_PLAN.md §3`. A milestone is not "done" until its **Exit gate** *and* its **🛡 Security Gate** pass.
- Checkbox convention: `[ ]` todo · `[~]` in progress · `[x]` done.

Legend for effort (rough): **S** ≤ half day · **M** ~1–2 days · **L** ~3–5 days.

---

## M0 — Project scaffolding & CI

Goal: `docker compose up` yields a healthy stack; CI is green; a request round-trips browser → proxy → api → db.

- [x] **M0-I1** (S) Initialize monorepo layout per `CLAUDE.md §4`: `apps/web`, `apps/api`, `packages/compliance`, `sandbox/`, root `README`, `.editorconfig`, `.gitignore`.
- [x] **M0-I2** (M) `docker-compose.yml` with services: `proxy` (Caddy), `web`, `api`, `worker`, `postgres:17`, `valkey:8`, `minio` (dev evidence store). Named volumes; internal network; only proxy exposes `:443`. **Add `--init` on `worker`**, `deploy.resources.limits` on all, healthchecks + `depends_on: service_healthy`. *(dep: M0-I1)*
- [x] **M0-I3** (S) `.env.example` with all placeholders; single `Settings` object (pydantic-settings) in `api`; no hardcoded hosts/keys/model names. *(dep: M0-I1)*
- [x] **M0-B1** (M) FastAPI skeleton: app factory, `/healthz` (liveness) + `/readyz` (DB+Valkey check), structured logging, `root_path="/api"`, CORS off (same-origin). *(dep: M0-I3)*
- [x] **M0-W1** (S) Celery app wired to Valkey via **`redis://` scheme** (not `valkey://`), separate logical DBs for broker/backend/cache/session; a `ping` task + **Flower (dev only** — pin the version; its last release is 2.0.1/2023, so verify it boots against our Celery version and prefer celery-exporter + Prometheus for any prod monitoring later). *(dep: M0-I2)*
- [x] **M0-F1** (M) Next.js (App Router) skeleton + Tailwind + shadcn/ui; typed API client scaffold; app shell with nav placeholders; `/health` page hitting `/api/healthz`. *(dep: M0-I3)*
- [x] **M0-I4** (M) Caddyfile: `/` → web, `/api/*` → api (with `root_path` awareness), **`reverse_proxy … { flush_interval -1 }`** on the RSC/streaming route (Caddy has no `proxy_buffering` directive — that is nginx; `flush_interval -1` forces immediate flushing), forwarded headers set, **`tls internal`** for local/air-gap. *(dep: M0-I2, M0-B1, M0-F1)*
- [x] **M0-D1** (S) Alembic initialized as a **one-shot migration service** in compose; empty baseline migration; DB-readiness gate. *(dep: M0-I2)*
- [x] **M0-I5** (M) CI pipeline: Ruff (lint+format), ESLint/Prettier, TS strict typecheck, `pytest` smoke, build images. Fails on any lint/type error. *(dep: M0-B1, M0-F1)*
- [x] **M0-T1** (S) Smoke test: bring stack up in CI, assert `/readyz` 200 and a browser→proxy→api→db round-trip. *(dep: M0-I4, M0-D1)*

### Security 🛡
- [x] **M0-SEC1** (M) 🛡 **CI security pipeline** (extends `M0-I5`) per `SECURITY_DEVELOPMENT_PLAN.md §5`: Semgrep + Bandit (SAST), Gitleaks (secrets, + pre-commit hook, full history), pip-audit/npm audit/OSV-Scanner (SCA), Trivy (image + `docker-compose.yml`/IaC), ZAP baseline against the running stack (DAST-on-self), Syft→CycloneDX SBOM artifact, and CI/CD hardening (pinned action SHAs, `permissions:` least-privilege, zizmor). **Secret findings and safety negatives block from day one; other thresholds report-only this phase.** All tool DBs mirror-able offline (air-gap). *(dep: M0-I5)*
- [x] **M0-SEC2** (S) 🛡 Verify `deploy.resources.limits` on all services + `--init` on worker (TM-12); confirm `.gitignore` excludes secrets and `.env.example` holds placeholders only (TM-5). *(dep: M0-I2, M0-I3)*

**Exit gate M0:** `docker compose up` → all services healthy; CI green; round-trip smoke test passes. **🛡 Security Gate:** CI security pipeline runs on every PR; no secret in history; resource limits enforced.

---

## M1 — Application foundation 🔒

Goal (brief): *a user can create an authorized engagement and add in-scope targets.* Every action audited. Scans/actions blocked without engagement+scope+ROE and for out-of-scope targets.

### Data & migrations
- [x] **M1-D1** (M) Migration: `organizations`, `users`, `sessions` + enum `user_role`; `citext` extension. *(dep: M0-D1)*
- [x] **M1-D2** (M) Migration: `engagements`, `scope_items`, `roe_acknowledgements` (incl. `terms_snapshot`), `approval_gates` (full state machine: `target_id`, `operation_digest`, `roe_ack_id`, `policy_version`, mandatory `expires_at`, revocation + consumption fields, state-machine CHECK) + enums `engagement_status`, `scan_intensity`, `scope_kind`, `scope_matcher`, `approval_status` (incl. `revoked`,`consumed`). *(dep: M1-D1)*
- [x] **M1-D3** (S) Migration: `targets` + enums `target_type`, `environment_label`, `auth_status`; **`ALTER TABLE approval_gates ADD FOREIGN KEY (target_id, engagement_id) → targets(id, engagement_id)`** (deferred FK — targets is created after approval_gates). *(dep: M1-D2)*
- [x] **M1-D4** (S) Migration: `audit_events` + enum `audit_outcome` (append-only; optional UPDATE/DELETE-deny rule). *(dep: M1-D1)*

### Auth & RBAC 🔒
- [x] **M1-B1** (M) Password hashing service: **Argon2id** (params per OWASP), pluggable to PBKDF2 if the FIPS gate flips (see `ROADMAP.md`). Unit-tested. *(dep: M1-D1)*
- [x] **M1-B2** (L) **Opaque session** lifecycle: create (store SHA-256 of high-entropy token in `__Host-` cookie; `HttpOnly; Secure; SameSite=Strict`), validate-per-request (check `revoked_at` + idle/absolute expiry), **regenerate on login**, logout, kill-all-sessions. Valkey cache with **write-through invalidation on revoke**. 🔒 *(dep: M1-B1)*
- [x] **M1-B3** (M) RBAC dependency (`core/deps.py`): resolve user+role from session; per-route guards for Admin/Tester/Reviewer/Read-only per the `ARCHITECTURE.md §9` matrix. 🔒 *(dep: M1-B2)*
- [x] **M1-B4** (S) User management endpoints (Admin only): create/deactivate user, set role, change password (revokes sessions). *(dep: M1-B3)*

### Audit 🔒
- [x] **M1-B5** (M) Audit service (`core/audit.py`): append-only writer; helper to log `(actor, action, object, engagement, outcome, detail)`. Wired as middleware/decorator so every state-changing route emits an event. 🔒 *(dep: M1-D4, M1-B3)*

### Engagement · scope · ROE 🔒
- [x] **M1-B6** (M) Engagement CRUD (Admin/Tester): all brief fields (name, client/system, window, `rate_limit_rps`, `max_intensity`, `hosted_models_allowed`, contacts, emergency-stop contact). Status transitions draft→active→paused→closed. *(dep: M1-B3, M1-B5)*
- [x] **M1-B7** (M) Scope management: CRUD allow/deny `scope_items`; validation of matchers (URL/domain/ip_cidr/api_base/repo). *(dep: M1-B6)*
- [x] **M1-B8** (M) **ROE acceptance**: render ROE text, on accept write immutable `roe_acknowledgements` with frozen `scope_snapshot` **+ `terms_snapshot` (test window, `rate_limit_rps`, `max_intensity`)** + `content_hash` (SHA-256 over roe_text ‖ scope_snapshot ‖ terms_snapshot). Re-acceptance required if scope **or any frozen term** changes after acceptance. 🔒 *(dep: M1-B7)*
- [x] **M1-B9** (L) **Scope-enforcement service** (`core/scope.py`) — the keystone. `authorize_operation(engagement, target, op, roe_ack, now) -> ExecutionAuthorization` raising `EngagementInactive | ROENotAccepted | ROEStale | ROETermsMismatch | OutsideTestWindow | ScopeViolation | IntensityNotAuthorized | HighRiskNotApproved`. Operates on a **typed, server-normalized operation** with **server-derived effective intensity** (not the caller's declared value); checks **ROE-terms equality** and the **test window against `now`**; blocklist wins over allowlist; CIDR/host/URL matching. Every raise → audit `outcome='blocked'`. Pure/deterministic (`now`, `roe_ack` injected). 🔒 *(dep: M1-B8)*

### Approvals 🔒
- [x] **M1-B11** (M) **Approval-gate state machine** (`services/approvals.py`): `request` (binds `target_id`, computes+stores `operation_digest` over the normalized operation, snapshots `roe_ack_id` + `policy_version`, sets **mandatory `expires_at`**), `decide` (Admin/Reviewer → approved/denied), `revoke` (approved→revoked, immediate). Expiry auto-transitions to `expired`. Single-use **atomic consumption** helper: conditional `UPDATE … WHERE status='approved' AND now()<expires_at AND revoked_at IS NULL` with affected-row check (0 ⇒ refuse). Worker/scope verification recomputes and compares `operation_digest`. All transitions audited. 🔒 *(dep: M1-D3, M1-B8)*

### Targets
- [x] **M1-B10** (M) Target inventory CRUD; `auth_config` stores references only (no plaintext secrets); findings-by-severity is a computed rollup (empty at M1). *(dep: M1-B6)*

### Frontend
- [x] **M1-F1** (M) Auth UI: login, logout, session-expiry handling, "kill all my sessions". *(dep: M1-B2)*
- [x] **M1-F2** (M) Engagements: list + create/edit form (all fields) + detail view with status control. *(dep: M1-B6)*
- [x] **M1-F3** (M) Scope editor (allow/deny lists) + **ROE acceptance flow** with the signed-acknowledgement confirmation. *(dep: M1-B7, M1-B8)*
- [x] **M1-F4** (M) Target inventory: list + add/edit (type, environment, auth status). *(dep: M1-B10)*
- [x] **M1-F5** (S) App shell polish: role-aware nav, current-engagement context, audit-log viewer (read-only, Admin/Reviewer). *(dep: M1-B5, M1-B3)*

### Tests 🔒
- [x] **M1-T1** (M) **Negative safety tests** (must pass to exit): actions blocked when no engagement / no scope / ROE not accepted / ROE-terms drift / outside test window; out-of-scope target blocked; blocklist overrides allowlist; over-max-intensity blocked; intensity-escalation-via-config blocked. Each asserts an audit `blocked` event. 🔒 *(dep: M1-B9)*
- [x] **M1-T2** (M) RBAC tests: each role can/can't reach the matrix's routes; session revocation is immediate (cache + DB). 🔒 *(dep: M1-B3, M1-B2)*
- [x] **M1-T3** (S) ROE immutability + hash-verification test; re-acceptance-on-scope-change **and on-terms-change** test. *(dep: M1-B8)*
- [x] **M1-T4** (S) **Approval state-machine tests**: mandatory expiry enforced; revoked approval refused; expired approval refused; **atomic single-use** — two concurrent consumption attempts, exactly one succeeds; `operation_digest` mismatch refused. Each blocked path audited. 🔒 *(dep: M1-B11)*

### Security 🛡 (M1 is the heaviest AppSec phase — the authZ core)
- [x] **M1-SEC1** (M) 🛡 **Cross-engagement IDOR/BOLA tests** (TM-3, OWASP A01:2025): every object read/mutation is proven scoped to the caller's org/engagement; fetching another engagement's engagement/scope/target/audit row by ID returns 403/404, never data. *(dep: M1-B6, M1-B10)*
- [x] **M1-SEC2** (S) 🛡 **Session/CSRF abuse tests** (TM-10): session-ID regenerated on login (fixation); state-changing request without a valid synchronizer CSRF token rejected; cross-origin request rejected; revoke effective in cache+DB immediately. (Complements M1-T2 RBAC/revocation.) *(dep: M1-B2)*
- [x] **M1-SEC3** (S) 🛡 **Scope host→resolved-IP + SSRF-precursor test** (TM-1 partial): scope engine resolves URL/domain targets to IP and blocks when the resolved IP is out of scope or is loopback/link-local/RFC-1918/metadata (169.254.169.254) unless explicitly in scope. *(dep: M1-B9)*
- [x] **M1-SEC4** (S) 🛡 Prove `evidence`/`roe_acknowledgements`/`audit_events` are insert-only under the app DB role (UPDATE/DELETE denied) (TM-9). *(dep: M1-D4)*
- [x] **M1-SEC5** (S) 🛡 **ASVS 5.0 Level 3 review** of auth/session/access-control/audit subsystems; record gaps as tasks. SAST/secret/SCA thresholds raised to **block on High**. *(dep: M1-B3, M1-B5)*

**Exit gate M1:** A tester creates an engagement, defines scope, accepts ROE, adds targets — all audited. M1-T1/T2/T3 green. RBAC enforced. No scan surface exists yet (that's M2/M3), but the enforcement service is callable and proven. **🛡 Security Gate:** M1-SEC1–SEC5 green; ASVS L3 review passed.

---

## M2 — AI/LLM test harness 🧩

Goal (brief): *a user can run AI security tests against an approved chatbot or LLM endpoint.* Results carry evidence, pass/fail, OWASP LLM mappings; every run audited and cancellable.

### Data & migrations
- [x] **M2-D1** (M) Migration: `scans`, `execution_authorizations` (immutable envelope; composite FKs to same-engagement `targets`/`approval_gates`), `test_runs`, `evidence`, `findings`, `finding_evidence`, `finding_status_history` + enums `scan_status`, `test_suite`, `evidence_kind`, `sarif_level`, `severity`, `finding_provenance`, `finding_status`. *(dep: M1-D3)*
- [x] **M2-D2** (S) Migration: `llm_interactions` + enum `llm_purpose`. *(dep: M2-D1)*

### Storage & LLM abstraction 🔒
- [x] **M2-B1** (M) `storage/` S3 client: `put_evidence(bytes, kind) -> evidence_row` (blob→object store first, hash, then commit metadata; two-phase), `get_evidence`, hash re-verify on read; orphan-sweep task. Dev/MVP runs against the archived MinIO OSS build **through the S3 abstraction only**; the **production WORM backend is a blocking pre-go-live gate** (MinIO repo archived 2026-04-25) — this task delivers the abstraction, not the production-complete evidence store. *(dep: M2-D1, M0-I2)*
- [x] **M2-B2** (L) **LLM provider abstraction** (`llm/`): thin interface + adapters for **Anthropic Claude** (hosted) and **Ollama** (local). Versioned prompt templates. **Redaction-before-egress** (fail-closed) + `hosted_models_allowed` enforcement (hosted adapters unavailable when false). Persist every call to `llm_interactions` (tokens, cost, `was_redacted`, `hosted`). 🔒 *(dep: M2-D2)*
- [x] **M2-T0** (S) Test: hosted egress blocked when `hosted_models_allowed=false`; redactor failure → egress blocked (fail-closed). 🔒 *(dep: M2-B2)*

### Worker & cancellation 🔒
- [x] **M2-W1** (M) Scan orchestration task: **re-read the `execution_authorization` envelope, re-derive every field from the live DB, recompute `operation_digest`, and refuse on any divergence** (test window against `now`, ROE-terms equality, approval state); for high-risk **atomically consume** the bound approval (approved→consumed; 0-row update ⇒ refuse). Then spawn the run in its uniform execution owner (§M2-W3), record process/container id, heartbeat. 🔒 *(dep: M1-B9, M2-B1)*
- [x] **M2-W2** (M) **Emergency stop (confirmed)**: `scans.cancel_requested` flag + signal path → `os.killpg`/container-stop (SIGTERM→SIGKILL); **confirm the process tree is gone**; PyRIT honours the `CancelToken`/child-owner (M2-B3) so an in-process suite also halts; mark `cancelled`; audit. 🔒 *(dep: M2-W1, M2-W3)*
- [x] **M2-W3** (L) **Uniform execution owner** (`workers/execution.py`): one launch/cancel/teardown contract for **both scanners and PyRIT**. Rootless per-run sandbox (rootless container / user namespace) with minimal mostly-read-only mounts, **all caps dropped + `no-new-privileges` + seccomp**, **short-lived scoped credentials** (no ambient worker secrets), egress **only via the engagement egress shaper** (M2-SEC1), and **verified teardown** (assert sandbox + process tree gone, transient creds revoked; teardown failure = surfaced job error). 🔒 *(dep: M2-W1)*

### LLM test runners 🧩
- [x] **M2-B3** (M) Define a `Runner` interface (`run(target, config, cancel: CancelToken) -> NormalizedResult`) and implement it for **PyRIT only** for the MVP. PyRIT is a **native Python library** (`pip install pyrit` from **`github.com/microsoft/PyRIT`** — the old `Azure/PyRIT` repo is archived), so it embeds in the Celery worker with **no subprocess** — which means process-group signalling can't selectively stop it. Give the suite a **cancellation identity**: run it under a **dedicated child owner** (killable) or honour a **bounded cooperative `CancelToken` checked between every prompt/turn** so emergency stop halts it within the cancellation budget. Runs go through the uniform execution owner (M2-W3). Pin exact version + hash. Design the interface + evidence-normalization schema so garak/promptfoo drop in later. *(dep: M2-B2, M2-W1, M2-W3)*
  - **Deferred to post-MVP (do NOT build now):** **garak** adapter = Python **subprocess** parsing its JSONL report (avoid the brittle in-process `cli.main` hack); **promptfoo** adapter = it is **Node.js**, not importable from Python — shell out to the `promptfoo` CLI, which forces a **Node 24 LTS** runtime (Node 20 reached EOL 2026-03-24; target the current active LTS, not an EOL line) into the worker image. Keeping the MVP on PyRIT keeps the worker image Python-only. These are three distinct adapters, not one plug-in; budget the polyglot image + per-engine result normalization when adding them.
- [x] **M2-B4** (L) **Prompt-injection suite** on PyRIT: direct, multi-turn/Crescendo, indirect (seed from LLMail-Inject/InjecAgent/AgentDojo corpora), instruction-hierarchy, jailbreak, sandboxed tool-call manipulation → transcript evidence → `findings` (provenance `automated`/`ai_generated`) mapped to LLM01. *(dep: M2-B3)* — MVP vertical slice: direct/jailbreak/instruction-hierarchy single-turn via PyRITRunner + one scripted multi-turn (per-turn cancel); deterministic canary detectors → automated LLM01 findings + transcript evidence. Deferred follow-ups: adaptive Crescendo (needs adversarial LLM), external corpora (LLMail-Inject/InjecAgent/AgentDojo), sandboxed tool-call manipulation.
- [x] **M2-B5** (L) **Data-leakage suite** on PyRIT: system-prompt leakage (LLM07), hidden-instruction disclosure, secret/token exposure (LLM02), RAG boundary + vector/embedding (LLM08), improper output handling (LLM05), and **bespoke cross-tenant isolation**. *(dep: M2-B3)* — MVP vertical slice: 6 probes (one per vector) on the shared B4 run engine (extracted to `app/suites/engine.py`); deterministic canary/regex detectors → `automated` findings mapped to LLM02/LLM05/LLM07/LLM08 with transcript evidence; cross-tenant is a scripted multi-turn probe (per-turn cancel). Deferred follow-ups: live RAG/vector-store fixtures, external leakage corpora, adaptive multi-turn.
- [x] **M2-B6** (M) LLM target connector: configure chatbot/LLM-wrapper target, scope-validated; expected-vs-actual adjudication → pass/fail on findings. *(dep: M2-B4, M2-B5)* — `app/connectors/llm_target.py` `HttpLLMTargetConnector` = the real `SuiteTarget`/`RunnerTarget` seam (single-shot `send` + multi-turn `open_conversation` history-replay) over HTTP; per-request + per-redirect-hop egress guard via scope keystone `assert_egress_allowed` (scope-name match + resolved-IP SSRF, TM-1); auth credential resolved from an `auth_config` reference to an in-memory header, never persisted/transcribed (TM-5). Transport shape in new `targets.connector_config` JSONB (migration 8c4e1f7a9b23). Deterministic detectors still adjudicate pass/fail (LLM never judges). Deferred: egress shaper (M2-SEC1), non-HTTP transports.

### Frontend
- [x] **M2-F1** (M) LLM target config UI + suite launcher (choose suites, intensity). *(dep: M2-B6)*
- [x] **M2-F2** (M) Live scan status (running/queued, cancel button wired to emergency stop). *(dep: M2-W2)*
- [x] **M2-F3** (M) Findings list + detail: evidence transcript viewer, OWASP LLM tags, provenance + status labels. *(dep: M2-D1)* — read seam `app/api/findings.py` (list by engagement/scan + detail with linked evidence + append-only status history + a single-blob content endpoint), all VIEW-guarded and org/engagement-scoped (cross-org → 404), evidence served THROUGH the API via the storage abstraction (SHA-256 re-verified, browser never hits object storage) with an evidence-link guard. Frontend: findings card on the engagement (severity/OWASP/provenance/status), dedicated list page, detail page with an on-demand transcript viewer; automated/AI-generated findings labeled as NOT human-validated (§2.9). `scripts/verify_findings.py` 21/21 live; `tests/e2e/findings.spec.ts` 3 headed-green (seeded via `seed_e2e_findings.py`).

### Tests
- [x] **M2-T1** (M) End-to-end: run prompt-injection + data-leakage against a local mock LLM (in `sandbox/`); assert findings with evidence, pass/fail, OWASP mapping, audit trail, and that a run is cancellable. *(dep: M2-B6, M2-W2)* — wiring `app/workers/suite_run.py` (`run_llm_suites` + `build_suite_owner`): reads the frozen envelope's suites, builds the scope-validated connector, runs PI+DL on PyRIT under the CancelToken, and persists findings via `create_findings_from_suite` (one `test_runs` row per suite). `sandbox/mock_llm.py` is the deliberately-vulnerable local target. `scripts/verify_e2e_llm_scan.py` **17/17 live** in the redteam image drives the real `orchestrate_scan` through `build_suite_owner` against the mock: 10 automated/open findings across LLM01/02/05/07/08 with hash-verified transcript evidence, forged system-override adjudicated PASS (no finding), `scan.started`/`scan.completed` audited, credential injected as a header and never in transcripts (TM-5), and a second run emergency-stopped once RUNNING → CANCELLED + audited. 5 CI-safe unit tests (`test_suite_run.py`). Production `run_scan`/queue-routing rewiring deferred (a UI launch still runs the placeholder) — the payload path is proven here.

### Security 🛡
- [x] **M2-SEC1** (M) 🛡 **Engagement-aware egress shaper** (default-deny + aggregate rate) — all run traffic routes through one choke point; the sandbox has no other network path. Reachable only: in-scope target IPs + configured LLM/provider endpoints; a decoy internal service and a cloud-metadata-IP probe are blocked (TM-1); adapters limit/re-validate redirect hops. **Enforces the engagement `rate_limit_rps` as an aggregate ceiling across concurrent runs and inside opaque scanner daemons** — test asserts the **observed** outbound rate under concurrent runs stays ≤ ceiling. Fails closed if unavailable. *(dep: M2-W1, M2-W3)* — `app/core/egress.py` `EgressShaper`: default-deny reachability (scope keystone + provider allowlist) + per-engagement aggregate `rate_limit_rps` via a shared Valkey leaky bucket (`ValkeyEgressLimiter`, fail-closed). Wired as the connector's `EgressGate` in `run_llm_suites`/`build_suite_owner` so real suite traffic passes through it. Live `verify_egress_shaper.py` 9/9: 3 concurrent runs observed 4.99 rps ≤ 5 ceiling; decoy + metadata-IP blocked with no egress; provider endpoint reachable with empty scope; fail-closed when the limiter is down. **MVP is app-level** — a network-level per-run netns default-deny is the documented hardening seam (with M2-W3's rootless sandbox). **DEFERRED T1 production wiring (run_scan owner-by-suite + redteam queue routing) NOT included — its own later task.**
- [x] **M2-SEC2** (M) 🛡 **Our-own-LLM indirect-injection guardrail test** (TM-4, OWASP LLM01 against *us*): an instruction embedded in evidence/scanner-output/target-response fed to our triage/remediation LLM does not change its declared severity/status/action; model input is data-not-instructions; structured output only; every cited evidence pointer resolves to a real record (unresolved ⇒ rejected). *(dep: M2-B2)* — `app/services/triage.py` `triage_finding` runs our LLM over a finding + its captured evidence to produce DRAFT narrative only: evidence travels as clearly-delimited UNTRUSTED DATA (system prompt `triage_system.v1` is the only instruction), the structured-output schema has NO severity/status/action field, `evaluate_triage_output` never reads a platform decision from the model and never mutates the finding, and every cited evidence label must resolve to a real linked record (invented ⇒ `TriageRejected` fail-closed). CI-safe unit tests `test_triage.py` (input builder + pure guardrail + full path through a real `LLMService`); 3 release-blocking negatives in `test_safety_negatives.py` (injected instruction leaves severity/status untouched; unresolved pointer rejected; non-structured reply rejected). `scripts/verify_triage.py` 22/22 live vs real Postgres + MinIO (evidence blob carries an embedded injection; finding never moves; pointer resolution; call audited purpose=triage).
- [x] **M2-SEC3** (S) 🛡 **Hostile-parser test** (TM-8): malformed/oversized/truncated transcripts and tool output fail safe (no crash, no unsafe deserialization — no `pickle`/`yaml.load`). *(dep: M2-B3)* — the two hostile-parse surfaces in M2 are hardened and pinned. **Tool output** (`app/connectors/llm_target.py`): `_post` now streams the target response under a hard `MAX_RESPONSE_BYTES` cap (a giant/never-ending body aborts before it can OOM the worker) and parses via `parse_target_json`, which fails safe as a `TargetConnectorError` on malformed, truncated, oversized, *and* deeply-nested (`RecursionError`) input. **Transcript blobs** (`app/services/triage.py`): `gather_finding_evidence` gates on the recorded `size_bytes` BEFORE reading, so an oversized/corrupted transcript is noted-not-loaded (never read into memory), and malformed bytes decode losslessly. No unsafe deserializer is reachable anywhere in the parse path (JSON only; the Celery broker accepts JSON only). Unit tests in `test_connectors.py` (oversized/malformed/truncated/nested `parse_target_json` + streaming cap) and `test_triage.py` (size-gate + lossy decode); **3 release-blocking negatives** in `test_safety_negatives.py` (AST scan proving no `pickle`/`marshal`/`yaml.load`/`eval`/`exec` in the parse modules, broker-JSON-only, oversized tool output fails safe). `scripts/verify_hostile_parser.py` **10/10 live** in the base api image: a hostile mock over real HTTP returns valid/non-JSON/truncated/nested/oversized bodies (each fails safe, valid still parses) and a finding linked to normal/oversized/malformed transcript blobs in real MinIO is gathered with the oversized one never read.
- [x] **M2-SEC4** (S) 🛡 Per-engagement **LLM token/cost ceiling** enforced (TM-12); redaction fail-closed + hosted-disallowed hard block covered by M2-T0. *(dep: M2-B2)* — `LLMService.complete` gained gate 1b: before egress (after the hosted gate, before redaction), `_enforce_budget` sums the engagement's `llm_interactions` (tokens + cost) and raises `LLMBudgetExceededError` fail-closed once a configured ceiling is reached — no adapter call, no interaction row. Ceilings are Settings-level and apply per-engagement bucket: `LLM_MAX_TOKENS_PER_ENGAGEMENT` (default 2M, bounds total work for any provider) and `LLM_MAX_COST_USD_PER_ENGAGEMENT` (default 0 = off, bounds hosted spend); a value `<= 0` disables that ceiling; a call with no engagement context (already local-only via the hosted gate) has no bucket. Because per-call usage is known only after the provider responds, the ceiling is enforced against already-consumed usage (the crossing call completes; every subsequent one is blocked — documented). Unit tests in `test_llm.py` (token block/allow, hosted cost block, disabled); **1 release-blocking negative** in `test_safety_negatives.py` (budget-exhausted engagement → no egress AND no persisted row). `scripts/verify_llm_budget.py` **11/11 live** vs real Postgres (stub adapter): pre-loaded usage at/under/over each ceiling drives block/allow with the interaction-row count asserted, plus disabled-ceilings pass-through. No schema change.

**M2 exit gate + 🛡 security gate MET.** All M2 tasks complete (D1-2, B1-6, T0-1, W1-3, F1-3, SEC1-4). Prompt-injection + data-leakage suites run end-to-end via PyRIT against an approved LLM target with evidence + OWASP LLM mappings; runs audited + cancellable; SEC1-4 green. **Still deferred (its own later task):** T1 production wiring — rewire `run_scan` owner-by-suite via `build_suite_owner` + route LLM-suite scans to a redteam Celery queue (base worker consumes `default` only); if done, adapt the F2 `scans.spec.ts` live-status "→Completed" e2e (dev stack has no redteam worker → scan stays Queued).

**Exit gate M2:** Against an approved LLM/chatbot target, prompt-injection (incl. multi-turn) and data-leakage suites run end-to-end via integrated engines; findings carry evidence + OWASP LLM mappings; runs are audited and cancellable. M2-T0/T1 green. **🛡 Security Gate:** M2-SEC1–SEC4 green; a `sandbox/` hostile mock target cannot pivot or inject.

---

## M3 — Scanner integrations 🧩  →  MVP COMPLETE

Goal (brief): *a user can run approved scanners and see findings in one dashboard.* Plus the MVP reporting slice (CVSS, OWASP/NIST mapping, POA&M CSV, Markdown report).

### Data & migrations
- [x] **M3-D1** (S) Migration: `scanner_runs`. *(dep: M2-D1)*
- [x] **M3-D2** (M) Migration: `cvss_scores` (+ enum `cvss_version`, range CHECK), `compliance_frameworks`, `compliance_controls`, `finding_compliance_mappings`. *(dep: M2-D1)*
- [x] **M3-D3** (S) Migration: `reports`, `report_findings` (+ enums `report_type`, `report_status`). *(dep: M2-D1)*

### Scanner framework & adapters 🧩🔒
- [x] **M3-W1** (L) **Scanner adapter framework** (`ScannerAdapter` contract): `validate_prerequisites`/`build_command`/`run`/`normalize`; scope-validated before run, timeout + **per-engagement rate limit enforced as an aggregate ceiling at the egress shaper (M2-SEC1)**, version+config+image-digest+rules-digest capture, raw→`evidence` + normalized→`findings`. Runs through the uniform execution owner (M2-W3) — rootless sandbox + confirmed cancellation + verified teardown. 🔒 *(dep: M2-W2, M2-W3, M2-B1)*
- [x] **M3-W2** (M) **Semgrep CE adapter** (SAST): run on uploaded/local code (`--json --metrics=off`), normalize to `findings`, capture rule_id/location(file+line). Run against a **vendored, content-hashed, license-cleared rule bundle on a local path** (OpenGrep/LGPL rules or an explicitly licensed set) — **not** floating registry aliases (`p/owasp-top-ten`/`p/default`), which are non-reproducible, air-gap-hostile, and license-restricted. Record the bundle SHA-256 + source + license in `scanner_runs.config`. *(dep: M3-W1)*
- [x] **M3-W3** (L) **ZAP by Checkmarx adapter** (DAST): ZAP image **pinned by digest** (`zaproxy/zap-stable@sha256:<digest>`, not the floating tag) daemon + API (API key injected at launch as runtime secret, **never persisted into `scanner_runs.config`**; JVM `-Xmx` sized); parse alerts → `findings` with endpoint/method location; native throttle set as floor under the orchestrator ceiling. **In CI use the passive baseline scan on PRs; reserve full/active scans for nightly** (active scans are slow and can be destructive). *(dep: M3-W1)*
- [x] **M3-B1** (M) Source upload: accept code archive → `evidence` (kind `source_archive`) → target of type `source_archive`; hand to Semgrep adapter. *(dep: M3-W2, M2-B1)*

### Normalized findings + dedup
- [x] **M3-B2** (M) Finding normalization + **SARIF 2.1.0 import/export**; compute `hash_code` over the defined field set + capture `partial_fingerprints`; dedup on (re)import via `hash_code` → set `duplicate_of`. *(dep: M3-W2, M3-W3)*

### CVSS + compliance mapping (reporting slice)
- [x] **M3-B3** (M) CVSS scoring: compute/parse with the `cvss` PyPI package (**v4.0 default + v3.1**); manual override with justification; insert-only history, one current row. *(dep: M3-D2)*
- [x] **M3-B4** (M) Seed `packages/compliance/` KB (OWASP LLM 2025, WSTG v4.2, NIST AI RMF + 600-1, 800-53 Rev 5.2.0, 800-115) and load into `compliance_*`; auto-map findings by rule/category; manual mapping edit. *(dep: M3-D2, M3-B2)*

### Reports (MVP exports)
- [x] **M3-B5** (M) **POA&M CSV export** (full field set) + **Markdown technical report** rendered from `reports.body`; editable before export. *(dep: M3-B3, M3-B4)*

### Frontend
- [x] **M3-F1** (M) Scan launcher (scanner + target + intensity; high-risk shows approval-gate requirement) + code upload UI. *(dep: M3-W2, M3-W3, M3-B1)*
- [x] **M3-F2** (M) Unified findings dashboard (all sources) + finding detail: evidence, source location, severity, **automated-vs-validated label**, CVSS editor, OWASP/NIST tags. *(dep: M3-B2, M3-B3, M3-B4)*
- [x] **M3-F3** (M) Report builder: assemble findings, edit, export CSV + Markdown. *(dep: M3-B5)*

### Tests 🔒
- [x] **M3-T1** (M) E2E per scanner: Semgrep against the **OWASP Juice Shop / BrokenCrystals source** and ZAP (baseline) against a running **OWASP Juice Shop** or **BrokenCrystals** container in `sandbox/` (both actively maintained and built for/used in automated scanning; avoid WebGoat/DVWA for scripted CI). Gate ZAP on the target's healthcheck. Assert normalized findings with evidence + scope enforcement + rate-limit respected + cancellable. 🔒 *(dep: M3-W2, M3-W3)*
- [ ] **M3-T2** (S) Dedup test (same finding across reimports links `duplicate_of`); SARIF round-trip import/export. *(dep: M3-B2)*
- [ ] **M3-T3** (S) Export tests: POA&M CSV has required columns; Markdown report renders; CVSS history preserved. *(dep: M3-B5)*

### Security 🛡
- [ ] **M3-SEC1** (M) 🛡 **Malicious-upload defenses** for source archives (TM-7): reject zip-bombs (compression-ratio + total-size + entry-count caps), zip-slip/`..`/absolute-path/symlink entries; extract to an isolated, quota'd, no-exec location; scan before processing. Negative tests for each. *(dep: M3-B1)*
- [ ] **M3-SEC2** (S) 🛡 **Normalizer/SARIF fuzz** (TM-8): malformed SARIF, truncated JSONL, oversized fields fail safe and don't crash/execute in the worker. *(dep: M3-B2)*
- [ ] **M3-SEC3** (S) 🛡 **Dogfood self-scan** (`SECURITY_DEVELOPMENT_PLAN.md §4`): point the new Semgrep + ZAP adapters at DAS Sentinel's own code/running app in CI and triage the findings. SAST/DAST/SCA thresholds raised to **production blocking**. CSV/formula-injection guard on POA&M export. *(dep: M3-W2, M3-W3, M3-B5)*

**Exit gate M3 (= MVP acceptance criteria):**
- [ ] Scans cannot run without engagement + approved scope; out-of-scope blocked *(M1-T1 still green)*.
- [ ] ≥1 AI/LLM suite (M2), ≥1 code scanner (Semgrep), ≥1 web/API scanner (ZAP) each work end-to-end.
- [ ] Findings normalize into the shared schema, carry evidence, map to OWASP + NIST.
- [ ] CVSS scoring works (v4.0 + v3.1).
- [ ] POA&M CSV + Markdown technical report export works.
- [ ] Audit log captures who/what/target/when.
- [ ] UI distinguishes automated vs. human-validated findings.
- [ ] **🛡 Security Gate:** M3-SEC1–SEC3 green; per-phase security gates (M0–M3) all still green; self-scan via our own adapters produces triaged findings.

---

## Cross-cutting "definition of done" (applies to every task)

- Passes lint + typecheck + its tests; safety-critical tasks (🔒) include negative tests.
- No hardcoded secrets/hosts/models; config via `Settings`.
- State-changing endpoints emit an audit event.
- New tables/columns arrive via an Alembic migration matching `DATABASE_SCHEMA.md`.
- LLM output is stored `ai_generated` and never auto-promoted to validated/fixed.
- Scanner processes are isolated, rate-limited, and cancellable.
- **Security DoD** (`SECURITY_DEVELOPMENT_PLAN.md §9`): CI security stages pass at the phase's blocking threshold; new/changed routes have RBAC + cross-engagement access tests; any new outbound call passes scope/egress + redaction with a negative test; any new external-input parser has a hostile-input test; any user input reaching a sink (SQL/shell/path/template/HTML/LLM prompt) is proven safe; security decisions **fail closed** with a deny-on-error test; no new plaintext-secret path or unjustified suppression; the §3 threat-model table is updated if a new surface was introduced.

## Explicitly NOT in the MVP (see ROADMAP.md)

Automated recon/triage/remediation/retest (M4), agent permission testing (M5), compliance-DB migration + exec reports + PDF/DOCX/JSON (M6), Nuclei/OSV/Gitleaks/TruffleHog (M4), SSO, and the production evidence-store backend + FIPS decision (Hardening gate).
