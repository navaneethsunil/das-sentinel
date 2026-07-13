# IMPLEMENTATION_PLAN.md — DAS Sentinel

> The build plan: how we go from an empty repo to a shippable MVP, in what order, with which gates. This sequences the work defined in `MVP_TASKS.md` (task IDs referenced as `M1-B9` etc.), grounded in `ARCHITECTURE.md`, `TRD.md`, `BACKEND_SCHEMA.md`, and `DATABASE_SCHEMA.md`. It is the *execution* document — the one an engineer follows day to day.

**Golden rule (from the brief & CLAUDE.md):** build a working vertical slice, safety-first. Foundation and scope controls before any scanner execution. Each phase ends with a demoable, tested increment.

**Security is continuous, not a final gate.** Every phase below carries a **🛡 Security Gate** in addition to its functional exit gate. These are defined in `SECURITY_DEVELOPMENT_PLAN.md §6` and back the platform's own application security (auth, SSRF, injection, secrets, supply chain, our own LLM egress) — distinct from the product-safety scope controls. The CI security pipeline (`SECURITY_DEVELOPMENT_PLAN.md §5`) runs from Phase 0; the pre-prod Hardening gate (§9) is the *final verification*, not where security begins.

---

## 0. Before writing code — decisions to lock

Two Decision Gates should be answered *now* because they're expensive to change later; the rest can wait for their milestone.

| Gate | Why decide now | Default if silent |
|---|---|---|
| 🚪 **Password hash / FIPS** (Argon2id vs PBKDF2) | Changing it after users exist forces a password-rehash migration. Depends on the target ATO (FedRAMP/FISMA/CMMC). | Argon2id; `password_hash` config flag makes the swap a one-line change *if done before first users*. |
| 🚪 **Air-gap posture** (hosted LLM allowed by default?) | Shapes M2 defaults and the demo environment. | Local-only default (`hosted_models_allowed=false`); hosted opt-in per engagement. |

Deferred to their gates (not blocking the start): production evidence-store backend (before go-live), worker engine (only if orchestration grows), LiteLLM vs thin adapter (when a 3rd provider is needed), SSO (post-MVP).

---

## 1. Delivery phases at a glance

```
  Phase 0 ──▶ Phase 1 ──▶ Phase 2 ──▶ Phase 3 ──▶ Phase 4 ──▶ Hardening gate
  Scaffold    Foundation   AI/LLM      Scanners    Reporting    (pre-prod)
  (M0)        (M1) 🔒       harness     (M3 core)   slice
                           (M2)                     (M3 reporting)
                                                        │
                                                   ── MVP COMPLETE ──
```

Phases 1→3 map to milestones M1→M3. The reporting slice (CVSS, mapping, POA&M CSV, Markdown) is folded into Phase 4 at the tail of M3, exactly as `ROADMAP.md`/`MVP_TASKS.md` specify. Post-MVP milestones M4–M6 are out of this plan's scope.

Phases are **dependency-ordered, not calendar-dated** — no fabricated timelines. Within a phase, lanes (backend/worker/frontend) run in parallel where task dependencies allow.

---

## 2. Phase 0 — Scaffolding (M0)

**Objective:** `docker compose up` yields a healthy stack; CI green; a request round-trips browser → proxy → api → db.

**Order of work**
1. `M0-I1` repo layout → `M0-I3` `Settings` + `.env.example` (config first, so nothing hardcodes).
2. `M0-B1` FastAPI skeleton (+ `/healthz` liveness with **no** dependency checks, `/readyz` with DB+Valkey) and `M0-F1` Next.js skeleton — parallel.
3. `M0-I2` compose (postgres 17, valkey 8, minio dev, worker with `--init`, resource limits, healthchecks) → `M0-W1` Celery on `redis://` scheme, separate logical DBs.
4. `M0-I4` Caddy (same-origin routing, `root_path`, RSC streaming pass-through, `tls internal`) → `M0-D1` Alembic one-shot migration service.
5. `M0-I5` CI (Ruff, ESLint/Prettier, TS strict, pytest smoke) → `M0-T1` round-trip smoke test.

**Exit:** M0 exit gate in `MVP_TASKS.md`. **Do not proceed until the smoke test is green in CI**, because every later phase lands on this skeleton.

**🛡 Security Gate (M0):** the CI security pipeline is live and runs on every PR — SAST (Semgrep + Bandit), Gitleaks (secrets), SCA (pip-audit/npm audit/OSV-Scanner), Trivy (image + compose/IaC), ZAP baseline against the running app, Syft SBOM, and CI/CD hardening (pinned action SHAs, least-privilege tokens). Report-only thresholds are acceptable *this phase only* — except **secret findings and safety negative tests block from day one**. Resource limits + `--init` on the worker enforced (TM-12). See `SECURITY_DEVELOPMENT_PLAN.md §5–6`.

**Watch-outs (from verification rounds):** `redis://` not `valkey://`; `--init`/tini on the worker; Caddy `tls internal` (never public ACME in dev/air-gap); one-shot migration service (not migrate-on-startup with multiple replicas); declare `pydantic[email]` in requirements now.

---

## 3. Phase 1 — Foundation (M1) 🔒

**Objective (brief):** a user can create an authorized engagement and add in-scope targets; every action audited; scans/actions blocked without engagement+scope+ROE and for out-of-scope targets.

**Critical path (must be sequential):**
```
 M1-D1 users/sessions ─▶ M1-B1 password hash ─▶ M1-B2 opaque session + CSRF ─▶ M1-B3 RBAC deps
        │                                                                            │
        ▼                                                                            ▼
 M1-D4 audit table ─▶ M1-B5 audit service ────────────────────────────────▶ M1-B6 engagement CRUD
                                                                                     │
 M1-D2 engagement/scope/roe/approval tables ─────────────────────────────────────────┤
                                                                                     ▼
                                             M1-B7 scope mgmt ─▶ M1-B8 ROE (hash+snapshot) ─▶ M1-B9 scope engine 🔒
                                                                                     │
 M1-D3 targets table ─▶ M1-B10 target inventory                                       │
```
**Then, in parallel:** frontend `M1-F1…F5` (auth, engagements, scope+ROE, targets, shell+audit viewer) against the now-stable API.

**Gating tests before exit:** `M1-T1` (safety negative matrix — the release-blocking one), `M1-T2` (RBAC + instant revocation), `M1-T3` (ROE immutability + re-acceptance).

**Why this order:** `M1-B9` (the scope-enforcement keystone) depends on engagement/scope/ROE existing, and everything downstream (all scanning) depends on `M1-B9`. Build and *prove* the safety core before anything can execute a tool. There is no scan surface yet — that's intentional.

**Demo at exit:** create engagement → define allow/deny scope → accept ROE → add targets; show an out-of-scope attempt blocked and audited; show RBAC + session kill.

**🛡 Security Gate (M1) — the heaviest security phase:** ASVS 5.0 **Level 3** review of the auth/session/access-control/audit subsystems. Green tests for cross-engagement IDOR/BOLA (TM-3), session fixation/instant-revoke/CSRF (TM-10), append-only audit+evidence (app DB role denied UPDATE/DELETE, TM-9), and scope host→resolved-IP checking (TM-1 partial). SAST/secret/SCA now **block on High**. See `SECURITY_DEVELOPMENT_PLAN.md §3, §6`.

---

## 4. Phase 2 — AI/LLM test harness (M2)

**Objective (brief):** run prompt-injection + data-leakage suites against an approved LLM target; evidence-backed, OWASP-mapped, audited, cancellable.

**Order of work**
1. `M2-D1`/`M2-D2` migrations (scans, test_runs, evidence, findings, finding_evidence, status_history, llm_interactions).
2. `M2-B1` storage/S3 client (two-phase write) — needed before any evidence is captured.
3. `M2-B2` LLM provider abstraction (Claude + Ollama, redaction fail-closed, hosted gate) → `M2-T0` its safety tests (**gating**: hosted-blocked-when-disallowed, fail-closed).
4. `M2-W1` scan orchestration task (re-runs scope gate in worker) → `M2-W2` emergency stop (process-group kill). These reuse into Phase 3.
5. `M2-B3` `Runner` interface with **PyRIT only** → `M2-B4` prompt-injection suite, `M2-B5` data-leakage suite (incl. bespoke cross-tenant) → `M2-B6` LLM target connector.
6. Frontend `M2-F1…F3` (LLM target config, live status + cancel, findings list/detail with provenance labels).

**Gating tests:** `M2-T0` (LLM gates) and `M2-T1` (end-to-end against a local mock LLM in `sandbox/`, cancellable).

**Why this order:** storage → LLM abstraction (with its gates proven) → worker execution/cancellation → the suites on top. The worker isolation/cancellation built here (`M2-W1/W2`) is the same machinery Phase 3 reuses, so it's built once, correctly.

**Watch-outs:** PyRIT from `github.com/microsoft/PyRIT` (pin version+hash); keep the worker image Python-only (defer garak/promptfoo); redaction must fail closed.

**🛡 Security Gate (M2):** worker **egress allowlist** (default-deny) enforced and tested against a decoy internal service + a cloud-metadata-IP probe (TM-1); indirect-injection defense for *our own* triage/remediation LLM — model input is data-not-instructions, structured output only, cited-evidence pointers validated programmatically, LLM cannot set scope/severity/status (TM-4); redaction fail-closed + hosted-disallowed hard block green (TM-5); transcript/result parsers treat tool output as hostile, no unsafe deserialization (TM-8); worker timeout+killpg and per-engagement LLM cost ceiling verified (TM-12). A `sandbox/` hostile mock target cannot pivot or inject. See `SECURITY_DEVELOPMENT_PLAN.md §6`.

---

## 5. Phase 3 — Scanner integrations (M3 core)

**Objective (brief):** run Semgrep + ZAP; findings appear normalized in one dashboard; cancellable; scope-enforced.

**Order of work**
1. `M3-D1` scanner_runs migration.
2. `M3-W1` `ScannerAdapter` framework (scope-validated, isolated `start_new_session` + `killpg`, rate-limit ceiling, version/config capture, raw→evidence + normalized→findings) — reuses `M2-W1/W2`.
3. `M3-W2` Semgrep CE adapter (`--json`, **vendored content-hashed rule bundle** — not floating registry packs) + `M3-B1` source upload → parallel with `M3-W3` ZAP adapter (**digest-pinned** ZAP image daemon + API key injected at launch + JVM sizing; baseline for routine).
4. `M3-B2` normalization + SARIF 2.1.0 import/export + dedup (`hash_code`/`partial_fingerprints` → `duplicate_of`).
5. Frontend `M3-F1` scan launcher (with the scope-gate + high-risk-approval UX) + `M3-F2` unified findings dashboard (automated-vs-validated labels).

**Gating tests:** `M3-T1` (Semgrep vs Juice Shop/BrokenCrystals source; ZAP baseline vs a running vulnerable container; scope + rate-limit + cancel) and `M3-T2` (dedup + SARIF round-trip).

**🛡 Security Gate (M3):** malicious-upload defenses green — zip-bomb (ratio/size cap), zip-slip/`..`/absolute/symlink rejection, isolated no-exec extraction (TM-7); SARIF + scanner-output normalizers fuzzed against malformed/hostile input (TM-8); adapters re-validate redirects/hops (TM-1). **Dogfood:** point the new Semgrep + ZAP adapters at DAS Sentinel itself in CI and triage the findings (`SECURITY_DEVELOPMENT_PLAN.md §4`). SAST/DAST/SCA now **blocking at production thresholds**.

---

## 6. Phase 4 — Reporting slice (M3 tail) → MVP COMPLETE

**Objective:** CVSS, OWASP/NIST mapping, and POA&M CSV + Markdown export — the reporting pieces the MVP acceptance criteria require.

**Order of work**
1. `M3-D2`/`M3-D3` migrations (cvss_scores, compliance_*, reports, report_findings).
2. `M3-B3` CVSS (v4.0 default + v3.1 via the `cvss` library; override + insert-only history).
3. `M3-B4` seed the `packages/compliance/` KB (OWASP LLM 2025, WSTG 4.2, NIST AI RMF+600-1, 800-53 Rev 5.2.0, 800-115) → load → auto-map + manual edit.
4. `M3-B5` POA&M CSV + Markdown export → frontend `M3-F3` report builder.

**Gating tests:** `M3-T3` (POA&M CSV columns, Markdown renders, CVSS history preserved).

**🛡 Security Gate (M4/reporting):** the export/render path is reviewed for template injection and **CSV/formula injection** (POA&M CSV opened in a spreadsheet must not execute `=`/`+`/`-`/`@`-prefixed cells) — see `SECURITY_DEVELOPMENT_PLAN.md §6` (post-MVP). All prior phase gates stay green.

**MVP exit = `ROADMAP.md` M3 exit gate = the brief's acceptance criteria.** Verify every checkbox before declaring MVP complete.

---

## 7. Integration & test strategy (all phases)

- **Test pyramid:** unit (services, scope matcher, normalizers, adapters) → integration → E2E. Use **testcontainers** (v4+, has Postgres and Valkey modules) for *narrow* DB/cache integration tests where isolation + auto-teardown matter, and the **docker-compose** stack for *full* end-to-end runs and Celery worker wiring (they're complementary, not either/or). Both need a reachable Docker daemon in CI. E2E runs the phase gating tests against `sandbox/` fixtures; **Playwright** for browser E2E (run `playwright install --with-deps` in CI, `--only-shell` for headless-only).
- **Safety negative tests are release-blocking** (`M1-T1`, `M2-T0`): scope bypass, missing ROE, over-intensity, hosted-egress-when-disallowed, fail-closed redaction, and the AI-finding provenance rule. CI fails the build if any fail.
- **Fixtures live in `sandbox/`:** a mock LLM endpoint (M2), OWASP Juice Shop + BrokenCrystals containers and their source (M3). No live external targets, ever.
- **CI gate (`M0-I5`, extended each phase):** Ruff + ESLint/Prettier + TS strict + the phase's test suites; safety suites block merge. **Plus the security pipeline** (SAST/secret/SCA/container/DAST-baseline/SBOM/CI-hardening) per `SECURITY_DEVELOPMENT_PLAN.md §5` — secret findings and safety negatives block from M0; other thresholds tighten per phase.
- **Abuse-case / negative security tests** (SSRF/egress, cross-engagement IDOR/BOLA, session/CSRF, LLM-injection, upload, parser fuzz) live in the same suite and are release-blocking — catalog in `SECURITY_DEVELOPMENT_PLAN.md §8`.
- **Verify each nontrivial increment end-to-end** (drive the real flow, per the prototype's Playwright approach), not just unit tests.

---

## 8. Environments

| Env | Purpose | Notes |
|---|---|---|
| **Local dev** | Day-to-day build | `docker compose up`; hot reload for web+api; MinIO dev evidence store; Flower (pinned) for tasks. |
| **CI** | Gate every merge | Ephemeral compose stack; runs the full test matrix incl. safety negatives + E2E against `sandbox/`. |
| **Staging / demo** | Exercise the MVP | Same compose topology; local-only LLM by default; used for the phase demos and MVP acceptance run. |
| **Production** | Real engagements | Only after the Hardening gate (§9). Air-gap-capable. |

Config differs only by `.env`; the topology is identical across environments (self-hosted Compose).

---

## 9. Hardening gate (before any production / real engagement) 🚪

Not a phase — the **final security verification** before the platform touches a real target, and the resolution of the deferred Decision Gates. It is *not* where platform security starts: per-phase 🛡 Security Gates (above) and the continuous CI security pipeline mean every item here should already have a green per-phase antecedent (`SECURITY_DEVELOPMENT_PLAN.md §10`). This gate confirms the built-in security holds end-to-end and closes the deferred decisions:

- [ ] 🚪 **Evidence-store backend** chosen and WORM enforcement **empirically verified** (delete-before-expiry rejected). Replace dev MinIO.
- [ ] 🚪 **Password hash / FIPS** confirmed against the actual ATO; if FIPS-required, `password_hash=pbkdf2` set **before** any real users.
- [ ] Security review of the platform itself; run our own SAST/secret/dependency scans on the codebase.
- [ ] **Secrets management** — externalized secret store (Vault / SOPS / cloud KMS); no secrets in env files, images, or compose; rotation policy. Critical: the platform holds target credentials and scan results.
- [ ] **API-layer abuse & SSRF controls** — per-user request throttling and scan-concurrency caps (distinct from container resource limits); **egress controls on scanner workers** so a crafted target can't be used for SSRF beyond the approved scope. A scan-launching tool is itself an SSRF/abuse amplifier — the scope allowlist is necessary but not sufficient.
- [ ] **Supply chain (2026 bar, beyond pinning)** — exact versions + hashes and scanner image digests *plus* **SBOM generation** (CycloneDX/SPDX), **artifact signing + verification** (Sigstore/cosign), **SLSA build provenance**, and minimal/low-CVE base images; internal mirror for air-gap.
- [ ] **Log retention & integrity** — off-box log shipping, defined retention windows, tamper-evidence (broader than the audit DB tables).
- [ ] Backup/restore drill (Postgres dump/WAL + evidence-store mirror); confirm object-lock survives restore.
- [ ] Resource limits tuned under a representative scan load; emergency stop verified to kill process groups within budget.
- [ ] TLS + security headers (incl. `frame-ancestors`, Permissions-Policy, COOP) verified at the proxy; no deprecated headers emitted.
- [ ] CSRF synchronizer token enforced on all state-changing routes; SameSite/Origin checks confirmed as defense-in-depth.
- [ ] Audit completeness spot-check: every state-changing action and every blocked attempt produces an event; audit/evidence tables are insert-only in the prod DB role.

---

## 10. Risk register (execution-level)

| Risk | Phase | Mitigation |
|---|---|---|
| Scope engine has a bypass | 1 | `M1-T1` negative matrix is release-blocking; two-point check (api + worker); fail-closed matching. |
| Worker can't kill a scanner subprocess | 2/3 | `start_new_session` + `killpg` + `--init`; test cancellation in `M2-T1`/`M3-T1`. |
| LLM leaks sensitive data to a hosted model | 2 | Hosted gate + fail-closed redaction; `M2-T0` gating tests; local-only default. |
| PyRIT/tool integration overruns estimate | 2 | MVP scoped to PyRIT only; garak/promptfoo deferred; `Runner` interface keeps them additive. |
| Evidence blob/metadata inconsistency | 2/3 | Two-phase write + orphan-sweep job; hash re-verify on read. |
| Migration race with multiple api replicas | 0 | One-shot migration service; single api replica if migrating on startup. |
| Compliance references drift | 4 | Versioned KB; currency check (NFR-9); versions pinned in CLAUDE.md. |

---

## 11. Definition of done (per increment, from MVP_TASKS §"Cross-cutting")

An increment is done when: it passes lint + typecheck + its tests (safety-critical ⇒ negative tests); no hardcoded secrets/hosts/models; state-changing endpoints audit; new tables/columns arrive via an Alembic migration matching `DATABASE_SCHEMA.md`; LLM output is stored `ai_generated` and never auto-promoted; scanner processes are isolated, rate-limited, and cancellable.

---

## 12. Document map (what governs what)

```
ai-security-testing-platform-build-brief.md   ── scope authority
CLAUDE.md                ── rules + safety invariants (how to build)
PRD.md / TRD.md          ── what/why + technical requirements
ARCHITECTURE.md          ── system shape + ADRs
DATABASE_SCHEMA.md       ── persistence (tables)
BACKEND_SCHEMA.md        ── API/service contracts (wire + interfaces)
APPFLOW.md               ── end-to-end flows + state machines
ROADMAP.md               ── milestone sequence + Decision Gates
MVP_TASKS.md             ── task breakdown (IDs)
IMPLEMENTATION_PLAN.md   ── THIS: build execution order + gates
SECURITY_DEVELOPMENT_PLAN.md ── secure-SDLC: platform self-AppSec, threat model, per-phase 🛡 security gates
ui-ux-prototype.html     ── the tested, clickable UI reference
```

Build order for a new engineer: read CLAUDE.md → this plan → `SECURITY_DEVELOPMENT_PLAN.md` → the milestone's tasks in MVP_TASKS.md → the relevant schema/flow doc as you touch each area.
