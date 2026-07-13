# ROADMAP.md — DAS Sentinel

> Delivery roadmap: what gets built, in what order, and how we know each stage is done. Sequenced from the build brief's six stages, grounded in the decisions in `CLAUDE.md` and `ARCHITECTURE.md`. This is the *when/what-order* document; `MVP_TASKS.md` breaks the near-term milestones into concrete tasks.

---

## Guiding principles

1. **Vertical slice over breadth.** Each milestone must work end-to-end before the next begins — a user can *do something real* at the end of every milestone, not just see scaffolding.
2. **Safety first, always.** Scope enforcement, ROE gating, RBAC, and audit logging ship in M1 and are non-negotiable prerequisites for any scanner execution.
3. **Evidence integrity from day one.** Raw-vs-normalized separation and the storage abstraction exist before the first scanner runs.
4. **Modular tools.** Each scanner/LLM provider is a pluggable adapter; adding one is additive, never a refactor.
5. **Defer what doesn't block the slice.** HA, k8s, SSO, PDF/DOCX, and the production evidence-store backend are explicitly parked (see Deferred, and the Decision Gates).
6. **We secure the platform itself, continuously.** Distinct from product safety (#2): the platform's *own* application security — auth, SSRF, injection, secrets, supply chain, our own LLM egress — is verified at a **🛡 Security Gate every milestone (M0→M3+)**, not deferred to the pre-prod Hardening gate. This is a parallel track running through all milestones; it is defined in **`SECURITY_DEVELOPMENT_PLAN.md`** (threat model, CI security pipeline, per-phase gates, ASVS 5.0 / OWASP Top 10:2025 / NIST SSDF targets).

Legend: 🔒 safety-critical · 🧩 pluggable adapter · 🚪 decision gate · ⏸ deferred · 🛡 platform-AppSec gate

---

## Milestone map

```
M0  Project scaffolding & CI
        │
M1  Application foundation  🔒   ── MVP begins ──
        │   (engagement · scope · ROE · targets · auth · audit)
M2  AI/LLM test harness     🧩
        │   (prompt-injection + data-leakage runners · LLM connector)
M3  Scanner integrations    🧩
        │   (Semgrep CE + ZAP · normalized findings)
        ▼
   ┌─────────── MVP COMPLETE (acceptance criteria met) ───────────┐
   │  +  Compliance/report subset pulled forward into M1–M3:      │
   │     CVSS scoring · OWASP/NIST mapping · POA&M CSV + Markdown  │
   └───────────────────────────────────────────────────────────────┘
        │
M4  Automated pentest workflows   (recon · triage · dedup · remediation · retest)
        │
M5  Agent permission testing  🧩  (sandboxed fake tools · policy · monitoring)
        │
M6  Compliance & reporting depth  (mapping DB · CVSS UI · exec/tech reports · PDF/DOCX/JSON)
        │
   Hardening & production-readiness  🚪  (evidence backend · FIPS · SSO · scale)
```

The brief's MVP spans **M1–M3 plus a thin slice of M6** (CVSS, OWASP/NIST mapping, POA&M CSV, Markdown report). We pull those specific reporting pieces forward because the MVP acceptance criteria require them; the *depth* of compliance/reporting stays in M6.

---

## M0 — Project scaffolding & CI *(pre-MVP)*

**Purpose:** a runnable skeleton so every later milestone lands in a real app, not a vacuum.

- Monorepo layout per `CLAUDE.md §4` (`apps/web`, `apps/api`, `packages/compliance`, `sandbox/`).
- `docker-compose.yml`: web, api, worker, postgres 17, valkey 8, evidence store (MinIO OSS dev build), reverse proxy. Resource limits + healthchecks + `--init` on worker from the start.
- FastAPI app skeleton, Next.js app skeleton, shared API client, health endpoints.
- Alembic wired as a **one-shot migration service**; empty initial migration.
- Lint/format/typecheck (Ruff, ESLint/Prettier, TS strict) + CI running them + a smoke test.
- `.env.example` with placeholders; config loaded through a single `Settings` object.

**Exit criteria:** `docker compose up` brings the whole stack healthy; CI is green; a "hello" round-trips browser → proxy → api → db. **🛡 Security gate:** the CI security pipeline (SAST/secret/SCA/container/DAST-baseline/SBOM/CI-hardening) runs on every PR; secret scanning blocks from day one.

---

## M1 — Application foundation 🔒 *(MVP)*

**Goal (from brief):** *a user can create an authorized engagement and add in-scope targets.*

- Auth: local email/password (Argon2id), **opaque server-side sessions** (`__Host-` cookie, ID regeneration on login, idle+absolute timeouts, write-through revocation).
- RBAC: Admin / Security Tester / Reviewer / Read-only, enforced as route dependencies.
- Engagement CRUD with all required fields (name, client/system, test window, rate limits, contacts, emergency-stop contact).
- Scope management: allowlist scope items (URL/domain/IP-CIDR/API base/repo) + out-of-scope blocklist.
- **ROE acknowledgement** with a signed/hashed immutable artifact (who accepted, when, scope snapshot). 🔒
- **Scope-enforcement service** (`core/scope.py`) — the keystone; blocks when no engagement/scope/ROE or target out of scope. Ships with negative tests. 🔒
- Target inventory (type, environment label, auth status, last-scan, risk summary, findings-by-severity — the last two start empty).
- **Append-only audit log** on every state change and every blocked attempt. 🔒
- UI: auth screens, engagements list/detail, scope editor, ROE flow, target inventory, app shell/nav.

**Exit criteria:** A tester creates an engagement, defines scope, accepts ROE, and adds targets. Every action is audited. Automated tests prove that scans/actions are blocked without engagement+scope+ROE and for out-of-scope targets. RBAC restricts actions by role. **🛡 Security gate:** ASVS 5.0 L3 review of auth/session/access-control/audit; cross-engagement IDOR/BOLA, session/CSRF, and scope→resolved-IP tests green.

---

## M2 — AI/LLM test harness 🧩 *(MVP)*

**Goal (from brief):** *a user can run AI security tests against an approved chatbot or LLM endpoint.*

- LLM target connector (chatbot endpoint / LLM API wrapper) — configured per target, scope-validated.
- LLM **provider abstraction** (`llm/`) with thin adapters: Anthropic Claude (hosted), Ollama (local). Redaction-before-egress + `hosted_models_allowed` enforcement. Prompt templates versioned. 🧩🔒
- **Integrate established red-team engines — do NOT build the attack generation bespoke.** Verified July 2026: mature, permissively-licensed OSS engines already implement these probes.
  - **Microsoft PyRIT** (MIT) — primary orchestration engine; embed as a library. Covers multi-turn/Crescendo attacks and indirect injection (XPIA) via tool-retrieved content.
  - **NVIDIA garak** (Apache-2.0) — batch probe breadth: system-prompt extraction, encoding bypasses, agent/tool probe.
  - **promptfoo** (MIT) — declarative, CI-gated regression runs; ships an OWASP-LLM-Top-10 preset that provides mapping largely for free.
  - These are complementary, not competing — but they are **three different integration mechanisms** (PyRIT = native Python library; garak = Python subprocess/JSONL; promptfoo = **Node.js** CLI, needs Node in the worker image). **Phasing (verified feasibility):** MVP ships **PyRIT only** behind a `Runner` interface; garak and promptfoo are added as post-MVP adapters. Note: PyRIT now lives at `github.com/microsoft/PyRIT` (old `Azure/PyRIT` archived); promptfoo was acquired by OpenAI (still MIT — supply-chain watch item).
- **Prompt-injection coverage:** direct, **multi-turn/Crescendo** (was missing — now table-stakes), indirect (via retrieved docs/tool output — seed from published corpora: LLMail-Inject, InjecAgent, AgentDojo attack suites for defensible provenance), instruction-hierarchy, jailbreak-resistance, sandboxed tool-call manipulation → LLM01.
- **Data-leakage coverage:** system-prompt leakage (LLM07), hidden-instruction disclosure, secret/token exposure, RAG boundary (LLM02) → plus **vector/embedding & RAG poisoning (LLM08)** and **improper output handling (LLM05,** generated content flowing into XSS/SQLi sinks). Explicitly decide LLM09 (misinformation) / LLM10 (unbounded consumption) in or out of MVP scope.
- **Build bespoke only** the differentiated layer the engines don't provide: evidence/transcript capture (prompt/response/expected/actual/pass-fail → evidence store), OWASP LLM mapping + normalization into the shared `Finding` schema, and **cross-tenant data-isolation tests** (no OSS tool covers your tenancy boundary).
- Test suites run through the worker with cancellation (emergency stop) support.
- UI: LLM target config, test-suite launcher, live status, results with evidence + OWASP LLM tags.

> 🚪 **Decision:** integrate vs. build bespoke. **Recommendation: integrate — PyRIT first for the MVP**, with garak and promptfoo added as post-MVP adapters behind the same `Runner` interface (tracked in Decision Gates). Pin exact versions + hashes for these dependencies (supply-chain hygiene) and confirm licenses (all MIT/Apache-2.0 — clean).

**Exit criteria:** Against an approved LLM/chatbot target, a user runs prompt-injection (incl. multi-turn) and data-leakage suites end-to-end via the integrated engines; results carry evidence, pass/fail, and OWASP LLM mappings; every run is audited and cancellable. **🛡 Security gate:** worker egress allowlist (anti-SSRF) enforced; indirect-injection guardrails on our *own* triage/remediation LLM proven; redaction fail-closed + hosted-disallowed hard block green.

---

## M3 — Scanner integrations 🧩 *(MVP)*

**Goal (from brief):** *a user can run approved scanners and see findings in one dashboard.*

- **Scanner adapter framework** (`ScannerAdapter` contract): scope-validated before run, subprocess isolation (`start_new_session` + process-group kill), timeout + rate-limit enforcement, version/config capture, raw→evidence-store + normalized→Postgres. 🧩🔒
- **Semgrep CE** adapter (SAST) — uploaded/local code, `--json`. Run against a **vendored, content-hashed, license-cleared rule bundle** (OpenGrep/LGPL rules), never floating registry packs (`p/owasp-top-ten`/`p/default`) — reproducible, air-gap-safe, and clear of the restrictive Semgrep Rules License.
- **ZAP by Checkmarx** adapter (DAST) — ZAP image **pinned by digest** (not the floating `zaproxy/zap-stable` tag) daemon + API, API key injected at launch as a runtime secret, JVM sizing.
- Normalized findings model + findings dashboard + finding-detail view (evidence, source, severity, status label). **Adopt SARIF 2.1.0** (OASIS standard — no 2.2 exists) as the import/export interchange format, but keep a **richer internal `Finding` model** as a superset (SARIF is static-analysis-centric and under-serves DAST/recon findings, which carry request/response pairs and endpoints, not file/line). Capture SARIF `partialFingerprints` + a computed `hash_code` over a defined field set for stable dedup identity.
- Emergency-stop wired to the worker process-group teardown across all scanners. 🔒
- **MVP reporting slice (pulled from M6):** CVSS scoring (v4.0 default + v3.1) with manual override + audit history; OWASP/NIST mapping from the local JSON/YAML knowledge base; **POA&M CSV export** + **Markdown technical report**.

**Exit criteria (= MVP acceptance criteria):** Scans can't run without engagement+approved scope; out-of-scope blocked. ≥1 AI/LLM suite (M2), ≥1 code scanner (Semgrep), ≥1 web/API scanner (ZAP) each work end-to-end. Findings normalize into the shared schema, carry evidence, and map to OWASP+NIST. CVSS scoring works. POA&M CSV + Markdown report export works. Audit log captures who/what/target/when. UI distinguishes automated vs. human-validated findings. **🛡 Security gate:** malicious-upload + normalizer-fuzz defenses green; we dogfood our own Semgrep + ZAP adapters against DAS Sentinel and triage the findings; SAST/DAST/SCA now blocking at production thresholds.

> 🎯 **MVP COMPLETE at the end of M3.** Everything below is post-MVP depth.

---

## M4 — Automated pentest workflows

**Goal (from brief):** *the platform can run a scoped automated assessment workflow from target inventory to draft findings.*

- **Automated reconnaissance** — **non-intrusive, not "passive"** (these tools send benign requests *to* the target; only third-party URL harvesting is truly passive — label scopes accordingly). Tech fingerprinting, HTTP header analysis, TLS checks, OpenAPI/Swagger discovery, sitemap/robots review, safe crawling limits. Excludes stealth/evasion/harvesting. **Tooling (verified July 2026):** standardize on the MIT-licensed **ProjectDiscovery stack** — `httpx` (headers/probing), `katana` (JS-aware crawl + endpoint/OpenAPI discovery), `nuclei` tech-detect/SSL templates — plus **WhatWeb** (enforce stealthy aggression=1) and **testssl.sh** (GPLv2). Avoid or legal-review **sslyze (AGPL-3.0)**.
- Scan-plan generation (recommend next scans from recon + target type).
- **Scanner-output triage** (deterministic + LLM, assistive — never autonomous): dedup, group related alerts, flag likely false positives, *propose* ranking, explain-why, recommend validation. 🔒 Guardrails (verified: LLMs are inconsistent at ranking and hallucinate severity): compute severity **deterministically (CVSS/SSVC)** — the LLM *explains*, it does not *decide*; the LLM operates only over supplied structured scanner output; **every cited evidence pointer is validated programmatically** against the source record (reject unresolved citations); **human-in-the-loop confirmation** required before anything is marked false-positive or de-prioritized.
- **Automated remediation guidance** per finding (plain-English + root cause + fix + secure code example + verification + standards refs). Patch suggestions marked "requires developer review."
- **Patch-validation workflow:** link finding→remediation attempt, rescan relevant tests, before/after diff, status (open/mitigated/fixed/accepted-risk/false-positive), audit trail. **Model the dedup + reimport semantics on DefectDojo** (BSD-3): reimport discards matches, auto-mitigates findings absent from a new scan, and auto-reopens closed findings that reappear. Copy the data model, or integrate DefectDojo outright (Decision Gate).
- **Next-wave scanners** (🧩, additive): Nuclei ≥v3.8.0, OSV-Scanner v2 + pip-audit/npm audit, Gitleaks (default) + TruffleHog (verification, AGPL shell-out only).

**Exit criteria:** From an in-scope target, the platform runs recon → scans → triaged, deduped, ranked draft findings with remediation guidance; a fixed finding can be retested and its status tracked with an audit trail.

---

## M5 — Agent permission testing 🧩

**Goal (from brief):** *the platform can test whether an AI agent respects its allowed tool permissions.*

- **Sandboxed fake tools** (`sandbox/`): `send_email` (log-only), `query_database` (seeded test data), `create_ticket` (local record), `call_webhook` (local mock). 🔒 Justified as bespoke (verified): OSS benchmarks don't provide controlled, auditable, no-side-effect execution with policy monitoring as a product feature.
- Agent policy definition (allowed tools + parameter boundaries).
- Tool-call monitoring + policy-decision engine (allowed/blocked + reason).
- Test suites: excessive agency, unauthorized tool use, parameter manipulation, confused-deputy, unsafe delegation, out-of-scope resource access. **Make the attack corpus pluggable** (AgentDojo / InjecAgent / newer suites) — agentic benchmarks saturate quickly against frontier models, so don't hard-code one corpus.
- **Map findings to the OWASP Top 10 for Agentic Applications 2026 (ASI02 Tool Misuse & Exploitation)** in addition to OWASP LLM06 Excessive Agency.
- Permission-boundary report per agent target (tool invoked, params, decision, evidence, severity, recommended boundary), normalized into `Finding`.

**Exit criteria:** Against an agent target with a defined policy, the platform exercises the permission tests in the sandbox, records allow/block decisions with evidence, and produces a permission-boundary report mapped to LLM06 + ASI02.

---

## M6 — Compliance & reporting depth

**Goal (from brief):** *a user can generate compliance-ready reports from validated findings.*

- Compliance mapping **database** (migrate the local JSON/YAML KB to DB-managed): OWASP LLM Top 10 (2025), **OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)**, OWASP WSTG v4.2, NIST AI RMF + AI 600-1, NIST SP 800-53 Rev 5.2.0, NIST SP 800-115.
- Full **CVSS scoring UI** (vector editor, bands, manual override + justification, audit history) — deepens the M3 slice.
- **POA&M generator** (full field set: weakness ID, description, asset, source, severity, CVSS, control mapping, remediation, owner, planned completion, status, milestones, risk-acceptance).
- **Executive report** (risk posture, severity breakdown, top risks, business/compliance impact, priorities) and **Technical report** (detailed findings, evidence, repro, endpoints/files, remediation, retest status).
- **Export formats:** PDF (exec + technical) and DOCX added to the existing CSV + Markdown + JSON. Reports editable before export.

**Exit criteria:** A reviewer generates editable executive and technical reports and a full POA&M from validated findings, exports to CSV/Markdown/PDF/DOCX/JSON, with complete OWASP/NIST mappings and CVSS history.

---

## Hardening & production-readiness 🚪

Not a feature milestone — the **final security verification** before any real-world / federal deployment, and where the deferred decisions resolve. Platform security does **not** start here: the per-milestone 🛡 Security Gates and continuous CI pipeline (`SECURITY_DEVELOPMENT_PLAN.md`) mean each item below should already have a green per-phase antecedent. This gate confirms the built-in security holds end-to-end and resolves:

- 🚪 **Evidence-store production backend (blocking — evidence storage is not "done" until resolved).** The MinIO OSS repository was archived **2026-04-25** (https://github.com/minio/minio); replace the dev MinIO build. Choose and verify a maintained WORM-capable backend (Ceph RGW, or SeaweedFS/RustFS *only after* empirically confirming compliance-mode delete-before-expiry is rejected). Until this resolves, the evidence-storage capability is functionally demonstrable but **not production-complete**.
- 🚪 **Password-hash / FIPS decision.** Confirm the target ATO (FedRAMP/FISMA/CMMC). If FIPS-validated crypto is mandated, switch Argon2id → PBKDF2-HMAC-SHA256 (≥600k). Decide *before* users exist (avoids a rehash migration).
- 🚪 **SSO (OIDC/SAML).** Implement against the existing auth abstraction; handle the `SameSite=Strict` handshake exception.
- Security review of the platform itself, dependency + secret scan of our own code, supply-chain pinning (esp. LiteLLM if adopted), backup/restore drill, resource-limit tuning under load.

---

## Decision gates (tracked)

| Gate | Decision | Needed by | Default if unresolved |
|---|---|---|---|
| 🚪 Evidence-store backend | Ceph RGW vs verified SeaweedFS/RustFS vs filesystem | **Before evidence storage is production-complete / before production** | Dev MinIO OSS continues (archived 2026-04-25; not production-safe — blocks the go-live DoD) |
| 🚪 Password hash / FIPS | Argon2id vs PBKDF2 | Before first real users (M1 hardening) | Argon2id |
| 🚪 SSO | OIDC and/or SAML, which IdP | M6 / pre-deploy | Local auth only |
| 🚪 Worker engine | Stay Celery vs Dramatiq/Temporal | Only if M4 orchestration grows multi-step/resumable | Celery |
| 🚪 LLM abstraction | Thin adapter vs LiteLLM | When a 3rd+ provider is needed | Thin in-house adapter |
| 🚪 LLM red-team engine | Integrate vs build bespoke; how many engines | M2 | **Integrate — PyRIT first**, add garak/promptfoo post-MVP |
| 🚪 Finding store / dedup | Build (DefectDojo-modeled) vs integrate DefectDojo | M3/M4 | Build, modeled on DefectDojo semantics |
| 🚪 AI-assisted dev security review (Codex Security) | Enable per track; hosted-source-egress sign-off for federal/air-gap (`SECURITY_DEVELOPMENT_PLAN.md §5a`) | M0 (dev track); before federal ATO | Dev track **on** (assistive only); federal/air-gap **off** until signed off |

---

## Deferred (out of scope until explicitly scheduled) ⏸

- Horizontal scaling, Kubernetes/Helm, multi-node HA.
- Multi-tenant SaaS isolation (org boundary exists in schema; enforcement stays single-org).
- PDF/DOCX/JSON export (M6, not MVP).
- Temporal/Dramatiq migration (only if worker orchestration outgrows Celery).
- Additional scanners beyond the M3/M4 set.

---

## Rough sequencing note

Milestones are ordered by dependency, not calendar. M0→M1→M2/M3 is the critical path to MVP; M2 and M3 can overlap once the M1 foundation and the finding schema exist (they share the normalized `Finding` model but touch different runners/adapters). M4–M6 are strictly post-MVP and can be reprioritized against real user feedback. No dates are committed here — estimates live with the task breakdown in `MVP_TASKS.md`.
