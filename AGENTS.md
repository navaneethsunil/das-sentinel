# AGENTS.md — DAS Sentinel

> Project rules and build instructions for Codex (and any coding assistant) working in this repository. Read this file in full before writing code. If a request conflicts with the **Safety invariants** below, stop and surface the conflict — do not proceed.

---

## 1. What this project is

**DAS Sentinel** is an **AI security testing and automated penetration-testing platform** for **authorized defensive security assessments** of web applications, APIs, source code, and AI/LLM applications.

It turns an approved engagement scope into evidence-backed, compliance-mapped, prioritized, report-ready findings. The value is not scanning — it is turning authorized testing evidence into clear, prioritized, compliance-ready action.

**Compliance references (pin these exact versions — verified current July 2026):**

- **OWASP Top 10 for LLM Applications — 2025 edition** (published under the OWASP GenAI Security Project). Codes `LLM01`–`LLM10`; note the 2025 additions **LLM07 System Prompt Leakage** and **LLM08 Vector and Embedding Weaknesses**, and that "Insecure Output Handling" is now **LLM05 Improper Output Handling**.
- **OWASP Web Security Testing Guide (WSTG) v4.2** (v5.0 in development — watch for it).
- **NIST AI RMF 1.0 (AI 100-1)** **plus** the Generative AI Profile **NIST AI 600-1** — reference both.
- **NIST SP 800-53 Rev 5.2.0** (Aug 2025) — not Rev 5.1.1.
- **NIST SP 800-115** (2008) — still the current technical testing guide; cite as-is.
- **CVSS v4.0** as the default for new findings, with **v3.1 retained** for historical CVEs (dual-scoring).

The authoritative product definition is `ai-security-testing-platform-build-brief.md`. When this file and the brief disagree on *scope*, the brief wins; when they disagree on *how to build*, this file wins.

---

## 2. Non-negotiable safety invariants

These are hard rules. They are not optional, and they are not to be "temporarily" disabled for convenience, tests, or demos.

> **Scope note — two security dimensions.** This section governs **product safety**: what the platform is forbidden to *do to targets*. The complementary discipline — **application security of the platform itself** (auth, SSRF, injection, secret handling, supply chain, our own LLM egress, and how we security-test our own code every phase) — is owned by **`SECURITY_DEVELOPMENT_PLAN.md`**. Both are mandatory; do not treat platform self-security as a pre-production afterthought (see §11).

1. **No scan runs without a saved engagement, a defined scope, and an accepted ROE.** The API must reject such requests at the service layer, not just hide a button in the UI.
2. **Every active target is validated against the engagement allowlist and out-of-scope blocklist** immediately before execution. Out-of-scope targets are blocked and the attempt is audit-logged.
3. **Default behavior is safe and non-destructive.** Passive/safe-active only unless a higher intensity is explicitly selected *and* authorized.
4. **High-risk actions require an explicit approval gate** (exploit validation, authenticated destructive checks, brute-force/password-spraying, large-scale crawling, data-modifying payloads). No auto-exploitation.
5. **No offensive/malicious capabilities.** Do not build stealth, evasion, persistence, credential theft/harvesting, data exfiltration, or default denial-of-service. Do not bypass auth outside approved scope.
6. **The LLM is never the source of truth.** Every finding must cite concrete evidence (scanner output, test transcript, source location, or captured response). The LLM must not invent evidence, CVEs, or line numbers.
7. **Redaction before egress.** Sensitive data is redacted before being sent to any hosted model, and hosted models are only used when the engagement's `hosted_models_allowed` flag is true.
8. **Everything is audited.** Who ran what, against which target, when, with what result. Audit events are append-only.
9. **Findings are clearly labeled** by status: automated, AI-generated, validated, manually-overridden. Never present an unreviewed AI finding as verified.
10. **Emergency stop always works.** A running scan must be cancellable, and cancellation must halt the underlying worker/tool process.

If a task would violate any invariant, refuse the unsafe part, explain why, and offer a safe alternative.

---

## 3. Technology stack (decided)

| Layer | Choice |
|---|---|
| Frontend | Next.js (App Router) + TypeScript, Tailwind CSS, shadcn/ui |
| Backend API | Python 3.12+, FastAPI, Pydantic v2 (≥2.7) |
| Workers | Celery (Valkey broker) for scanner/LLM jobs — see §6a on cancellation |
| Database | **PostgreSQL 17** (JSONB for *structured* findings only), SQLAlchemy 2.x + Alembic migrations |
| Object storage | **S3-compatible evidence store** (production backend is a **blocking pre-go-live gate** — the MinIO OSS repository was archived **2026-04-25**, https://github.com/minio/minio; the dev MinIO build is not production-safe, and evidence storage is not "done" until a maintained WORM-capable backend is selected and its compliance-mode WORM is empirically verified) for raw scanner output / evidence blobs — content-hashed, object-lock/WORM (compliance mode) for chain-of-custody. Access only via the `storage/` abstraction so the backend stays swappable |
| Cache / queue | **Valkey 8** (BSD-3, Linux Foundation fork of Redis; drop-in, avoids Redis SSPL/AGPL licensing friction for federal/air-gapped) |
| Auth | Local email/password (**Argon2id**; see FIPS note below), **opaque server-side sessions** (random ID → session row in Postgres/Valkey), RBAC. SSO-ready abstraction (OIDC/SAML later) |
| LLM | Provider abstraction (thin adapter, or LiteLLM if multi-provider); default **Anthropic Codex** (`Codex-opus-4-8` workhorse, `Codex-sonnet-5` for volume triage, `Codex-haiku-4-5` for classification) |
| Local models | **Ollama** (dev / single-analyst / CPU) and **vLLM** (GPU-backed air-gapped server) behind the abstraction |
| First scanners | **Semgrep CE** (SAST — see license note), **ZAP by Checkmarx** (DAST). Next wave: **Nuclei ≥ v3.8.0**, OSV-Scanner v2 / pip-audit / npm audit, **Gitleaks** (default) + TruffleHog (verification) |
| Deployment | Docker Compose (self-hosted, air-gap friendly) |
| Exports (MVP) | POA&M CSV, Markdown technical report. Later: PDF, DOCX, JSON |

**Stack currency & licensing notes (verified July 2026):**

- **Postgres 17** is the floor for this greenfield build (16 is two majors behind; 18 stable / 19 beta exist). Pin to whatever your hardened/FIPS-accredited base image ships if that dictates 16.
- **Raw evidence never goes in a JSONB column.** Large blobs hit TOAST read-amplification and the 1 GB field cap; store them in MinIO with a hash + object key, and keep only queryable structured findings as JSONB (GIN-indexed).
- **Valkey over Redis:** Redis relicensed to SSPL/RSAL (2024) and added AGPLv3 (2025); AGPL's network-copyleft is commonly treated as legally radioactive by gov/enterprise legal. Valkey is clean BSD-3 and protocol-compatible — no code changes.
- **Argon2id + FIPS caveat:** Argon2id is OWASP's #1 (≥19 MiB, t=2, p=1). But Argon2 is **not FIPS-approved** — if the target ATO (FedRAMP/FISMA/CMMC) mandates FIPS-validated crypto for password storage, fall back to **PBKDF2-HMAC-SHA256** (≥600k iterations). Confirm the compliance regime before locking this in.
- **Sessions:** opaque server-side sessions (not JWT) — chosen for instant revocation, forced logout, "kill all sessions," and clean audit, which an audit-heavy tool needs. Session ID is a high-entropy random token in an **HttpOnly, Secure, SameSite=Strict** cookie; the session row (user, role, created/last-seen, IP/UA) lives in Postgres with a Valkey cache. Future OIDC/SAML exchanges the IdP assertion for a local session rather than passing IdP tokens around.
- **Semgrep license:** Semgrep CE engine is LGPL-2.1, but Semgrep-maintained *rules* are under the restrictive "Semgrep Rules License v1.0" (no redistribution in a competing/SaaS product) and interprocedural taint analysis is paid-only. If we need to bundle rules or want free cross-file analysis, pilot **OpenGrep** (LGPL fork, rule-format compatible).
- **TruffleHog is AGPL-3.0** — safe to shell out to as an unmodified binary, but do not link/modify/bundle without legal sign-off. **Gitleaks (MIT)** is the default; TruffleHog adds live-credential verification.
- **LLM param currency:** current Codex models use `thinking: {type: "adaptive"}` only — legacy `budget_tokens`/`temperature`/`top_p` and date-suffixed IDs return HTTP 400. Prefer `Codex-opus-4-8`/`Codex-sonnet-5` as defaults; **Fable 5 runs cyber-content classifiers that can return `stop_reason: "refusal"` on security-adjacent prompts** — a real false-positive risk for a pentest tool, so avoid it as the default (or ship the `fallbacks` param).

Do not introduce a different framework, database, or paid managed service without asking. Prefer adding a scanner over swapping the stack.

---

## 4. Repository layout

```
das-sentinel/
├── ai-security-testing-platform-build-brief.md   # source of truth for scope
├── AGENTS.md                                       # this file
├── ARCHITECTURE.md  ROADMAP.md  DATABASE_SCHEMA.md  MVP_TASKS.md  (+ PRD/TRD/etc.)
├── docker-compose.yml
├── .env.example                                    # never commit real secrets
├── apps/
│   ├── web/                # Next.js frontend
│   └── api/                # FastAPI backend
│       ├── app/
│       │   ├── main.py
│       │   ├── core/       # config, security, scope-enforcement, audit
│       │   ├── models/     # SQLAlchemy models
│       │   ├── schemas/    # Pydantic schemas
│       │   ├── api/        # routers (engagements, targets, scans, findings, reports)
│       │   ├── services/   # business logic (scope, cvss, compliance mapping)
│       │   ├── scanners/   # one module per scanner (adapter pattern)
│       │   ├── storage/    # MinIO/S3 client: raw evidence blobs (hash, object-lock)
│       │   ├── llm/        # provider abstraction + adapters + prompt templates
│       │   ├── workers/    # celery tasks (cancellable — see §6a)
│       │   └── reports/    # exporters (csv, markdown, later pdf/docx)
│       └── migrations/     # alembic
├── packages/
│   └── compliance/         # OWASP/NIST mapping knowledge base (JSON/YAML)
└── sandbox/                # mock vulnerable apps + fake agent tools for safe testing
```

---

## 5. Coding rules

- **Language/versions:** Python 3.12+, **Node 24 LTS** (Node 20 reached end-of-life 2026-03-24 — do not target it; 22 is maintenance-LTS, 24 is the current active LTS), TypeScript strict mode on.
- **Backend:** async FastAPI endpoints; Pydantic v2 for all request/response models; SQLAlchemy 2.0 style; all DB access through the session dependency. Type hints everywhere.
- **Frontend:** Server Components by default; Client Components only when interactivity requires it. Data fetching via a typed API client generated from / aligned with the OpenAPI schema. No `any`.
- **Formatting/lint:** Python = Ruff (lint+format). Frontend = ESLint + Prettier. Code must pass lint before it's considered done.
- **Config:** all config via environment variables loaded through a single `Settings` object. No hardcoded hosts, keys, or model names.
- **Secrets:** never commit secrets. Read keys from env / secrets manager. Provide `.env.example` with placeholders only.
- **Errors:** fail loud and specific. Never swallow scanner or LLM errors silently — surface them as job failures with captured stderr.
- **Comments:** only where the code can't explain itself (a constraint, a safety gate, a standard being enforced). No narration comments.
- **Tests:** every scope-enforcement, auth, and scanner-adapter path needs a test. Safety gates must have explicit negative tests (proves out-of-scope/no-ROE is blocked).

---

## 6. Scanner adapter contract

Every scanner is a self-contained module implementing a common interface so tools can be added/removed without touching orchestration:

```
class ScannerAdapter:
    name: str
    version() -> str
    validate_prerequisites() -> None        # tool installed, reachable
    build_command(target, config) -> ...     # never runs against unvalidated target
    run(target, config, on_progress) -> RawResult   # enforces timeout + rate limit
    normalize(raw: RawResult) -> list[Finding]       # maps to shared Finding schema
```

Rules:
- **Scope is validated before `run()` is ever called** — the adapter trusts nothing.
- **Raw output and normalized findings are stored separately** — raw evidence goes to MinIO (hashed, immutable), normalized findings to Postgres. Never mutate raw.
- Record scanner **version and configuration** on every run.
- Enforce **timeouts and rate limits** inside the worker; respect the engagement's rate-limit setting.
- Scanner processes run isolated (subprocess/container) and are killable for emergency stop.

### 6a. Worker cancellation (emergency stop)

Emergency stop is a hard safety invariant (§2.10), and Celery is architecturally fire-and-forget — cancelling an in-flight subprocess is not a first-class primitive. So:

- Each scanner task must launch its tool in a **child process/container whose PID/container ID is recorded** with the scan record. Cancellation = terminate that process group (SIGTERM → SIGKILL), not just Celery `revoke` (which won't stop an already-running task's subprocess).
- Tasks must **heartbeat** progress and check a cancellation flag between steps.
- Reassess if orchestration grows to multi-step, resumable, long-running pipelines: **Dramatiq** (simpler, more reliable actor model) or **Temporal** (durable execution + first-class cancellation) become better fits than Celery. Not an MVP change — noted so we don't over-invest in Celery-specific retry plumbing.

---

## 7. LLM usage rules

- All model calls go through the provider abstraction (`app/llm`), never a vendor SDK directly in a router or service. Roll a thin adapter if we only ever need Codex + one local backend; use **LiteLLM** if we need many providers.
- Default provider is Anthropic Codex (`Codex-opus-4-8` default, `Codex-sonnet-5` for high-volume triage, `Codex-haiku-4-5` for classification). **Ollama** covers local/dev; **vLLM** covers GPU-backed air-gapped servers.
- Use current Codex params only: `thinking: {type: "adaptive"}`, structured output via strict tool use / `output_config.format`. Do **not** use `budget_tokens`, `temperature`, `top_p`, or date-suffixed model IDs — they 400. Avoid Fable 5 as default (cyber-content refusal risk for pentest prompts); if used, set the `fallbacks` param to `Codex-opus-4-8`.
- **Redaction layer runs before any hosted call.** If `hosted_models_allowed` is false for the engagement, hosted providers are unavailable and only local models may be used.
- Prompt templates live in versioned files under `app/llm/prompts/`, not inline strings.
- Track tokens and cost per interaction; persist LLM interactions for audit.
- LLM output is **draft analysis**. It must reference supplied evidence and is stored with an `ai-generated` label until a human validates it. Never let the model set final CVSS or mark a finding "fixed."

---

## 8. Build order (follow this sequence)

1. **Foundation:** UI shell, API, DB schema, auth+RBAC, engagement + scope + ROE, target inventory, audit logging. *Goal: a user can create an authorized engagement and add in-scope targets.*
2. **AI/LLM test harness:** prompt-injection + data-leakage runners, LLM target connector, evidence capture, pass/fail.
3. **Scanner integrations:** Semgrep CE + ZAP by Checkmarx, normalized findings model.
4. **Automated pentest workflows:** recon, scan-plan generation, triage, dedup, remediation guidance, patch validation.
5. **Agent permission testing:** sandboxed fake tools, agent policy, tool-call monitoring, permission-boundary reports.
6. **Compliance & reporting:** OWASP/NIST mapping, CVSS UI, POA&M export, executive + technical reports, PDF/CSV/Markdown.

**Prioritize a working vertical slice over broad-but-shallow features.** Ship stage N end-to-end before starting stage N+1.

---

## 9. Definition of done (MVP)

The MVP is done when all acceptance criteria in the brief hold, verifiably:
- Scans cannot run without engagement + approved scope; out-of-scope targets are blocked (with tests proving it).
- ≥1 AI/LLM test suite, ≥1 code scanner (Semgrep), and ≥1 web/API scanner (ZAP) each work end-to-end.
- Findings normalize into the shared schema, carry evidence, and map to OWASP + NIST references.
- CVSS scoring works; POA&M CSV + Markdown technical report export works.
- Audit log captures who/what/target/when; UI distinguishes automated vs. human-validated findings.

---

## 10. Working agreement for the assistant

- Start from the foundation and safety controls before any scanner execution.
- Do **not** run live scans against public or third-party targets. Use `sandbox/` mock apps, intentionally-vulnerable labs, or explicitly user-owned/authorized systems only.
- Keep scanner execution modular; keep raw and normalized data separate; treat LLM output as draft.
- On security-relevant changes, use AI-assisted security review (Codex Security, `SECURITY_DEVELOPMENT_PLAN.md §5a`) as a second opinion during development — assistive only; it never replaces the negative tests or CI gates, and its patches go through normal review.
- When unsure whether an action is in-scope or safe, stop and ask.
- Make the UI usable for security testers, engineers, and compliance reviewers alike.

---

## 11. Secure development of the platform itself

DAS Sentinel is a concentrated high-value target (it holds target credentials, evidence, ROEs, LLM keys, and findings) and, by design, an SSRF/abuse amplifier. It must be held to the security standard it sells. **`SECURITY_DEVELOPMENT_PLAN.md` is the authoritative secure-SDLC document; read it before writing security-relevant code.** The non-negotiables:

1. **Security testing is continuous, not a final gate.** Every milestone (M0→M3 and beyond) ships with the security tests, scans, and threat-model updates for the surface it introduced. The pre-production Hardening gate is the *final verification*, not where platform security begins.
2. **A security CI pipeline runs from M0** (extends `M0-I5`): SAST (Semgrep + Bandit), secret scanning (Gitleaks), SCA (pip-audit / npm audit / OSV-Scanner), container/IaC scan (Trivy), DAST baseline (ZAP against our own running app), SBOM (Syft→CycloneDX), and CI/CD hardening (pinned action SHAs, least-privilege tokens). Secret findings and the safety negative tests block the build from day one; other thresholds tighten per milestone.
3. **Dogfood our own scanners on our own code.** The Semgrep and ZAP adapters built in M3 are pointed at DAS Sentinel itself in CI. If they can't find bugs in our code, they aren't good enough to ship.
4. **Build to current standards (verified July 2026):** OWASP ASVS 5.0 (target L2 app-wide, L3 for auth/session/crypto/audit), OWASP Top 10:2025 (our web app), OWASP Top 10 for LLM 2025 (**our own** triage/remediation LLM usage — untrusted scanner output and target responses are an indirect-injection surface against us), and NIST SSDF (SP 800-218/218A) for the federal ATO story.
5. **Abuse-case / negative tests are mandatory** for scope, access control (cross-engagement IDOR/BOLA), sessions/CSRF, SSRF/egress, LLM gates, uploads, and parsers — release-blocking, in the same CI gate as functional tests. See `SECURITY_DEVELOPMENT_PLAN.md §8` and the Security Definition of Done (§9 there).
6. **Fail closed, everywhere a security decision is made** (scope, redaction, egress, prereq validation, exceptional conditions). Never swallow errors into a fail-open path (aligns with OWASP A10:2025).
7. **AI-assisted security review runs during development, not just in CI.** Use an agentic AI security reviewer — **OpenAI Codex Security** — in the inner loop and on PRs to catch issues while code is written (identify → validate → propose a human-reviewed patch; it never auto-merges). It is **assistive, not a gate**: it never replaces the deterministic CI pipeline (#2) or the release-blocking abuse-case tests (#5), and its findings/patches are triaged and reviewed like any other (consistent with §2.6 — the LLM is never the source of truth). Because it ingests our own source into a hosted model, its use is **egress-gated per track** (dev track on; federal/air-gap off until signed off) and must never be a hard CI dependency. Full control + guardrails in **`SECURITY_DEVELOPMENT_PLAN.md §5a`**.
