# SECURITY_DEVELOPMENT_PLAN.md — DAS Sentinel

> **How we secure the platform itself, continuously, while we build it.** This is the secure-SDLC / application-security plan for DAS Sentinel's *own* code, infrastructure, and supply chain. It exists so that security testing is a per-phase gate from M0 onward — **not** a one-time pre-production "Hardening gate" bolted on at the end.
>
> Read alongside `CLAUDE.md` (rules + safety invariants), `IMPLEMENTATION_PLAN.md` (build order + gates), `MVP_TASKS.md` (task IDs), and `TRD.md` (technical requirements). Where those documents and this one overlap, this document is authoritative on *how the platform's own security is verified*; `CLAUDE.md §2` remains authoritative on *what the platform is forbidden to do to targets*.

---

## 0. Two different security problems — don't conflate them

DAS Sentinel has **two** security dimensions. The existing docs cover the first thoroughly; this document owns the second.

| | **A. Product safety** (already covered) | **B. Platform application security** (this document) |
|---|---|---|
| Question | "Can this tool be misused to harm a target?" | "Can this platform itself be attacked, and does its own code hold up?" |
| Governs | Scope enforcement, ROE, intensity gates, no-offensive-capabilities, emergency stop | Auth, authZ, SSRF, injection, secret handling, supply chain, our own CI/CD, our own LLM egress |
| Authority | `CLAUDE.md §2` (safety invariants), `ARCHITECTURE.md §9` | **This document** + `TRD.md §9` |
| Failure looks like | An out-of-scope host gets scanned | An attacker exfiltrates stored target credentials / evidence, or pivots through the scanner worker |

**Why B is not optional and not "later":** DAS Sentinel is a *concentrated high-value target*. In one place it holds authorized-target credentials, raw evidence and captured responses, signed ROEs, LLM provider keys, and full findings for multiple engagements. It is also, by design, an **SSRF/abuse amplifier** — a service whose whole job is to send attacker-influenced traffic outward. A security testing product that is not itself continuously security-tested is a contradiction, and for the federal/ATO market it is a non-starter. So we **shift security left**: every milestone ships with the security tests, scans, and threat-model updates for the surface it introduced.

---

## 1. Governing standards (verified current, July 2026)

We build the platform to these; we do not merely map *client findings* to them.

| Standard | Version / status | How we use it |
|---|---|---|
| **OWASP ASVS** | **5.0.0** (released 30 May 2025; browse at asvs.dev) | The verification checklist for our own code. **Target: ASVS Level 2 across the app; Level 3 for the auth, session, crypto, and audit subsystems.** Note 5.0 dropped direct CWE mappings in favor of OWASP CRE. |
| **OWASP Top 10** | **2025 edition** (released 6 Nov 2025) | Web-app risk baseline for *our* app. Note the 2025 shape: **A01 Broken Access Control** (still #1), **A02 Security Misconfiguration**, **A03 Software Supply Chain Failures** (new), **A10 Mishandling of Exceptional Conditions** (new). Supply chain and misconfiguration moving up directly implicate a self-hosted, adapter-heavy, container-based product like ours. |
| **OWASP Top 10 for LLM Applications** | 2025 | Applies to **our own LLM usage** (triage/remediation/report), not just to LLM targets we test. We feed untrusted scanner output and captured target responses into our models — that is a live indirect-injection surface **against us** (see §3, TM-4). |
| **OWASP Proactive Controls** | current | The "build-it-right" companion to ASVS; the default control vocabulary for design reviews. |
| **NIST SSDF — SP 800-218** | 1.1 | Federal secure-software-development framework. Our ATO story needs demonstrable SSDF practices (PO/PS/PW/RV). This plan is our SSDF evidence. |
| **NIST SSDF + Generative AI — SP 800-218A** | current | Extends SSDF to AI/ML development; relevant because we embed models and red-team tooling. |
| **OWASP CI/CD Security Top 10** | current | Our pipeline is itself in scope (it can build and deploy the thing that holds all the secrets). See §5 and §7. |
| **SLSA** | v1.0 | Build-provenance target for release artifacts (see §7). |
| **OWASP SAMM / DSOMM** | current | Maturity frame we self-assess against, so "are we doing enough security work?" has a defensible answer, not a vibe. |

> **Currency rule (mirrors `CLAUDE.md`):** these versions are pinned as verified in July 2026. Re-verify at each milestone's security gate; if a standard revs (e.g., ASVS 5.0.1, a WSTG 5.0), record the bump here with a date before adopting it.

---

## 2. Assets, trust boundaries, and adversaries

**Assets, ranked by "what an attacker wants most":**

1. **Target credentials** (`targets.auth_config` references + whatever the secrets manager holds) — keys to *other people's* systems.
2. **LLM provider API keys** — billable, and egress-capable.
3. **Evidence & captured responses** (object store) — may contain secrets pulled from targets, PII, proprietary source.
4. **Signed ROEs & scope** — tamper here and you relax what the platform will attack.
5. **Findings & reports** — pre-disclosure vulnerability intelligence about real systems.
6. **Audit log** — tamper here to hide everything above.
7. **The worker's outbound network position** — the SSRF/pivot prize.
8. **Sessions & user accounts** — especially Admin/Reviewer (approve high-risk gates).

**Trust boundaries** (from `ARCHITECTURE.md §2–3`): browser→proxy, proxy→api, api→worker (job queue), worker→target (outbound, attacker-influenced), worker/api→LLM provider (egress), app→object store, app→Postgres/Valkey. **Every one of these is a place a control must live and a place a test must exercise.**

**Adversary classes we design against:**

- **A malicious or compromised target.** The single most under-appreciated threat: a target we are authorized to scan returns crafted responses to attack *us* (SSRF pivots, injection into triage LLM, deserialization/parse bugs in our normalizers, zip-bombs / decompression bombs in uploaded source archives).
- **A lower-privileged authenticated user** attempting privilege escalation, IDOR/BOLA across engagements, or scope/ROE bypass.
- **A supply-chain adversary** (poisoned Python/npm dependency, poisoned scanner image, malicious Semgrep/Nuclei rule, compromised GitHub Action).
- **A network-adjacent attacker** (missing security headers, session theft, CSRF).
- **An insider** (why audit is append-only and evidence is WORM).

---

## 3. Platform threat model (STRIDE-tinted), with test ownership

Each threat lists where it is mitigated and **which phase's security gate must prove it**. IDs (`TM-n`) are referenced by the per-phase tasks in `MVP_TASKS.md`.

| ID | Threat | Primary mitigation (where) | Proven in |
|---|---|---|---|
| **TM-1** | **SSRF / worker pivot** — crafted target or redirect makes the worker hit internal services, cloud metadata (169.254.169.254), or out-of-scope hosts | Scope engine resolves host→IP and re-checks the *resolved* IP (`TRD TR-11.2`); **worker egress allowlist** (default-deny) so only approved scope IPs are reachable; block link-local/loopback/RFC-1918 unless explicitly in scope; disable/limit redirect following in adapters and re-validate each hop | **M1** (scope+resolved-IP) → **M2/M3** (egress policy on the worker) |
| **TM-2** | **Scope-engine bypass** — logic/parsing gap lets an out-of-scope target through | Single keystone (`core/scope.py`), fail-closed matching, checked at api *and* worker; release-blocking negative matrix (`TRD TR-31`) | **M1** |
| **TM-3** | **Broken access control / IDOR / BOLA** (OWASP A01:2025) — user reads/acts on another engagement's data | Default-deny RBAC deps (`TRD TR-26`); every object query scoped to the caller's org/engagement; automated per-role, per-route, cross-engagement access tests | **M1**, re-run every phase that adds routes |
| **TM-4** | **Indirect prompt injection into *our* LLM** — scanner output / target response / uploaded code contains instructions that hijack our triage/remediation model | Treat all model input as untrusted data, never instructions; structured-output tool-use only; **the LLM never decides scope, severity, status, or actions** (`TRD TR-16.4`); programmatic validation of every evidence pointer the model cites; redaction fail-closed before hosted egress (`TRD TR-16.2`) | **M2** (LLM layer), reinforced in **M4** (triage) |
| **TM-5** | **Secret exposure** — target creds / LLM keys leak via logs, errors, DB, evidence, or model egress | No plaintext secrets in DB/code (`TRD TR-23`); secrets via env/secrets manager; log redaction; egress redaction; secret-scanning in CI on every commit | **M0** (CI secret scan) → **M2** (egress) |
| **TM-6** | **Injection** (SQLi/command/path/template) in our own code | Parameterized SQLAlchemy only; no shell=True; `build_command` uses arg vectors never string concatenation; path-canonicalize + confine uploads; SAST every commit | **M0** (SAST) → each phase |
| **TM-7** | **Malicious upload** — source archive is a zip/decompression bomb, path-traversal (zip-slip), or symlink escape | Size + entry-count + compression-ratio limits; safe extraction (reject `..`/absolute/symlink entries); extract to an isolated, quota'd, no-exec location; scan before processing | **M3** (source upload) |
| **TM-8** | **Deserialization / parser abuse** — malicious scanner/tool output or SARIF crashes or exploits our normalizer | Parse in the worker (isolated), never `pickle`/`yaml.load`; bounded/streaming JSON/JSONL parsing; treat all tool output as hostile; fuzz the normalizers | **M2/M3** |
| **TM-9** | **Audit/evidence tampering** — hide activity or break chain-of-custody | Insert-only tables + prod DB role denies UPDATE/DELETE (`TRD TR-19`); WORM object-lock verified (`ARCHITECTURE §7`); off-box log shipping (hardening) | **M1** (append-only) → hardening (integrity) |
| **TM-10** | **Session attacks** — fixation, theft, CSRF, weak revocation | `__Host-` cookie, ID regen on login, hashed at rest, idle+absolute timeouts, write-through revoke (`TRD TR-22`); synchronizer CSRF token (`TRD TR-22.1`) | **M1** |
| **TM-11** | **Supply-chain compromise** (OWASP A03:2025) — poisoned dep, scanner image, Semgrep/Nuclei rule, or GitHub Action | Hash-pinned deps (`--require-hashes`), digest-pinned images, pinned + least-privilege Actions, SCA + container scan in CI, SBOM per build, internal mirror for air-gap (`TRD TR-25`) | **M0** (baseline) → hardening (SBOM+signing+SLSA) |
| **TM-12** | **DoS / resource exhaustion of the platform** — runaway scan starves shared services; unbounded LLM cost | `deploy.resources.limits` on all services (`ARCHITECTURE §13`); per-user throttle + scan-concurrency cap; worker wall-clock timeouts + killpg; LLM token/cost ceilings per engagement | **M0** (limits) → **M2/M3** (concurrency, timeouts) |
| **TM-13** | **Security misconfiguration** (OWASP A02:2025) — missing headers, verbose errors, dev flags in prod, open CORS | Proxy security headers (`TRD TR-24`); RFC 9457 errors without stack traces; CORS off (same-origin); config via `Settings` only; DAST/header checks in CI | **M0** (headers/DAST-baseline on self) → each phase |
| **TM-14** | **Mishandling of exceptional conditions** (OWASP A10:2025) — a swallowed error opens a gate, or a failure fails *open* | Fail-closed everywhere a security decision is made (scope, redaction, scope re-check, prereq validation); never swallow scanner/LLM errors — surface as job failure (`CLAUDE.md §5`); tests assert deny-on-error | Each phase (design rule + tests) |

---

## 4. The core principle: dogfood our own scanners on our own code

We are building SAST, DAST, secret, dependency, and (later) container tooling. **We run all of it against our own repository, continuously, as the first customer.** This is both the strongest self-test and the best product validation — if our own Semgrep/ZAP integration can't find bugs in our own code, it isn't good enough to sell.

Concretely: the same Semgrep and ZAP adapters built in M3 are pointed at DAS Sentinel itself in CI (ZAP baseline against the app running in the ephemeral compose stack; Semgrep against `apps/`). Until an adapter exists, we use the underlying tool directly in CI so coverage starts at M0, then switch to "via our own adapter" once M3 lands.

---

## 5. Continuous security pipeline (CI) — runs from M0

Extends the `M0-I5` CI gate. **These run on every PR unless noted.** A finding at or above the stated severity **fails the build** (blocking), except where marked *report-only* (surface it, track it, don't block) to avoid day-one gridlock — blocking thresholds tighten by milestone (§6).

| Stage | Tool (verified July 2026, all OSS) | Scope | Gate |
|---|---|---|---|
| **SAST (Python)** | Semgrep CE (**vendored, content-hashed rule bundle** — OWASP/default/python rules, pinned by SHA-256, not fetched from the floating registry at CI time) + **Bandit** | `apps/api`, `apps/**/workers` | Block on High; report Medium |
| **SAST (JS/TS)** | Semgrep (**vendored, content-hashed rule bundle** — javascript/typescript/react rules, pinned by SHA-256) | `apps/web` | Block on High |
| **Secret scanning** | **Gitleaks** (full history on PR + pre-commit hook) | whole repo | **Block on any** verified secret |
| **Dependency / SCA** | **pip-audit**, **npm audit**, **OSV-Scanner v2** | lockfiles | Block on High/Critical with a fix; report otherwise |
| **Container / IaC** | **Trivy** (image + config/`docker-compose.yml` + Dockerfiles) | all images + compose | Block on High/Critical in our layers; report base-image CVEs without a fix |
| **DAST (self)** | **ZAP baseline** against the app in the ephemeral compose stack | running app | Block on High alerts; report Medium |
| **Security headers** | ZAP baseline / explicit header assertions | proxy responses | Block if a required header (`TRD TR-24`) is missing |
| **SBOM** | **Syft** → CycloneDX, attached as a build artifact | all images | Generate every build; **enforcement** (signing/SLSA) at hardening |
| **CI/CD hardening** | pinned action SHAs, `permissions: {}` least-privilege, `zizmor` (GitHub Actions linter) | workflows | Block on unpinned actions / excessive token scope |
| **Safety negatives** | pytest (`TRD TR-31/32/33`) | scope, auth, LLM gates | **Release-blocking, always** |

Notes:
- **Fail-closed CI:** a scanner stage that errors is a *failed* stage, not a skipped one (don't let a broken tool wave code through — same principle as TM-14).
- **Suppressions are code-reviewed and expiring:** any `# nosemgrep`, `.gitleaksignore`, or audit-ignore entry needs an inline justification and an owner; a periodic job flags stale suppressions.
- **Air-gap:** all tools and their rule/CVE databases must be mirror-able offline (matches the product's air-gap posture). No CI stage may hard-depend on live internet.

### 5a. AI-assisted security review during development — Codex Security (from M0)

The §5 pipeline is deterministic and release-gating. **Alongside it we use an agentic AI security reviewer, OpenAI Codex Security, in the development inner loop and on pull requests** — so that security review happens *while* code is written (including AI-assisted / "vibe" coding), not only at the CI gate. Codex Security works like a security researcher rather than a pattern scanner: it reads the repo, scans **commit by commit**, and runs a three-stage flow — **identify** (explore realistic attack paths), **validate** (attempt to reproduce each issue in an isolated environment before surfacing it, to cut false positives), and **remediate** (propose a *minimal, root-cause* patch). It **does not modify our code**: patches are surfaced for human review and raised as normal PRs. During development it can also be driven from the coding assistant itself (e.g. the `openai/codex-plugin-cc` plugin, which lets Codex review code / take delegated tasks from Claude Code) so a developer gets a security-specialist second opinion on a change before it is even committed.

**How it fits — and its hard limits (these are non-negotiable, they mirror the product's own invariants):**
- **Assistive, never authoritative.** Codex Security is a *reviewer*, not a gate and not a source of truth — the same rule the product enforces on its own LLM (CLAUDE.md §2.6). Its findings are triaged like any other (validated → human-confirmed), its patches go through normal code review, and it **never auto-merges**. Shipping is still decided by the deterministic §5 pipeline and the release-blocking safety/abuse tests in §8 — Codex Security **does not replace, relax, or override** any of them.
- **Hosted-egress gated.** Codex Security is a hosted service that ingests our source. That is *our own code leaving to a third-party model* — exactly the egress decision we gate for the product via `hosted_models_allowed`. So its use is **track-dependent**: enabled for the open/commercial development track; for the **federal / air-gapped ATO track it is off by default** and may only be enabled after the same data-egress + supply-chain sign-off we require for any hosted model (§7). It must **never be a hard dependency of a CI stage** (the air-gap rule above): CI stays green with only the offline §5 tools. The repo it scans already contains no secrets (Gitleaks blocks them from day one), which bounds the exposure but does not remove the source-disclosure decision.
- **Research-preview currency (watch-item).** Codex Security is an OpenAI *research preview* (ChatGPT Enterprise/Business/Edu/Pro); availability, scope, and terms may change. Treat it like every other pinned dependency in this repo — re-verify before relying on it, and record the enablement decision (which tracks, which repos) with an owner. Tracked as a Decision Gate in `ROADMAP.md`.

---

## 6. Per-phase security gates (shift-left)

Each phase adds a **Security Gate** that must pass to exit, alongside the functional exit gate already in `IMPLEMENTATION_PLAN.md` / `MVP_TASKS.md`. Gates are cumulative — later phases keep earlier gates green.

### Phase 0 / M0 — establish the security baseline
- Stand up the full §5 CI security pipeline (report-only thresholds acceptable *this phase only* except secrets + safety negatives, which block from day one).
- `deploy.resources.limits` on every service; `--init` on worker (TM-12).
- `.gitignore` covers `.env`/secrets; pre-commit Gitleaks hook; `.env.example` placeholders only (TM-5).
- Pin base-image digests; pin GitHub Action SHAs (TM-11).
- **Enable AI-assisted security review (Codex Security, §5a)** on the repo for the development track — commit-by-commit review in the inner loop + on PRs — and record the enablement decision + owner (off by default on the federal/air-gap track pending egress sign-off).
- **Gate:** CI security pipeline runs and reports on every PR; no secret in history; resource limits enforced. (Codex Security is an assistive reviewer, **not** part of the pass/fail gate — §5a.)

### Phase 1 / M1 — the safety & authZ core (heaviest security phase)
- **TM-2** scope engine: the release-blocking negative matrix (`TRD TR-31`) — this is also the product-safety keystone.
- **TM-3** access control: automated per-role/per-route + **cross-engagement IDOR/BOLA** tests (every object query proven org/engagement-scoped).
- **TM-10** sessions/CSRF: fixation-regen, instant revoke across cache+DB, idle/absolute expiry, synchronizer-CSRF on all state-changing routes (`TRD TR-32`).
- **TM-9** audit/evidence append-only: prove UPDATE/DELETE denied for the app DB role.
- **TM-1 (partial):** scope resolves host→IP and checks the resolved IP.
- **Gate:** ASVS 5.0 **L3** review of auth/session/access-control/audit; TM-2/3/9/10 tests green; SAST/secret/SCA now **block on High**.

### Phase 2 / M2 — LLM harness & worker execution
- **TM-4** our-own-LLM injection: model input is data-not-instructions; structured output only; cited-evidence pointers validated programmatically; LLM cannot set scope/severity/status.
- **TM-5** egress: redaction fail-closed + `hosted_models_allowed=false` hard block (`TRD TR-33`).
- **TM-1** worker egress allowlist (default-deny) enforced and tested against a decoy internal service + a metadata-IP probe.
- **TM-8** transcript/result parsers treat tool output as hostile; no unsafe deserialization.
- **TM-12** worker timeouts + killpg (emergency stop) verified; LLM token/cost ceiling per engagement.
- **Gate:** LLM gate tests green; SSRF/egress test green; a mock hostile target (in `sandbox/`) cannot pivot or inject.

### Phase 3 / M3 — scanners, uploads, normalization
- **TM-7** malicious upload defenses: zip-bomb / zip-slip / symlink / size / ratio limits, isolated no-exec extraction.
- **TM-8** SARIF + scanner-output normalizers fuzzed against malformed/hostile input.
- **TM-1** each adapter re-validates redirects/hops; native tool throttles set as floor under the orchestrator ceiling.
- **Dogfood:** point the new Semgrep + ZAP adapters at DAS Sentinel itself (§4).
- **Gate:** upload abuse tests green; normalizer fuzz clean; self-scan via our own adapters produces (and we triage) real findings; SAST/DAST/SCA all **blocking** at production thresholds.

> **M3-SEC3 implementation note (2026-07-24):** SAST + SCA already block on High (M1-SEC5); DAST (ZAP baseline against our own running app) was raised to **block on FAIL/High** alerts (WARN/Medium stay report-only) — our app currently reports 0 FAIL. The Semgrep adapter now dogfoods our own scan output in CI (`scripts/dogfood_semgrep.py`). **Container scanning (Trivy image/config) intentionally stays report-only:** the only current High/Critical are the **node base image's bundled npm tooling** (`tar`, `undici`, `brace-expansion`) — our own `package-lock.json` already carries the patched versions, and no patched node base image ships these 2026 CVE fixes yet. Base-image supply-chain hardening + SBOM signing/SLSA is owned by the pre-prod **Hardening gate** (§7, §10); container-blocking is deferred there rather than blocking the MVP gate on an upstream base-image bump or an expiring suppression. Re-verify at the Hardening gate.

### Post-MVP (M4–M6) — keep shifting left
- **M4 (recon/triage):** recon tooling gets the same egress allowlist; triage LLM guardrails (TM-4) hardened — deterministic severity, human-in-loop for FP/de-prioritization; new scanners (Nuclei/OSV/Gitleaks/TruffleHog) each ship with their own adapter security review.
- **M5 (agent testing):** the fake-tool sandbox must itself be escape-proof (no real side effects, resource-bounded, network-isolated) — a sandbox that leaks is worse than none.
- **M6 (reporting):** export/render path reviewed for template injection, formula/CSV injection (POA&M CSV → spreadsheet), and PDF/DOCX generation SSRF/XXE.

---

## 7. Supply-chain & secrets hygiene — from day one, not just at hardening

The 2025 elevation of **Software Supply Chain Failures to OWASP A03** and the LiteLLM PyPI backdoor already noted in `ARCHITECTURE.md §13` make this a build-time discipline, not a pre-prod checkbox.

- **Dependencies:** hash-pinned (`--require-hashes` / lockfiles with integrity), SCA on every PR, no unpinned floating ranges. Treat any LLM gateway (LiteLLM) as untrusted-until-verified.
- **Container images:** digest-pinned (never `:latest`), Trivy-scanned, minimal/low-CVE bases, internal mirror for air-gap.
- **Scanner rules & templates:** Semgrep/Nuclei/etc. rule sets are pinned by version/commit and reviewed before bump — a malicious rule can exfiltrate code or suppress findings.
- **CI/CD (OWASP CI/CD Security Top 10):** least-privilege tokens (`permissions: {}` + explicit grants), pinned action SHAs, no secrets in logs, protected branches, required reviews on this repo.
- **SBOM & provenance:** CycloneDX SBOM per build from M0 (visibility); **signing (Sigstore/cosign) + SLSA v1.0 provenance** enforced at the Hardening gate for release artifacts. Record every bundled model's weight license in the SBOM (`ARCHITECTURE §13`).
- **Secrets:** never in DB/code/images/compose/env-in-repo; externalized store (Vault/SOPS/KMS) target for production; rotation policy; `targets.auth_config` holds references only (`TRD TR-23`).
- **AI-assisted dev tooling egress (Codex Security, §5a):** using a hosted AI reviewer means our own source is ingested by a third-party model — treat it as a supply-chain / data-governance decision, not a free add-on. Enabled per-track with recorded sign-off; off by default on the federal/air-gap track; never a hard CI dependency; scanned repo must remain secret-free (Gitleaks-enforced).

---

## 8. Security tests as first-class, release-blocking tests

Security tests live in the same suite as functional tests and run in the same CI gate. **Abuse-case / negative tests are mandatory for every security-relevant change** (mirrors `CLAUDE.md §5`: "Safety gates must have explicit negative tests").

Minimum negative/abuse catalog (extends `TRD §11`):

- **Scope (TM-2):** the full `TRD TR-31` matrix — release-blocking.
- **Access control (TM-3):** each role × each route (allow/deny); cross-engagement object access denied; direct-object-reference by ID from another engagement returns 403/404, never data.
- **Session/CSRF (TM-10):** fixation regen; revoke-is-instant (cache+DB); expired/idle rejected; state-changing request without a valid CSRF token rejected; cross-origin request blocked.
- **SSRF/egress (TM-1):** target resolving to loopback/link-local/RFC-1918/metadata-IP is blocked; redirect to an out-of-scope host is blocked; worker cannot reach a decoy internal service.
- **LLM (TM-4/TM-5):** hosted egress blocked when disallowed; redactor-failure ⇒ egress blocked (fail-closed); injected instruction in evidence does not change the model's declared severity/status/action; every cited evidence pointer resolves to a real record (unresolved ⇒ rejected).
- **Upload (TM-7):** zip-bomb rejected by ratio/size cap; `../` and absolute-path and symlink entries rejected; extraction confined.
- **Parsers (TM-8):** malformed SARIF / truncated JSONL / oversized fields fail safe, don't crash the worker, don't execute.
- **Exceptional conditions (TM-14):** every security decision point tested for deny-on-error (no fail-open path).

---

## 9. Security Definition of Done (adds to `MVP_TASKS.md` cross-cutting DoD)

An increment touching a security-relevant surface is done only when, in addition to the existing DoD:

- [ ] The §5 CI security stages pass at the phase's current blocking threshold.
- [ ] New/changed routes have RBAC + cross-engagement access tests (TM-3).
- [ ] Any new outbound network call (target, LLM, or third party) passes through scope/egress + redaction controls, with a negative test (TM-1/TM-5).
- [ ] Any new parser/deserializer of external input has a hostile-input test (TM-8).
- [ ] Any new user input reaching a sink (SQL, shell, path, template, HTML, LLM prompt) is proven safe (TM-6/TM-4).
- [ ] Security decisions fail closed, with a deny-on-error test (TM-14).
- [ ] No new plaintext secret path; no new suppression without justification+owner (TM-5/TM-11).
- [ ] The threat-model table (§3) is updated if the change introduced a new surface.

---

## 10. Relationship to the Hardening gate

The pre-production **Hardening gate** (`IMPLEMENTATION_PLAN.md §9`, `ROADMAP.md`) does **not** go away and is **not** where platform security starts. With this plan in place, the Hardening gate becomes the **final verification and the resolution of deferred decisions** (production evidence backend + WORM proof, FIPS/password-hash decision, externalized secrets store, off-box log integrity, backup/restore drill, SBOM signing + SLSA enforcement, full external/independent security review) — confirming that security built in continuously actually holds end-to-end, rather than attempting to add it late. Every Hardening-gate item should already have a green per-phase antecedent here.

---

## 11. Ownership, cadence, and how to use this document

- **Every engineer** runs the §5 pipeline locally (pre-commit hooks) and owns the Security DoD (§9) for their increment.
- **Each milestone** opens with a 30-minute threat-model review (update §3 for the new surface) and closes with its Security Gate (§6).
- **This document is living:** when a standard revs, a new surface appears, or an incident teaches us something, update §1/§3/§6 with a dated note — same currency discipline as `CLAUDE.md §3`.
- **Order for a new engineer:** `CLAUDE.md` → `IMPLEMENTATION_PLAN.md` → **this document** → the milestone's tasks in `MVP_TASKS.md`.

> Bottom line: DAS Sentinel is held to the same standard it sells. We test the platform the way we'd test a client's — from M0, every phase, with the results blocking the build.
