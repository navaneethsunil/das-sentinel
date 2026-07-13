# PRD.md — DAS Sentinel

> **Product Requirements Document.** Defines *what* we are building and *why*, for whom, and how we will know it succeeded. The *how* (stack, data model, tasks) lives in `ARCHITECTURE.md`, `DATABASE_SCHEMA.md`, and `MVP_TASKS.md`; the *scope authority* is `ai-security-testing-platform-build-brief.md`. Where this PRD and the brief differ on scope, the brief wins.

| | |
|---|---|
| **Product** | DAS Sentinel — AI Security Testing & Automated Penetration-Testing Platform |
| **Owner** | Security Assessment Group |
| **Status** | Draft for MVP (M1–M3) |
| **Last updated** | 2026-07-03 |
| **Related docs** | Build brief · CLAUDE.md · ARCHITECTURE.md · ROADMAP.md · DATABASE_SCHEMA.md · MVP_TASKS.md · UI/UX prototype |

---

## 1. Overview

DAS Sentinel is a self-hosted platform for **authorized defensive security assessments** of web applications, APIs, source code, and AI/LLM applications. It takes a security team from an approved engagement scope through automated AI/web/code testing, evidence-backed findings, AI-assisted triage and remediation, compliance mapping, and report export — with safety controls enforced at every step.

The differentiator is **not scanning**. Many tools scan. DAS Sentinel's value is turning *authorized testing evidence* into *clear, prioritized, compliance-ready action* — with a federal-grade audit trail and an AI/LLM testing capability most traditional scanners lack.

---

## 2. Problem statement

Security teams assessing modern systems face three gaps:

1. **AI/LLM applications are undertested.** Traditional DAST/SAST tools don't test for prompt injection, data leakage, or excessive agent permissions — the OWASP LLM Top 10 risks. Teams either skip these or test them ad hoc with no evidence trail.
2. **Scanner output is noise, not action.** Raw scanner results are voluminous, duplicated, full of false positives, and not mapped to the compliance frameworks (OWASP, NIST) that federal and regulated work requires. Turning them into a defensible POA&M is slow, manual work.
3. **Authorization and evidence discipline are afterthoughts.** Tools make it easy to point a scanner anywhere. For authorized/federal work, teams need enforced scope, accepted Rules of Engagement, immutable evidence, and a complete audit trail — and most tools don't provide this structurally.

DAS Sentinel addresses all three in one platform, safety-first.

---

## 3. Goals & non-goals

### Goals
- **G1** — Make authorized AI/LLM security testing (prompt injection, data leakage, agent permissions) as routine as running a DAST scan.
- **G2** — Normalize findings from all sources into one evidence-backed model and cut triage effort through AI-assisted (never AI-authoritative) dedup, ranking, and remediation drafting.
- **G3** — Produce compliance-ready output (OWASP + NIST mapping, CVSS, POA&M) with minimal manual rework.
- **G4** — Enforce authorization, scope, and evidence discipline structurally, so unsafe or out-of-scope actions are impossible by construction, not by policy.
- **G5** — Run fully self-hosted, including air-gapped, with no mandatory outbound internet beyond in-scope targets.

### Non-goals
- **NG1** — Not an unrestricted offensive/red-team tool. No stealth, evasion, persistence, credential theft, destructive payloads, exfiltration, or default DoS.
- **NG2** — Not a multi-tenant SaaS at MVP (single-org; org boundary exists in the schema for later).
- **NG3** — Not a replacement for human judgment. AI output is draft analysis requiring validation; findings are labeled by provenance.
- **NG4** — Not a general vulnerability *management* suite (ticketing, SLA dashboards) — it produces findings and reports; deep VM workflow is out of scope.

---

## 4. Target users & personas

| Persona | Role | Primary needs | Key screens |
|---|---|---|---|
| **Alex — Security Tester** | Runs assessments | Define scope, launch scoped scans/AI tests, capture evidence, triage findings | Scan Launcher, Findings, Finding Detail |
| **Priya — Reviewer** | Validates & approves | Validate AI-generated findings, approve high-risk actions (in the scan flow), adjust CVSS, sign off reports | Findings, Finding Detail, Reports |
| **Dana — Compliance Reviewer** | Owns the paper trail | OWASP/NIST mappings, POA&M, exec/technical reports, audit completeness | Reports, Audit Log, Overview |
| **Sam — Admin** | Runs the platform | User/role management (under Settings), LLM provider config, safety controls, engagement setup | Settings, Engagement |
| **Riley — Read-only Stakeholder** | Consumes results | Risk posture at a glance; no ability to change anything | Overview, Findings (read), Reports (read) |

The four RBAC roles (Admin, Security Tester, Reviewer, Read-only) map to these personas and are enforced per `ARCHITECTURE.md §9`.

---

## 5. User stories (MVP)

Format: *As a [persona], I want [capability] so that [outcome].* Each maps to a milestone.

**Engagement & authorization (M1)**
- As a Tester, I want to create an engagement with scope, rate limits, and contacts so that all testing is bound to an authorized boundary.
- As a Tester, I want to accept the ROE with an immutable signed record so that authorization is provable in an audit.
- As the platform, I want to block any scan when no engagement/scope/ROE exists or the target is out of scope so that unsafe testing is impossible.
- As an Admin, I want role-based access so that only the right people can launch scans, approve high-risk actions, or validate findings.
- As any user, I want every action recorded in an append-only audit log so that we can answer who did what, to which target, when.

**AI/LLM testing (M2)**
- As a Tester, I want to run prompt-injection and data-leakage suites against an approved LLM endpoint so that I can find OWASP LLM risks with captured evidence.
- As a Tester, I want AI test findings labeled "AI-generated / unvalidated" so that they are never mistaken for confirmed results.
- As an Admin, I want to disable hosted LLMs per engagement (local models only) so that sensitive engagements never send data off-box.

**Scanning & findings (M3)**
- As a Tester, I want to run Semgrep on code and ZAP on a web app so that SAST and DAST findings appear in one normalized dashboard.
- As a Tester, I want to stop a running scan immediately so that I can halt anything unexpected.
- As a Reviewer, I want to assign/override CVSS with justification so that severity is defensible.
- As a Compliance Reviewer, I want findings mapped to OWASP and NIST and exportable as POA&M CSV and a Markdown technical report so that I can produce compliance-ready output.

---

## 6. Functional requirements

Requirements are labeled **FR-n** with priority **[MVP]** (M1–M3) or **[Post-MVP]** (M4–M6). Detailed behavior traces to the build brief modules.

### 6.1 Engagement, scope & authorization  🔒
- **FR-1 [MVP]** Create/edit engagements with: name, client/system, authorized targets, out-of-scope targets, test window, rate limit, auth method, ROE acknowledgement, coordination contact, emergency-stop contact.
- **FR-2 [MVP]** Maintain an allowlist and out-of-scope blocklist of scope items (URL, domain, IP/CIDR, API base, repo). Blocklist overrides allowlist.
- **FR-3 [MVP]** Require ROE acceptance before any active scan; store an immutable, hashed acknowledgement with a frozen scope snapshot. Re-acceptance required if scope changes.
- **FR-4 [MVP]** Block scans when there is no engagement, no scope, unaccepted ROE, an out-of-scope target, or an intensity above the engagement maximum. Every block is audit-logged.
- **FR-5 [MVP]** Enforce four scan-intensity levels (passive, safe-active, authenticated-active, high-risk). Default is non-destructive.
- **FR-6 [MVP]** Gate high-risk actions behind an explicit approval by an Admin/Reviewer; log the decision.

### 6.2 Targets
- **FR-7 [MVP]** Maintain a target inventory per engagement (type, environment, auth status, last-scan, computed findings-by-severity). Supported types: web app, REST, GraphQL, source repo, source archive, AI chatbot, LLM API wrapper, AI agent.

### 6.3 AI/LLM security testing  🔒
- **FR-8 [MVP]** Prompt-injection suite: direct, multi-turn/Crescendo, indirect (via retrieved content), instruction-hierarchy, jailbreak, sandboxed tool-call manipulation. Output includes prompt, response, expected vs. actual, pass/fail, evidence, OWASP LLM mapping, suggested severity.
- **FR-9 [MVP]** Data-leakage suite: system-prompt leakage, hidden-instruction disclosure, secret/token exposure, RAG boundary, vector/embedding, improper output handling, cross-tenant isolation.
- **FR-10 [Post-MVP]** Agent-permission testing in a sandbox with fake tools: excessive agency, unauthorized tool use, parameter manipulation, confused-deputy, unsafe delegation. Mapped to LLM06 + OWASP Agentic ASI02.

### 6.4 Scanner orchestration  🔒
- **FR-11 [MVP]** Orchestrate Semgrep (SAST) and ZAP (DAST); each run is scope-validated, rate-limited, timed out, version/config-captured, isolated in a killable process, and cancellable.
- **FR-12 [MVP]** Store raw scanner output as immutable evidence separately from normalized findings.
- **FR-13 [Post-MVP]** Add Nuclei, dependency scanners (OSV/pip-audit/npm audit), and secret scanners (Gitleaks/TruffleHog); add automated non-intrusive reconnaissance.

### 6.5 Findings, triage & remediation
- **FR-14 [MVP]** Normalize all findings into a shared model (SARIF 2.1.0 superset) with evidence references, severity, provenance label (automated / AI-generated / validated / manually-overridden), and dedup identity.
- **FR-15 [MVP]** CVSS scoring (v4.0 default + v3.1) with manual override + justification and insert-only history.
- **FR-16 [MVP]** Map findings to OWASP LLM Top 10, OWASP WSTG, NIST AI RMF/600-1, and NIST SP 800-53/800-115. (SP 800-115 is current but dates to 2008 — pair it with the newer OWASP WSTG for web methodology.)
- **FR-17 [Post-MVP]** AI-assisted triage (dedup, grouping, false-positive flagging, ranking-as-suggestion, explain-why) — evidence-grounded, human-confirmed, never authoritative on severity.
- **FR-18 [Post-MVP]** AI-assisted remediation drafting and patch suggestions labeled "requires developer review"; patch-validation/retest with before/after evidence and status tracking.

### 6.6 Reporting
- **FR-19 [MVP]** Export POA&M as CSV and a technical report as Markdown; reports editable before export.
- **FR-20 [Post-MVP]** Executive summary + full technical report; PDF, DOCX, JSON export.

### 6.7 LLM layer  🔒
- **FR-21 [MVP]** Model-provider abstraction (default Anthropic Claude; local via Ollama). Per-engagement hosted-models toggle; redaction-before-egress that fails closed; token/cost tracking; every interaction logged with redaction + hosted flags.

### 6.8 Safety, audit & access  🔒
- **FR-22 [MVP]** Emergency stop halts running scans (terminates the worker process group).
- **FR-23 [MVP]** Append-only audit log of every state change and blocked attempt.
- **FR-24 [MVP]** RBAC (Admin, Tester, Reviewer, Read-only) enforced at the service layer.
- **FR-25 [MVP]** UI clearly distinguishes automated vs. AI-generated vs. human-validated findings.

---

## 7. Non-functional requirements

- **NFR-1 Safety-by-construction** — scope/ROE/intensity checks live in the service layer and are re-checked in the worker; they cannot be bypassed by a crafted request. Negative tests are mandatory.
- **NFR-2 Evidence integrity** — raw evidence is immutable, content-hashed, and stored under WORM/object-lock (compliance mode); findings reference it. Chain-of-custody is preserved.
- **NFR-3 Self-hosted / air-gap** — the full stack runs via Docker Compose on a single node with no mandatory outbound internet except to in-scope targets; hosted LLMs are opt-in.
- **NFR-4 Auditability** — 100% of state-changing actions and blocked attempts produce audit events; audit and evidence are never mutated or deleted.
- **NFR-5 Security of the platform itself** — opaque server-side sessions, Argon2id password hashing (or **PBKDF2-HMAC-SHA-256** where the ATO requires a FIPS 140-3-validated module / approved algorithm — Argon2 is not NIST-approved; PBKDF2 is approved as a KDF under SP 800-132), least-privilege config, no plaintext secrets, dependency/supply-chain pinning.
- **NFR-6 Usability** — usable by testers, engineers, and compliance reviewers alike; summary-before-detail; state encoded in form (severity, provenance, status); responsive.
- **NFR-7 Modularity** — scanners and LLM providers are pluggable adapters; adding one is additive.
- **NFR-8 Performance (MVP target)** — dashboard interactions < 300 ms on a single-org dataset; scans run async with live status and are cancellable within a few seconds.
- **NFR-9 Compliance currency** — framework references pinned to current versions (OWASP LLM 2025, WSTG 4.2, NIST 800-53 Rev 5.2.0, AI 600-1, CVSS 4.0) and updatable via the mapping KB/DB.

---

## 8. Success metrics

**Adoption / value**
- A tester can go from new engagement → first evidence-backed finding in **under 30 minutes**.
- **≥ 70%** of exported findings require no manual edit to their compliance mapping.
- Median triage time per finding drops measurably vs. raw-scanner-output baseline (tracked post-MVP once triage ships).

**Safety / trust (must hold at all times)**
- **100%** of out-of-scope or no-ROE scan attempts are blocked and audited (verified by automated negative tests).
- **0** AI-generated findings reach "confirmed/fixed" without a recorded human validation.
- **100%** of hosted-LLM egress events occur only when `hosted_models_allowed=true` and after redaction.

**Quality**
- Every finding has at least one evidence reference.
- Every scan record answers who/what/target/when.

**MVP acceptance** — all criteria in `ROADMAP.md` M3 exit gate (= the brief's acceptance criteria) pass.

---

## 9. Release scope

- **MVP (M1–M3):** engagement/scope/ROE, target inventory, RBAC, audit; prompt-injection + data-leakage AI suites; Semgrep + ZAP; normalized findings; CVSS; OWASP/NIST mapping; POA&M CSV + Markdown report. See `MVP_TASKS.md`.
- **Post-MVP (M4–M6):** recon + AI triage + remediation + retest; agent-permission testing; compliance-DB, exec reports, PDF/DOCX/JSON.
- **Explicitly out of scope:** offensive tooling (NG1), multi-tenant SaaS (NG2), deep VM workflow (NG4), HA/k8s, SSO (post-MVP hardening).

---

## 10. Assumptions & dependencies

- Users operate only against systems they are authorized to test; the platform enforces scope but authorization itself is a legal precondition the user attests to.
- A hosted-LLM API key is available *if* hosted models are used; otherwise local models (Ollama/vLLM) cover the LLM layer.
- External tools (Semgrep CE, ZAP by Checkmarx, PyRIT, etc.) remain available under their current licenses; license caveats are tracked in `CLAUDE.md`.
- The production evidence-store backend and the Argon2id-vs-FIPS decision are resolved before real-world deployment (Decision Gates, `ROADMAP.md`).

---

## 11. Risks & mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Misuse as an offensive tool | High (legal/ethical) | Safety invariants (CLAUDE.md §2); no offensive capabilities built; scope + ROE + approval gates enforced structurally |
| LLM hallucinates evidence/severity | High (false findings) | LLM is draft-only, evidence-grounded; severity computed deterministically; provenance labels; human validation required |
| Evidence-store backend (MinIO) archived | Medium | S3 abstraction; production backend deferred to a Decision Gate; WORM enforcement verified empirically |
| Scope-enforcement bypass | Critical | Single keystone service, checked twice (request + worker); mandatory negative tests |
| Supply-chain compromise of a dependency (e.g., LiteLLM incident) | Medium | Version + hash pinning, internal mirror, network segmentation; thin adapter preferred |
| Compliance references drift out of date | Medium | Versioned mapping KB → DB; NFR-9 currency requirement |

---

## 12. Open questions

1. Target ATO/compliance regime (FedRAMP/FISMA via NIST 800-53 SC-13; CMMC via 800-171 3.13.11) — all can require a FIPS 140-3-validated cryptographic module, which forces **PBKDF2-HMAC-SHA-256** over the non-approved Argon2id. Decide **before** first users exist (avoids a password-rehash migration). CMMC's acquisition rule (48 CFR) took effect 2025-11-10, so this is live for DoD-adjacent work.
2. Production evidence-store backend (Ceph RGW vs. verified alternative).
3. Whether the MVP LLM layer must ship with a local model by default (air-gap posture) or hosted-by-default with local optional.
4. SSO/IdP requirements and timing (post-MVP).

These are tracked as Decision Gates in `ROADMAP.md`.
