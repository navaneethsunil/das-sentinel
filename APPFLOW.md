# APPFLOW.md — DAS Sentinel

> End-to-end application flows: how users move through the product and how the system responds, screen by screen and state by state. Ties `PRD.md` (what), `TRD.md` (how), `DATABASE_SCHEMA.md` (entities), and the UI prototype together. Diagrams are ASCII for portability. Safety-critical decision points are marked 🔒.

---

## 1. The core journey (happy path)

The product's spine — an authorized assessment from setup to closure:

```
  ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
  │ 1. Create│──▶│ 2. Define │──▶│ 3. Accept│──▶│ 4. Add   │──▶│ 5. Launch│──▶│ 6. Triage│──▶│ 7. Report│
  │ engagement│  │  scope    │   │   ROE 🔒 │   │ targets  │   │ scan 🔒  │   │ findings │   │ & export │
  └──────────┘   └───────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘
       │              │               │              │              │              │              │
   engagement    scope_items    roe_ack (hash    targets      scans +        findings +     reports +
   (draft)       (allow/deny)   + snapshot)                   scanner/test   cvss + status  POA&M CSV /
                                                               runs+evidence  transitions    Markdown
```

Steps 1–4 gate step 5: **no scan can run until an engagement exists, scope is defined, ROE is accepted, and the target is in scope.** Steps 6–7 loop as findings are validated, remediated, and retested (retest is post-MVP).

---

## 2. Screen navigation map

From the prototype (`ui-ux-prototype.html`). Persistent left nav; the current engagement is the working context throughout.

```
                         ┌───────────────── Top bar: engagement context · Emergency Stop 🔒 · user/role ─────────────────┐
                         │                                                                                              │
   ┌─────────┐           ▼
   │ Sidebar │   ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
   │  nav    │──▶│  Overview  │   │ Engagement │   │  Targets   │   │   Scan     │
   │         │   │ (dashboard)│   │ scope+ROE  │   │ inventory  │   │  Launcher  │
   │         │   └─────┬──────┘   └────────────┘   └─────┬──────┘   └─────┬──────┘
   │         │         │ "View all"                      │ row→          │ launch
   │         │         ▼                                 ▼ prefill       ▼
   │         │   ┌────────────┐   drill in   ┌───────────────────┐   (queues scan → status)
   │         │──▶│  Findings  │────────────▶ │  Finding Detail   │
   │         │   │ dashboard  │◀──── back ── │ evidence·CVSS·map │
   │         │   └─────┬──────┘              │ ·status lifecycle │
   │         │         │ "Add to report"     └───────────────────┘
   │         │         ▼
   │         │   ┌────────────┐   ┌────────────┐   ┌────────────┐
   │         │──▶│  Reports   │   │ Audit Log  │   │ LLM&Safety │
   │         │   │  builder   │   │ (read-only)│   │ (settings) │
   │         │   └────────────┘   └────────────┘   └────────────┘
```

Role visibility (per `ARCHITECTURE.md §9`): Read-only sees Overview/Findings/Reports (read); Tester adds Scan Launcher + engagement/scope + validate; Reviewer adds approvals + validation + CVSS; Admin adds Settings + user management.

---

## 3. Authentication & session flow

```
  Login form ──POST /api/auth/login──▶ verify Argon2id/PBKDF2 hash
       │                                     │ ok
       │                                     ▼
       │                          revoke any prior session (fixation defense)
       │                          create session row (store SHA-256 of token)
       │                          set __Host- cookie (HttpOnly·Secure·SameSite=Strict)
       │                          issue CSRF synchronizer token
       ▼                                     │
  every request ──cookie──▶ validate: Valkey cache → Postgres
                             ├─ revoked_at set?      → 401
                             ├─ past idle/absolute?  → 401
                             └─ ok → slide idle; resolve role (RBAC)
       │
  logout / logout-all ──▶ set revoked_at + purge Valkey  ⇒ instant revocation
```

🔒 Revocation is immediate because every request validates against the store (opaque session, not a stateless JWT). Cache is write-through invalidated on revoke.

---

## 4. Engagement → scope → ROE setup flow

```
  Create engagement (status=draft)
        │  fields: name, client/system, window, rate_limit, max_intensity,
        │          hosted_models_allowed, contacts, emergency-stop contact
        ▼
  Add scope_items  ──▶  allow: url|domain|ip_cidr|api_base|repo
        │               deny:  (out-of-scope; always wins)
        ▼
  Review ROE  ──accept──▶ write roe_acknowledgements (immutable)
        │                  content_hash = SHA256(roe_text ‖ scope_snapshot)
        │                  freeze scope_snapshot
        ▼
  Engagement → active   ⇒  scans now permitted (subject to §5 gate)

  ⤷ If scope_items edited AFTER acceptance → engagement flagged "ROE re-acceptance required";
     scan attempts blocked until re-accepted. 🔒
```

---

## 5. Scope-enforcement decision flow 🔒 (the keystone)

Runs at **two** points: in `api` before enqueue, and again in `worker` before the tool launches (re-reads DB + the immutable `execution_authorization` envelope, re-derives everything, trusts nothing). Same function, `authorize_operation(engagement, target, op, roe_ack, now)` — where `op` carries the typed/normalized config and the **server-derived** effective intensity (not the caller's declared value).

```
                          ┌─────────────────────────────┐
   scan request  ───────▶ │ engagement.status == active?│──no──▶ 409 EngagementInactive ─┐
                          └──────────────┬──────────────┘                                 │
                                    yes  ▼                                                 │
                          ┌─────────────────────────────┐                                 │
                          │ ROE accepted & not stale?    │──no──▶ 403 ROENotAccepted ──────┤
                          └──────────────┬──────────────┘                                 │
                                    yes  ▼                                                 │
                          ┌─────────────────────────────┐                                 │
                          │ live terms == accepted ROE?  │──no──▶ 409 ROETermsMismatch ────┤
                          │ (window/rate/max-intensity)  │        (re-acceptance required)  │
                          └──────────────┬──────────────┘                                 │
                                    yes  ▼                                                 │
                          ┌─────────────────────────────┐                                 │
                          │ now ∈ test window?           │──no──▶ 403 OutsideTestWindow ───┤
                          └──────────────┬──────────────┘                                 │
                                    yes  ▼                                                 │
                          ┌─────────────────────────────┐                                 │
                          │ target matches an ALLOW item?│──no──▶ 403 ScopeViolation ──────┤
                          └──────────────┬──────────────┘                                 │
                                    yes  ▼                                                 ▼
                          ┌─────────────────────────────┐                          ┌─────────────┐
                          │ target matches ANY DENY item?│──yes─▶ 403 ScopeViolation │ audit event │
                          └──────────────┬──────────────┘        (deny wins)        │ outcome=    │
                                     no  ▼                                           │  blocked 🔒 │
                          ┌─────────────────────────────┐                          └─────────────┘
                          │ effective (server-derived)   │──no──▶ 422 IntensityNotAuthorized ▲
                          │ intensity ≤ max_intensity?   │                                  │
                          └──────────────┬──────────────┘                                 │
                                    yes  ▼                                                 │
                          ┌─────────────────────────────┐                                 │
                          │ effective intensity ==       │──yes─▶ valid approval whose ─no─┘
                          │ high_risk?                   │        operation_digest == op?
                          └──────────────┬──────────────┘        (HighRiskNotApproved;
                                     no  │       yes + matching   worker atomically consumes)
                                         ▼        approval
                                  ✓ CLEARED → write execution_authorization envelope → enqueue / execute
```

Matching rules (TR-11.2): `url`=scheme+host+path-prefix; `domain`=host/subdomain; `ip_cidr`=address∈CIDR (resolve host→IP and check too); `api_base`=URL prefix; `repo`=normalized identity. **Unresolvable/ambiguous → fail closed (out of scope).**

---

## 6. Scan lifecycle state machine

```
        POST /api/scans (passes §5 gate)
                 │
                 ▼
            ┌─────────┐   worker picks up, re-runs §5 gate,      ┌──────────┐
            │ queued  │──────── validate_prerequisites ─────────▶│ running  │
            └─────────┘                                          └────┬─────┘
                 │                                                    │
      gate fails at enqueue                          ┌────────────────┼───────────────┐
      (never created)                                ▼                ▼               ▼
                                                 tool exits 0    tool errors    cancel_requested 🔒
                                                      │               │          (Emergency Stop)
                                                      ▼               ▼               ▼
                                                ┌───────────┐   ┌─────────┐    ┌───────────┐
                                                │ completed │   │ failed  │    │ cancelled │
                                                └─────┬─────┘   └─────────┘    └───────────┘
                                                      │ raw→evidence, normalize→findings
                                                      ▼
                                              findings created (provenance=automated|ai_generated)
```

Cancellation path (🔒): `POST /api/scans/{id}:cancel` sets `cancel_requested`; the worker signals the recorded process group/container `SIGTERM → SIGKILL` **and confirms the process tree is gone** (in-process PyRIT halts via its cooperative `CancelToken`), verifies sandbox teardown, marks `cancelled`, and audits. A scan is cancellable while `queued` or `running`.

---

## 7. Scan execution sequence (system view)

```
 api                     worker                  ExecutionOwner (rootless sandbox)  object store        db
  │  enqueue(scan_id)      │                              │                        │               │
  │───────────────────────▶ re-load scan + execution_authorization envelope + engagement/target ────▶│
  │                        │  re-derive + authorize_operation() 🔒 (re-check; recompute digest)       │
  │                        │  if high-risk: atomically consume approval (0 rows ⇒ refuse) ───────────▶│
  │                        │  scanner_runs(status=running, version, image_digest, rules_digest) ─────▶│
  │                        │  launch in sandbox (dropped caps, scoped creds); record proc/container ──▶│
  │                        │─── run (timeout; egress via shaper = aggregate rate ceiling) ─▶│         │
  │                        │◀────── raw output ──────────────────────────│                            │
  │                        │  stream raw ─────────────────────────────────────────▶ blob (hashed)     │
  │                        │  evidence(object_key, sha256, retain_until) ───────────────────────────▶ │
  │                        │  normalize() → findings + finding_evidence ─────────────────────────────▶│
  │                        │  ExecutionOwner verifies teardown (sandbox gone, creds revoked)          │
  │                        │  scan/scanner_run → completed; audit ───────────────────────────────────▶│
  │  GET /scans/{id} (poll)│                                                                          │
```

LLM/agent test suites (M2/M5) follow the same shape via `test_runs`; the transcript is the evidence.

---

## 8. LLM call flow (with safety gates) 🔒

```
  service needs a model call (triage/remediation/test-gen)
        │
        ▼
  app/llm abstraction
        │
        ├─ hosted model requested?
        │       │yes
        │       ▼
        │   engagement.hosted_models_allowed == true? ──no──▶ BLOCK (local-only) 🔒
        │       │yes
        │       ▼
        │   redaction pass (PII + secrets) ──error/timeout──▶ FAIL CLOSED: block egress 🔒
        │       │ok (redacted)
        ▼       ▼
  provider adapter (Claude hosted | Ollama/vLLM local)
        │  current params only (adaptive thinking, strict tool use)
        ▼
  response → stored as ai_generated, must cite supplied evidence
        │
        ▼
  log llm_interactions (provider, model, was_redacted, hosted, tokens, cost)
```

The LLM never sets final CVSS and never moves a finding to confirmed/fixed.

---

## 9. Finding lifecycle & the provenance rule 🔒

```
   created ── provenance ∈ {automated, ai_generated}
        │
        ▼
   ┌────────┐   triage    ┌──────────┐   human validates   ┌───────────┐
   │  open  │────────────▶│ in_triage│────────────────────▶│ confirmed │
   └────────┘             └──────────┘                      └─────┬─────┘
        │                       │                                 │ remediation + retest (post-MVP)
        │                       │ deemed not real                 ▼
        │                       ▼                           ┌───────────┐
        │                 false_positive                    │  fixed    │
        │                                                   └───────────┘
        ├─▶ accepted_risk (with note)      ├─▶ out_of_scope
        │
   is_false_positive flag + duplicate_of (dedup) tracked separately

   🔒 RULE: a finding with provenance=ai_generated CANNOT move to confirmed/fixed
      without an authenticated human transition recorded in finding_status_history.
```

Every transition writes a `finding_status_history` row (who, from→to, reason). Dedup on (re)import: matching `hash_code` for the target → link `duplicate_of` instead of a new open finding.

---

## 10. Triage → remediation → retest flow (post-MVP, M4)

```
   scanner/test findings ──▶ LLM-assisted triage (evidence-grounded, advisory)
        │  dedup · group · flag likely FPs · propose rank · explain-why
        ▼  (severity computed deterministically via CVSS; LLM explains, not decides)
   human confirms ──▶ remediation guidance (draft, "requires developer review")
        │
        ▼
   fix applied ──▶ retest (rerun relevant tests) ──▶ before/after evidence diff
        │
        ▼
   status → mitigated / fixed  (auto on absent-in-rescan) | reopened (if reappears)
```

---

## 11. Report generation flow

```
   Reports builder
        │ choose type: POA&M | Technical | (Executive — post-MVP)
        ▼
   select findings (report_findings)  ── validated findings recommended;
        │                                AI-unvalidated shown but flagged
        ▼
   edit report.body (JSON, editable while status=draft)
        │
        ▼
   export ──▶ POA&M CSV (weakness id, asset, severity, CVSS, control map, owner, dates, status, milestones)
        └──▶ Markdown technical report (findings, evidence, repro, remediation, retest status)
   (PDF / DOCX / JSON — post-MVP)
```

---

## 12. Emergency stop flow 🔒 (always available)

```
   Top-bar "Emergency Stop" (any screen)
        │
        ▼
   POST /api/scans/{id}:cancel for each running scan in the engagement
        │  set cancel_requested; UI shows termination banner
        ▼
   worker: kill process group (SIGTERM→SIGKILL), mark scans cancelled, audit
        │
        ▼
   "Resume control" clears the banner once scans are halted
```

---

## 13. Audit event points (append-only)

Every state-changing action and every blocked attempt emits an `audit_event` (`actor, action, object, engagement, outcome, detail, ts`). Key points:

| Flow | Events |
|---|---|
| Auth | `auth.login`, `auth.logout`, `session.revoked` |
| Engagement/scope/ROE | `engagement.created/updated`, `scope.updated`, `roe.accepted` |
| Scope enforcement 🔒 | `scope.blocked` (per denied reason), `approval.requested/decided` |
| Scans | `scan.queued`, `scan.started`, `scan.completed/failed/cancelled` |
| Findings | `finding.validated`, `finding.status_changed`, `cvss.overridden`, `finding.false_positive` |
| LLM | `llm.call` (with hosted/redacted flags) |
| Reports | `report.generated`, `report.exported` |

Audit and evidence are never mutated or deleted (insert-only; production role denies UPDATE/DELETE).

---

## 14. Error & edge-case flows

| Situation | System behavior |
|---|---|
| Scan attempt, no engagement/scope/ROE | Blocked (409 inactive / 403 ROE-not-accepted), audited, no job enqueued |
| Out-of-scope / deny-matched target | Blocked (403 ScopeViolation), audited |
| Intensity above engagement max | Blocked (422 IntensityNotAuthorized) |
| High-risk without approval | Blocked (403 HighRiskNotApproved); user routed to request approval |
| Hosted LLM when `hosted_models_allowed=false` | Blocked in abstraction; local-only |
| Redactor error before hosted egress | Fail closed — egress blocked |
| Scope edited after ROE | Engagement requires ROE re-acceptance; scans blocked until re-accepted |
| Session revoked/expired mid-use | 401; client redirects to login |
| Scanner tool crashes | `scan.failed`; stderr captured to run record (not swallowed) |
| Evidence blob written, metadata commit fails | Orphan-sweep reconciles; no dangling finding reference |
| AI finding, attempt to mark confirmed without human | Rejected; provenance rule enforced |
