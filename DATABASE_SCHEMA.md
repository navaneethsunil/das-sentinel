# DATABASE_SCHEMA.md — DAS Sentinel

> The persistent data model. Target engine: **PostgreSQL 17**, accessed via SQLAlchemy 2.x + Alembic. This document is the source of truth for entities and relationships; the ORM models in `apps/api/app/models/` must match it, and every change goes through an Alembic migration. Large raw evidence lives in the **object store**, not in Postgres — this schema holds the *structured, queryable* data and *references* to evidence blobs (see `ARCHITECTURE.md §7`).

---

## 1. Conventions

- **Primary keys:** `uuid` PKs. App supplies **UUIDv7** (time-ordered → ~25% smaller B-tree indexes and far less insert fragmentation than random v4) where possible; DB default is `gen_random_uuid()` (v4, core built-in since PG13 — no extension needed) as a fallback. Postgres 17 has no native `uuidv7()`; that arrives in 18, at which point the DB default can switch to `uuidv7()`. Trade-off (accepted): UUIDv7 leaks approximate row-creation time — fine for internal PKs; use v4 for any externally-exposed unguessable token.
- **Required extensions:** `citext` (case-insensitive email) and `pgcrypto` is *not* needed (`gen_random_uuid()` is core on PG13+). Enable `citext` in the initial migration.
- **DDL ordering:** the blocks below are illustrative and grouped by topic, so a few forward references appear (e.g. `scanner_runs.raw_evidence_id` → `evidence`). Alembic resolves creation order by dependency (create `evidence` before `scanner_runs`/`test_runs`, or add the FK via `ALTER TABLE`); there are no true cycles.
- **Timestamps:** `timestamptz` in UTC. Mutable rows carry `created_at` and `updated_at` (both `default now()`); append-only tables carry only `created_at`.
- **Soft delete:** `deleted_at timestamptz NULL` on user-facing domain rows (engagements, targets, findings, reports). Evidence, audit events, ROE acknowledgements, and CVSS history are **never** soft-deleted or updated — they are immutable records.
- **Multi-tenancy:** every top-level row carries `organization_id`. Enforcement is single-org for now (see `ROADMAP.md`), but the column and FKs exist so row-level scoping can be turned on later without a migration of shape.
- **Hashes:** SHA-256 stored as `bytea` (32 bytes), never hex text.
- **Enumerations:** stable, security-critical sets use native `CREATE TYPE ... AS ENUM` (listed in §14). Sets we expect to extend often (compliance frameworks/controls) use lookup **tables**, not enums.
- **JSONB:** used only for moderate-size structured data (tool config, parsed attributes, SARIF fingerprints), GIN-indexed where queried. Never for large raw blobs.
- **Money/tokens:** LLM cost stored as `numeric(12,6)` (USD); token counts as `integer`.
- **FK actions:** `ON DELETE RESTRICT` by default (protect evidence chains); explicit `CASCADE` only where a child cannot outlive its parent (e.g., scope items under an engagement) and no evidence is involved.

---

## 2. Entity-relationship overview

```
organizations ─┬─< users ─────< sessions
               │      └────────< audit_events (actor)
               │
               ├─< engagements ─┬─< scope_items
               │                ├─< roe_acknowledgements
               │                ├─< approval_gates
               │                ├─< targets ─┬─< scans ─┬─< scanner_runs ──< evidence
               │                │            │          └─< test_runs ─────< evidence   (LLM/agent suites)
               │                │            └─< agent_policies              (M5)
               │                └─< reports ──< report_findings >── findings
               │
               └─< findings ─┬─< cvss_scores           (history; current flagged)
                             ├─< finding_status_history
                             ├─< remediations ──< retests
                             ├─< finding_evidence >── evidence
                             └─< finding_compliance_mappings >── compliance_controls >── compliance_frameworks

llm_interactions ── (polymorphic ref to scan/test_run/finding/report)
```

`>──` denotes a join/association table (many-to-many); `─<` denotes one-to-many.

---

## 3. Identity & access

```sql
CREATE TABLE organizations (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    email            citext NOT NULL,                    -- case-insensitive (requires CREATE EXTENSION citext)
    -- Alt for later: normalized-lowercase text + UNIQUE, or an ICU nondeterministic collation.
    -- Note: citext folds case only (not accents); ICU collations don't support LIKE on PG17.
    password_hash    text NOT NULL,                      -- Argon2id (or PBKDF2 if FIPS; see CLAUDE.md)
    display_name     text NOT NULL,
    role             user_role NOT NULL DEFAULT 'read_only',   -- admin|tester|reviewer|read_only
    is_active        boolean NOT NULL DEFAULT true,
    last_login_at    timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at       timestamptz,
    UNIQUE (organization_id, email)
);

-- Opaque server-side sessions (NOT JWT). We store only a HASH of the session token.
CREATE TABLE sessions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    bytea NOT NULL UNIQUE,                 -- SHA-256 of the high-entropy cookie value
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    idle_expires_at     timestamptz NOT NULL,            -- sliding
    absolute_expires_at timestamptz NOT NULL,            -- hard cap
    revoked_at    timestamptz,                           -- set on logout / kill-all / privilege change
    ip_address    inet,
    user_agent    text
);
CREATE INDEX ix_sessions_user_active ON sessions (user_id) WHERE revoked_at IS NULL;
```

Notes: the raw session token never touches the DB — only its SHA-256. A plain fast SHA-256 (no salt/KDF) is correct here — the token is a high-entropy random value, not brute-forceable, so bcrypt/Argon2 would be over-engineering (this at-rest hashing follows OWASP ASVS V3 / the treat-the-session-ID-as-a-credential principle). Revocation is instant **only because every request validates against the store** (opaque session, not stateless JWT): the check reads the row and rejects if `revoked_at IS NOT NULL` or past expiry. The Valkey cache entry must be write-through invalidated on revoke (see `ARCHITECTURE.md §13`). Session ID is regenerated on login (new row, old row revoked) to defeat fixation.

---

## 4. Engagement, scope & authorization 🔒

```sql
CREATE TABLE engagements (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    name                  text NOT NULL,
    client_system_name    text NOT NULL,
    status                engagement_status NOT NULL DEFAULT 'draft',  -- draft|active|paused|closed
    test_window_start     timestamptz,
    test_window_end       timestamptz,
    rate_limit_rps        integer NOT NULL DEFAULT 5,     -- authoritative outbound ceiling (worker enforces)
    max_intensity         scan_intensity NOT NULL DEFAULT 'safe_active',
    hosted_models_allowed boolean NOT NULL DEFAULT false, -- gates hosted LLM egress
    coordination_contact  text,
    emergency_stop_contact text,
    created_by            uuid NOT NULL REFERENCES users(id),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);

-- Allowlist AND blocklist live here; blocklist always wins in the scope service.
CREATE TABLE scope_items (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id  uuid NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    kind           scope_kind NOT NULL,                   -- allow | deny
    matcher_type   scope_matcher NOT NULL,                -- url | domain | ip_cidr | api_base | repo
    value          text NOT NULL,                         -- e.g. 'https://app.example.com', '10.0.0.0/24'
    notes          text,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_scope_items_engagement ON scope_items (engagement_id, kind);

-- Immutable signed ROE artifact: snapshot + hash at time of acceptance.
CREATE TABLE roe_acknowledgements (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id      uuid NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    accepted_by        uuid NOT NULL REFERENCES users(id),
    accepted_at        timestamptz NOT NULL DEFAULT now(),
    roe_text           text NOT NULL,                     -- full ROE shown at acceptance
    scope_snapshot     jsonb NOT NULL,                    -- frozen copy of scope_items at acceptance
    terms_snapshot     jsonb NOT NULL,                    -- frozen authorization-relevant terms at acceptance:
                                                           -- {test_window_start, test_window_end, rate_limit_rps, max_intensity}
    content_hash       bytea NOT NULL,                    -- SHA-256 over (roe_text || scope_snapshot || terms_snapshot)
    ip_address         inet
);
-- No updated_at / deleted_at: acceptances are permanent audit records.

-- High-risk action approval gate — a complete state machine bound to an EXACT operation.
-- States: pending → approved → consumed  (or → denied / → expired / → revoked).
CREATE TABLE approval_gates (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id    uuid NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    target_id        uuid NOT NULL,                        -- approval is for ONE target, not the whole engagement
    requested_by     uuid NOT NULL REFERENCES users(id),
    action_type      text NOT NULL,                        -- e.g. 'exploit_validation','brute_force','large_crawl'
    justification    text NOT NULL,

    -- Immutable subject: the exact operation this approval authorizes. Computed at request time over the
    -- normalized (engagement, target, action_type, effective intensity, typed+canonicalized scanner/suite
    -- config, server-derived capabilities). API and worker both recompute this digest from the pending scan
    -- and refuse to proceed unless it equals operation_digest — an approved row cannot be paired with
    -- independently chosen execution fields.
    operation_digest bytea NOT NULL,                       -- SHA-256 over the canonical operation subject
    roe_ack_id       uuid NOT NULL REFERENCES roe_acknowledgements(id),  -- ROE version this approval was made under
    policy_version   text NOT NULL,                        -- authorization/policy ruleset version at decision time

    status           approval_status NOT NULL DEFAULT 'pending',  -- pending|approved|denied|expired|revoked|consumed
    decided_by       uuid REFERENCES users(id),            -- must be admin or reviewer; NULL until decided
    decided_at       timestamptz,
    decision_reason  text,
    expires_at       timestamptz NOT NULL,                 -- MANDATORY expiry; past expiry ⇒ treated as expired
    revoked_at       timestamptz,
    revoked_by       uuid REFERENCES users(id),
    revocation_reason text,
    consumed_at      timestamptz,                          -- set atomically when a scan claims this approval
    consumed_by_scan_id uuid,                              -- the single scan that used it (single-use)
    created_at       timestamptz NOT NULL DEFAULT now(),

    UNIQUE (id, engagement_id),              -- composite key so scans can enforce same-engagement FK
    -- NOTE: the composite FK (target_id, engagement_id) → targets(id, engagement_id) is added by
    -- ALTER TABLE in the targets migration (below), because targets is created after approval_gates.
    -- State-machine integrity, enforced in the DDL (not just app code):
    CONSTRAINT approval_decided_fields CHECK (
        (status = 'pending'  AND decided_at IS NULL AND decided_by IS NULL) OR
        (status IN ('approved','denied') AND decided_at IS NOT NULL AND decided_by IS NOT NULL) OR
        (status = 'expired') OR
        (status = 'revoked'  AND revoked_at IS NOT NULL) OR
        (status = 'consumed' AND consumed_at IS NOT NULL AND consumed_by_scan_id IS NOT NULL)
    )
);
CREATE INDEX ix_approval_gates_engagement ON approval_gates (engagement_id, target_id);
-- Atomic single-use consumption: at most one scan may consume an approval. The transition
-- approved → consumed is a conditional UPDATE (… WHERE status='approved' AND now() < expires_at
-- AND revoked_at IS NULL) whose affected-row-count is checked; 0 rows ⇒ the approval was already
-- used/expired/revoked ⇒ the scan is refused. This is the atomic reuse guard.
```

The **scope-enforcement service** reads `engagements.status`, `roe_acknowledgements`, `scope_items`, `max_intensity`, and (for high-risk) an approved `approval_gates` row before any scan is enqueued and again in the worker. For high-risk scans it additionally: (a) recomputes `operation_digest` from the pending scan and requires equality; (b) requires `status='approved'`, `now() < expires_at`, `revoked_at IS NULL`, and a matching `target_id`; (c) verifies `roe_ack_id` equals the engagement's current ROE acknowledgement and `policy_version` matches the active policy; (d) **atomically consumes** the approval (approved → consumed) so it cannot be reused. The worker repeats (a)–(c) before launch. Every check — pass, block, or failed consumption — writes an `audit_event`.

---

## 5. Targets

```sql
CREATE TABLE targets (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id    uuid NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    name             text NOT NULL,
    target_type      target_type NOT NULL,   -- web_app|rest_api|graphql_api|source_repo|source_archive|
                                             -- ai_chatbot|llm_api_wrapper|ai_agent
    environment      environment_label NOT NULL DEFAULT 'dev',  -- dev|staging|production
    primary_value    text NOT NULL,          -- URL / base URL / repo URL / object key of uploaded archive
    auth_status      auth_status NOT NULL DEFAULT 'none',       -- none|configured|verified
    auth_config      jsonb,                  -- redacted/encrypted refs to test creds; never plaintext secrets
    last_scan_at     timestamptz,
    risk_summary     text,                   -- denormalized rollup for inventory view
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at       timestamptz,
    UNIQUE (id, engagement_id)               -- composite key so scans (and approval_gates) can enforce same-engagement FK
);
CREATE INDEX ix_targets_engagement ON targets (engagement_id);

-- Deferred FK: bind each approval to a target in the SAME engagement (approval_gates is created earlier).
ALTER TABLE approval_gates
    ADD FOREIGN KEY (target_id, engagement_id) REFERENCES targets (id, engagement_id) ON DELETE RESTRICT;
```

`auth_config` stores references/handles (e.g., a secrets-manager key id), not raw credentials. Findings-by-severity counts for the inventory are computed from `findings`, not stored here (avoids drift).

---

## 6. Scans, runs & evidence 🔒

A **scan** is a user-initiated unit of work against one target at one intensity. It fans out into one or more **scanner_runs** (external tools) and/or **test_runs** (LLM/agent suites). Both produce **evidence**.

```sql
CREATE TABLE scans (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id    uuid NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    target_id        uuid NOT NULL,
    intensity        scan_intensity NOT NULL,
    status           scan_status NOT NULL DEFAULT 'queued',  -- queued|running|completed|failed|cancelled
    approval_gate_id uuid,                                    -- required when intensity='high_risk'
    initiated_by     uuid NOT NULL REFERENCES users(id),
    queued_at        timestamptz NOT NULL DEFAULT now(),
    started_at       timestamptz,
    finished_at      timestamptz,
    cancel_requested boolean NOT NULL DEFAULT false,          -- emergency-stop flag
    error_summary    text,
    -- Composite FKs force the target AND approval to belong to THIS scan's engagement:
    -- a valid-but-cross-engagement target/approval cannot be spliced in (defense in depth
    -- behind the global org/engagement-qualified query rule). Requires the UNIQUE (id,
    -- engagement_id) keys added to targets and approval_gates below.
    FOREIGN KEY (target_id, engagement_id)
        REFERENCES targets (id, engagement_id) ON DELETE RESTRICT,
    FOREIGN KEY (approval_gate_id, engagement_id)
        REFERENCES approval_gates (id, engagement_id)   -- nullable pair: enforced only when approval_gate_id is set
);
CREATE INDEX ix_scans_engagement ON scans (engagement_id);
CREATE INDEX ix_scans_status ON scans (status) WHERE status IN ('queued','running');

-- Immutable execution-authorization envelope: the frozen record of WHAT was authorized for one scan.
-- Written once at enqueue (after the scope gate passes) and never mutated. The worker job carries only
-- scan_id; the worker re-reads this envelope AND re-derives every field from the live DB, and refuses to
-- launch unless they match. This replaces the ID-only job that could not reconstruct the approved operation.
CREATE TABLE execution_authorizations (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id             uuid NOT NULL UNIQUE REFERENCES scans(id) ON DELETE RESTRICT,
    engagement_id       uuid NOT NULL,
    target_id           uuid NOT NULL,
    requested_by        uuid NOT NULL REFERENCES users(id),
    effective_intensity scan_intensity NOT NULL,   -- SERVER-derived from typed config classification, not caller-declared
    normalized_config   jsonb NOT NULL,            -- typed, canonicalized, REDACTED operation config (no runtime secrets)
    server_capabilities jsonb NOT NULL,            -- capabilities the server derived/granted for this run (not caller input)
    roe_ack_id          uuid NOT NULL REFERENCES roe_acknowledgements(id),  -- ROE version in force at authorization
    policy_version      text NOT NULL,             -- authorization/policy ruleset version at authorization
    approval_gate_id    uuid,                       -- bound approval for high-risk (NULL for non-high-risk)
    operation_digest    bytea NOT NULL,            -- SHA-256 over the canonical subject; == approval_gates.operation_digest when high-risk
    test_window         tstzrange,                  -- authorized execution window derived from the ROE (NULL ⇒ any time while engagement active)
    created_at          timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (target_id, engagement_id)
        REFERENCES targets (id, engagement_id) ON DELETE RESTRICT,
    FOREIGN KEY (approval_gate_id, engagement_id)
        REFERENCES approval_gates (id, engagement_id)
);
CREATE INDEX ix_exec_auth_engagement ON execution_authorizations (engagement_id);
-- Insert-only (see §immutable-tables): production DB role denies UPDATE/DELETE.

CREATE TABLE scanner_runs (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id          uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner_name     text NOT NULL,          -- 'semgrep','zap','nuclei','osv-scanner','gitleaks','trufflehog'
    scanner_version  text NOT NULL,          -- captured for reproducibility
    image_digest     text,                   -- pinned scanner image (…@sha256:<digest>), never a floating tag
    rules_digest     text,                   -- SHA-256 of the vendored rule/template bundle (Semgrep rules, Nuclei templates)
    config           jsonb NOT NULL,         -- typed, REDACTED persisted config: args/policy/rule-bundle ref + license.
                                             -- MUST NOT contain runtime secret material (e.g. the ZAP API key) —
                                             -- control secrets are injected at launch from the secrets manager and
                                             -- never written here, to logs, to evidence, to errors, or to exports.
    status           scan_status NOT NULL DEFAULT 'queued',
    os_process_group integer,                -- recorded PID/PGID for emergency-stop teardown
    raw_evidence_id  uuid REFERENCES evidence(id),   -- the immutable raw tool output
    started_at       timestamptz,
    finished_at      timestamptz,
    error_summary    text
);
CREATE INDEX ix_scanner_runs_scan ON scanner_runs (scan_id);

-- LLM/agent test suites (M2/M5) mirror scanner_runs.
CREATE TABLE test_runs (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id          uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    suite            test_suite NOT NULL,    -- prompt_injection|data_leakage|agent_permission
    engine           text,                   -- 'pyrit','garak','promptfoo','bespoke'
    engine_version   text,
    config           jsonb NOT NULL,         -- corpus refs, target endpoint, params
    status           scan_status NOT NULL DEFAULT 'queued',
    started_at       timestamptz,
    finished_at      timestamptz,
    error_summary    text
);
CREATE INDEX ix_test_runs_scan ON test_runs (scan_id);

-- Immutable pointer to a blob in the object store. Never mutated; never soft-deleted.
CREATE TABLE evidence (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    object_key       text NOT NULL,          -- key in the S3-compatible evidence store
    content_sha256   bytea NOT NULL,         -- integrity check, verified on read
    size_bytes       bigint NOT NULL,
    content_type     text NOT NULL,
    kind             evidence_kind NOT NULL, -- raw_scanner_output|http_transcript|llm_transcript|source_archive
    retain_until     timestamptz,            -- mirrors object-lock retention (compliance mode)
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (object_key)
);
CREATE UNIQUE INDEX ux_evidence_hash ON evidence (content_sha256);  -- content-addressable dedup
```

Write order is blob→object store first, then the `evidence` row commit (two-phase; see `ARCHITECTURE.md §13`). An orphan-sweep job reconciles blobs whose metadata commit failed.

---

## 7. Findings (SARIF-aligned) 🔒

The core artifact. Modeled as a **superset of SARIF 2.1.0** so we can import/export SARIF while carrying DAST/recon/LLM fields SARIF under-serves. Every finding carries a **provenance label** (automated vs. AI-generated vs. human-validated) and a **dedup identity**.

```sql
CREATE TABLE findings (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id      uuid NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    target_id          uuid NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
    scan_id            uuid REFERENCES scans(id),
    scanner_run_id     uuid REFERENCES scanner_runs(id),
    test_run_id        uuid REFERENCES test_runs(id),

    -- SARIF-aligned core
    rule_id            text,                -- SARIF result.ruleId (e.g. semgrep rule, ZAP alert id)
    title              text NOT NULL,
    message            text NOT NULL,       -- SARIF result.message.text
    sarif_level        sarif_level,         -- none|note|warning|error (interchange)
    location           jsonb,               -- file/line/region (SAST) OR endpoint/method (DAST) OR prompt ref (LLM)

    -- Triage & risk
    severity           severity NOT NULL DEFAULT 'informational', -- critical|high|medium|low|informational
    -- current CVSS is a flagged row in cvss_scores; severity here is the working band
    provenance         finding_provenance NOT NULL,   -- automated|ai_generated|validated|manually_overridden
    status             finding_status NOT NULL DEFAULT 'open',
        -- open|in_triage|confirmed|mitigated|fixed|accepted_risk|false_positive|out_of_scope
    is_false_positive  boolean NOT NULL DEFAULT false,

    -- Dedup identity (DefectDojo-style + SARIF fingerprints)
    hash_code            bytea NOT NULL,    -- SHA-256 over a defined field set (rule_id+location+target)
    partial_fingerprints jsonb,             -- SARIF partialFingerprints for cross-tool stable identity
    duplicate_of         uuid REFERENCES findings(id),  -- set when detected as a dup on reimport

    description        text,
    impact             text,
    recommendation     text,                -- short remediation summary; full guidance in remediations
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    deleted_at         timestamptz
);
CREATE INDEX ix_findings_engagement ON findings (engagement_id);
CREATE INDEX ix_findings_target_status ON findings (target_id, status);
CREATE INDEX ix_findings_hash ON findings (hash_code);         -- dedup lookups
CREATE INDEX ix_findings_fp_gin ON findings USING gin (partial_fingerprints);

-- Many-to-many: a finding can cite multiple evidence blobs.
CREATE TABLE finding_evidence (
    finding_id   uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id  uuid NOT NULL REFERENCES evidence(id) ON DELETE RESTRICT,
    caption      text,
    PRIMARY KEY (finding_id, evidence_id)
);

-- Append-only status transition log (who moved it, when, why).
CREATE TABLE finding_status_history (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id   uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    from_status  finding_status,
    to_status    finding_status NOT NULL,
    changed_by   uuid REFERENCES users(id),     -- NULL when changed by automated reimport
    reason       text,
    changed_at   timestamptz NOT NULL DEFAULT now()
);
```

**Provenance rule (enforced in service layer):** an LLM-produced finding is written `provenance='ai_generated'` and cannot move to `confirmed`/`fixed` without a human transition recorded in `finding_status_history`. This is how the UI's "automated vs. validated" distinction stays truthful.

**Status-model note:** DefectDojo models status as *orthogonal booleans* (a finding can be simultaneously active + verified, or mitigated + risk-accepted). We deliberately collapse the mutually-exclusive lifecycle into `status` for simplicity, but preserve the two flags DefectDojo keeps genuinely independent — `is_false_positive` and `duplicate_of` — as their own columns. If we later need the active-vs-verified distinction as independent axes, promote them to separate columns rather than adding enum values.

---

## 8. CVSS scoring (with history)

```sql
CREATE TABLE cvss_scores (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id     uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    version        cvss_version NOT NULL,        -- v4_0 (default) | v3_1
    vector_string  text NOT NULL,                -- v4.0 begins 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'
    base_score     numeric(3,1) NOT NULL CHECK (base_score >= 0.0 AND base_score <= 10.0),
    severity_band  severity NOT NULL,            -- derived from score
    is_current     boolean NOT NULL DEFAULT true,
    is_manual_override boolean NOT NULL DEFAULT false,
    override_justification text,                 -- required when is_manual_override
    scored_by      uuid REFERENCES users(id),    -- NULL if computed automatically
    created_at     timestamptz NOT NULL DEFAULT now()
);
-- Exactly one current score per finding.
CREATE UNIQUE INDEX ux_cvss_current ON cvss_scores (finding_id) WHERE is_current;
```

Score changes never update in place — a new row is inserted, the prior `is_current` is cleared. The full table *is* the audit history. Manual overrides require a justification (CHECK enforced in app + optional DB CHECK). **Compute scores with the maintained `cvss` PyPI package (RedHatProductSecurity/cvss, supports v2/v3/v4)** — v4.0's MacroVector/interpolation scoring is error-prone; do not hand-roll it. The `ux_cvss_current` partial unique index guarantees *at most one* current row per finding; the service layer ensures at least one exists.

---

## 9. Remediation & patch validation

```sql
CREATE TABLE remediations (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id         uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    guidance_text      text NOT NULL,       -- plain-English + root cause + fix + verification
    secure_code_example text,
    patch_suggestion   text,                -- ALWAYS labeled "requires developer review"
    is_ai_generated    boolean NOT NULL DEFAULT true,
    created_by         uuid REFERENCES users(id),
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE retests (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id         uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    remediation_id     uuid REFERENCES remediations(id),
    rescan_scan_id     uuid REFERENCES scans(id),     -- the scan that re-tested this
    before_evidence_id uuid REFERENCES evidence(id),
    after_evidence_id  uuid REFERENCES evidence(id),
    result             retest_result NOT NULL,        -- still_present|resolved|inconclusive
    performed_by       uuid REFERENCES users(id),
    performed_at       timestamptz NOT NULL DEFAULT now()
);
```

Reimport/retest semantics follow DefectDojo (see `ROADMAP.md M4`): a rescan that no longer surfaces a finding auto-transitions it toward `mitigated`/`fixed` (recorded in `finding_status_history`), and a reappearing finding auto-reopens.

---

## 10. Compliance mapping (lookup tables, not enums)

```sql
CREATE TABLE compliance_frameworks (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key         text NOT NULL UNIQUE,   -- 'owasp_llm_2025','owasp_asi_2026','owasp_wstg_4_2',
                                        -- 'nist_ai_rmf','nist_ai_600_1','nist_800_53_r5','nist_800_115'
    name        text NOT NULL,
    version     text NOT NULL,
    source_url  text
);

CREATE TABLE compliance_controls (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id uuid NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    code         text NOT NULL,          -- 'LLM01','ASI02','AC-6','WSTG-ATHZ-02', ...
    title        text NOT NULL,
    description  text,
    UNIQUE (framework_id, code)
);

CREATE TABLE finding_compliance_mappings (
    finding_id   uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    control_id   uuid NOT NULL REFERENCES compliance_controls(id) ON DELETE RESTRICT,
    mapped_by    finding_provenance NOT NULL DEFAULT 'automated',  -- how the mapping was produced
    confidence   numeric(3,2),           -- 0–1 when LLM-assisted
    PRIMARY KEY (finding_id, control_id)
);
```

Seeded from the versioned JSON/YAML KB in `packages/compliance/` at M3; promoted to DB-managed at M6. Frameworks include OWASP LLM Top 10 **2025**, OWASP Agentic Top 10 **2026 (ASI01–ASI10)**, WSTG **v4.2**, NIST AI RMF + **AI 600-1**, NIST SP 800-53 **Rev 5.2.0**, NIST SP 800-115.

---

## 11. Reports

```sql
CREATE TABLE reports (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id    uuid NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    report_type      report_type NOT NULL,      -- executive|technical|poam
    title            text NOT NULL,
    status           report_status NOT NULL DEFAULT 'draft',  -- draft|final
    body             jsonb NOT NULL,            -- editable structured content before export
    generated_by     uuid REFERENCES users(id),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at       timestamptz
);

-- Which findings a report includes, and the snapshot ordering.
CREATE TABLE report_findings (
    report_id    uuid NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    finding_id   uuid NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    sort_order   integer NOT NULL DEFAULT 0,
    PRIMARY KEY (report_id, finding_id)
);
```

Exports (CSV/Markdown at MVP; PDF/DOCX/JSON at M6) are rendered from `reports.body`; the row stays editable until `status='final'`.

---

## 12. Audit & LLM interactions (append-only)

```sql
-- The audit log. Append-only: no updated_at, no deletes, ever.
CREATE TABLE audit_events (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    actor_user_id    uuid REFERENCES users(id),        -- NULL for system/automated actions
    action           text NOT NULL,     -- 'scan.queued','scope.blocked','roe.accepted','finding.validated',...
    object_type      text NOT NULL,     -- 'scan','engagement','finding',...
    object_id        uuid,
    engagement_id    uuid REFERENCES engagements(id),
    outcome          audit_outcome NOT NULL DEFAULT 'success',  -- success|blocked|failure
    detail           jsonb,             -- structured context (e.g. why a scope check blocked)
    ip_address       inet,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_engagement_time ON audit_events (engagement_id, created_at DESC);
CREATE INDEX ix_audit_actor_time ON audit_events (actor_user_id, created_at DESC);

-- Every LLM call, for cost tracking and evidence-grounding audit.
CREATE TABLE llm_interactions (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    engagement_id    uuid REFERENCES engagements(id),
    purpose          llm_purpose NOT NULL,   -- test_gen|triage|remediation|mapping|report|summarization
    provider         text NOT NULL,          -- 'anthropic','ollama','vllm'
    model            text NOT NULL,          -- 'claude-opus-4-8', ...
    prompt_template  text,                   -- template id + version
    was_redacted     boolean NOT NULL DEFAULT false,
    hosted           boolean NOT NULL,       -- true if egress left the box
    input_tokens     integer,
    output_tokens    integer,
    cost_usd         numeric(12,6),
    -- polymorphic reference to what this call was about:
    ref_object_type  text,                   -- 'scan','test_run','finding','report'
    ref_object_id    uuid,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_llm_engagement_time ON llm_interactions (engagement_id, created_at DESC);
```

`audit_events` and `llm_interactions` are insert-only. LLM interactions record whether redaction ran and whether egress was hosted — required to prove the `hosted_models_allowed` control held.

---

## 13. Agent policies (M5)

```sql
CREATE TABLE agent_policies (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id        uuid NOT NULL REFERENCES targets(id) ON DELETE CASCADE,  -- an 'ai_agent' target
    name             text NOT NULL,
    allowed_tools    jsonb NOT NULL,        -- tool names + allowed parameter bounds
    created_by       uuid REFERENCES users(id),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
```

The sandboxed fake tools and per-tool-call decisions execute in the worker; each decision (allowed/blocked + reason) is captured as evidence and rolled into `findings` mapped to LLM06 + ASI02.

---

## 14. Enumerated types

```sql
CREATE TYPE user_role          AS ENUM ('admin','tester','reviewer','read_only');
CREATE TYPE engagement_status  AS ENUM ('draft','active','paused','closed');
CREATE TYPE scan_intensity     AS ENUM ('passive','safe_active','authenticated_active','high_risk');
CREATE TYPE scope_kind         AS ENUM ('allow','deny');
CREATE TYPE scope_matcher      AS ENUM ('url','domain','ip_cidr','api_base','repo');
CREATE TYPE approval_status    AS ENUM ('pending','approved','denied','expired','revoked','consumed');
CREATE TYPE target_type        AS ENUM ('web_app','rest_api','graphql_api','source_repo','source_archive',
                                        'ai_chatbot','llm_api_wrapper','ai_agent');
CREATE TYPE environment_label  AS ENUM ('dev','staging','production');
CREATE TYPE auth_status        AS ENUM ('none','configured','verified');
CREATE TYPE scan_status        AS ENUM ('queued','running','completed','failed','cancelled');
CREATE TYPE test_suite         AS ENUM ('prompt_injection','data_leakage','agent_permission');
CREATE TYPE evidence_kind      AS ENUM ('raw_scanner_output','http_transcript','llm_transcript','source_archive');
CREATE TYPE sarif_level        AS ENUM ('none','note','warning','error');
CREATE TYPE severity           AS ENUM ('critical','high','medium','low','informational');
CREATE TYPE finding_provenance AS ENUM ('automated','ai_generated','validated','manually_overridden');
CREATE TYPE finding_status     AS ENUM ('open','in_triage','confirmed','mitigated','fixed',
                                        'accepted_risk','false_positive','out_of_scope');
CREATE TYPE cvss_version       AS ENUM ('v4_0','v3_1');
CREATE TYPE retest_result      AS ENUM ('still_present','resolved','inconclusive');
CREATE TYPE report_type        AS ENUM ('executive','technical','poam');
CREATE TYPE report_status      AS ENUM ('draft','final');
CREATE TYPE audit_outcome      AS ENUM ('success','blocked','failure');
CREATE TYPE llm_purpose        AS ENUM ('test_gen','triage','remediation','mapping','report','summarization');
```

Adding an enum value uses `ALTER TYPE ... ADD VALUE` in a migration. Precise behavior (PG12+, still true on 17): the statement *can* run inside a transaction block, but **the new value cannot be used until after that transaction commits**. Enum values **cannot be dropped** (no `DROP VALUE`) and are renamed with `ALTER TYPE ... RENAME VALUE`. That irremovability is the main reason churny sets (compliance frameworks/controls) live in lookup tables instead.

---

## 15. Integrity, retention & performance notes

- **Immutability:** `evidence`, `roe_acknowledgements`, `audit_events`, `llm_interactions`, `cvss_scores`, and all `*_history`/`retests` rows are insert-only. Enforce at the service layer; optionally add a DB rule/trigger denying `UPDATE`/`DELETE` on these tables in production.
- **Evidence retention** mirrors object-store object-lock: `evidence.retain_until` reflects the compliance-mode retention set on the blob; the DB never deletes an evidence row whose blob is still locked.
- **Dedup path:** on (re)import, compute `hash_code`; if a live finding with the same `hash_code` exists for the target, link `duplicate_of` instead of inserting a new open finding. `partial_fingerprints` supports cross-tool matching where `rule_id` differs.
- **Hot indexes:** partial indexes on active scans/sessions keep queue and auth lookups cheap; time-ordered UUIDv7 PKs keep inserts append-friendly.
- **Findings-by-severity** for the target inventory is a query/rollup (optionally a materialized view refreshed on scan completion), never a stored counter — avoids drift.
- **Migrations** run as a one-shot Alembic step (see `ARCHITECTURE.md §13`); keep `api` single-replica if migrating on startup instead.
- **Secrets** (test credentials, API keys) are never stored in plaintext columns — `targets.auth_config` holds references to a secrets manager / encrypted material only.
