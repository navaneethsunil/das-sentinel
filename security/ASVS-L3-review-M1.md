# ASVS 5.0 Level 3 review — M1 auth / session / access-control / audit

> **Task:** M1-SEC5 (`MVP_TASKS.md`) — ASVS 5.0 **Level 3** review of the
> authentication, session-management, access-control, and audit subsystems
> built in M1; record gaps as tracked tasks. Companion to the M1-SEC5 CI change
> that raises SAST/secret/SCA to **block on High**.
>
> **Standard:** OWASP Application Security Verification Standard **5.0.0**
> (May 2025). Chapters referenced: **V6 Authentication**, **V7 Session
> Management**, **V8 Authorization**, **V16 Security Logging and Error
> Handling**. Target assurance for these four subsystems: **L3** (highest —
> `CLAUDE.md §11.4`: L3 for auth/session/crypto/audit).
>
> **Scope note:** this reviews the *platform's own* application security
> (`SECURITY_DEVELOPMENT_PLAN.md`), not product-safety controls (`CLAUDE.md §2`).
> Reviewer: engineering (self-assessment). Date: 2026-07-16. Commit: M1-SEC5.

---

## Verdict summary

| Subsystem | ASVS ch. | L3 verdict | Open gaps (tracked below) |
|---|---|---|---|
| Authentication | V6 | **Meets L3 for the implemented surface**; MVP is single-factor by design | SEC-DEBT-1 (login throttling), SEC-DEBT-2 (MFA), SEC-DEBT-3 (breached-password check) |
| Session management | V7 | **Meets L3** | — |
| Authorization | V8 | **Meets L3** | — |
| Security logging | V16 | **Meets L3 for the implemented surface** | SEC-DEBT-4 (log-integrity role separation), SEC-DEBT-5 (time-sync/retention ops) |

No gap blocks the M1 exit gate: the L3 controls that M1 is responsible for
(fixation, revocation, expiry, CSRF, RBAC, cross-engagement isolation,
append-only audit) are implemented and test-backed. The gaps are additive
hardening (throttling, MFA) and operational controls (retention, role
separation) whose natural homes are M2+ and the pre-go-live Hardening gate.

---

## V6 — Authentication

**Implementation:** `app/core/security.py` (PasswordService), `app/api/auth.py`
(login/logout/logout-all/me), `app/api/users.py` (admin credential lifecycle).

| Area | ASVS 5.0 intent (L2/L3) | Status | Evidence |
|---|---|---|---|
| Password storage | Memory-hard hash, per-user salt, no fast hashes | **Met** | Argon2id, OWASP params (19 MiB, t=2, p=1); PBKDF2-HMAC-SHA256 ≥600k FIPS fallback via `PASSWORD_HASH_SCHEME`. `security.py` |
| Self-describing hashes + upgrade | Rehash on parameter/algorithm change | **Met** | `needs_rehash()` dispatched on hash prefix; login re-hashes transparently. `auth.py:116` |
| Credential-error uniformity | No account enumeration via response or timing | **Met** | Single generic 401 for unknown-email / wrong-password / inactive; dummy-hash verify on the unknown-email path equalizes timing. `auth.py:50,56,87` |
| Password min length / no silly limits | ≥12 chars L2; no composition rules; allow long | **Partial** | Length floor enforced at the schema; **no breached-password (k-anonymity/HIBP) check** — offline-friendly list deferred → **SEC-DEBT-3** |
| Anti-automation on login | Rate-limit / lockout / progressive delay | **GAP** | No per-account or per-IP throttle. Abuse tested for CSRF/fixation (M1-SEC2) but not brute-force → **SEC-DEBT-1** |
| Multi-factor | L3 expects MFA available for the auth flow | **GAP (by MVP scope)** | Local email+password only; SSO/OIDC + MFA are a post-MVP abstraction (`CLAUDE.md §3`, ROADMAP) → **SEC-DEBT-2** |
| Credential lifecycle | Admin create/deactivate/set-role/change-password revokes sessions | **Met** | `users.py`; role/password change revokes the target's sessions; no self-deactivate/self-demote |

**Assessment:** the *stored-credential* and *enumeration* L3 controls are met.
The residual L3 items (anti-automation, MFA) are genuine gaps, tracked below;
they are hardening on top of a correct core, not defects in it.

## V7 — Session Management

**Implementation:** `app/core/sessions.py`, `app/core/deps.py` (per-request
resolution), `app/core/config.py` (TTLs).

| Area | ASVS 5.0 intent (L2/L3) | Status | Evidence |
|---|---|---|---|
| Opaque, high-entropy id | ≥128-bit random, not a self-contained token | **Met (exceeds)** | 256-bit token; only SHA-256 of it is stored (DB + Valkey). `sessions.py:33` |
| Cookie hardening | `HttpOnly; Secure; SameSite`; host-scoped | **Met (exceeds)** | `__Host-` prefix ⇒ Secure + host-scoped + path=/; `HttpOnly`; `SameSite=Strict`. `sessions.py` cookie helpers |
| Fixation defense | New id on privilege change (login) | **Met** | `regenerate_on_login()` mints a fresh id and drops the pre-auth one. `sessions.py:114`; test M1-SEC2 |
| Idle + absolute timeout | Both required at L3 | **Met** | Idle 900 s (sliding), absolute 28 800 s (hard cap); both checked, DB authoritative. `config.py:37-38`, `sessions.py:160-170` |
| Immediate revocation | Logout + admin/kill-all effective at once across caches | **Met** | Write-through: revoke deletes the Valkey entry and sets `revoked_at`; cache miss falls through to authoritative DB. Logout-all covered. `sessions.py`; tests M1-T2 / M1-SEC2 |
| Fail-closed validation | Any error/miss/expiry ⇒ unauthenticated | **Met** | `validate_session` returns `None` on any anomaly; `get_principal` → 401. `sessions.py:11`, `deps.py:88` |

**Assessment:** **meets L3.** Opaque server-side sessions with instant
revocation were chosen precisely for this audit-heavy tool (`CLAUDE.md §3`);
the entropy and cookie scoping exceed the L3 floor.

## V8 — Authorization

**Implementation:** `app/core/deps.py` (capability matrix + `require()`),
`app/services/*` + routers (org/engagement scoping), `app/core/scope.py`
(product scope engine, separate concern).

| Area | ASVS 5.0 intent (L2/L3) | Status | Evidence |
|---|---|---|---|
| Enforced server-side, single source | Access decisions centralized, not in UI | **Met** | `CAPABILITY_ROLES` is the one encoding of the ARCHITECTURE §9 matrix; routes declare a capability, never a role set. `deps.py:48` |
| Deny by default | Unmapped/unknown ⇒ denied | **Met** | `require()` 403s unless the role holds the capability; `get_principal` 401s with no valid session. |
| Function-level access (RBAC) | Every state-changing route guarded | **Met** | Structural test proves every domain route is guarded and no mutation sits behind `VIEW` only. `tests/test_rbac_routes.py`; matrix in `tests/test_deps_rbac.py` |
| Object-level access (IDOR/BOLA) | Every object query scoped to the caller | **Met** | Cross-org reads/writes → 404 (no data), incl. foreign object id nested under caller's own engagement path; audit rows org-scoped (M1-F5). `scripts/verify_idor.py` (ALL PASS) |
| Least privilege for oversight data | Sensitive reads not granted to all viewers | **Met** | Audit log is `VIEW_AUDIT` (Admin/Reviewer), deliberately *not* plain `VIEW`. `api/audit.py`, `deps.py` |
| Error-path consistency | No authz leak via status/message | **Met** | Cross-tenant is 404-not-403 (no existence oracle); 403 reserved for role-denied on own-org objects. |

**Assessment:** **meets L3.** The capability indirection + the structural test
make an unguarded or under-guarded route a build failure, and the IDOR harness
proves object-level scoping across two orgs both directly and via BOLA.

## V16 — Security Logging and Error Handling

**Implementation:** `app/core/audit.py` (writer + coverage middleware),
`app/models/audit.py` + migration (append-only trigger), `app/api/audit.py`
(read), `app/schemas/audit.py`.

| Area | ASVS 5.0 intent (L2/L3) | Status | Evidence |
|---|---|---|---|
| Security events logged | AuthN, authZ decisions, and state changes recorded | **Met** | Domain events via transactional `AuditService.log`; a middleware coverage net records every authenticated state-changing request (incl. 403 as `blocked`). `audit.py` |
| Sufficient event detail | who / what / when / outcome / source | **Met** | actor, action, object, engagement, outcome, structured `detail`, `ip_address`, `created_at`. `models/audit.py` |
| Log integrity / tamper-evidence | Append-only; no silent edit/delete | **Met (exceeds)** | DB trigger *raises* on UPDATE/DELETE (loud, not DO-NOTHING); app writer only inserts. Same enforced for `roe_acknowledgements`. `models/audit.py`, migration `4ba81961ace3`; `scripts/verify_insert_only.py` |
| No sensitive data in logs | Don't log secrets/credentials | **Met** | `detail` carries ids/reasons/field names; login logs never carry the password (generic-failure path); `auth_config` is refs-only by construction (TR-23). |
| Log access controlled | Read restricted, org-scoped | **Met** | `VIEW_AUDIT` (Admin/Reviewer); reads org-scoped, foreign engagement filter returns empty. `api/audit.py`; audit IDOR cases in `verify_idor.py` |
| Fail-open protection | A logging failure must not mask the action, nor wave it through | **Met** | Middleware audit write on an independent session; failure is logged loudly (operational alarm), the domain-critical events use the atomic path. `audit.py:109` |
| Log-integrity role separation | App DB role cannot alter/delete history | **Partial** | Enforced today by the raising trigger under the app role; **full DB-role separation** (a distinct, append-only-granted role) is deferred to Hardening → **SEC-DEBT-4** |
| Time source / retention | Trusted clock + defined retention | **Partial (ops)** | `created_at` is DB `now()` (single node); NTP discipline + retention/rotation policy are deployment concerns → **SEC-DEBT-5** |

**Assessment:** **meets L3** for the application-enforced controls; the two
partials are operational/infrastructure hardening, not app-code defects.

---

## Recorded gaps (tracked tasks)

Each gap is additive hardening; none regresses an implemented M1 control. IDs
are referenced from `SECURITY_DEVELOPMENT_PLAN.md` follow-ups.

| ID | Gap | ASVS | Severity | Planned home |
|---|---|---|---|---|
| **SEC-DEBT-1** | No login anti-automation (per-account + per-IP throttle / progressive delay / lockout). | V6 | Medium | M2 (add alongside the abuse-surface work); interim mitigations: generic errors + Argon2id cost already blunt online guessing. |
| **SEC-DEBT-2** | No MFA (single-factor by MVP scope). | V6 | Medium | Post-MVP with the SSO/OIDC abstraction (`CLAUDE.md §3`, ROADMAP). |
| **SEC-DEBT-3** | No breached-password (k-anonymity/offline list) check at set/change. | V6 | Low | Hardening; use an offline breach corpus to keep air-gap posture. |
| **SEC-DEBT-4** | Audit/evidence immutability relies on the raising trigger under the app DB role; no separate append-only DB role. | V16 | Low | Hardening (full role separation) — already noted in `models/audit.py`. |
| **SEC-DEBT-5** | No documented log retention/rotation or NTP time-sync requirement. | V16 | Low | Deployment/Hardening runbook. |

Related non-subsystem follow-up already tracked (carried out of M0, not part of
this review's four subsystems but noted for completeness): nonce-based CSP to
replace `'unsafe-inline'` in `script-src` (ASVS **V3** Web Frontend) — see the
M0 follow-ups in `m0-build-progress` memory / ROADMAP.

---

## CI threshold change shipped with this review (M1-SEC5)

`.github/workflows/security.yml` — SAST and SCA now **block on High**
(secrets already blocked from day one):

- **SAST · semgrep** — blocks on ERROR-severity **security** findings (category
  `security` / CWE / OWASP-tagged). The vendored opengrep bundle's non-security
  ERRORs (maintainability/portability) stay report-only, so the gate tracks
  real security Highs, not lint noise. *Current: 0 blocking.*
- **SAST · bandit** — blocks on **HIGH**-severity findings
  (`--severity-level high`). *Current: 0.*
- **SCA · osv-scanner** — the severity-aware gate for both `uv.lock` and
  `package-lock.json`; blocks on any vuln group with **CVSS ≥ 7.0**; unscored
  vulns are report-only, an unparseable score is treated as High (fail-closed).
  *Current: 1 Medium (postcss 6.1, transitive under Next.js) — below High.*
- **SCA · npm audit** — blocks on `--audit-level=high`. *Current: 1 moderate
  (same postcss) — below High.*
- **SCA · pip-audit** — remains report-only (no built-in severity threshold);
  osv-scanner is the severity-gated Python SCA block. *Current: 0 vulns.*

Fail-closed throughout: report-only applies to *findings*, never to tool errors
— a scanner that breaks fails the job (TM-14).
