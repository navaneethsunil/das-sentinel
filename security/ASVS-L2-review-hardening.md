# ASVS 5.0 app-wide Level 2 review — Hardening gate

> **Task:** Pre-go-live Hardening-gate review (`ROADMAP §Hardening`, `CLAUDE.md
> §11.4`) — OWASP ASVS **5.0.0** application-wide **Level 2** self-assessment of
> the platform's own application security, across the chapters *not* covered by
> the M1 Level-3 review. The four M1 subsystems (**V6** Authentication, **V7**
> Session, **V8** Authorization, **V16** Audit logging) are reviewed at **L3** in
> [`ASVS-L3-review-M1.md`](./ASVS-L3-review-M1.md) and are only referenced here.
>
> **Target assurance:** L2 app-wide (`CLAUDE.md §11.4`); L3 retained for
> auth/session/crypto/audit. Crypto (**V11**) is therefore held to L3.
>
> **Scope note:** this reviews the *platform's own* application security
> (`SECURITY_DEVELOPMENT_PLAN.md`), not product-safety controls (`CLAUDE.md §2`).
> Reviewer: engineering (self-assessment), aided by four independent read-only
> code-evidence sweeps. Date: 2026-07-28.
>
> **Method note:** every "Met" below cites concrete code (`file:line` at review
> time) or a test — no control is asserted without evidence (§2.6). Line numbers
> are a snapshot and may drift.

---

## Verdict summary

| ASVS 5.0 chapter | Target | Verdict | Open gaps |
|---|---|---|---|
| V1 Encoding & Injection | L2 | **Meets L2** | SEC-DEBT-9 (arg-injection `--` guard) |
| V2 Validation & Business Logic | L2 | **Meets L2** | — |
| V3 Web Frontend Security | L2 | **Meets L2** | SEC-DEBT-12 (`style-src 'unsafe-inline'`) |
| V4 API & Web Service | L2 | **Meets L2 with gaps** | ~~SEC-DEBT-7 (docs exposed)~~ **resolved**, SEC-DEBT-8 (no global body cap) |
| V5 File Handling | L2 | **Meets L2** | — |
| V11 Cryptography | L3 | **Meets L3 for implemented surface** | SEC-DEBT go-live: WORM off by default |
| V12 Secure Communication | L2 | **Meets L2** | SEC-DEBT-15 (in-cluster plaintext, dev) |
| V13 Configuration | L2 | **Meets L2 with gaps** | SEC-DEBT-11 (weak compose defaults), SEC-DEBT-14 (ZAP key in URL) |
| V14 Data Protection | L2 | **Meets L2** | SEC-DEBT-10 (regex-only redaction) |
| V16 Error Handling (non-audit) | L2 | **Meets L2** | SEC-DEBT-13 (`str(exc)` echoed) |
| SSRF / egress (V1.14, product-critical) | L2 | **Meets L2 with one gap** | SEC-DEBT-6 (DNS-rebinding TOCTOU) |

**Not applicable:** V9 (self-contained tokens — we use opaque server-side
sessions), V10 (OAuth/OIDC — post-MVP), V15 (secure coding / SBOM — covered by
CI SCA + SBOM/SLSA attestation, see "Closed this pass").

**Bottom line:** the platform meets ASVS L2 across the reviewed surface (L3 for
crypto), with the four M1 subsystems already at L3. No gap is an unmitigated
critical: the security-defining surfaces (command execution, SSRF/egress, file
upload, crypto, secret handling) are defended with concrete, fail-closed
controls. The one substantive technical finding is the DNS-rebinding TOCTOU
(SEC-DEBT-6); the rest are hardening/config-posture items and documented
ceilings.

---

## V1 / V2 / V5.3 — Injection, validation, command execution

**Why it matters most here:** DAS Sentinel launches external scanner
subprocesses, so OS-command and argument injection are first-class risks.

| Control | Status | Evidence |
|---|---|---|
| No `shell=True` / `os.system` / `os.popen` anywhere | **Met** | Single launch owner `asyncio.create_subprocess_exec(*argv)`, `execution.py:188`; grep of `app/` finds zero shell-form spawns |
| Command args are lists; target is a discrete element | **Met** | every scanner `build_command` returns `argv=[...]` (`nuclei.py:119`, `semgrep.py:107`, `osv.py:100`, …); URL scanners use `-target <url>` (flag-guarded) |
| Target scope-validated before launch | **Met** | `authorize_operation` (`scope.py:358`) runs at request-time (`scans.py:100`) and re-checked in the worker (`orchestration.py:118`) before any subprocess |
| Parameterized SQL only | **Met** | SQLAlchemy 2.0 `select().where()`; no f-string/`%`/`.format` SQL; only `text()` use is a constant health probe `main.py:50` |
| Request bodies are Pydantic v2 | **Met** | all `app/schemas/*`; no route reads `request.json()`/`.body()`; `dict` fields pass explicit validators (`schemas/targets.py:50-57`) |
| No unsafe deserialization / XXE | **Met** | no `pickle`/`yaml.load`/`eval`/`exec`; Celery JSON-only, pickle disabled (`celery_app.py:25`); SARIF/ZAP ingest is JSON (`json.loads`), no XML on untrusted paths |
| Untrusted scanner output bounded & type-coerced | **Met** | `parse_sarif` size/version/count caps + defensive `isinstance` (`sarif.py:158-246`); nuclei `normalize` 64 MB cap + hostile-field coercion (TM-8) |
| End-of-options (`--`) guard for path-target scanners | **Partial** | `semgrep.py:116` / `gitleaks.py:90` / `osv.py:101` append the target as a trailing positional with no `--`; a leading-`-` value could be read as a flag (arg-injection, **not** shell injection). Inputs are internal extraction dirs or scope-validated → low exploitability → **SEC-DEBT-9** |

## V3 — Web Frontend Security

| Control | Status | Evidence |
|---|---|---|
| Nonce-based CSP, no `script-src 'unsafe-inline'` | **Met** | `middleware.ts:16-27` per-request nonce + `'strict-dynamic'`, set on request & response |
| `frame-ancestors 'none'` (clickjacking) | **Met** | web `middleware.ts:26`; API `Caddyfile:67` |
| Full TR-24 header set + fingerprint stripping | **Met** | HSTS, `nosniff`, `no-referrer`, Permissions-Policy, COOP; `-Server`/`-X-Powered-By`/`-X-XSS-Protection` removed (`Caddyfile:41-50`) |
| `style-src 'unsafe-inline'` | **Partial** | deliberate — nonces don't cover style attributes; React/Tailwind inline styles. Script surface is clean; residual is lower-severity → **SEC-DEBT-12** |

## V4 — API & Web Service

| Control | Status | Evidence |
|---|---|---|
| CSRF defense-in-depth beyond SameSite | **Met** | double-submit cookie, outermost middleware (`csrf.py`, registered last `main.py:129`); safe methods skipped; `hmac.compare_digest`; `/auth/login` exempt (root_path-normalized, exact) |
| No permissive CORS | **Met** | no `CORSMiddleware` registered at all → same-origin only behind the proxy |
| OpenAPI docs surface | **Met (resolved)** | `docs_url`/`redoc_url`/`openapi_url` now gated behind `expose_api_docs` (fail-safe **off**; dev sets `EXPOSE_API_DOCS=true`). Prod serves no `/api/docs`·`/api/openapi.json`, so the route map isn't leaked and the `/api` CSP `'unsafe-inline'` (dev Swagger only) is inert on the JSON-only surface. `main.py`, `config.py`; tests in `test_health.py` — **SEC-DEBT-7 resolved** |
| Global request-body size cap | **Gap** | per-endpoint caps exist (upload 100 MiB `targets.py:148`, SARIF `findings.py:127`) but no global ceiling at Caddy/FastAPI → unbounded generic JSON = memory-DoS → **SEC-DEBT-8** |

## V5 — File Handling (source-archive upload)

Route `POST …/source-archive` → `targets.py:122-196`, `services/source_archive.py`.

| Control | Status | Evidence |
|---|---|---|
| Bounded upload read (100 MiB), reject empty | **Met** | `source_archive.py:41`, `targets.py:148-155` (413/422) |
| Content detected by magic bytes, not client MIME | **Met** | `is_zipfile`/tar-open detection; stored `content_type` derived, not trusted (`source_archive.py:67-77`) |
| Zip-slip / path traversal blocked (zip + tar) | **Met** | `_safe_dest` rejects absolute + `..` via `resolve()` + parent check, plus lexical dry-run (`source_archive.py:84-93,239-242`) |
| Zip-bomb defense (3 layers, on real bytes) | **Met** | 500 MiB total cap + 200:1 streamed ratio + declared-size pre-check + 20k entry cap (`source_archive.py:41-49,116-124,146`) |
| Symlink/special-file & exec-bit stripping | **Met** | only regular files, forced `0o600` (`source_archive.py:186-193,126-128`) |
| Content-addressed immutable storage; per-run temp wiped | **Met** | stored as `sha256/<hex>` evidence; extraction to `mkdtemp` wiped in `finally` (`scanner_run.py:261-265,375`) |

## V11 — Cryptography (held to L3)

| Control | Status | Evidence |
|---|---|---|
| Evidence hash verified on read (tamper-evident) | **Met** | `load_evidence` recomputes SHA-256, raises `EvidenceIntegrityError` (`evidence.py:221-231`) |
| Password hashing | **Met** | Argon2id OWASP params (19 MiB/t=2/p=1); PBKDF2-HMAC-SHA256 ≥600k FIPS fallback; PHC self-describing + rehash (`security.py:25-39`) |
| Session token entropy | **Met** | 256-bit `secrets.token_urlsafe(32)`, only SHA-256 stored (`sessions.py:29-41`) |
| No md5/sha1 for security; no hardcoded keys/IVs | **Met** | grep-clean across `app/` |
| WORM object-lock (COMPLIANCE) | **Partial (config)** | supported + wired, but `evidence_worm_retention_days` defaults **0/OFF**; production enablement is the tracked go-live gate (not code-asserted) → see go-live register |

## V12 — Secure Communication

| Control | Status | Evidence |
|---|---|---|
| TLS via internal CA, no public ACME (air-gap) | **Met** | `Caddyfile:13-16` `local_certs` |
| HSTS + Secure/HttpOnly/SameSite cookies + `__Host-` | **Met** | `Caddyfile:41`; `sessions.py:267-306` |
| No disabled cert validation | **Met** | zero `verify=False`/`CERT_NONE` in `app/llm`, `app/scanners`, `app/connectors` |
| In-cluster transport | **Partial** | `minio_secure=false` default → evidence moves plaintext over the internal Docker net (dev/single-node OK) → **SEC-DEBT-15** |

## V13 — Configuration & Secrets

| Control | Status | Evidence |
|---|---|---|
| Single `Settings` object, no hardcoded hosts/keys/models | **Met** | `config.py:16-187`, `get_settings()` sole entry |
| Secrets typed `SecretStr`, `.get_secret_value()` only at boundary | **Met** | `config.py:68,87,98,128` |
| Container base images digest-pinned | **Met** | every compose `image:` `@sha256:` + both Dockerfiles (TR-25, closed this pass) |
| ZAP API key never persisted to config/evidence/logs | **Met** | `scanners/zap.py:92-98`; only a live query param |
| Weak default secrets if `.env` absent | **Gap** | `POSTGRES_PASSWORD:-devpassword`, `MINIO_ROOT_PASSWORD:-devpassword`, `ZAP_API_KEY:-change-me` (`docker-compose.yml:25,70,292`); no prod guard rejects them → **SEC-DEBT-11** |
| ZAP key passed as URL query param | **Gap (low)** | `apikey=` in the request URL can land in the ZAP daemon's own access log (not ours); a header is cleaner (`zap.py:139,201`) → **SEC-DEBT-14** |

## V14 — Data Protection

| Control | Status | Evidence |
|---|---|---|
| Target creds stored as references only (no plaintext) | **Met** | `auth_config` `<name>_ref`; `validate_auth_config_references` rejects plaintext-looking values (`services/targets.py:44-59`) |
| Redaction-before-egress, fail-closed | **Met** | `llm/service.py:91-105`; blocks egress if redaction can't complete |
| Log hygiene (no bodies/secrets serialized) | **Met** | JSON formatter emits ts/level/logger/msg/exc only (`logging.py:14-24`); `SecretStr` masks reprs |
| Web container gets no secrets | **Met** | no `env_file` on `web` (`docker-compose.yml:410-413`) |
| Redaction completeness | **Partial** | regex + Shannon-entropy (keys/JWT/auth-headers/IPv4/emails); misses free-form PII & unusual secret shapes → accepted MVP, Presidio upgrade path → **SEC-DEBT-10** |

## V16 — Error Handling (non-audit; audit is L3 in the M1 doc)

| Control | Status | Evidence |
|---|---|---|
| No stack traces to clients; generic 500 | **Met** | no custom handler, `debug` never set → default `{"detail":"Internal Server Error"}` |
| Readiness fails closed, logs detail server-side only | **Met** | `main.py:98-109` (503 `"unavailable"`, full detail logged) |
| Auth/session/CSRF fail closed | **Met** | 401/403 on any anomaly (`deps.py:127-158`, `sessions.py:157-168`, `csrf.py:57-61`) |
| Domain `str(exc)` echoed to client | **Partial** | ~11 routes return `detail=str(exc)` for caught domain errors (422/409/400) — intentional validation messages, not traces, but each is a spot to confirm no internal string leaks → **SEC-DEBT-13** |

---

## Closed during this Hardening pass (evidence of shift-left)

| Item | ASVS | Commit |
|---|---|---|
| Nonce-based CSP (removed `script-src 'unsafe-inline'`) | V3 | `bf35b08` |
| Trivy HIGH triage — removed bundled npm from web runtime | V13/V15 | `12e621b` |
| Base-image digest-pinning (TR-25) | V13 | `b03282a` |
| Web runtime → distroless (22→6 HIGH/CRIT, no shell, nonroot) | V13 | `313db7d` |
| SBOM signing + SLSA v1.0 provenance (keyless Sigstore, TR-26.4) | V15 | `5497f40` |
| WORM retention policy wired (prod-activatable) | V11 | `93b6cd7` |

---

## Consolidated gap register (continues the M1 SEC-DEBT series)

None regresses an implemented control; all are additive hardening or config
posture. Ranked by severity.

| ID | Gap | ASVS | Severity | Recommended fix / planned home |
|---|---|---|---|---|
| **SEC-DEBT-6** | DNS-rebinding TOCTOU — scope guard validates the resolved IP but `httpx` re-resolves the hostname independently at connect; the vetted IP is not pinned (`connectors/llm_target.py:348-353` vs `scope.py:306-329`). | V1.14 | **Med** | Connect to the validated IP (pin address, preserve SNI/Host) or a custom transport reusing the vetted address. Fix the over-stated docstring. |
| ~~**SEC-DEBT-7**~~ | ~~OpenAPI docs exposed in prod.~~ **RESOLVED:** `expose_api_docs` Settings flag (fail-safe off) unregisters `/docs`·`/redoc`·`/openapi.json`; the `/api` CSP `'unsafe-inline'` is now inert (JSON-only surface, dev Swagger the sole exception). `main.py`, `config.py`, `test_health.py`. | V4/V14 | ~~Med~~ Closed | Done. |
| **SEC-DEBT-8** | No global request-body size cap; only per-endpoint caps. | V4 | Low-Med | Caddy `request_body { max_size }` set comfortably above the 100 MiB upload cap. |
| **SEC-DEBT-11** | Weak compose default secrets (`devpassword`/`change-me`) reachable if `.env` is absent; no prod guard. | V13 | Low-Med | Remove the `:-default` fallbacks or fail-fast in a prod profile. Deployment/ATO runbook. |
| **SEC-DEBT-10** | Regex/entropy-only egress redaction — free-form PII & unusual secret shapes can leak to hosted models. | V14 | Low-Med | Presidio (or NER) upgrade behind the existing `hosted_models_allowed` gate. Defense-in-depth, not sole control. |
| **SEC-DEBT-9** | No `--` end-of-options guard for path-target scanners (`semgrep`/`gitleaks`/`osv`); a leading-`-` target could be read as a flag. | V5.3 | Low | Insert `"--"` before the positional target (verify each tool's CLI accepts it) or reject leading-dash targets. |
| **SEC-DEBT-12** | `style-src 'unsafe-inline'` on the web CSP. | V3 | Low | Nonce/hash the few inline styles, or accept as documented residual. |
| **SEC-DEBT-13** | Domain `str(exc)` echoed in ~11 error responses. | V16 | Low | Skim each site; ensure no internal detail embeds. |
| **SEC-DEBT-14** | ZAP API key passed as a URL query param (daemon access-log surface). | V13 | Low | Send via header if the ZAP client supports it. |
| **SEC-DEBT-15** | MinIO transport plaintext in-cluster (`minio_secure=false` dev default). | V12 | Low | Enable TLS if the deployment network is shared; N/A for single-node air-gap. |

### Accepted / documented ceilings (not new debt)

- **Network-level egress default-deny (nftables per-run namespace) deferred** — the egress choke point is application-level; a worker RCE with a raw socket bypasses it. Self-documented seam **M2-W3** (`core/egress.py:24-28`).
- **In-container sandbox is best-effort** — `PR_SET_NO_NEW_PRIVS` + RLIMITs, no seccomp/userns/network isolation yet. Self-documented seam **M2-SEC1** (`workers/execution.py:22-27`).
- **WORM off by default** — production must set `EVIDENCE_WORM_RETENTION_DAYS>0` against the WORM-verified backend; the empirical proof harness is `scripts/verify_worm.py`. This is the tracked go-live retention-activation gate.
- **Egress provider-allowlist bypass** — hosts in `EGRESS_PROVIDER_ALLOWLIST` skip scope + SSRF re-validation by design (operator-trusted egress); warrants an operator config-review note, not a code fix.
- Carried from M1: **SEC-DEBT-2** (MFA), **SEC-DEBT-3** (breached-password check), **SEC-DEBT-4** (append-only DB-role separation), **SEC-DEBT-5** (log retention/NTP).

---

## Verdict

The platform **meets OWASP ASVS 5.0 Level 2 application-wide**, with **Level 3**
on auth/session/authorization/audit (M1 review) and cryptography. The
remediation backlog above is the prioritized output of this gate; SEC-DEBT-6
(DNS-rebinding) and SEC-DEBT-7 (docs exposure) are the highest-value next fixes.
