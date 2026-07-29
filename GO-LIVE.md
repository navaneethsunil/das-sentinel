# GO-LIVE.md — DAS Sentinel production go-live runbook

> The application is **code-complete** (all feature milestones + the ASVS-L2
> hardening pass + every carried SEC-DEBT code item). What remains to reach a
> real engagement is **deployment, configuration, and a few decisions** — this
> file is the ordered procedure. Tick each box as you complete it.
>
> Companion docs: `IMPLEMENTATION_PLAN.md §9` (the gate this operationalizes),
> `security/log-retention-runbook.md`, `SECURITY_DEVELOPMENT_PLAN.md`.
>
> **Golden rule:** `DAS_ENV=prod` makes the app **fail closed** on weak/placeholder
> secrets — it will refuse to boot until Phase B is done. That is intentional.

---

## Phase A — Decisions (set the values later phases use)

- [ ] **A1. FIPS / password hashing.** If the target ATO (FedRAMP/FISMA/CMMC)
  mandates FIPS-validated crypto → `PASSWORD_HASH_SCHEME=pbkdf2_sha256`; else keep
  `argon2id`. **Decide before creating real users** (existing hashes upgrade on
  next login, but starting correct avoids churn).
- [ ] **A2. Hosted-LLM policy.** Per engagement, `hosted_models_allowed`. For
  air-gapped/federal, default **off** (local Ollama/vLLM only). Redaction runs
  before any hosted call regardless; this decides whether hosted is reachable.
- [ ] **A3. Image publishing.** Do you push images to a registry (ghcr.io /
  private)? This gates **image signing** (Phase E). SBOM + SLSA provenance already
  attest local build artifacts (keyless Sigstore, TR-26.4).
- [ ] **A4. Retention windows.** Choose `EVIDENCE_WORM_RETENTION_DAYS` and
  `AUDIT_ARCHIVE_RETENTION_DAYS` from your compliance regime (often years).

---

## Phase B — Production secrets & config

- [ ] **B1. Generate strong secrets** (never the `change-me` placeholders):
  ```bash
  openssl rand -base64 32   # POSTGRES_PASSWORD, POSTGRES_APP_PASSWORD, MINIO_SECRET_KEY, ZAP_API_KEY
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # MFA_SECRET_ENCRYPTION_KEY
  ```
- [ ] **B2. External secret store.** Put the above in Vault / SOPS / cloud KMS and
  inject at runtime (env from the orchestrator). No secrets in `.env`, images, or
  compose. *Verify:* `git check-ignore .env` succeeds; Trivy secret scan (CI) clean;
  `docker history <image>` shows no secret.
- [ ] **B3. Base prod env.** `DAS_ENV=prod`, `EXPOSE_API_DOCS` unset/false,
  `PASSWORD_HASH_SCHEME` per A1. Boot once and confirm the app starts (proves no
  weak-secret fail-closed remains).

---

## Phase C — Stand up infrastructure

- [ ] **C1. WORM evidence backend.** Bring up the maintained WORM backend
  (SeaweedFS profile is wired + WORM-verified):
  ```bash
  docker compose --profile seaweedfs up -d seaweedfs
  # point the app at it:
  #   MINIO_ENDPOINT=seaweedfs:8333   MINIO_SECURE=false   (in-cluster)
  ```
- [ ] **C2. Off-box log shipping + NTP** (see `security/log-retention-runbook.md`):
  Vector/Fluent Bit sidecar (or compose `syslog`/`fluentd` driver) → Loki/OpenSearch/
  syslog on a separate host; point the host at disciplined NTP/chrony (internal
  stratum-1 in air-gap). Set bounded local log rotation.

---

## Phase D — Activate security toggles, then verify each

> Run each verify script inside the compose network:
> `docker compose run --rm --no-deps -v "$PWD/apps/api/scripts:/app/scripts:ro" \`
> `  --entrypoint sh api -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/<name>.py"`

- [ ] **D1. WORM retention on.** Set `EVIDENCE_WORM_RETENTION_DAYS` +
  `AUDIT_ARCHIVE_RETENTION_DAYS` (A4). Prove against the **deployed** backend:
  `scripts/verify_worm.py` — delete-before-expiry must be rejected.
- [ ] **D2. Least-privilege DB role.** `POSTGRES_USE_APP_ROLE=true` (+ strong
  `POSTGRES_APP_PASSWORD`). Re-run migrations (owner), then `scripts/verify_db_role.py`
  (no UPDATE/DELETE on the 7 append-only tables).
- [ ] **D3. MFA.** `MFA_SECRET_ENCRYPTION_KEY` set; enroll admins first.
  `scripts/verify_mfa.py`.
- [ ] **D4. Full breached-password corpus.** Mount a full offline list and set
  `BREACHED_PASSWORD_LIST_PATH` (e.g. a SecLists rockyou file). `scripts/verify_password_breach.py`.
- [ ] **D5. Abuse controls sanity.** Confirm `API_RATE_LIMIT_MAX_PER_USER` and
  `MAX_CONCURRENT_SCANS_PER_{ENGAGEMENT,ORG}` suit your load (defaults 300/60s,
  5, 20). These are already enforced in code.
- [ ] **D6. Schedule audit archival.** Cron
  `scripts/archive_audit_log.py --since <last> --until <now>` on the retention
  cadence; keep each JSON manifest as the chain-of-custody record.

---

## Phase E — Drills & supply-chain finalization

- [ ] **E1. Backup/restore drill.** DB: logical or WAL backup, restore to a scratch
  DB, confirm the audit append-only trigger + row counts survive — run from the
  repo root with the stack up: `bash apps/api/scripts/backup_restore_drill.sh`.
  Evidence store: object-lock survival is
  **backup-tool-specific** — use versioned-bucket replication / a backup that
  preserves retention metadata (a naive object copy drops the lock); re-run
  `scripts/verify_worm.py` against the restored bucket.
- [ ] **E2. Load & emergency-stop drill.** Run a representative concurrent-scan
  load; confirm resource limits hold and emergency stop kills the process tree
  within budget (`scripts/verify_emergency_stop.py` is the functional proof).
- [ ] **E3. Image signing** *(if A3 = publish).* Add cosign keyless signing to the
  release workflow; verify on pull (`cosign verify …`). *(Not yet implemented —
  gated on A3.)*
- [ ] **E4. `api` minimal/hardened base** *(optional).* Only worth it if the ~23
  no-fix report-only CVEs matter for your ATO; the scanners stage needs Debian
  userland. Deferred.

---

## Fastest path to staging

`A1 → B1,B2,B3 → C1 → D1,D2,D3,D4` gets you a hardened, WORM-backed, MFA-gated,
least-privilege deployment. Phase C2 + Phase E are production-hardening you can
iterate on after a working staging stand-up.

## Status legend
`- [ ]` not started · `- [~]` in progress · `- [x]` done. Update as you go and
commit — this file is the auditable go-live record.
