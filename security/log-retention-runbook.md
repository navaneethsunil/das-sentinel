# Log retention & integrity runbook (SEC-DEBT-5)

> Covers `IMPLEMENTATION_PLAN.md §9` item "Log retention & integrity — off-box
> log shipping, defined retention windows, tamper-evidence (broader than the
> audit DB tables)". Most of this is **deployment posture**; the code pieces
> DAS Sentinel ships are marked ✅.

## 1. Application & container logs → off-box shipping

- ✅ **The app emits structured JSON, one object per line, to stdout**
  (`app/core/logging.py`; uvicorn access/error logs share the shape). This is
  12-factor and air-gap friendly — the app writes no network log sink itself.
- **Deployment:** ship stdout off-box to an append-only collector so a host
  compromise cannot rewrite history. Options, in order of air-gap friendliness:
  - A **Vector**/**Fluent Bit** sidecar tailing the Docker json-file logs →
    Loki / OpenSearch / a syslog server on a separate host.
  - The compose **logging driver** (`syslog`/`fluentd`/`gelf`) pointed at that
    collector. Do **not** rely on the local `json-file` driver alone — it is
    host-local and rotates.
- Set a bounded local rotation so a log flood can't fill the disk
  (`logging.options.max-size` / `max-file` per service).

## 2. Audit-log retention (the compliance record)

- ✅ **Tamper-evident in the hot DB already:** `audit_events` (and the other
  chain-of-custody tables) carry a raising `BEFORE UPDATE OR DELETE` trigger
  (role-independent floor), and the least-privilege runtime role `das_app` has
  **no UPDATE/DELETE** privilege on them (SEC-DEBT-4). Nothing the app can do
  mutates history.
- ✅ **Off-box immutable archive:** `scripts/archive_audit_log.py` exports a time
  window of `audit_events` to the object store as deterministic, content-hashed
  NDJSON with a **COMPLIANCE object-lock** (`app/services/audit_archive.py`).
  Because serialization is deterministic (sorted keys), an archive's integrity
  is re-verifiable by re-hashing it against the manifest SHA-256.
  ```
  # run as the owner role; emits a JSON chain-of-custody manifest to stdout
  docker compose run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/archive_audit_log.py \
        --since 2026-07-01T00:00:00Z --until 2026-08-01T00:00:00Z"
  ```
- **Retention window:** set `AUDIT_ARCHIVE_RETENTION_DAYS` to the regime's
  requirement (often years) so each archive is object-locked for that long. `0`
  (dev default) writes the archive but applies no lock. This requires a
  WORM-verified backend (see the evidence-store go-live gate).
- **Schedule:** run the export from cron / a scheduled worker on the retention
  cadence (e.g. monthly), passing `--since <last until>` as the watermark; keep
  each run's manifest line as the chain-of-custody record.
- **Hot-DB pruning is deliberately NOT automated.** The append-only trigger
  blocks deletion for everyone; pruning would require an owner to disable the
  trigger, which is an explicit, audited maintenance action — not a background
  job. Archive first (above), then prune under an approved policy only if the
  hot table's growth demands it.

## 3. Trusted time (NTP)

- **Deployment:** run the host under a disciplined NTP/chrony source so
  `created_at`/`ts` are defensible. In an air-gap, point chrony at the site's
  internal stratum-1/GPS source. Timestamps are only as trustworthy as the host
  clock; the DB stamps `now()` server-side (not client-supplied), so a single
  trusted clock on the DB host covers the audit record.

## 4. What's code vs deployment

| Piece | Where |
|---|---|
| Structured JSON logs on stdout | ✅ code (`core/logging.py`) |
| Audit append-only + no-mutate role | ✅ code (triggers + `das_app`, SEC-DEBT-4) |
| Off-box immutable audit archive + retention lock | ✅ code (`archive_audit_log.py`) |
| Off-box shipping of container logs | deployment (collector + driver) |
| Retention **value** + archive schedule | deployment (`AUDIT_ARCHIVE_RETENTION_DAYS` + cron) |
| NTP / trusted clock | deployment (host chrony) |
