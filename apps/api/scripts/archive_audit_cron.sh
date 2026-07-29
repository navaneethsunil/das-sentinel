#!/usr/bin/env bash
# D6 (GO-LIVE): scheduled audit-log archival to the WORM evidence store.
#
# Archives the window (last watermark, now] via archive_audit_log.py, appends the
# emitted JSON manifest to a chain-of-custody log, and advances the watermark ONLY
# on success (set -e: a failed run leaves the watermark untouched so the next run
# retries the same window — no gaps). Invoke from cron or the bundled systemd timer
# (security/systemd/). State lives in $AUDIT_ARCHIVE_STATE_DIR (default REPO/.audit-archive).
#
# Retention lock on each archived object comes from AUDIT_ARCHIVE_RETENTION_DAYS
# (set it before scheduling — 0 = no lock). See security/log-retention-runbook.md.
#
# Usage:  archive_audit_cron.sh [--dry-run]
set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
STATE_DIR="${AUDIT_ARCHIVE_STATE_DIR:-$REPO_DIR/.audit-archive}"
WATERMARK="$STATE_DIR/last-until"
MANIFESTS="$STATE_DIR/manifests.jsonl"
mkdir -p "$STATE_DIR"

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
since_args=()
[[ -s "$WATERMARK" ]] && since_args=(--since "$(cat "$WATERMARK")")

if [[ "${1:-}" == "--dry-run" ]]; then
  echo "would archive window: since=${since_args[1]:-<all-history>} until=$now"
  exit 0
fi

cd "$REPO_DIR"
manifest="$(docker compose run --rm --no-deps \
  -v "$REPO_DIR/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
  -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/archive_audit_log.py ${since_args[*]:-} --until $now")"

# Persist the manifest (chain-of-custody), then advance the watermark.
printf '%s\n' "$manifest" | tail -1 | tee -a "$MANIFESTS"
printf '%s\n' "$now" > "$WATERMARK"
