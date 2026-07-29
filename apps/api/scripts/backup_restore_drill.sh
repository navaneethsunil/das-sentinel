#!/usr/bin/env bash
# Backup/restore integrity drill for the Postgres side of the evidence chain
# (GO-LIVE.md E1). Takes a logical backup of the live DB, restores it into a
# throwaway scratch database, and asserts the chain-of-custody guarantees
# survived: the audit_events append-only trigger is present AND still blocks
# UPDATE on a real row, and the row count matches the source. Read-only against
# the live DB (pg_dump only); all writes go to the scratch DB, which is dropped.
#
# Evidence-store WORM survival is NOT covered here — object-lock preservation is
# backup-tool-specific (versioned-bucket replication); re-run verify_worm.py
# against the restored bucket. See GO-LIVE.md E1.
#
# Run from the repo root with the stack up:  bash apps/api/scripts/backup_restore_drill.sh
# No `set -e`: the trigger test deliberately runs a command expected to fail and
# reports via check() rather than aborting.
set -uo pipefail

SCRATCH="das_restore_drill"
DUMP="/tmp/das_restore_drill.dump"
fails=0

check() { # name, condition(0=pass)
  if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1"; fails=$((fails + 1)); fi
}

# Shell (no SQL) inside the postgres container. -T: no TTY (script-friendly).
psh() { docker compose exec -T postgres sh -c "$1"; }
# SQL via stdin (avoids nested-quote hell); $1 = database, reads query from stdin.
# ON_ERROR_STOP=1 so a SQL error (e.g. the append-only trigger's RAISE) exits
# non-zero — without it psql swallows errors and returns 0.
psql_db() { docker compose exec -T postgres sh -c 'psql -tA -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d '"$1"; }

echo "== backup =="
psh 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f '"$DUMP"
check "pg_dump of the live DB succeeded" $?
src_count=$(echo "SELECT count(*) FROM audit_events" | psql_db '"$POSTGRES_DB"' | tr -d '[:space:]')
echo "source audit_events rows: ${src_count:-?}"

echo "== restore into scratch =="
psh 'dropdb -U "$POSTGRES_USER" --if-exists '"$SCRATCH"' >/dev/null 2>&1; createdb -U "$POSTGRES_USER" '"$SCRATCH"
restore_out=$(psh 'pg_restore -U "$POSTGRES_USER" -d '"$SCRATCH"' --no-owner --no-privileges '"$DUMP"' 2>&1'); restore_rc=$?
check "pg_restore into scratch DB exited clean" "$restore_rc"
[ "$restore_rc" -ne 0 ] && printf -- '--- pg_restore output ---\n%s\n-------------------------\n' "$(echo "$restore_out" | tail -8)"

echo "== integrity of the restored copy =="
dst_count=$(echo "SELECT count(*) FROM audit_events" | psql_db "$SCRATCH" | tr -d '[:space:]')
[ "${src_count:-0}" = "${dst_count:-x}" ]; check "restored row count matches source ($src_count == ${dst_count:-?})" $?

trg=$(echo "SELECT count(*) FROM pg_trigger WHERE tgname = 'audit_events_no_update_delete'" | psql_db "$SCRATCH" | tr -d '[:space:]')
[ "${trg:-0}" = "1" ]; check "append-only trigger present on restored audit_events" $?

if [ "${dst_count:-0}" != "0" ]; then
  # Row-level trigger → must target a real row to fire. Expect FAILURE (rc != 0).
  echo "UPDATE audit_events SET action = action WHERE id = (SELECT id FROM audit_events LIMIT 1)" \
    | psql_db "$SCRATCH" >/dev/null 2>&1
  [ $? -ne 0 ]; check "restored trigger blocks UPDATE on a real row" $?
else
  echo "SKIP: restored audit_events empty — structural trigger check above still applies"
fi

echo "== cleanup =="
psh 'dropdb -U "$POSTGRES_USER" '"$SCRATCH"' >/dev/null 2>&1; rm -f '"$DUMP"

if [ "$fails" -eq 0 ]; then echo -e "\nALL PASS"; else echo -e "\n$fails FAILURE(S)"; fi
exit "$fails"
