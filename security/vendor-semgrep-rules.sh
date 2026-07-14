#!/usr/bin/env bash
# Vendor the Semgrep SAST rule bundle (M0-SEC1, SECURITY_DEVELOPMENT_PLAN §5).
#
# CLAUDE.md §3 forbids floating registry packs (p/owasp-top-ten, p/default) at
# scan time: non-reproducible, air-gap-hostile, and Semgrep-maintained registry
# rules carry the restrictive "Semgrep Rules License v1.0". This script instead
# vendors a content-hashed snapshot of opengrep/opengrep-rules — the pre-relicense
# community ruleset, licensed LGPL-2.1 with Commons Clause (see MANIFEST.json;
# internal use scanning our own code is fine — REDISTRIBUTING rules inside the
# shipped product is a separate license decision, tracked for M3).
#
# Idempotent: re-running against the same pinned commit reproduces the same
# bundle and the same bundle_sha256. To bump the ruleset: update COMMIT and
# TARBALL_SHA256, re-run, review the diff (a malicious rule can suppress or
# exfiltrate findings — SECURITY_DEVELOPMENT_PLAN §7), commit.
set -euo pipefail

COMMIT="f1d2b562b414783763fd02a6ed2736eaed622efa"
TARBALL_SHA256="9a5f1cd5c625418cc1c776120123e2d4371df9bb66e099426b17c3488e13619d"
SOURCE_REPO="https://github.com/opengrep/opengrep-rules"
# Languages we ship (CLAUDE.md §3 stack): api/workers = python, web = js/ts.
RULE_DIRS=(python javascript typescript)

cd "$(dirname "$0")"
BUNDLE_DIR="semgrep-rules"

command -v sha256sum >/dev/null && SHA256="sha256sum" || SHA256="shasum -a 256"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

echo "Downloading ${SOURCE_REPO} @ ${COMMIT} ..."
curl -fsSL -o "$workdir/rules.tar.gz" "${SOURCE_REPO}/archive/${COMMIT}.tar.gz"

echo "${TARBALL_SHA256}  $workdir/rules.tar.gz" | $SHA256 -c - >/dev/null \
  || { echo "FATAL: tarball SHA-256 mismatch — refusing to vendor." >&2; exit 1; }

tar -xzf "$workdir/rules.tar.gz" -C "$workdir"
src="$workdir/opengrep-rules-${COMMIT}"

rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR"
cp "$src/LICENSE" "$BUNDLE_DIR/LICENSE"

# Rules only (*.yaml), never the test fixtures that sit alongside them.
for dir in "${RULE_DIRS[@]}"; do
  (cd "$src" && find "$dir" -type f -name '*.yaml' ! -name '*.test.yaml') |
    while IFS= read -r f; do
      mkdir -p "$BUNDLE_DIR/$(dirname "$f")"
      cp "$src/$f" "$BUNDLE_DIR/$f"
    done
done

# Deterministic bundle hash: sha256 over the sorted per-file "hash  path" list.
# CI re-verifies this before every scan (security/verify-semgrep-bundle.sh).
hashes="$(cd "$BUNDLE_DIR" && find . -type f -name '*.yaml' -print0 |
  LC_ALL=C sort -z | xargs -0 $SHA256)"
bundle_sha256="$(printf '%s\n' "$hashes" | $SHA256 | cut -d' ' -f1)"
file_count="$(printf '%s\n' "$hashes" | wc -l | tr -d ' ')"

cat > "$BUNDLE_DIR/MANIFEST.json" <<EOF
{
  "source_repo": "${SOURCE_REPO}",
  "commit": "${COMMIT}",
  "tarball_sha256": "${TARBALL_SHA256}",
  "license": "LGPL-2.1-only WITH Commons-Clause (see LICENSE; snapshot of pre-relicense semgrep-rules)",
  "license_note": "Cleared for internal CI use on our own code. Bundling into the shipped product is a separate decision (CLAUDE.md §3 Semgrep note, M3).",
  "rule_dirs": ["python", "javascript", "typescript"],
  "file_count": ${file_count},
  "bundle_sha256": "${bundle_sha256}"
}
EOF

echo "Vendored ${file_count} rule files; bundle_sha256=${bundle_sha256}"
