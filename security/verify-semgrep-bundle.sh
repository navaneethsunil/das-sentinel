#!/usr/bin/env bash
# Integrity gate for the vendored Semgrep rule bundle (M0-SEC1).
# Recomputes the content hash of security/semgrep-rules/ and compares it to
# MANIFEST.json. Runs in CI before every SAST scan and fails closed: a drifted
# or tampered bundle blocks the build (a malicious rule edit can silently
# suppress findings — SECURITY_DEVELOPMENT_PLAN §7).
set -euo pipefail

cd "$(dirname "$0")/semgrep-rules"

command -v sha256sum >/dev/null && SHA256="sha256sum" || SHA256="shasum -a 256"

expected="$(python3 -c "import json;print(json.load(open('MANIFEST.json'))['bundle_sha256'])")"
actual="$(find . -type f -name '*.yaml' -print0 | LC_ALL=C sort -z | xargs -0 $SHA256 | $SHA256 | cut -d' ' -f1)"

if [ "$actual" != "$expected" ]; then
  echo "FATAL: semgrep rule bundle hash mismatch" >&2
  echo "  expected (MANIFEST.json): $expected" >&2
  echo "  actual:                   $actual" >&2
  echo "Re-vendor via security/vendor-semgrep-rules.sh and review the diff." >&2
  exit 1
fi
echo "Semgrep rule bundle verified: $actual"
