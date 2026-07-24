#!/usr/bin/env sh
# M3-T1: extract the OWASP Juice Shop backend source from the SAME digest-pinned
# image the DAST target runs (one pinned source of truth, air-gap-consistent — no
# separate clone, no repo bloat). Populates sandbox/juice-shop-src/ (gitignored),
# which the T1 SAST verify mounts and points Semgrep at. Idempotent; re-run to refresh.
#
# Run from the repo root:  sh sandbox/extract_juice_shop_source.sh
set -eu

DIGEST="sha256:e68144772ebaaca0ec117b38d44903af92416793230288ef7c5437fc4f26850a"
IMAGE="bkimminich/juice-shop@${DIGEST}"
DEST="sandbox/juice-shop-src"

# The vulnerable backend TypeScript — routes/handlers, helper libs, and data
# models — is where SAST finds real issues. node_modules and the built frontend
# are intentionally excluded (huge, not first-party source).
SUBDIRS="routes lib models data app.ts package.json"

echo "extracting Juice Shop source from ${IMAGE}"
cid=$(docker create "${IMAGE}")
trap 'docker rm "${cid}" >/dev/null 2>&1 || true' EXIT

rm -rf "${DEST}"
mkdir -p "${DEST}"
for item in ${SUBDIRS}; do
  docker cp "${cid}:/juice-shop/${item}" "${DEST}/" 2>/dev/null || echo "  (skipped ${item})"
done

count=$(find "${DEST}" \( -name '*.ts' -o -name '*.js' \) | wc -l | tr -d ' ')
echo "extracted ${count} source files → ${DEST}"
