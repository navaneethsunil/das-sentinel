# security/ — CI security pipeline assets (M0-SEC1)

Companion to `.github/workflows/security.yml` and `SECURITY_DEVELOPMENT_PLAN.md §5`.

## Contents

- `semgrep-rules/` — vendored, content-hashed Semgrep SAST rule bundle
  (snapshot of [opengrep/opengrep-rules](https://github.com/opengrep/opengrep-rules),
  LGPL-2.1 + Commons Clause — see `semgrep-rules/LICENSE` and `MANIFEST.json`).
  Internal use on our own code is cleared; **bundling rules into the shipped
  product is a separate license decision** (CLAUDE.md §3, due with the M3
  Semgrep adapter).
- `vendor-semgrep-rules.sh` — re-vendors the bundle from a pinned commit +
  tarball SHA-256. Bumping the ruleset = edit the pins, re-run, **review the
  rule diff** (a malicious rule can suppress or exfiltrate findings), commit.
- `verify-semgrep-bundle.sh` — recomputes the bundle hash and compares it to
  `MANIFEST.json.bundle_sha256`. CI runs this before every SAST scan and fails
  closed on drift.

## Blocking policy (Phase 0 / M0)

Blocking from day one: **Gitleaks** (any leak, full history), **safety negative
tests** (pytest, in `ci.yml`), **zizmor** (unpinned actions / token scope),
**TR-24 header assertions**, and **rule-bundle integrity**. Everything else
(Semgrep/Bandit/pip-audit/npm audit/OSV/Trivy/ZAP findings) is report-only this
phase; report-only applies to *findings* only — a tool that errors fails its
stage (fail closed, TM-14). Thresholds tighten per milestone
(`SECURITY_DEVELOPMENT_PLAN.md §6`).

## Local developer loop

```sh
uvx pre-commit install                 # once per clone — Gitleaks blocks secret commits
uvx pre-commit run gitleaks --all-files
./security/verify-semgrep-bundle.sh
uvx semgrep@1.169.0 scan --config security/semgrep-rules --metrics=off apps
uvx bandit@1.9.4 -r apps/api/app
```

## Air-gap / offline mirrors (§5 note: no stage may hard-depend on live internet)

| Stage | Offline path |
|---|---|
| Semgrep rules | already in-repo (this bundle) — nothing to mirror |
| semgrep / bandit / pip-audit / zizmor / pre-commit (PyPI) | internal PyPI mirror; `uv` honors `UV_INDEX_URL` |
| gitleaks / osv-scanner / syft binaries | mirror the pinned GitHub release archives (SHA-256s are recorded in the workflow) |
| pip-audit / OSV-Scanner vuln data | OSV offline database mirror (`--offline-vulnerabilities` in OSV-Scanner; pip-audit via local OSV/PyPI mirror) |
| npm audit | needs an npm registry mirror; OSV-Scanner already covers `package-lock.json` offline, so npm audit is the online convenience path, not the only path |
| Trivy vulnerability DB | OCI artifact — mirror and point `TRIVY_DB_REPOSITORY` at it |
| ZAP image | mirror `ghcr.io/zaproxy/zaproxy@sha256:8d387b…` into the internal registry |
| GitHub Actions | SHA-pinned; mirror-able with an internal Actions cache/registry when CI moves inside the air gap |
