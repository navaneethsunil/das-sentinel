"""OSV-Scanner adapter (M4 next-wave) — SCA via the ScannerAdapter contract.

Wraps OSV-Scanner v2 (Apache-2.0) behind the uniform contract: `build_command`
yields the argv to run `osv-scanner scan source --format json` over a local
extracted source tree (the same `source_path` the SAST path materializes,
M3-B1) — it auto-detects lockfiles/SBOMs (uv.lock, package-lock.json,
requirements.txt, go.mod, …) and reports known-vulnerable dependencies from the
OSV database. `normalize` maps OSV-Scanner's JSON into the shared finding
vocabulary, one finding per (package, vulnerability group). The framework
(workers/scanner_run.py) owns execution through the killable, confined owner.

Severity is the group's `max_severity` CVSS mapped to a working band — the SAME
gate this project's CI SCA step uses (unscored → LOW; unparseable → HIGH,
fail-closed); the authoritative CVSS is computed later (M3-B3).

NETWORK: by default OSV-Scanner looks up advisories against osv.dev — the same
egress this project already accepts for its CI SCA gate. In an air-gapped /
`hosted_models_allowed=false`-style deployment, run it against a pre-provisioned
local database (`--offline-vulnerabilities --local-db-path …`); wiring that path
is a hardening seam, not part of this adapter's default.

Runs only in the `scanners` image where the osv-scanner binary is installed; in
any other image `validate_prerequisites` fails loud (ScannerPrerequisiteError),
never degrading to a fake-empty result (§5, TM-14).
"""

import json
import shutil
import subprocess
from typing import Any

from app.models.finding import Severity
from app.scanners.base import (
    NormalizedFinding,
    OutputMode,
    RawScannerResult,
    ScannerConfig,
    ScannerError,
    ScannerInvocation,
    ScannerPrerequisiteError,
    ScannerTarget,
    resolve_local_target_path,
)

_MAX_OUTPUT_BYTES = 64 * 1024 * 1024  # bound the JSON we parse back (TM-8)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _severity_for(max_severity: Any) -> Severity:
    """Map a group's `max_severity` CVSS to a working band — mirrors the project's
    CI SCA gate: unscored (None/"") → LOW (report-only there); an unparseable score
    → HIGH (fail-closed). Authoritative CVSS is computed later (M3-B3)."""
    if max_severity in (None, ""):
        return Severity.LOW
    try:
        score = float(max_severity)
    except (TypeError, ValueError):
        return Severity.HIGH  # unparseable → treat as High (fail-closed)
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.LOW


class OsvScanner:
    name = "osv-scanner"

    def __init__(self, *, binary: str | None = None) -> None:
        self._bin = binary or shutil.which("osv-scanner") or "osv-scanner"

    def version(self) -> str:
        try:
            # Fixed argv, shell=False, no target input — a controlled version probe.
            proc = subprocess.run(  # noqa: S603  # nosemgrep
                [self._bin, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ScannerPrerequisiteError(f"osv-scanner --version failed: {exc}") from exc
        return (proc.stdout or proc.stderr or "unknown").strip().splitlines()[0] or "unknown"

    def validate_prerequisites(self) -> None:
        if shutil.which(self._bin) is None:
            raise ScannerPrerequisiteError(f"osv-scanner binary not found ({self._bin})")

    def build_command(self, target: ScannerTarget, config: ScannerConfig) -> ScannerInvocation:
        target_path = resolve_local_target_path(config, target)
        timeout_s = float(config.params.get("timeout_s", 300.0))
        argv = [
            self._bin,
            "scan",
            "source",
            "--format",
            "json",
            "--recursive",
            target_path,
        ]
        return ScannerInvocation(
            argv=argv,
            env={
                "HOME": "/tmp",  # noqa: S108 — writable scratch for the sandboxed child
                "PATH": "/usr/local/bin:/usr/bin:/bin",
            },
            output_mode=OutputMode.STDOUT,
            raw_content_type="application/json",
            timeout_s=timeout_s,
            persisted_config={
                "command": "scan source --recursive",
                "database": "osv.dev (online)",
                "rate_limit_rps": config.rate_limit_rps,
            },
        )

    def normalize(self, raw: RawScannerResult) -> list[NormalizedFinding]:
        if not raw.output:
            return []
        if len(raw.output) > _MAX_OUTPUT_BYTES:
            raise ScannerError("osv-scanner output exceeds bound")
        try:
            parsed = json.loads(raw.output.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise ScannerError(f"osv-scanner output not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ScannerError("osv-scanner output is not an object")
        findings: list[NormalizedFinding] = []
        for result in _as_list(parsed.get("results")):
            source = _as_dict(_as_dict(result).get("source")).get("path")
            source_str = source if isinstance(source, str) else None
            for pkg_entry in _as_list(_as_dict(result).get("packages")):
                findings.extend(self._package_findings(_as_dict(pkg_entry), source_str))
        return findings

    def _package_findings(
        self, pkg_entry: dict[str, Any], source_path: str | None
    ) -> list[NormalizedFinding]:
        pkg = _as_dict(pkg_entry.get("package"))
        name = str(pkg.get("name") or "unknown")
        version = str(pkg.get("version") or "unknown")
        ecosystem = str(pkg.get("ecosystem") or "unknown")
        # Group = one dedup'd advisory group (may span aliased CVE/GHSA ids).
        out: list[NormalizedFinding] = []
        for group in _as_list(pkg_entry.get("groups")):
            group = _as_dict(group)
            ids = [i for i in _as_list(group.get("ids")) if isinstance(i, str)]
            primary = ids[0] if ids else "OSV-UNKNOWN"
            severity = _severity_for(group.get("max_severity"))
            out.append(
                NormalizedFinding(
                    fingerprint=f"{ecosystem}:{name}@{version}:{primary}",
                    title=f"Vulnerable dependency: {name}@{version} ({primary})",
                    message=(
                        f"{name} {version} ({ecosystem}) is affected by {', '.join(ids) or primary}"
                    ),
                    severity=severity,
                    rule_id=primary,
                    location={
                        "ecosystem": ecosystem,
                        "package": name,
                        "version": version,
                        "advisory_ids": ids,
                        "max_severity": group.get("max_severity"),
                        "lockfile": source_path,
                    },
                    description=f"Known vulnerability in {name} {version}: "
                    f"{', '.join(ids) or primary}.",
                    recommendation=(
                        f"Upgrade {name} to a release that resolves {', '.join(ids) or primary}; "
                        "review the linked OSV/CVE advisories for the fixed version."
                    ),
                )
            )
        return out
