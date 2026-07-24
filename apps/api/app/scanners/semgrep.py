"""Semgrep CE scanner adapter (M3-W2) — SAST via the ScannerAdapter contract.

Wraps Semgrep CE behind the uniform contract: `build_command` yields the argv to
run `semgrep scan --json` against a VENDORED, content-hashed rule bundle on a
local path (CLAUDE.md §3 — never a floating registry alias like p/owasp-top-ten,
which is non-reproducible, air-gap-hostile, and license-restricted). `normalize`
maps Semgrep's JSON results into the shared finding vocabulary. The framework
(workers/scanner_run.py) owns execution through the killable, confined owner.

The rule bundle (default /app/security/semgrep-rules) is the M0-SEC1 vendored,
license-cleared opengrep bundle; its SHA-256, source, and license are recorded in
scanner_runs.config on every run for reproducibility + provenance. Network is
disabled (--metrics=off --disable-version-check) so a run is deterministic and
air-gap-safe.

Runs only in the `scanners` image stage where Semgrep is installed; in any other
image `validate_prerequisites` fails loud (ScannerPrerequisiteError), never
degrading to a fake-empty result (§5, TM-14).
"""

import json
import shutil
import subprocess
from pathlib import Path
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
)

DEFAULT_RULES_PATH = "/app/security/semgrep-rules"
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024  # bound the JSON we parse back (TM-8)

# Semgrep severities are coarse; CVSS is computed later (M3-B3). This is the
# working severity band only.
_SEMGREP_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "LOW": Severity.LOW,
}


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a possibly-hostile tool-output field to a dict (empty if it is not
    one) so downstream `.get(...)` can never raise on crafted JSON (TM-8)."""
    return value if isinstance(value, dict) else {}


def _read_manifest(rules_path: str) -> dict[str, Any]:
    manifest = Path(rules_path) / "MANIFEST.json"
    if not manifest.is_file():
        return {}
    try:
        return json.loads(manifest.read_text())
    except (ValueError, OSError):
        return {}


class SemgrepScanner:
    name = "semgrep"

    def __init__(self, *, binary: str | None = None) -> None:
        self._bin = binary or shutil.which("semgrep") or "semgrep"

    def version(self) -> str:
        try:
            # Fixed argv, shell=False, no target input — a controlled version probe.
            proc = subprocess.run(  # noqa: S603  # nosemgrep
                [self._bin, "--version", "--disable-version-check"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ScannerPrerequisiteError(f"semgrep --version failed: {exc}") from exc
        return (proc.stdout or proc.stderr or "unknown").strip().splitlines()[0]

    def validate_prerequisites(self) -> None:
        if shutil.which(self._bin) is None and not Path(self._bin).is_file():
            raise ScannerPrerequisiteError(f"semgrep binary not found ({self._bin})")
        rules_path = DEFAULT_RULES_PATH
        if not Path(rules_path).is_dir():
            raise ScannerPrerequisiteError(f"vendored rule bundle missing at {rules_path}")

    def build_command(self, target: ScannerTarget, config: ScannerConfig) -> ScannerInvocation:
        rules_path = config.params.get("rules_path", DEFAULT_RULES_PATH)
        # The scannable code lives at a local path: the verified extraction dir of
        # an uploaded archive / checked-out repo (M3-B1 supplies `source_path`).
        # The Target's primary_value is the scope-matched repo/archive identifier,
        # not a filesystem path — fall back to it only when no source_path is given.
        target_path = config.params.get("source_path") or target.primary_value
        timeout_s = float(config.params.get("timeout_s", 300.0))
        manifest = _read_manifest(rules_path)
        argv = [
            self._bin,
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--config",
            rules_path,
            target_path,
        ]
        return ScannerInvocation(
            argv=argv,
            # Complete, secret-free child env. HOME is writable so Semgrep's core can
            # write its scratch; PATH lets the wrapper find semgrep-core in the venv.
            env={
                "HOME": "/tmp",  # noqa: S108 — writable scratch for the sandboxed child
                "PATH": "/app/.venv/bin:/usr/local/bin:/usr/bin:/bin",
                "SEMGREP_SETTINGS_FILE": "/tmp/.semgrep_settings.yml",  # noqa: S108
            },
            output_mode=OutputMode.STDOUT,
            raw_content_type="application/json",
            rules_digest=manifest.get("bundle_sha256"),
            timeout_s=timeout_s,
            persisted_config={
                "config_path": rules_path,
                "rules_source": manifest.get("source_repo"),
                "rules_commit": manifest.get("commit"),
                "rules_license": manifest.get("license"),
                "rules_sha256": manifest.get("bundle_sha256"),
                "rate_limit_rps": config.rate_limit_rps,
            },
        )

    def normalize(self, raw: RawScannerResult) -> list[NormalizedFinding]:
        if not raw.output:
            return []
        if len(raw.output) > _MAX_OUTPUT_BYTES:
            raise ScannerError("semgrep output exceeds bound")
        try:
            parsed = json.loads(raw.output.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise ScannerError(f"semgrep output not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ScannerError("semgrep output is not an object")
        results = parsed.get("results")
        if not isinstance(results, list):
            return []
        return [self._to_finding(r) for r in results if isinstance(r, dict)]

    def _to_finding(self, result: dict[str, Any]) -> NormalizedFinding:
        # All fields come from hostile tool output (TM-8): coerce any sub-object that
        # is not the expected type to a safe empty default so a crafted result can
        # never raise AttributeError/TypeError and crash the worker.
        check_id = str(result.get("check_id") or "semgrep.unknown")
        path = result.get("path")
        start = _as_dict(result.get("start"))
        end = _as_dict(result.get("end"))
        start_line = start.get("line")
        extra = _as_dict(result.get("extra"))
        metadata = _as_dict(extra.get("metadata"))
        message = str(extra.get("message") or "").strip()
        sev = _SEMGREP_SEVERITY.get(str(extra.get("severity") or "INFO").upper(), Severity.LOW)
        # Prefer Semgrep's own fingerprint; else compose a stable rule+location id.
        fingerprint = str(extra.get("fingerprint") or f"{check_id}:{path}:{start_line}")
        short = check_id.rsplit(".", 1)[-1].replace("-", " ")
        references = metadata.get("references")
        ref_strs = (
            [r for r in references if isinstance(r, str)] if isinstance(references, list) else []
        )
        fix = extra.get("fix")
        fix_str = fix if isinstance(fix, str) else None
        recommendation = fix_str or ("See: " + ", ".join(ref_strs) if ref_strs else None)
        return NormalizedFinding(
            fingerprint=fingerprint,
            title=short or check_id,
            message=message or check_id,
            severity=sev,
            rule_id=check_id,
            location={
                "file": path,
                "start_line": start_line,
                "end_line": end.get("line"),
                "start_col": start.get("col"),
                "cwe": metadata.get("cwe"),
                "owasp": metadata.get("owasp"),
                "category": metadata.get("category"),
            },
            description=message or None,
            recommendation=recommendation,
        )
