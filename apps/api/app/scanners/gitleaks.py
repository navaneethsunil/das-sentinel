"""Gitleaks secret scanner adapter (M4 next-wave) — SAST-for-secrets via the
ScannerAdapter contract.

Wraps Gitleaks (MIT, CLAUDE.md §3 default secret scanner) behind the uniform
contract: `build_command` yields the argv to run `gitleaks dir <source> --report-
format json` over a local extracted source tree (the same `source_path` the SAST
path materializes, M3-B1). `normalize` maps Gitleaks' JSON report into the shared
finding vocabulary. The framework (workers/scanner_run.py) owns execution through
the killable, confined SubprocessOwner.

Gitleaks embeds its default ruleset, so pinning the tool VERSION pins the rules
(no vendored bundle to hash, unlike Semgrep) — the version is recorded on every
run. It runs fully offline on a directory (no network, no vuln DB), so a run is
deterministic and air-gap-safe.

Defensive posture (CLAUDE.md §2.5 — we detect secrets so they can be remediated;
we do NOT harvest them): the tool runs with `--redact`, so the raw secret value is
never written to the report or our evidence store — only its type, location, and
fingerprint, which is all remediation needs.

Runs only in the `scanners` image where the gitleaks binary is installed; in any
other image `validate_prerequisites` fails loud (ScannerPrerequisiteError), never
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

_REPORT_FILENAME = "gitleaks-report.json"
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024  # bound the JSON we parse back (TM-8)
# A leaked live credential is treated as HIGH; Gitleaks emits no severity of its
# own, and the authoritative CVSS is computed later (M3-B3).
_SECRET_SEVERITY = Severity.HIGH
_RECOMMENDATION = (
    "Treat the exposed credential as compromised: revoke/rotate it, purge it from "
    "source and version-control history, and load it from a secrets manager instead."
)


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a possibly-hostile tool-output field to a dict (empty if it is not
    one) so downstream access can never raise on crafted JSON (TM-8)."""
    return value if isinstance(value, dict) else {}


class GitleaksScanner:
    name = "gitleaks"

    def __init__(self, *, binary: str | None = None) -> None:
        self._bin = binary or shutil.which("gitleaks") or "gitleaks"

    def version(self) -> str:
        try:
            # Fixed argv, shell=False, no target input — a controlled version probe.
            proc = subprocess.run(  # noqa: S603  # nosemgrep
                [self._bin, "version"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ScannerPrerequisiteError(f"gitleaks version failed: {exc}") from exc
        return (proc.stdout or proc.stderr or "unknown").strip().splitlines()[0] or "unknown"

    def validate_prerequisites(self) -> None:
        if shutil.which(self._bin) is None and not Path(self._bin).is_file():
            raise ScannerPrerequisiteError(f"gitleaks binary not found ({self._bin})")

    def build_command(self, target: ScannerTarget, config: ScannerConfig) -> ScannerInvocation:
        # Scannable code lives at a local path: the verified extraction dir of an
        # uploaded archive / checked-out repo (M3-B1 supplies `source_path`). The
        # Target's primary_value is the scope-matched identifier, not a path — fall
        # back to it only when no source_path is given.
        target_path = config.params.get("source_path") or target.primary_value
        timeout_s = float(config.params.get("timeout_s", 300.0))
        argv = [
            self._bin,
            "dir",
            target_path,
            "--report-format",
            "json",
            "--report-path",
            _REPORT_FILENAME,  # relative to the framework-owned run workdir (cwd)
            "--no-banner",
            "--redact",  # never write the raw secret to the report (§2.5)
            "--exit-code",
            "0",  # findings are not a tool error; the framework reads the report
        ]
        return ScannerInvocation(
            argv=argv,
            env={
                "HOME": "/tmp",  # noqa: S108 — writable scratch for the sandboxed child
                "PATH": "/usr/local/bin:/usr/bin:/bin",
            },
            output_mode=OutputMode.FILE,
            output_filename=_REPORT_FILENAME,
            raw_content_type="application/json",
            timeout_s=timeout_s,
            persisted_config={
                "command": "dir",
                "redacted": True,
                "rate_limit_rps": config.rate_limit_rps,
            },
        )

    def normalize(self, raw: RawScannerResult) -> list[NormalizedFinding]:
        if not raw.output:
            return []
        if len(raw.output) > _MAX_OUTPUT_BYTES:
            raise ScannerError("gitleaks output exceeds bound")
        try:
            parsed = json.loads(raw.output.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise ScannerError(f"gitleaks output not valid JSON: {exc}") from exc
        # Gitleaks reports a top-level JSON array of findings (null when none).
        if parsed is None:
            return []
        if not isinstance(parsed, list):
            raise ScannerError("gitleaks output is not a JSON array")
        return [self._to_finding(r) for r in parsed if isinstance(r, dict)]

    def _to_finding(self, result: dict[str, Any]) -> NormalizedFinding:
        # All fields are hostile tool output (TM-8): coerce every value to the
        # expected type so a crafted report can never raise and crash the worker.
        rule_id = str(result.get("RuleID") or "gitleaks.generic")
        file = result.get("File")
        file_str = file if isinstance(file, str) else None
        start_line = result.get("StartLine")
        start_line = start_line if isinstance(start_line, int) else None
        end_line = result.get("EndLine")
        description = str(result.get("Description") or "").strip()
        tags = result.get("Tags")
        tag_strs = [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []
        # Prefer Gitleaks' own stable fingerprint; else compose rule+location.
        fingerprint = str(result.get("Fingerprint") or f"{rule_id}:{file_str}:{start_line}")
        short = rule_id.replace("-", " ")
        where = f"{file_str}:{start_line}" if file_str else "source"
        return NormalizedFinding(
            fingerprint=fingerprint,
            title=f"Hardcoded secret: {short}",
            message=description or f"Potential secret ({rule_id}) detected in {where}",
            severity=_SECRET_SEVERITY,
            rule_id=rule_id,
            location={
                "file": file_str,
                "start_line": start_line,
                "end_line": end_line if isinstance(end_line, int) else None,
                "tags": tag_strs,
                "commit": result.get("Commit") if isinstance(result.get("Commit"), str) else None,
                # `Match` is "REDACTED" (we run --redact) — safe context, no secret.
                "match": result.get("Match") if isinstance(result.get("Match"), str) else None,
            },
            description=description or None,
            recommendation=_RECOMMENDATION,
        )
