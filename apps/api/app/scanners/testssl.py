"""testssl.sh adapter (M4 recon, slice 3) — TLS/cipher/certificate assessment via
the ScannerAdapter contract.

Wraps testssl.sh (drwetter, GPLv2) behind the uniform contract: `build_command`
yields the argv to run a bounded `testssl.sh -p -S -h --jsonfile <file>` against a
TLS endpoint, and `normalize` maps testssl's JSON into the shared finding
vocabulary (protocol support, certificate trust/validity, security-header gaps).
GPLv2 keeps us to shelling out to the UNMODIFIED script (no linking/bundling);
testssl uses its own bundled openssl. The framework (workers/scanner_run.py) owns
execution through the killable, confined SubprocessOwner, and — like the other
active paths — scope is validated before the framework ever launches the tool.

Non-intrusive by construction: benign TLS handshakes against a single host:port,
bounded to protocol + server-default + header checks (not a full cipher sweep),
with connect/openssl timeouts. `--warnings batch` keeps it non-interactive.

Runs only in the `scanners` image where testssl.sh is installed; in any other
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

_BINARY = "testssl.sh"
_REPORT_FILENAME = "testssl-report.json"
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024  # bound the JSON we parse back (TM-8)

# testssl severity → our band. OK/INFO/DEBUG lines are status, not findings.
_TESTSSL_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "WARN": Severity.LOW,
}


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


class TestsslScanner:
    __test__ = False  # not a pytest test class despite the "Test" prefix
    name = "testssl"

    def __init__(self, *, binary: str | None = None) -> None:
        self._bin = binary or shutil.which(_BINARY) or "/opt/testssl/testssl.sh"

    def version(self) -> str:
        try:
            # Fixed argv, shell=False, no target input — a controlled version probe.
            proc = subprocess.run(  # noqa: S603  # nosemgrep
                [self._bin, "--version"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ScannerPrerequisiteError(f"testssl.sh --version failed: {exc}") from exc
        text = (proc.stdout or proc.stderr or "").strip()
        for line in text.splitlines():
            if "version" in line.lower():
                return " ".join(line.split())  # collapse the banner's whitespace/escapes
        return "unknown"

    def validate_prerequisites(self) -> None:
        if shutil.which(self._bin) is None and not Path(self._bin).is_file():
            raise ScannerPrerequisiteError(f"testssl.sh not found ({self._bin})")

    def build_command(self, target: ScannerTarget, config: ScannerConfig) -> ScannerInvocation:
        url = target.primary_value  # scope already validated before the framework launches us
        timeout_s = float(config.params.get("timeout_s", 300.0))
        argv = [
            self._bin,
            "--jsonfile",
            _REPORT_FILENAME,  # relative to the framework-owned run workdir (cwd)
            "--quiet",
            "--color",
            "0",
            "--warnings",
            "batch",  # non-interactive
            "--connect-timeout",
            "10",
            "--openssl-timeout",
            "10",
            "-p",  # protocol version support
            "-S",  # server defaults (certificate, chain, trust)
            "-h",  # HTTP security headers
            url,
        ]
        return ScannerInvocation(
            argv=argv,
            env={
                "HOME": "/tmp",  # noqa: S108 — writable scratch for the sandboxed child
                "PATH": "/usr/local/bin:/opt/testssl:/usr/bin:/bin",
            },
            output_mode=OutputMode.FILE,
            output_filename=_REPORT_FILENAME,
            raw_content_type="application/json",
            timeout_s=timeout_s,
            persisted_config={
                "mode": "recon-tls",
                "intrusive": False,
                "checks": "protocols,server-defaults,headers",
            },
        )

    def normalize(self, raw: RawScannerResult) -> list[NormalizedFinding]:
        if not raw.output:
            return []
        if len(raw.output) > _MAX_OUTPUT_BYTES:
            raise ScannerError("testssl output exceeds bound")
        try:
            parsed = json.loads(raw.output.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise ScannerError(f"testssl output not valid JSON: {exc}") from exc
        if not isinstance(parsed, list):
            raise ScannerError("testssl output is not a JSON array")
        findings: list[NormalizedFinding] = []
        for entry in parsed:
            if not isinstance(entry, dict):
                continue
            finding = self._to_finding(entry)
            if finding is not None:
                findings.append(finding)
        return findings

    def _to_finding(self, result: dict[str, Any]) -> NormalizedFinding | None:
        severity = _TESTSSL_SEVERITY.get(str(result.get("severity") or "").upper())
        if severity is None:
            return None  # OK / INFO / DEBUG status lines are not findings
        check_id = str(result.get("id") or "testssl.unknown")
        finding_text = str(result.get("finding") or check_id).strip()
        ip = _as_str(result.get("ip"))
        port = _as_str(result.get("port"))
        cve = _as_str(result.get("cve"))
        return NormalizedFinding(
            fingerprint=f"{check_id}:{ip}:{port}",
            title=f"TLS: {check_id}",
            message=finding_text,
            severity=severity,
            rule_id=check_id,
            location={
                "check_id": check_id,
                "ip": ip,
                "port": port,
                "cve": cve,
                "cwe": _as_str(result.get("cwe")),
                "testssl_severity": _as_str(result.get("severity")),
            },
            description=finding_text or None,
            recommendation=None,
        )
