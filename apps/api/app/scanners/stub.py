"""Stub scanner adapter (M3-W1) — proves the ScannerAdapter contract end-to-end.

Not a real scanner: it launches a trivial, dependency-free child (`echo` for the
happy path, `sleep` for the cancellable path) and emits a fixed set of findings as
JSON on stdout, which `normalize` parses back. This exercises the entire framework
path — validate_prerequisites → build_command → launch through the killable,
confined SubprocessOwner → capture raw output → normalize → persist scanner_runs +
findings — without needing Semgrep or ZAP installed. The Semgrep (M3-W2) and ZAP
(M3-W3) adapters drop into the same contract.

The stub reads no target value into a shell (argv vector only) and makes no
network calls, so it is safe to run in the base image and in CI.
"""

import json
import shutil
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

_ECHO = shutil.which("echo") or "/bin/echo"
_SLEEP = shutil.which("sleep") or "/bin/sleep"

# Bound the JSON the stub will parse back (hostile-parse posture; full normalizer
# fuzzing is M3-SEC2).
_MAX_OUTPUT_BYTES = 1 * 1024 * 1024

# The deterministic findings the stub reports, keyed to the target so the
# fingerprint (and therefore the finding hash_code) is stable across re-runs.
_STUB_FINDINGS: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "stub.hardcoded-secret",
        "title": "Hard-coded secret (stub)",
        "severity": "high",
        "message": "A credential-shaped literal was found in source (stub finding).",
        "location": {"file": "app/example.py", "start_line": 12, "end_line": 12},
        "description": "Demonstration SAST-style finding produced by the stub adapter.",
        "recommendation": "Move secrets to the secrets manager; never commit them.",
    },
    {
        "rule_id": "stub.weak-hash",
        "title": "Weak hash function (stub)",
        "severity": "medium",
        "message": "Use of a weak hash primitive (stub finding).",
        "location": {"file": "app/example.py", "start_line": 30, "end_line": 30},
        "description": "Demonstration SAST-style finding produced by the stub adapter.",
        "recommendation": "Use a modern algorithm (e.g. SHA-256) for integrity.",
    },
)


class StubScanner:
    """Reference ScannerAdapter used to validate the framework."""

    name = "stub"

    def version(self) -> str:
        return "0.1.0"

    def validate_prerequisites(self) -> None:
        if shutil.which("echo") is None and not _ECHO:
            raise ScannerPrerequisiteError("stub scanner requires an 'echo' binary")

    def build_command(self, target: ScannerTarget, config: ScannerConfig) -> ScannerInvocation:
        # A cancellable payload for exercising emergency stop: a long-running child
        # with no output. The happy path echoes the fixed findings as JSON.
        if config.params.get("hang"):
            return ScannerInvocation(
                argv=[_SLEEP, "30"],
                output_mode=OutputMode.STDOUT,
                persisted_config={"mode": "hang", "rate_limit_rps": config.rate_limit_rps},
            )
        findings = [
            {**f, "fingerprint": f"{f['rule_id']}@{target.primary_value}"} for f in _STUB_FINDINGS
        ]
        return ScannerInvocation(
            # argv vector only — the target value is passed as data, never shell.
            argv=[_ECHO, json.dumps(findings, separators=(",", ":"))],
            output_mode=OutputMode.STDOUT,
            raw_content_type="application/json",
            image_digest=None,
            rules_digest="stub-rules-v1",
            persisted_config={
                "mode": "echo",
                "rate_limit_rps": config.rate_limit_rps,
                "rule_count": len(findings),
            },
        )

    def normalize(self, raw: RawScannerResult) -> list[NormalizedFinding]:
        if not raw.output:
            return []
        if len(raw.output) > _MAX_OUTPUT_BYTES:
            raise ScannerError("stub output exceeds bound")
        try:
            parsed = json.loads(raw.output.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            # Fail safe on hostile/malformed output — never crash the worker (TM-8).
            raise ScannerError(f"stub output not valid JSON: {exc}") from exc
        if not isinstance(parsed, list):
            raise ScannerError("stub output is not a findings list")
        findings: list[NormalizedFinding] = []
        for item in parsed:
            findings.append(
                NormalizedFinding(
                    fingerprint=str(item["fingerprint"]),
                    title=str(item["title"]),
                    message=str(item["message"]),
                    severity=Severity(item["severity"]),
                    rule_id=item.get("rule_id"),
                    location=item.get("location") or {},
                    description=item.get("description"),
                    recommendation=item.get("recommendation"),
                )
            )
        return findings
