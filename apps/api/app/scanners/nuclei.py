"""Nuclei DAST scanner adapter (M4 next-wave) — active web checks via the
ScannerAdapter contract.

Wraps Nuclei (projectdiscovery, MIT) behind the uniform contract: `build_command`
yields the argv to run `nuclei -target <url> -jsonl` against a URL target using a
VENDORED, content-hashed template bundle (default /app/security/nuclei-templates)
— never a floating registry pack, and never `-update-templates` (CLAUDE.md §3:
non-reproducible + air-gap-hostile). `normalize` maps Nuclei's JSONL output into
the shared finding vocabulary. The framework (workers/scanner_run.py) owns
execution through the killable, confined SubprocessOwner, and — as with ZAP
(M3-W3) — scope is validated before the framework ever launches the tool, so the
adapter reaches only the already-authorized target.

Safe-active by construction (CLAUDE.md §2.3): the bundled templates are single
benign GETs with matchers only (no payloads / fuzzing / brute-force / OOB), OOB
interactions are disabled (`-no-interactsh`), and intrusive/dos/fuzz-tagged
templates are excluded (`-exclude-tags`) as defence-in-depth. Native rate is
floored to the engagement's aggregate ceiling (`-rate-limit`), per §6. The bundle
content digest is computed from the template files at run time and recorded as
`rules_digest` for reproducibility + provenance.

Runs only in the `scanners` image where the nuclei binary is installed; in any
other image `validate_prerequisites` fails loud (ScannerPrerequisiteError), never
degrading to a fake-empty result (§5, TM-14).
"""

import hashlib
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

DEFAULT_TEMPLATES_PATH = "/app/security/nuclei-templates"
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024  # bound the JSONL we parse back (TM-8)
# Excluded even though our vendored bundle carries none — defence-in-depth so the
# safe-active envelope holds if the bundle ever grows (CLAUDE.md §2.3).
_EXCLUDE_TAGS = "intrusive,dos,fuzz,fuzzing,brute-force"

_NUCLEI_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
    "unknown": Severity.INFORMATIONAL,
}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _bundle_digest(templates_path: str) -> str | None:
    """SHA-256 over the sorted (relpath, bytes) of every *.yaml template — a stable
    content digest of the vendored bundle, computed at run time so a tampered or
    swapped template is visible in the recorded provenance."""
    root = Path(templates_path)
    if not root.is_dir():
        return None
    h = hashlib.sha256()
    for path in sorted(root.rglob("*.yaml")):
        h.update(str(path.relative_to(root)).encode())
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


class NucleiScanner:
    name = "nuclei"

    def __init__(self, *, binary: str | None = None) -> None:
        self._bin = binary or shutil.which("nuclei") or "nuclei"

    def version(self) -> str:
        try:
            # Fixed argv, shell=False, no target input — a controlled version probe.
            proc = subprocess.run(  # noqa: S603  # nosemgrep
                [self._bin, "-version", "-disable-update-check"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ScannerPrerequisiteError(f"nuclei -version failed: {exc}") from exc
        # nuclei prints the version banner to stderr.
        text = (proc.stderr or proc.stdout or "").strip()
        for line in text.splitlines():
            if "version" in line.lower():
                return line.strip()
        return text.splitlines()[0] if text else "unknown"

    def validate_prerequisites(self) -> None:
        if shutil.which(self._bin) is None and not Path(self._bin).is_file():
            raise ScannerPrerequisiteError(f"nuclei binary not found ({self._bin})")
        templates_path = DEFAULT_TEMPLATES_PATH
        if not Path(templates_path).is_dir():
            raise ScannerPrerequisiteError(f"vendored template bundle missing at {templates_path}")

    def build_command(self, target: ScannerTarget, config: ScannerConfig) -> ScannerInvocation:
        templates_path = config.params.get("templates_path", DEFAULT_TEMPLATES_PATH)
        url = target.primary_value  # scope already validated before the framework launches us
        timeout_s = float(config.params.get("timeout_s", 300.0))
        rate = max(1, int(config.rate_limit_rps))
        argv = [
            self._bin,
            "-target",
            url,
            "-templates",
            templates_path,
            "-exclude-tags",
            _EXCLUDE_TAGS,
            "-jsonl",  # one JSON object per finding, to stdout
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-no-interactsh",  # no out-of-band callbacks (air-gap + safety)
            "-rate-limit",
            str(rate),  # cap native throughput under the engagement ceiling (§6)
        ]
        return ScannerInvocation(
            argv=argv,
            env={
                "HOME": "/tmp",  # noqa: S108 — writable scratch for the sandboxed child
                "PATH": "/usr/local/bin:/usr/bin:/bin",
            },
            output_mode=OutputMode.STDOUT,
            raw_content_type="application/x-ndjson",
            rules_digest=_bundle_digest(templates_path),
            timeout_s=timeout_s,
            persisted_config={
                "templates_path": templates_path,
                "profile": "safe-active",
                "excluded_tags": _EXCLUDE_TAGS,
                "interactsh": False,
                "rate_limit_rps": rate,
            },
        )

    def normalize(self, raw: RawScannerResult) -> list[NormalizedFinding]:
        if not raw.output:
            return []
        if len(raw.output) > _MAX_OUTPUT_BYTES:
            raise ScannerError("nuclei output exceeds bound")
        findings: list[NormalizedFinding] = []
        for line in raw.output.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, RecursionError) as exc:
                raise ScannerError(f"nuclei output line is not valid JSON: {exc}") from exc
            if isinstance(obj, dict):
                findings.append(self._to_finding(obj))
        return findings

    def _to_finding(self, result: dict[str, Any]) -> NormalizedFinding:
        # All fields are hostile tool output (TM-8): coerce each to the expected
        # type so a crafted line can never raise and crash the worker.
        template_id = str(result.get("template-id") or result.get("templateID") or "nuclei.unknown")
        info = _as_dict(result.get("info"))
        name = str(info.get("name") or template_id)
        sev_key = str(info.get("severity") or "info").lower()
        sev = _NUCLEI_SEVERITY.get(sev_key, Severity.INFORMATIONAL)
        matched = result.get("matched-at") or result.get("matched") or result.get("host")
        matched_str = str(matched) if matched is not None else None
        host = result.get("host")
        tags = info.get("tags")
        tag_strs = [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []
        description = str(info.get("description") or "").strip()
        remediation = info.get("remediation")
        fingerprint = str(result.get("matcher-name") or "")
        fingerprint = f"{template_id}:{matched_str}:{fingerprint}"
        return NormalizedFinding(
            fingerprint=fingerprint,
            title=name,
            message=f"{name} at {matched_str or host or 'target'}",
            severity=sev,
            rule_id=template_id,
            location={
                "url": matched_str,
                "host": str(host) if host is not None else None,
                "type": str(result.get("type")) if result.get("type") is not None else None,
                "matcher": result.get("matcher-name"),
                "tags": tag_strs,
            },
            description=description or None,
            recommendation=(remediation.strip() if isinstance(remediation, str) else None),
        )
