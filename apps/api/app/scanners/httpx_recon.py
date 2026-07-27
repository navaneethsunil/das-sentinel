"""httpx reconnaissance adapter (M4 recon, slice 1) — non-intrusive HTTP
fingerprinting via the ScannerAdapter contract.

Wraps ProjectDiscovery httpx (MIT) behind the uniform contract: `build_command`
yields the argv to run `httpx -u <url> -json` with tech-detection, status/title,
web-server, and TLS grab enabled. `normalize` maps httpx's JSON into the shared
finding vocabulary as INFORMATIONAL recon facts (endpoint fingerprint + one entry
per detected technology) — these feed scan-plan generation and the technical
report, not a vulnerability verdict. The framework (workers/scanner_run.py) owns
execution through the killable, confined SubprocessOwner, and — as with the ZAP
(M3-W3) and Nuclei active paths — scope is validated before the framework ever
launches the tool, so the adapter reaches only the already-authorized target.

Non-intrusive by construction (CLAUDE.md §2.3 + M4 recon note: these are benign
requests TO the target, not "passive"): a single probe per URL, no crawling, no
payloads, no OOB. Native throughput is floored to the engagement's aggregate rate
ceiling (`-rate-limit`, §6); the update check is disabled so no floating data is
fetched at run time (air-gap-safe, CLAUDE.md §3).

The ProjectDiscovery binary is installed as `pdhttpx` (the Python `httpx`
library ships its own `httpx` CLI that would otherwise shadow it on PATH). Runs
only in the `scanners` image where that binary is installed; in any other image
`validate_prerequisites` fails loud (ScannerPrerequisiteError), never degrading to
a fake-empty result (§5, TM-14).
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

_MAX_OUTPUT_BYTES = 32 * 1024 * 1024  # bound the JSONL we parse back (TM-8)
# ProjectDiscovery httpx binary name — deliberately NOT "httpx" to avoid the
# Python httpx library's CLI shadowing it on PATH.
_BINARY = "pdhttpx"


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str_list(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


class HttpxReconScanner:
    name = "httpx"

    def __init__(self, *, binary: str | None = None) -> None:
        self._bin = binary or shutil.which(_BINARY) or f"/usr/local/bin/{_BINARY}"

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
            raise ScannerPrerequisiteError(f"httpx -version failed: {exc}") from exc
        # httpx prints its version banner to stderr.
        text = (proc.stderr or proc.stdout or "").strip()
        for line in text.splitlines():
            if "version" in line.lower() or line.strip().startswith("v"):
                return line.strip()
        return text.splitlines()[0] if text else "unknown"

    def validate_prerequisites(self) -> None:
        if shutil.which(self._bin) is None and not Path(self._bin).is_file():
            raise ScannerPrerequisiteError(f"httpx (pdhttpx) binary not found ({self._bin})")

    def build_command(self, target: ScannerTarget, config: ScannerConfig) -> ScannerInvocation:
        url = target.primary_value  # scope already validated before the framework launches us
        timeout_s = float(config.params.get("timeout_s", 120.0))
        rate = max(1, int(config.rate_limit_rps))
        argv = [
            self._bin,
            "-u",
            url,
            "-json",  # one JSON object per probed URL, to stdout
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-tech-detect",
            "-status-code",
            "-title",
            "-web-server",
            "-tls-grab",
            "-include-response-header",
            "-timeout",
            "10",
            "-rate-limit",
            str(rate),
        ]
        return ScannerInvocation(
            argv=argv,
            env={
                "HOME": "/tmp",  # noqa: S108 — writable scratch for the sandboxed child
                "PATH": "/usr/local/bin:/usr/bin:/bin",
            },
            output_mode=OutputMode.STDOUT,
            raw_content_type="application/x-ndjson",
            timeout_s=timeout_s,
            persisted_config={
                "mode": "recon-fingerprint",
                "intrusive": False,
                "rate_limit_rps": rate,
            },
        )

    def normalize(self, raw: RawScannerResult) -> list[NormalizedFinding]:
        if not raw.output:
            return []
        if len(raw.output) > _MAX_OUTPUT_BYTES:
            raise ScannerError("httpx output exceeds bound")
        findings: list[NormalizedFinding] = []
        for line in raw.output.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, RecursionError) as exc:
                raise ScannerError(f"httpx output line is not valid JSON: {exc}") from exc
            if isinstance(obj, dict):
                findings.extend(self._facts_for(obj))
        return findings

    def _facts_for(self, result: dict[str, Any]) -> list[NormalizedFinding]:
        # All fields are hostile tool output (TM-8): coerce each to the expected type.
        url = str(result.get("url") or result.get("input") or "target")
        status = result.get("status_code")
        title = result.get("title")
        webserver = result.get("webserver")
        techs = _str_list(result.get("tech")) or _str_list(result.get("technologies"))
        tls = _as_dict(result.get("tls"))
        scheme = result.get("scheme")

        out: list[NormalizedFinding] = [
            NormalizedFinding(
                fingerprint=f"fingerprint:{url}",
                title=f"HTTP endpoint fingerprint ({status})"
                if status is not None
                else "HTTP endpoint fingerprint",
                message=(
                    f"{url} responded"
                    + (f" {status}" if status is not None else "")
                    + (f' "{title}"' if isinstance(title, str) and title else "")
                    + (f" — {webserver}" if isinstance(webserver, str) and webserver else "")
                ),
                severity=Severity.INFORMATIONAL,
                rule_id="httpx-fingerprint",
                location={
                    "url": url,
                    "scheme": scheme if isinstance(scheme, str) else None,
                    "status_code": status if isinstance(status, int) else None,
                    "title": title if isinstance(title, str) else None,
                    "webserver": webserver if isinstance(webserver, str) else None,
                    "technologies": techs,
                    "tls_version": tls.get("tls_version") if isinstance(tls, dict) else None,
                    "content_type": result.get("content_type")
                    if isinstance(result.get("content_type"), str)
                    else None,
                },
                description="Reconnaissance fingerprint of a live HTTP endpoint (non-intrusive).",
                recommendation=None,
            )
        ]
        for tech in techs:
            out.append(
                NormalizedFinding(
                    fingerprint=f"tech:{url}:{tech}",
                    title=f"Technology detected: {tech}",
                    message=f"httpx fingerprinted '{tech}' on {url}",
                    severity=Severity.INFORMATIONAL,
                    rule_id="httpx-tech",
                    location={"url": url, "technology": tech},
                    description=(
                        "Detected technology/version disclosed by the target — informs "
                        "which follow-on scans to plan and may itself be an information leak."
                    ),
                    recommendation=None,
                )
            )
        return out
