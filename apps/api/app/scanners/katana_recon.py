"""Katana crawl adapter (M4 recon, slice 2) — bounded, in-scope endpoint discovery
via the ScannerAdapter contract.

Wraps ProjectDiscovery katana (MIT) behind the uniform contract: `build_command`
yields the argv to run `katana -u <url> -jsonl` as a SAFE crawl, and `normalize`
maps each discovered request into an INFORMATIONAL "endpoint discovered" recon
fact (URL surface for scan-plan generation + the technical report). The framework
(workers/scanner_run.py) owns execution through the killable, confined
SubprocessOwner, and — as with the ZAP/Nuclei/httpx active paths — scope is
validated before the framework ever launches the tool.

Safe crawling limits (CLAUDE.md §2.3 + M4 recon "safe crawling limits"):
  - `-field-scope fqdn` keeps the crawl on the seed's exact host, so it can never
    follow a link to an out-of-scope host (§2.2) — a strict subset of the
    engagement allowlist, never broader;
  - bounded `-depth` and `-crawl-duration`, low `-concurrency`, and `-rate-limit`
    floored to the engagement's aggregate ceiling (§6);
  - NO automatic form-fill, NO headless browser, NO XHR replay — a passive link/JS
    crawl (benign GETs), never a mutating one;
  - `-disable-update-check` so no floating data is fetched at run time (§3).

Runs only in the `scanners` image where the katana binary is installed; in any
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

_MAX_OUTPUT_BYTES = 64 * 1024 * 1024  # bound the JSONL we parse back (TM-8)
_DEFAULT_DEPTH = 2
_DEFAULT_CRAWL_DURATION = "60"  # seconds (katana's default unit)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class KatanaReconScanner:
    name = "katana"

    def __init__(self, *, binary: str | None = None) -> None:
        self._bin = binary or shutil.which("katana") or "/usr/local/bin/katana"

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
            raise ScannerPrerequisiteError(f"katana -version failed: {exc}") from exc
        text = (proc.stderr or proc.stdout or "").strip()
        for line in text.splitlines():
            if "version" in line.lower():
                return line.strip()
        return text.splitlines()[0] if text else "unknown"

    def validate_prerequisites(self) -> None:
        if shutil.which(self._bin) is None and not Path(self._bin).is_file():
            raise ScannerPrerequisiteError(f"katana binary not found ({self._bin})")

    def build_command(self, target: ScannerTarget, config: ScannerConfig) -> ScannerInvocation:
        url = target.primary_value  # scope already validated before the framework launches us
        depth = int(config.params.get("depth", _DEFAULT_DEPTH))
        crawl_duration = str(config.params.get("crawl_duration", _DEFAULT_CRAWL_DURATION))
        timeout_s = float(config.params.get("timeout_s", 300.0))
        rate = max(1, int(config.rate_limit_rps))
        argv = [
            self._bin,
            "-u",
            url,
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-field-scope",
            "fqdn",  # never leave the seed host (§2.2)
            "-depth",
            str(depth),
            "-crawl-duration",
            crawl_duration,
            "-rate-limit",
            str(rate),
            "-concurrency",
            "2",
            "-timeout",
            "10",
            "-omit-body",  # we only need the endpoint surface, not response bodies
            "-omit-raw",
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
                "mode": "recon-crawl",
                "intrusive": False,
                "field_scope": "fqdn",
                "depth": depth,
                "crawl_duration": crawl_duration,
                "form_fill": False,
                "headless": False,
                "rate_limit_rps": rate,
            },
        )

    def normalize(self, raw: RawScannerResult) -> list[NormalizedFinding]:
        if not raw.output:
            return []
        if len(raw.output) > _MAX_OUTPUT_BYTES:
            raise ScannerError("katana output exceeds bound")
        seen: set[str] = set()
        findings: list[NormalizedFinding] = []
        for line in raw.output.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, RecursionError) as exc:
                raise ScannerError(f"katana output line is not valid JSON: {exc}") from exc
            if not isinstance(obj, dict):
                continue
            finding = self._endpoint_for(obj, seen)
            if finding is not None:
                findings.append(finding)
        return findings

    def _endpoint_for(self, result: dict[str, Any], seen: set[str]) -> NormalizedFinding | None:
        # katana JSONL nests the discovered request under "request"; be liberal.
        request = _as_dict(result.get("request"))
        endpoint = request.get("endpoint") or result.get("endpoint") or result.get("url")
        if not isinstance(endpoint, str) or not endpoint:
            return None
        method = str(request.get("method") or result.get("method") or "GET")
        response = _as_dict(result.get("response"))
        status = response.get("status_code")
        tag = request.get("tag") or result.get("tag")
        source = request.get("source") or result.get("source")
        key = f"{method}:{endpoint}"
        if key in seen:  # dedup repeated discoveries within one crawl
            return None
        seen.add(key)
        return NormalizedFinding(
            fingerprint=f"endpoint:{key}",
            title=f"Endpoint discovered: {method} {endpoint}",
            message=f"katana discovered {method} {endpoint}",
            severity=Severity.INFORMATIONAL,
            rule_id="katana-endpoint",
            location={
                "url": endpoint,
                "method": method,
                "status_code": status if isinstance(status, int) else None,
                "tag": tag if isinstance(tag, str) else None,
                "source": source if isinstance(source, str) else None,
            },
            description="Endpoint discovered by a bounded, in-scope crawl (recon surface).",
            recommendation=None,
        )
