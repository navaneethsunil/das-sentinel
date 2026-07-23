"""ZAP by Checkmarx DAST adapter (M3-W3) — daemon + API via the framework.

Unlike Semgrep (a one-shot subprocess), ZAP runs as a long-lived, digest-pinned
daemon on the internal network; this adapter drives it over its API (an
`ApiScannerAdapter`, run IN-PROCESS under the CancelToken like the M2 LLM suites,
not through SubprocessOwner). One baseline pass: access the target so ZAP's
passive scanner sees it, spider a bounded depth, wait for the passive-scan queue
to drain, then read alerts → normalized findings with endpoint/method location.

Security (CLAUDE.md §3 / TR-23): the ZAP API key is a runtime secret injected
into the adapter (and the daemon) and is NEVER written into scanner_runs.config,
evidence, logs, errors, or exports. The pinned image digest is recorded for
reproducibility. Scope is enforced by the orchestrator before this runs; ZAP —
not our worker — reaches the target, and only in-scope targets get here.

Cancellation (§2.10): every poll loop checks the CancelToken and, when tripped,
stops the in-flight spider and returns a `cancelled` result so a partial scan is
never mistaken for a complete one.

MVP scope: passive baseline (spider + passive rules). Active/attack scanning is a
higher-intensity, approval-gated follow-up; CI uses the passive baseline on PRs
and reserves full scans for nightly (MVP_TASKS M3-W3/T1).
"""

import asyncio
from typing import Any

import httpx

from app.core.config import get_settings
from app.models.finding import Severity
from app.scanners.base import (
    NormalizedFinding,
    ScannerConfig,
    ScannerError,
    ScannerPrerequisiteError,
    ScannerResult,
    ScannerTarget,
)
from app.workers.execution import CancelToken

_ZAP_RISK = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFORMATIONAL,
}
_POLL_INTERVAL_S = 1.0
_DEFAULT_SPIDER_MAX_CHILDREN = 10
_DEFAULT_MAX_WAIT_S = 240.0


class ZapScanner:
    name = "zap"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        image_digest: str | None = None,
    ) -> None:
        # Fetch Settings only for values not explicitly provided (so tests can
        # construct the adapter without loading Settings / a live daemon).
        if base_url is None or api_key is None or image_digest is None:
            s = get_settings()
            base_url = base_url if base_url is not None else s.zap_api_url
            api_key = api_key if api_key is not None else s.zap_api_key.get_secret_value()
            image_digest = image_digest if image_digest is not None else s.zap_image_digest
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._image_digest = image_digest

    def version(self) -> str:
        # The live daemon version is read in scan(); this is the offline best-effort
        # identity (the pinned image), never a network call.
        return self._image_digest or "zaproxy"

    def validate_prerequisites(self) -> None:
        # Sync, no network: the reachability check happens in scan() and fails loud.
        if not self._api_key:
            raise ScannerPrerequisiteError("ZAP API key not configured (ZAP_API_KEY)")
        if not self._base:
            raise ScannerPrerequisiteError("ZAP API URL not configured (ZAP_API_URL)")

    async def scan(
        self, target: ScannerTarget, config: ScannerConfig, cancel: CancelToken
    ) -> tuple[ScannerResult, bytes]:
        url = target.primary_value
        max_children = int(config.params.get("spider_max_children", _DEFAULT_SPIDER_MAX_CHILDREN))
        max_wait_s = float(config.params.get("max_wait_s", _DEFAULT_MAX_WAIT_S))
        persisted = {
            "zap_mode": "baseline",
            "base_url": self._base,  # internal daemon URL — not a secret
            "spider_max_children": max_children,
            "rate_limit_rps": config.rate_limit_rps,
            "image_digest": self._image_digest,
        }

        cancelled = False
        raw = b""
        findings: list[NormalizedFinding] = []
        version = self._image_digest or "unknown"
        async with httpx.AsyncClient(base_url=self._base, timeout=30.0) as client:
            try:
                version = await self._version(client)
                # Access the target so ZAP proxies + passively scans the response.
                await self._get(
                    client, "/JSON/core/action/accessUrl/", url=url, followRedirects="true"
                )
                scan_id = await self._spider_start(client, url, max_children)
                cancelled = await self._await_or_cancel(
                    client, cancel, max_wait_s, spider_id=scan_id
                )
                if not cancelled:
                    raw, alerts = await self._alerts(client, url)
                    findings = [self._to_finding(a) for a in alerts]
            except httpx.HTTPError as exc:
                raise ScannerError(f"ZAP API error: {exc}") from exc

        result = ScannerResult(
            scanner_name=self.name,
            scanner_version=version,
            findings=tuple(findings),
            config=persisted,
            raw_content_type="application/json",
            image_digest=self._image_digest or None,
            rules_digest=None,
            os_process_group=None,  # daemon-driven; no worker-side subprocess
            cancelled=cancelled,
            metadata={"alert_count": len(findings)},
        )
        return result, raw

    # ── ZAP API helpers ──────────────────────────────────────────────────────
    async def _get(self, client: httpx.AsyncClient, path: str, **params: str) -> dict[str, Any]:
        resp = await client.get(path, params={"apikey": self._api_key, **params})
        resp.raise_for_status()
        return resp.json()

    async def _version(self, client: httpx.AsyncClient) -> str:
        return str((await self._get(client, "/JSON/core/view/version/")).get("version", "unknown"))

    async def _spider_start(self, client: httpx.AsyncClient, url: str, max_children: int) -> str:
        data = await self._get(
            client,
            "/JSON/spider/action/scan/",
            url=url,
            maxChildren=str(max_children),
            recurse="true",
        )
        return str(data.get("scan", "0"))

    async def _await_or_cancel(
        self, client: httpx.AsyncClient, cancel: CancelToken, max_wait_s: float, *, spider_id: str
    ) -> bool:
        """Wait for the spider to finish AND the passive-scan queue to drain,
        checking the CancelToken each poll. Returns True if cancelled."""
        waited = 0.0
        # Spider progress.
        while waited < max_wait_s:
            if cancel.cancelled:
                await self._spider_stop(client, spider_id)
                return True
            status = (await self._get(client, "/JSON/spider/view/status/", scanId=spider_id)).get(
                "status", "0"
            )
            if str(status) == "100":
                break
            await asyncio.sleep(_POLL_INTERVAL_S)
            waited += _POLL_INTERVAL_S
        # Passive-scan queue drain.
        while waited < max_wait_s:
            if cancel.cancelled:
                return True
            recs = (await self._get(client, "/JSON/pscan/view/recordsToScan/")).get(
                "recordsToScan", "0"
            )
            if str(recs) == "0":
                break
            await asyncio.sleep(_POLL_INTERVAL_S)
            waited += _POLL_INTERVAL_S
        return False

    async def _spider_stop(self, client: httpx.AsyncClient, spider_id: str) -> None:
        try:
            await self._get(client, "/JSON/spider/action/stop/", scanId=spider_id)
        except httpx.HTTPError:
            pass  # best-effort stop; the run is being torn down regardless

    async def _alerts(self, client: httpx.AsyncClient, url: str) -> tuple[bytes, list[dict]]:
        resp = await client.get(
            "/JSON/core/view/alerts/", params={"apikey": self._api_key, "baseurl": url}
        )
        resp.raise_for_status()
        return resp.content, resp.json().get("alerts", [])

    def _to_finding(self, alert: dict[str, Any]) -> NormalizedFinding:
        name = str(alert.get("alert") or alert.get("name") or "ZAP alert")
        risk = _ZAP_RISK.get(str(alert.get("risk", "Informational")), Severity.INFORMATIONAL)
        plugin = str(alert.get("pluginId") or alert.get("pluginid") or "")
        a_url = alert.get("url", "")
        method = alert.get("method")
        param = alert.get("param")
        fingerprint = f"zap:{plugin}:{name}:{method}:{a_url}:{param}"
        return NormalizedFinding(
            fingerprint=fingerprint,
            title=name,
            message=str(alert.get("description") or name).strip()[:2000] or name,
            severity=risk,
            rule_id=f"zap.{plugin}" if plugin else "zap.alert",
            location={
                "url": a_url,
                "method": method,
                "param": param,
                "evidence": alert.get("evidence"),
                "cweid": alert.get("cweid"),
                "wascid": alert.get("wascid"),
                "confidence": alert.get("confidence"),
            },
            description=str(alert.get("description") or "").strip() or None,
            recommendation=str(alert.get("solution") or "").strip() or None,
        )
