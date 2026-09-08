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

One daemon, one scan at a time (sec-17): the daemon is SHARED across worker
processes, and the per-run Host-pin replacer rule (sec-14) is global daemon
state — two concurrent scans would rewrite each other's Host headers and taint
each other's evidence. Every scan therefore holds a cross-process Valkey lock on
the daemon for its whole duration; the rule is additionally restricted to the
exact pinned origin and to the two request initiators the baseline uses; a daemon
found holding a stale pin rule is cleaned before use or refused; and a cleanup
that fails is a daemon-health failure that fails THIS run loud (the next run's
pre-check then refuses the daemon until the rule is gone).
# ponytail: serializing on one daemon caps DAST throughput at one scan at a time;
# a ZAP-instance-per-scan pool is the upgrade if that ever matters.

Cancellation (§2.10): every poll loop checks the CancelToken and, when tripped,
stops the in-flight spider and returns a `cancelled` result so a partial scan is
never mistaken for a complete one.

MVP scope: passive baseline (spider + passive rules). Active/attack scanning is a
higher-intensity, approval-gated follow-up; CI uses the passive baseline on PRs
and reserves full scans for nightly (MVP_TASKS M3-W3/T1).
"""

import asyncio
import ipaddress
import re
import time
import uuid
from typing import Any, Protocol

import httpx
from redis.asyncio import Redis
from redis.exceptions import LockNotOwnedError, RedisError

from app.core.config import WEAK_SECRETS, get_settings
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

# Host-pin replacer rules (sec-14) are named with this prefix so a stale one left
# by a crashed run is recognizable — and removable — before the daemon is reused.
_PIN_RULE_PREFIX = "das-host-pin-"
# ZAP HttpSender initiators the baseline sends requests through: 3 = SPIDER,
# 6 = MANUAL_REQUEST (core/action/accessUrl). The pin rule applies to nothing else.
_PIN_RULE_INITIATORS = "3,6"
# The daemon lock outlives the longest possible scan (max_wait_s + API calls) by a
# wide margin; it is a crash backstop, not the release path.
_LOCK_TTL_MARGIN_S = 600.0
_LOCK_POLL_S = 1.0


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _pinned_origin_regex(url: httpx.URL) -> str:
    """Regex matching ONLY URLs under the pinned origin ZAP is driven at, so the
    Host-pin rule can never rewrite a request to any other host. The port is
    optional in the pattern because ZAP may render the scheme default port either
    way."""
    port = url.port or (443 if url.scheme == "https" else 80)
    return rf"^{re.escape(url.scheme)}://{re.escape(url.host)}(?::{port})?(?:/.*)?$"


class ZapDaemonLock(Protocol):
    """Cross-process mutex on the shared ZAP daemon."""

    async def acquire(self, cancel: CancelToken) -> bool:
        """True once held; False if the run was cancelled while waiting."""
        ...

    async def release(self) -> None: ...


class ValkeyZapDaemonLock:
    """Production lock: a Valkey `SET NX PX` mutex (redis-py Lock) so scans in any
    worker process take turns on the daemon. Fail-closed: a lock backend error
    refuses the scan rather than running unserialized."""

    def __init__(
        self,
        cache: Redis,
        *,
        ttl_s: float,
        wait_s: float,
        key: str = "zap:daemon",
        owns_cache: bool = False,
    ) -> None:
        self._cache = cache
        self._owns_cache = owns_cache
        self._lock = cache.lock(key, timeout=ttl_s, blocking=False)
        self._wait_s = wait_s

    async def acquire(self, cancel: CancelToken) -> bool:
        deadline = time.monotonic() + self._wait_s
        while True:
            if cancel.cancelled:
                return False
            try:
                if await self._lock.acquire(blocking=False):
                    return True
            except RedisError as exc:
                raise ScannerError(
                    "ZAP daemon lock unavailable (Valkey); refusing to scan"
                ) from exc
            if time.monotonic() >= deadline:
                raise ScannerError(
                    f"timed out after {self._wait_s:.0f}s waiting for the shared ZAP daemon"
                )
            await asyncio.sleep(_LOCK_POLL_S)

    async def release(self) -> None:
        try:
            await self._lock.release()
        except LockNotOwnedError as exc:
            # The TTL backstop fired mid-scan: another run may have shared the
            # daemon with this one. Surface it — the evidence may be tainted.
            raise ScannerError("ZAP daemon lock expired during the scan") from exc
        except RedisError as exc:
            raise ScannerError("ZAP daemon lock release failed (Valkey)") from exc
        finally:
            if self._owns_cache:
                await self._cache.aclose()


class ZapScanner:
    name = "zap"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        image_digest: str | None = None,
        lock: ZapDaemonLock | None = None,
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
        self._lock = lock  # None → a Valkey lock built per scan from Settings

    def version(self) -> str:
        # The live daemon version is read in scan(); this is the offline best-effort
        # identity (the pinned image), never a network call.
        return self._image_digest or "zaproxy"

    def validate_prerequisites(self) -> None:
        # Sync, no network: the reachability check happens in scan() and fails loud.
        if not self._api_key:
            raise ScannerPrerequisiteError("ZAP API key not configured (ZAP_API_KEY)")
        # A known placeholder is not a credential — the ZAP daemon is dual-homed
        # onto the targets network, so a default/empty key would let a popped lab
        # drive the scanner (sec-5). Refuse to run rather than scan on a weak key.
        if self._api_key.strip().casefold() in WEAK_SECRETS:
            raise ScannerPrerequisiteError(
                "ZAP API key is a known-weak default (ZAP_API_KEY); set a strong unique key "
                "before running scans"
            )
        if not self._base:
            raise ScannerPrerequisiteError("ZAP API URL not configured (ZAP_API_URL)")

    def _daemon_lock(self, max_wait_s: float) -> ZapDaemonLock:
        if self._lock is not None:
            return self._lock
        return ValkeyZapDaemonLock(
            Redis.from_url(get_settings().cache_url),
            ttl_s=max_wait_s + _LOCK_TTL_MARGIN_S,
            wait_s=max_wait_s + _LOCK_TTL_MARGIN_S,
            owns_cache=True,
        )

    async def scan(
        self, target: ScannerTarget, config: ScannerConfig, cancel: CancelToken
    ) -> tuple[ScannerResult, bytes]:
        target_url = httpx.URL(target.primary_value)
        target_host = target_url.host
        # DNS-rebinding pin (sec-14, CWE-918): ZAP resolves hostnames ITSELF, so the
        # address the scope keystone vetted is not the address ZAP would connect to.
        # The framework resolves + scope-vets the host immediately before this run
        # and passes the vetted IP as `pinned_ip`; every URL handed to ZAP uses that
        # IP, with the original hostname carried in the Host header via a replacer
        # rule. A hostname target with no pin is refused — fail closed, never an
        # unpinned scan. An IP-literal target cannot rebind and needs no pin.
        pinned_ip = str(config.params.get("pinned_ip") or "") or None
        host_header: str | None = None
        if _is_ip_literal(target_host):
            url = str(target_url)
        elif pinned_ip is None:
            raise ScannerError(
                f"refusing to scan hostname target {target_host!r} without a vetted pinned IP "
                "(sec-14 DNS-rebinding guard); the scan framework supplies params.pinned_ip"
            )
        else:
            url = str(target_url.copy_with(host=pinned_ip))
            host_header = target_url.netloc.decode("ascii")
        max_children = int(config.params.get("spider_max_children", _DEFAULT_SPIDER_MAX_CHILDREN))
        max_wait_s = float(config.params.get("max_wait_s", _DEFAULT_MAX_WAIT_S))
        persisted = {
            "zap_mode": "baseline",
            "base_url": self._base,  # internal daemon URL — not a secret
            "spider_max_children": max_children,
            "rate_limit_rps": config.rate_limit_rps,
            "image_digest": self._image_digest,
            # The exact connect address for the audit trail: the vetted IP ZAP was
            # pinned to, and the hostname it stands for (sec-14).
            "target_host": target_host,
            "pinned_ip": pinned_ip,
            "daemon_serialized": True,  # held the cross-process daemon lock (sec-17)
        }

        def _result(
            *, findings: list[NormalizedFinding], version: str, cancelled: bool
        ) -> ScannerResult:
            return ScannerResult(
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

        # Serialize on the shared daemon BEFORE touching it (sec-17). Waiting is
        # cancellable: an emergency stop while queued returns a cancelled result.
        lock = self._daemon_lock(max_wait_s)
        if not await lock.acquire(cancel):
            version = self._image_digest or "unknown"
            return _result(findings=[], version=version, cancelled=True), b""
        try:
            return await self._scan_locked(
                url=url,
                host_header=host_header,
                target_url=target_url,
                pinned_ip=pinned_ip,
                max_children=max_children,
                max_wait_s=max_wait_s,
                cancel=cancel,
                result=_result,
            )
        finally:
            await lock.release()

    async def _scan_locked(
        self,
        *,
        url: str,
        host_header: str | None,
        target_url: httpx.URL,
        pinned_ip: str | None,
        max_children: int,
        max_wait_s: float,
        cancel: CancelToken,
        result,
    ) -> tuple[ScannerResult, bytes]:
        cancelled = False
        raw = b""
        findings: list[NormalizedFinding] = []
        version = self._image_digest or "unknown"
        # Auth via the X-ZAP-API-Key header, not an `apikey` query param — the key
        # must not land in the ZAP daemon's request/access logs or any URL (SEC-DEBT-14).
        async with httpx.AsyncClient(
            base_url=self._base,
            timeout=30.0,
            headers={"X-ZAP-API-Key": self._api_key},
        ) as client:
            pin_rule: str | None = None
            try:
                version = await self._version(client)
                # Daemon health (sec-17): a Host-pin rule left behind by an earlier
                # run would rewrite THIS run's requests. Under the lock nothing else
                # is running, so a stale rule is removed here; one that will not go
                # is a daemon we refuse to reuse.
                await self._assert_no_stale_pin_rules(client)
                if host_header is not None:
                    # Carry the real hostname to the target while the socket goes to
                    # the pinned IP (sec-14). The rule is scoped to this run's pinned
                    # origin and to the spider/accessUrl initiators only, is unique
                    # per run, and is removed in the finally below. If the replacer
                    # add-on is missing this raises → the run FAILS rather than
                    # scanning unpinned (fail closed).
                    pin_rule = f"{_PIN_RULE_PREFIX}{uuid.uuid4().hex[:12]}"
                    await self._get(
                        client,
                        "/JSON/replacer/action/addRule/",
                        description=pin_rule,
                        enabled="true",
                        matchType="REQ_HEADER",
                        matchRegex="false",
                        matchString="Host",
                        replacement=host_header,
                        initiators=_PIN_RULE_INITIATORS,
                        url=_pinned_origin_regex(target_url.copy_with(host=pinned_ip or "")),
                    )
                # Access the target so ZAP proxies + passively scans the response.
                # followRedirects is OFF (sec-3): only the scope-authorized URL was
                # vetted, so a malicious in-scope target must not be able to bounce
                # ZAP — a dual-homed daemon — to an internal or out-of-scope service
                # via a Location header. The spider (seeded from the same URL) stays
                # within the target's scope for any legitimate same-origin redirects.
                await self._get(
                    client, "/JSON/core/action/accessUrl/", url=url, followRedirects="false"
                )
                scan_id = await self._spider_start(client, url, max_children)
                cancelled = await self._await_or_cancel(
                    client, cancel, max_wait_s, spider_id=scan_id
                )
                if not cancelled:
                    raw, alerts = await self._alerts(client, url)
                    # Tool output is hostile (TM-8): skip any non-dict alert so a
                    # crafted daemon response can't raise and crash the run.
                    findings = [self._to_finding(a) for a in alerts if isinstance(a, dict)]
            except httpx.HTTPError as exc:
                raise ScannerError(f"ZAP API error: {exc}") from exc
            finally:
                if pin_rule is not None:
                    # A rule we cannot prove removed is a daemon-health failure: the
                    # daemon would rewrite the NEXT run's Host headers. Fail this run
                    # loud (never swallowed); the next run's pre-check refuses the
                    # daemon until the rule is actually gone.
                    await self._remove_pin_rule(client, pin_rule)

        return result(findings=findings, version=version, cancelled=cancelled), raw

    # ── ZAP API helpers ──────────────────────────────────────────────────────
    async def _get(self, client: httpx.AsyncClient, path: str, **params: str) -> dict[str, Any]:
        resp = await client.get(path, params=params)
        resp.raise_for_status()
        # Tool output is hostile (TM-8): a non-JSON body fails safe as a scan error,
        # a non-dict body degrades to {} so callers' .get(...) defaults apply.
        try:
            body = resp.json()
        except ValueError as exc:
            raise ScannerError(f"ZAP {path} response not valid JSON: {exc}") from exc
        return body if isinstance(body, dict) else {}

    async def _version(self, client: httpx.AsyncClient) -> str:
        return str((await self._get(client, "/JSON/core/view/version/")).get("version", "unknown"))

    async def _pin_rules(self, client: httpx.AsyncClient) -> list[str]:
        rules = (await self._get(client, "/JSON/replacer/view/rules/")).get("rules")
        return [
            str(r["description"])
            for r in (rules if isinstance(rules, list) else [])
            if isinstance(r, dict) and str(r.get("description", "")).startswith(_PIN_RULE_PREFIX)
        ]

    async def _assert_no_stale_pin_rules(self, client: httpx.AsyncClient) -> None:
        try:
            stale = await self._pin_rules(client)
            for description in stale:
                await self._get(
                    client, "/JSON/replacer/action/removeRule/", description=description
                )
            remaining = await self._pin_rules(client) if stale else []
        except httpx.HTTPError as exc:
            raise ScannerError(
                "ZAP daemon health check failed (could not read/clean replacer rules); "
                f"refusing to reuse the daemon: {exc}"
            ) from exc
        if remaining:
            raise ScannerError(
                f"ZAP daemon holds {len(remaining)} stale Host-pin rule(s) that could not be "
                "removed; refusing to reuse the daemon until it is cleaned/restarted"
            )

    async def _remove_pin_rule(self, client: httpx.AsyncClient, description: str) -> None:
        try:
            await self._get(client, "/JSON/replacer/action/removeRule/", description=description)
            remaining = await self._pin_rules(client)
        except (httpx.HTTPError, ScannerError) as exc:
            raise ScannerError(
                f"ZAP Host-pin rule cleanup failed ({exc}); daemon must not be reused until "
                "the rule is removed"
            ) from exc
        if description in remaining:
            raise ScannerError(
                "ZAP Host-pin rule still present after removal; daemon must not be reused "
                "until the rule is removed"
            )

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
        resp = await client.get("/JSON/core/view/alerts/", params={"baseurl": url})
        resp.raise_for_status()
        try:
            body = resp.json()
        except ValueError as exc:
            raise ScannerError(f"ZAP alerts response not valid JSON: {exc}") from exc
        alerts = body.get("alerts") if isinstance(body, dict) else None
        return resp.content, alerts if isinstance(alerts, list) else []

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
