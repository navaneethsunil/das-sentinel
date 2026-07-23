"""Run the configured scanners for one scan and persist findings (M3-W1).

The scanner-side sibling of workers/suite_run.py. This is the payload the
execution owner launches for a scanner scan — the wire that turns a launched scan
into evidence-backed findings. It reads the scan's frozen envelope to learn which
scanners were authorized, and for each one drives the uniform framework path:

    validate_prerequisites → build_command → launch the tool through a killable,
    confined SubprocessOwner (M2-W3) → capture raw output → normalize → persist a
    scanner_runs row + raw evidence + automated findings.

Scope is already enforced before this runs: the orchestrator re-derives
authorization via the scope keystone (which checks scope/window/intensity)
BEFORE launching the owner, so the adapter trusts nothing and never re-validates
scope itself (CLAUDE.md §6). The engagement's aggregate `rate_limit_rps` is passed
into each adapter so it can set the tool's NATIVE throttle as a floor; enforcing
that ceiling in aggregate across concurrent runs and inside opaque scanner daemons
is the network-level egress-shaper seam (M2-SEC1, hardening) — an opaque
subprocess tool's own sockets are not app-interceptable, unlike our LLM connector.

`build_scanner_owner` wraps `run_scanners` into the in-process thunk
`InProcessOwner` launches, exactly like `build_suite_owner`, so orchestration and
emergency stop treat a scanner scan uniformly: the outer cancel token is checked
between scanners and propagated to SIGTERM/SIGKILL the in-flight tool.
"""

import asyncio
import contextlib
import shutil
import tempfile
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.sessions import utcnow
from app.models.engagement import Engagement
from app.models.evidence import Evidence, EvidenceKind
from app.models.scan import ExecutionAuthorization, Scan, ScanStatus
from app.models.scanner import ScannerRun
from app.models.target import Target
from app.scanners.base import (
    OutputMode,
    RawScannerResult,
    ScannerAdapter,
    ScannerConfig,
    ScannerError,
    ScannerResult,
)
from app.scanners.semgrep import SemgrepScanner
from app.scanners.stub import StubScanner
from app.services.scanner_findings import create_findings_from_scanner
from app.storage.evidence import BlobStore, store_evidence
from app.workers.execution import (
    CancelToken,
    ExecutionOwner,
    InProcessOwner,
    RunHandle,
    RunOutcome,
    RunSpec,
    SubprocessOwner,
)

# One adapter factory per registered scanner. Semgrep (M3-W2) and ZAP (M3-W3)
# register here; the stub proves the framework in M3-W1.
_SCANNER_ADAPTERS: dict[str, Callable[[], ScannerAdapter]] = {
    StubScanner.name: StubScanner,
    SemgrepScanner.name: SemgrepScanner,
}


class ScannerRunError(Exception):
    """A precondition the scanner run cannot proceed past (missing scan/envelope,
    or an envelope naming an unknown scanner). Surfaced as a failed run."""


def scanners_from_config(normalized_config: dict) -> list[str]:
    """Resolve the ordered, de-duplicated scanners frozen in the envelope. Fails
    loud on an unknown scanner — the worker never silently skips authorized work."""
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in normalized_config.get("scanners", []):
        name = str(raw)
        if name not in _SCANNER_ADAPTERS:
            raise ScannerRunError(f"envelope names unknown scanner {name!r}")
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    if not ordered:
        raise ScannerRunError("envelope configures no runnable scanners")
    return ordered


async def _await_or_cancel(
    owner: ExecutionOwner, handle: RunHandle, cancel: CancelToken, poll_s: float
) -> RunOutcome | None:
    """Await one tool while watching the cancel token. Returns the RunOutcome on
    completion, or None if the run was cancelled (the tool is SIGTERM/SIGKILLed
    within the poll cadence). This gives mid-tool killability (§2.10)."""
    completion: asyncio.Task[RunOutcome] = asyncio.ensure_future(owner.await_completion(handle))
    try:
        while True:
            if cancel.cancelled:
                await owner.cancel(handle)
                return None
            done, _pending = await asyncio.wait({completion}, timeout=poll_s)
            if completion in done:
                return completion.result()
    finally:
        if not completion.done():
            completion.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await completion


async def _run_one_scanner(
    adapter: ScannerAdapter,
    target: Target,
    *,
    rate_limit_rps: int,
    scanner_params: dict,
    scan_id: uuid.UUID,
    cancel: CancelToken,
    poll_s: float,
) -> tuple[ScannerResult, bytes]:
    """Framework execution of a single scanner: validate → build → launch through a
    fresh killable SubprocessOwner → capture raw → normalize. Returns the
    normalized result AND the verbatim raw output bytes (stored immutably as
    evidence by the caller). Never raises for a successful-but-nonzero-exit tool
    (scanners legitimately exit nonzero when they find issues); a genuine tool
    error is captured in `ScannerResult.error`."""
    adapter.validate_prerequisites()
    config = ScannerConfig(rate_limit_rps=rate_limit_rps, params=scanner_params)
    inv = adapter.build_command(target, config)

    owner = SubprocessOwner()
    workdir: str | None = None
    if inv.output_mode is OutputMode.FILE:
        workdir = tempfile.mkdtemp(prefix="dassscan-")  # framework-owned; read then wipe
    spec = RunSpec(
        label=f"{scan_id}:{adapter.name}",
        argv=inv.argv,
        env=inv.env,
        timeout_s=inv.timeout_s,
        workdir=workdir,
    )
    os_process_group: int | None = None
    cancelled = False
    outcome: RunOutcome | None = None
    handle: RunHandle | None = None
    raw_output = b""
    try:
        handle = await owner.launch(spec)
        with contextlib.suppress(ValueError):
            os_process_group = int(handle.runner_ref)
        outcome = await _await_or_cancel(owner, handle, cancel, poll_s)
        cancelled = outcome is None
        if not cancelled and outcome is not None:
            raw_output = _read_raw(outcome, inv, workdir)
    finally:
        if handle is not None:
            await owner.teardown(handle)
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)

    def _result(*, findings: tuple, error: str | None) -> ScannerResult:
        return ScannerResult(
            scanner_name=adapter.name,
            scanner_version=adapter.version(),
            findings=findings,
            config=inv.persisted_config,
            raw_content_type=inv.raw_content_type,
            image_digest=inv.image_digest,
            rules_digest=inv.rules_digest,
            os_process_group=os_process_group,
            cancelled=cancelled,
            error=error,
        )

    if cancelled:
        return _result(findings=(), error=None), b""

    error: str | None = None
    findings: tuple = ()
    try:
        raw = RawScannerResult(
            exit_code=outcome.exit_code if outcome else None,
            output=raw_output,
            stderr=outcome.stderr if outcome else b"",
        )
        findings = tuple(adapter.normalize(raw))
    except ScannerError as exc:
        error = str(exc)
    return _result(findings=findings, error=error), raw_output


def _read_raw(outcome: RunOutcome, inv, workdir: str | None) -> bytes:
    """Raw report bytes: stdout for STDOUT mode, the report file for FILE mode."""
    if inv.output_mode is OutputMode.STDOUT:
        return outcome.stdout
    if workdir is not None and inv.output_filename is not None:
        path = Path(workdir) / inv.output_filename
        if path.is_file():
            return path.read_bytes()
    return b""


async def run_scanners(
    sessionmaker: async_sessionmaker[AsyncSession],
    store: BlobStore,
    *,
    scan_id: uuid.UUID,
    now: datetime,
    cancel: CancelToken,
    poll_s: float | None = None,
) -> RunOutcome:
    """Run every configured scanner against the scan's target and persist findings.

    A completed run is `ok=True` regardless of how many findings surfaced. A run
    the CancelToken halted mid-scan reports `ok=False, detail='cancelled'` so
    orchestration finalizes it `cancelled`."""
    settings = get_settings()
    poll = poll_s if poll_s is not None else settings.scan_cancel_poll_seconds

    async with sessionmaker() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            raise ScannerRunError(f"scan {scan_id} missing")
        envelope = (
            await db.execute(
                select(ExecutionAuthorization).where(ExecutionAuthorization.scan_id == scan_id)
            )
        ).scalar_one_or_none()
        if envelope is None:
            raise ScannerRunError(f"execution envelope for scan {scan_id} missing")
        scanners = scanners_from_config(envelope.normalized_config)
        scanner_params: dict = envelope.normalized_config.get("scanner_config", {})
        target = await db.get(Target, scan.target_id)
        if target is None:
            raise ScannerRunError(f"target {scan.target_id} missing")
        engagement = await db.get(Engagement, scan.engagement_id)
        if engagement is None:
            raise ScannerRunError(f"engagement {scan.engagement_id} missing")
        rate_limit_rps = engagement.rate_limit_rps
        engagement_id = scan.engagement_id
        db.expunge_all()

    total_findings = 0
    cancelled = False
    for name in scanners:
        if cancel.cancelled:
            cancelled = True
            break
        adapter = _SCANNER_ADAPTERS[name]()
        result, raw_output = await _run_one_scanner(
            adapter,
            target,
            rate_limit_rps=rate_limit_rps,
            scanner_params=scanner_params.get(name, {}),
            scan_id=scan_id,
            cancel=cancel,
            poll_s=poll,
        )
        total_findings += await _persist_scanner_run(
            sessionmaker,
            store,
            scan_id=scan_id,
            engagement_id=engagement_id,
            result=result,
            raw_output=raw_output,
            now=now,
        )
        if result.cancelled:
            cancelled = True
            break

    if cancelled:
        return RunOutcome(ok=False, detail="cancelled")
    return RunOutcome(
        ok=True, detail=f"{total_findings} finding(s) across {len(scanners)} scanner(s)"
    )


async def _persist_scanner_run(
    sessionmaker: async_sessionmaker[AsyncSession],
    store: BlobStore,
    *,
    scan_id: uuid.UUID,
    engagement_id: uuid.UUID,
    result: ScannerResult,
    raw_output: bytes,
    now: datetime,
) -> int:
    """Record one scanner_runs row (with its raw evidence) and its findings in a
    single committed transaction. The verbatim raw tool output is stored FIRST as
    immutable, content-addressed evidence (kind raw_scanner_output), and every
    finding cites it. Returns the number of findings created/reused."""
    async with sessionmaker() as db:
        engagement = await db.get(Engagement, engagement_id)
        scan = await db.get(Scan, scan_id)
        target = await db.get(Target, scan.target_id)

        raw_evidence: Evidence | None = None
        if not result.cancelled and raw_output:
            raw_evidence = await store_evidence(
                db,
                store,
                organization_id=engagement.organization_id,
                content=raw_output,
                kind=EvidenceKind.RAW_SCANNER_OUTPUT,
                content_type=result.raw_content_type,
            )

        status = (
            ScanStatus.CANCELLED
            if result.cancelled
            else (ScanStatus.FAILED if result.error else ScanStatus.COMPLETED)
        )
        scanner_run = ScannerRun(
            scan_id=scan_id,
            scanner_name=result.scanner_name,
            scanner_version=result.scanner_version,
            image_digest=result.image_digest,
            rules_digest=result.rules_digest,
            config=result.config,
            status=status,
            os_process_group=result.os_process_group,
            raw_evidence_id=raw_evidence.id if raw_evidence is not None else None,
            started_at=now,
            finished_at=now,
            error_summary=result.error,
        )
        db.add(scanner_run)
        await db.flush()

        findings = await create_findings_from_scanner(
            db,
            engagement=engagement,
            target=target,
            scan=scan,
            scanner_run=scanner_run,
            result=result,
            raw_evidence=raw_evidence,
            now=now,
        )
        await db.commit()
        return len(findings)


def build_scanner_owner(
    sessionmaker: async_sessionmaker[AsyncSession],
    store: BlobStore,
    *,
    scan_id: uuid.UUID,
    now: datetime | None = None,
    poll_s: float | None = None,
) -> InProcessOwner:
    """The execution owner for a scanner scan: an `InProcessOwner` that runs
    `run_scanners` under its cancel token. Orchestration launches it exactly like
    an LLM-suite scan (build_suite_owner), and emergency stop cancels it through
    the same token `run_scanners` checks between (and within) scanners. `poll_s`
    tunes how quickly an in-flight tool reacts to that token (defaults to
    Settings.scan_cancel_poll_seconds)."""
    stamp = now if now is not None else utcnow()

    def _run_fn(cancel: CancelToken) -> Awaitable[RunOutcome]:
        return run_scanners(
            sessionmaker, store, scan_id=scan_id, now=stamp, cancel=cancel, poll_s=poll_s
        )

    return InProcessOwner(_run_fn)
