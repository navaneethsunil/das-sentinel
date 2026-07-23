"""Uniform execution owner — one launch/cancel/teardown contract for every run
(M2-W3, CLAUDE.md §6/§6a).

A run (a scanner in M3, a PyRIT suite in M2-B3) is launched, watched, cancelled,
and torn down through a single `ExecutionOwner`. `SubprocessOwner` is the real
MVP implementation: it runs the payload in its **own process group** so the run
has a killable identity (the group-leader PID is recorded as the scan's
`runner_ref`, so emergency stop — M2-W2 — can terminate that exact tree), with
the confinement achievable inside the worker container today:

  - **No ambient secrets.** The child receives ONLY `RunSpec.env` — the worker's
    environment (DB password, LLM keys) is not inherited. Scoped, short-lived
    credentials are passed explicitly per run, never ambiently.
  - **No-new-privileges.** `PR_SET_NO_NEW_PRIVS` is set in the child pre-exec, so
    it cannot gain privileges through a setuid binary (best-effort off Linux).
  - **Resource limits.** RLIMIT_* caps (CPU, file size, open files, procs).
  - **Per-run scratch cwd** (0700), wiped on teardown.
  - **Verified teardown.** The process group is terminated (SIGTERM→SIGKILL) and
    the owner CONFIRMS the tree is gone before removing scratch; a teardown that
    cannot confirm raises — it is surfaced as a job error, never swallowed.

HARDENING SEAMS (M2-W3 follow-up — need a Linux host + a hardened base image +
the engagement egress shaper, M2-SEC1): a rootless container / user namespace,
all-capabilities-dropped, a seccomp profile, and egress ONLY via the engagement
egress shaper. These are the production containment; this owner delivers the
uniform contract and the in-container confinement, not yet the sandbox. It is not
network-isolated here — that lands with M2-SEC1.

`CancelToken` is the cooperative-cancel path for **in-process** suites (PyRIT is
a native library with no subprocess, so `killpg` can't select it — M2-B3 runs it
under a token checked between prompts/turns). `StubOwner` remains for tests and
for orchestration paths with no real payload.
"""

import asyncio
import contextlib
import ctypes
import os
import resource
import shutil
import signal
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

# prctl option number (Linux); harmless no-op call elsewhere (guarded).
_PR_SET_NO_NEW_PRIVS = 38

# Conservative default per-run resource ceilings (seconds / bytes / counts).
_DEFAULT_RLIMITS: tuple[tuple[int, int], ...] = (
    (resource.RLIMIT_FSIZE, 512 * 1024 * 1024),
    (resource.RLIMIT_NOFILE, 256),
    (resource.RLIMIT_NPROC, 128),
)


class ExecutionError(Exception):
    """Base for execution-owner failures."""


class ExecutionTeardownError(ExecutionError):
    """Teardown could not confirm the run's process tree is gone. Surfaced as a
    job error — a run we cannot prove is dead is a safety failure (§2.10)."""


# Cap on how much of a child's stdout/stderr is retained on the RunOutcome (a
# runaway/malicious tool can emit unbounded output — TM-12). The full raw report
# for a scanner should be written to a file in `workdir` instead; captured
# streams are for stdout-mode tools (Semgrep `--json`) and failure detail.
_MAX_CAPTURED_STREAM_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class RunSpec:
    """What to launch. `env` is the COMPLETE environment the child sees — pass
    only scoped, non-secret values; nothing from the worker is inherited.

    `workdir`, when set, is a caller-owned working directory used as the child's
    cwd; the owner does NOT create or wipe it (the caller owns its lifecycle), so
    a file the tool writes there survives for the caller to read as evidence
    (file-mode scanners, M3-W3). When None the owner mints a private 0700 scratch
    dir and wipes it on teardown (the default; stdout-mode tools)."""

    label: str
    argv: list[str]
    env: dict[str, str] = field(default_factory=dict)
    scratch_prefix: str = "dassrun-"
    timeout_s: float = 300.0
    workdir: str | None = None


@dataclass(frozen=True)
class RunHandle:
    runner_ref: str  # group-leader PID (or container id) recorded on the scan


@dataclass(frozen=True)
class RunOutcome:
    ok: bool
    detail: str | None = None
    # Captured child streams (bounded). Empty for in-process/stub owners; a
    # subprocess scanner reads stdout here for stdout-mode tools (M3-W1).
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: int | None = None


class CancelToken:
    """Bounded cooperative cancellation for in-process suites (M2-B3): the suite
    checks it between prompts/turns and stops once tripped. `killpg` cannot
    selectively stop an embedded library, so this is its cancellation identity."""

    def __init__(self) -> None:
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled


class ExecutionOwner(Protocol):
    async def launch(self, spec: RunSpec) -> RunHandle: ...

    async def await_completion(self, handle: RunHandle) -> RunOutcome: ...

    async def cancel(self, handle: RunHandle) -> None: ...

    async def teardown(self, handle: RunHandle) -> None: ...


def _child_preexec(rlimits: tuple[tuple[int, int], ...]) -> Callable[[], None]:
    """Return a preexec_fn (runs in the forked child, before exec): set
    no-new-privileges and resource limits. Every step is best-effort — a
    platform without a given primitive degrades, it does not crash the launch."""

    def _apply() -> None:
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        except (OSError, AttributeError):
            # non-Linux / no libc: no-new-privileges is a Linux-only hardening,
            # its absence degrades containment but must not fail the launch.
            pass
        for res, limit in rlimits:
            try:
                resource.setrlimit(res, (limit, limit))
            except (ValueError, OSError):
                pass

    return _apply


@dataclass
class _RunState:
    proc: asyncio.subprocess.Process
    pgid: int
    scratch: Path
    spec: RunSpec
    owns_scratch: bool  # False when the caller supplied RunSpec.workdir


class SubprocessOwner:
    """Real per-run execution owner (M2-W3). See module docstring for the
    confinement it provides and the hardening seams it does not."""

    def __init__(self, rlimits: tuple[tuple[int, int], ...] = _DEFAULT_RLIMITS) -> None:
        self._rlimits = rlimits
        self._runs: dict[str, _RunState] = {}

    async def launch(self, spec: RunSpec) -> RunHandle:
        if spec.workdir is not None:
            scratch = Path(spec.workdir)  # caller-owned: not created, not wiped
            owns_scratch = False
        else:
            scratch = Path(tempfile.mkdtemp(prefix=spec.scratch_prefix))
            scratch.chmod(0o700)
            owns_scratch = True
        # Justified subprocess launch (S603 / semgrep dangerous-asyncio-create-exec):
        # exec form, shell=False, argv is a controlled RunSpec built by the
        # platform (placeholder now, PyRIT/scanner arg-vectors later — never string-
        # concatenated from target input, CLAUDE.md §6). Launching a child is the
        # whole point of the execution owner. Owner: workers/execution.
        proc = await asyncio.create_subprocess_exec(  # noqa: S603  # nosemgrep
            *spec.argv,
            cwd=str(scratch),
            env=spec.env,  # COMPLETE env — worker secrets are not inherited
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group → killable identity
            preexec_fn=_child_preexec(self._rlimits),
        )
        ref = str(proc.pid)
        self._runs[ref] = _RunState(
            proc=proc, pgid=proc.pid, scratch=scratch, spec=spec, owns_scratch=owns_scratch
        )
        return RunHandle(runner_ref=ref)

    async def await_completion(self, handle: RunHandle) -> RunOutcome:
        state = self._runs.get(handle.runner_ref)
        if state is None:
            return RunOutcome(ok=False, detail="run not found")
        try:
            stdout, stderr = await asyncio.wait_for(
                state.proc.communicate(), timeout=state.spec.timeout_s
            )
        except TimeoutError:
            await self._terminate(state)
            return RunOutcome(ok=False, detail=f"timeout after {state.spec.timeout_s}s")
        stdout = stdout[:_MAX_CAPTURED_STREAM_BYTES]
        stderr = stderr[:_MAX_CAPTURED_STREAM_BYTES]
        code = state.proc.returncode
        if code == 0:
            return RunOutcome(ok=True, stdout=stdout, stderr=stderr, exit_code=code)
        detail = stderr.decode("utf-8", "replace")[:500] or f"exit {code}"
        return RunOutcome(ok=False, detail=detail, stdout=stdout, stderr=stderr, exit_code=code)

    async def cancel(self, handle: RunHandle) -> None:
        state = self._runs.get(handle.runner_ref)
        if state is not None:
            await self._terminate(state)

    async def teardown(self, handle: RunHandle) -> None:
        state = self._runs.pop(handle.runner_ref, None)
        if state is None:
            return
        await self._terminate(state)
        if not await self._confirm_gone(state.pgid):
            raise ExecutionTeardownError(f"process group {state.pgid} still alive after SIGKILL")
        if state.owns_scratch:
            shutil.rmtree(state.scratch, ignore_errors=False)

    async def _terminate(self, state: _RunState) -> None:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(state.pgid, sig)
            except ProcessLookupError:
                return  # group already gone
            if await self._confirm_gone(state.pgid):
                return

    async def _confirm_gone(self, pgid: int, attempts: int = 20, delay: float = 0.05) -> bool:
        for _ in range(attempts):
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                return True
            await asyncio.sleep(delay)
        return False


@dataclass
class _InProcState:
    task: asyncio.Task
    token: CancelToken


class InProcessOwner:
    """Uniform execution owner for **in-process** suites (M2-B3). PyRIT is a native
    library embedded in the worker with no subprocess, so `killpg` cannot select
    it. This owner runs a provided coroutine under a `CancelToken` it holds, giving
    the suite the same launch/await/cancel/teardown identity a subprocess scanner
    has — so orchestration and emergency stop (M2-W2) treat both uniformly.

    `cancel` is **cooperative**, not a kill: a coroutine cannot be force-terminated
    mid-CPU, so "stopped" means the suite observed the token (checked between
    prompts/turns) and returned. `run_fn` receives THIS owner's token, so
    `owner.cancel(handle)` — what `signal_cancellation` calls — is exactly the
    token the suite is checking. Teardown confirms the task finished (the
    in-process analogue of SubprocessOwner "confirm the tree is gone") and, as a
    last-resort backstop, asyncio-cancels a task that ignores the token; a run that
    still cannot be confirmed stopped raises (surfaced, never swallowed — §2.10)."""

    def __init__(
        self,
        run_fn: Callable[[CancelToken], Awaitable[RunOutcome]],
        *,
        teardown_grace_s: float = 30.0,
    ) -> None:
        self._run_fn = run_fn
        self._grace = teardown_grace_s
        self._runs: dict[str, _InProcState] = {}

    async def launch(self, spec: RunSpec) -> RunHandle:
        token = CancelToken()
        task = asyncio.ensure_future(self._run_fn(token))
        ref = f"inproc:{spec.label}"
        self._runs[ref] = _InProcState(task=task, token=token)
        return RunHandle(runner_ref=ref)

    async def await_completion(self, handle: RunHandle) -> RunOutcome:
        state = self._runs.get(handle.runner_ref)
        if state is None:
            return RunOutcome(ok=False, detail="run not found")
        try:
            return await asyncio.shield(state.task)
        except asyncio.CancelledError:
            return RunOutcome(ok=False, detail="cancelled")
        except Exception as exc:  # noqa: BLE001 — runner faults surface as a failed run
            return RunOutcome(ok=False, detail=f"{type(exc).__name__}: {exc}")

    async def cancel(self, handle: RunHandle) -> None:
        state = self._runs.get(handle.runner_ref)
        if state is not None:
            state.token.cancel()  # cooperative — suite stops at its next turn check

    async def teardown(self, handle: RunHandle) -> None:
        state = self._runs.pop(handle.runner_ref, None)
        if state is None:
            return
        state.token.cancel()
        if not state.task.done():
            try:
                await asyncio.wait_for(asyncio.shield(state.task), timeout=self._grace)
            except TimeoutError:
                state.task.cancel()  # backstop for a token-ignoring suite
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await state.task
        if not state.task.done():
            raise ExecutionTeardownError(
                f"in-process run {handle.runner_ref} did not stop after cancel"
            )


class StubOwner:
    """No-op owner for tests and payload-free orchestration paths: records a
    deterministic runner ref and completes immediately without spawning
    anything."""

    async def launch(self, spec: RunSpec) -> RunHandle:
        return RunHandle(runner_ref=f"stub:{spec.label}")

    async def await_completion(self, handle: RunHandle) -> RunOutcome:
        return RunOutcome(ok=True)

    async def cancel(self, handle: RunHandle) -> None:
        return None

    async def teardown(self, handle: RunHandle) -> None:
        return None
