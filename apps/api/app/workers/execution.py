"""Uniform execution owner — one launch/cancel/teardown contract for every run
(M2-W3, CLAUDE.md §6/§6a).

A run (a scanner in M3, a PyRIT suite in M2-B3) is launched, watched, cancelled,
and torn down through a single `ExecutionOwner`. `SubprocessOwner` is the real
MVP implementation: it runs the payload in its **own process group** so the run
has a killable identity (the group-leader PID is recorded as the scan's
`runner_ref`, so emergency stop — M2-W2 — can terminate that exact tree), with:

  - **No ambient secrets.** The child receives ONLY `RunSpec.env` — the worker's
    environment (DB password, LLM keys) is not inherited. Scoped, short-lived
    credentials are passed explicitly per run, never ambiently.
  - **No-new-privileges.** `PR_SET_NO_NEW_PRIVS` is set in the child pre-exec, so
    it cannot gain privileges through a setuid binary (best-effort off Linux).
  - **Resource limits.** RLIMIT_* caps (CPU, file size, open files, procs).
  - **Per-run scratch cwd** (0700), wiped on teardown.
  - **Per-run namespace sandbox** (sec-15/sec-18, below): private user, PID,
    mount and network namespaces; egress ONLY to the run's vetted destinations.
  - **Verified teardown.** The process group is terminated (SIGTERM→SIGKILL) and
    the owner CONFIRMS the tree is gone before removing scratch and the run's
    network plumbing; a teardown that cannot confirm raises — it is surfaced as a
    job error, never swallowed.

`CancelToken` is the cooperative-cancel path for **in-process** suites (PyRIT is
a native library with no subprocess, so `killpg` can't select it — M2-B3 runs it
under a token checked between prompts/turns). `StubOwner` remains for tests and
for orchestration paths with no real payload.
"""

import asyncio
import contextlib
import ctypes
import enum
import functools
import ipaddress
import os
import resource
import secrets
import shutil
import signal
import subprocess
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


class SandboxUnavailableError(ExecutionError):
    """The deployment requires the per-run namespace sandbox but this host cannot
    provide it. Fail closed: the run is refused rather than launched with the
    worker's credentials readable from /proc or with the control plane reachable
    (sec-15 / sec-18)."""


# ── Per-run namespace sandbox (sec-15 + sec-18, CWE-653) ─────────────────────
# A scanner child parses hostile input (that is the product), so a parser RCE is
# the threat model. Every scanner child is wrapped in unprivileged namespaces and
# entered through app/workers/sandbox_entry.sh:
#   --user --map-root-user  new user ns (root ONLY inside it; uid 10001 outside):
#                           the child cannot ptrace/read any process in the parent
#                           ns (environ reads are EPERM). Root-in-ns is what lets
#                           the entry script mount; it drops every capability
#                           (empty bounding set) before exec'ing the tool.
#   --pid --fork            new PID ns → the worker's PIDs are not even visible,
#                           and the ns init's death reaps the whole tree (so no
#                           --kill-child, whose pidfd_open is ENOSYS under
#                           Rosetta-emulated amd64 dev containers)
#   --mount                 new mount ns → the entry script hides the shared /tmp
#                           under a private tmpfs (only the run's OWN scratch is
#                           re-bound), and pins /etc/hosts to the vetted names
#                           with an empty resolv.conf (no DNS). Copied mounts are
#                           kernel-locked, so no nested namespace can peek under.
#   --net                   new EMPTY network ns. Offline tools stay that way. A
#                           network scanner gets ONE veth the parent attaches,
#                           NAT'd through the container, with an nftables forward
#                           allowlist keyed on (child ip . destination ip): the
#                           scope-vetted target (+ declared online DBs) and nothing
#                           else — postgres/valkey/minio/api/zap are unroutable.
#                           The rules live in the WORKER's netns, which the child
#                           has no capability over.
# Results come back over the only channel the child has: its stdout/stderr pipes
# and the bind-mounted run workdir the parent owns and reads — no credential or
# control-plane access is ever handed to the tool.
# Parent-side requirements (compose `scanner-worker`): ambient CAP_NET_ADMIN via
# capsh, iproute2 + nftables, net.ipv4.ip_forward=1, and the vendored seccomp
# profile permitting unshare + the mount family (kernel userns checks still apply).


class SandboxPolicy(enum.Enum):
    NONE = "none"  # trusted platform payloads (e.g. the orchestrator no-op)
    ISOLATE = "isolate"  # user+PID+mount ns; private netns with egress to RunSpec.egress_ips
    ISOLATE_NO_NET = "isolate_no_net"  # user+PID+mount ns; EMPTY network ns


_ENTRY_SCRIPT = Path(__file__).with_name("sandbox_entry.sh")
_NFT_TABLE = "das_sandbox"
_NFT_SET = "allowed"
_VETH_PREFIX = "das"  # + child pid; ifnames are capped at 15 chars
_DEFAULT_SANDBOX_CIDR = "10.200.0.0/16"


def _sandbox_wrapper(policy: SandboxPolicy, *, own_netns: bool = True) -> list[str]:
    # Absolute paths: the child env is the scrubbed RunSpec.env, whose PATH may not
    # include the wrapper's location.
    unshare = shutil.which("unshare") or "/usr/bin/unshare"
    argv = [unshare, "--user", "--map-root-user", "--pid", "--fork", "--mount"]
    if own_netns:
        argv.append("--net")
    return [*argv, "--", str(_ENTRY_SCRIPT)]


def _probe_env() -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "DAS_SANDBOX_KEEP": "",
        "DAS_SANDBOX_HOSTS": "",
        "DAS_SANDBOX_NET": "",
    }


@functools.cache
def sandbox_supported() -> bool:
    """Probe once per process: can this host create the unprivileged user+PID+mount
    +net namespaces the sandbox uses AND run the entry script (tmpfs/bind mounts,
    setpriv) inside them? False on macOS, on kernels/seccomp profiles that block
    unprivileged userns or the mount family, or on images without util-linux."""
    true_bin = shutil.which("true") or "/bin/true"
    try:
        probe = subprocess.run(  # noqa: S603 — fixed argv, no target input
            [*_sandbox_wrapper(SandboxPolicy.ISOLATE_NO_NET), true_bin],
            capture_output=True,
            env=_probe_env(),
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


@functools.cache
def network_sandbox_supported() -> bool:
    """Probe once per process: can the parent plumb per-run egress? Needs
    iproute2 + nftables and an effective CAP_NET_ADMIN (ambient, via the compose
    capsh entrypoint) in the worker's netns."""
    nft = shutil.which("nft")
    ip = shutil.which("ip")
    if nft is None or ip is None:
        return False
    try:
        probe = subprocess.run(  # noqa: S603 — fixed argv
            [nft, "list", "ruleset"], capture_output=True, timeout=15
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


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
    # Namespace isolation for this run (sec-15). Scanner payloads set ISOLATE /
    # ISOLATE_NO_NET; how strictly it is honored is the owner's sandbox_mode.
    sandbox: SandboxPolicy = SandboxPolicy.NONE
    # ISOLATE only: the ONLY IPv4 destinations the child may reach (sec-18) — the
    # scope-vetted pinned target and any declared online-DB hosts, resolved and
    # vetted by the caller immediately before launch. Empty = refuse to launch.
    egress_ips: tuple[str, ...] = ()
    # (ip, name) pairs pinned into the sandbox's /etc/hosts — the only names the
    # tool can resolve (there is no DNS inside).
    hosts: tuple[tuple[str, str], ...] = ()
    # Dirs under /tmp this run owns (its workdir / extracted source) that stay
    # visible inside the private /tmp. Everything else under /tmp is hidden.
    keep_paths: tuple[str, ...] = ()


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


@dataclass(frozen=True)
class NetPlan:
    """The per-run egress plumbing: a /30 veth link (child ↔ worker netns) and the
    nftables allowlist elements `child_ip . egress_ip`."""

    child_ip: str
    gateway_ip: str
    prefixlen: int
    egress_ips: tuple[str, ...]

    @property
    def child_cidr(self) -> str:
        return f"{self.child_ip}/{self.prefixlen}"


@dataclass(frozen=True)
class LaunchPlan:
    argv: list[str]
    env: dict[str, str]
    net: NetPlan | None  # attach a veth after spawn (ISOLATE with egress)


@dataclass
class _RunState:
    proc: asyncio.subprocess.Process
    pgid: int
    scratch: Path
    spec: RunSpec
    owns_scratch: bool  # False when the caller supplied RunSpec.workdir
    net: NetPlan | None = None
    ifname: str | None = None


def _nft_base_ruleset(cidr: str) -> str:
    return f"""
table ip {_NFT_TABLE} {{
    set {_NFT_SET} {{ type ipv4_addr . ipv4_addr ; }}
    chain forward {{
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        ip saddr . ip daddr @{_NFT_SET} accept
    }}
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "{_VETH_PREFIX}*" drop
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {cidr} masquerade
    }}
}}
"""


class SubprocessOwner:
    """Real per-run execution owner (M2-W3). See module docstring for the
    confinement it provides."""

    def __init__(
        self,
        rlimits: tuple[tuple[int, int], ...] = _DEFAULT_RLIMITS,
        *,
        sandbox_mode: str = "best_effort",
        sandbox_cidr: str = _DEFAULT_SANDBOX_CIDR,
    ) -> None:
        self._rlimits = rlimits
        self._sandbox_mode = sandbox_mode
        self._sandbox_net = ipaddress.ip_network(sandbox_cidr, strict=True)
        if self._sandbox_net.version != 4 or self._sandbox_net.prefixlen > 24:
            raise ValueError(
                f"scanner sandbox CIDR must be an IPv4 block of /24 or larger: {sandbox_cidr!r}"
            )
        self._runs: dict[str, _RunState] = {}

    # ── planning ─────────────────────────────────────────────────────────────
    def _plan(self, spec: RunSpec, *, scratch: str | None = None) -> LaunchPlan:
        """The argv/env to launch and whether to plumb egress, honoring the
        sandbox policy under the configured mode. `required` fails CLOSED when
        any needed primitive is unavailable; `best_effort` degrades to the
        in-container confinement (dev/macOS); `off` never wraps."""
        if spec.sandbox is SandboxPolicy.NONE or self._sandbox_mode == "off":
            return LaunchPlan(argv=spec.argv, env=spec.env, net=None)
        if not sandbox_supported():
            if self._sandbox_mode == "required":
                raise SandboxUnavailableError(
                    "scanner sandbox is required (SCANNER_SANDBOX=required) but this host cannot "
                    "create unprivileged user/mount namespaces — refusing to run the scanner "
                    "with the worker's /proc credentials and /tmp readable (sec-15)"
                )
            return LaunchPlan(argv=spec.argv, env=spec.env, net=None)

        net: NetPlan | None = None
        own_netns = True
        if spec.sandbox is SandboxPolicy.ISOLATE:
            if not spec.egress_ips:
                raise SandboxUnavailableError(
                    f"run {spec.label!r} needs network but has no vetted egress destination; "
                    "refusing to launch a network scanner without an authorized target (sec-18)"
                )
            if network_sandbox_supported():
                net = self._allocate_net(spec.egress_ips)
            elif self._sandbox_mode == "required":
                raise SandboxUnavailableError(
                    "target-only egress is required (SCANNER_SANDBOX=required) but this worker "
                    "cannot plumb it (needs ambient CAP_NET_ADMIN + iproute2 + nftables) — "
                    "refusing to run a network scanner with control-plane reach (sec-18)"
                )
            else:
                own_netns = False  # best_effort: keep the container netns (dev only)

        keep = [*spec.keep_paths, *([scratch] if scratch else [])]  # own cwd stays visible
        env = {
            **spec.env,
            "DAS_SANDBOX_KEEP": ":".join(keep),
            "DAS_SANDBOX_HOSTS": "\n".join(f"{ip} {name}" for ip, name in spec.hosts),
            "DAS_SANDBOX_NET": f"{net.child_cidr} {net.gateway_ip}" if net else "",
        }
        argv = [*_sandbox_wrapper(spec.sandbox, own_netns=own_netns), *spec.argv]
        return LaunchPlan(argv=argv, env=env, net=net)

    def _allocate_net(self, egress_ips: tuple[str, ...]) -> NetPlan:
        """Pick a free /30 inside the sandbox block: .1 = worker end, .2 = child.
        Freedom is checked against the worker's live addresses (a live run holds
        its gateway address); a stale collision would only break THAT run's
        networking, never widen it."""
        in_use = self._worker_addresses()
        subnets = list(self._sandbox_net.subnets(new_prefix=30))
        for _ in range(64):
            sub = subnets[secrets.randbelow(len(subnets))]
            hosts = list(sub.hosts())
            gw, child = str(hosts[0]), str(hosts[1])
            if gw not in in_use:
                for ip in egress_ips:
                    if ipaddress.ip_address(ip).version != 4:
                        raise SandboxUnavailableError(f"egress destination is not IPv4: {ip!r}")
                return NetPlan(child_ip=child, gateway_ip=gw, prefixlen=30, egress_ips=egress_ips)
        raise SandboxUnavailableError("no free sandbox subnet for a new run")

    @staticmethod
    def _worker_addresses() -> set[str]:
        ip = shutil.which("ip") or "/usr/sbin/ip"
        try:
            out = subprocess.run(  # noqa: S603 — fixed argv
                [ip, "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=15
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return set()
        addrs: set[str] = set()
        for line in out.splitlines():
            parts = line.split()
            if "inet" in parts:
                addrs.add(parts[parts.index("inet") + 1].split("/")[0])
        return addrs

    # ── launch / plumbing ────────────────────────────────────────────────────
    async def launch(self, spec: RunSpec) -> RunHandle:
        if spec.workdir is not None:
            scratch = Path(spec.workdir)  # caller-owned: not created, not wiped
            owns_scratch = False
        else:
            scratch = Path(tempfile.mkdtemp(prefix=spec.scratch_prefix))
            scratch.chmod(0o700)
            owns_scratch = True
        # An owner-minted scratch is the child's cwd; it must stay visible inside
        # the private /tmp (a caller-owned workdir is already in keep_paths).
        plan = self._plan(spec, scratch=str(scratch) if owns_scratch else None)
        # Justified subprocess launch (S603 / semgrep dangerous-asyncio-create-exec):
        # exec form, shell=False, argv is a controlled RunSpec built by the
        # platform (placeholder now, PyRIT/scanner arg-vectors later — never string-
        # concatenated from target input, CLAUDE.md §6). Launching a child is the
        # whole point of the execution owner. Owner: workers/execution.
        proc = await asyncio.create_subprocess_exec(  # noqa: S603  # nosemgrep
            *plan.argv,
            cwd=str(scratch),
            env=plan.env,  # COMPLETE env — worker secrets are not inherited
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group → killable identity
            preexec_fn=_child_preexec(self._rlimits),
        )
        ref = str(proc.pid)
        state = _RunState(
            proc=proc,
            pgid=proc.pid,
            scratch=scratch,
            spec=spec,
            owns_scratch=owns_scratch,
            net=plan.net,
        )
        self._runs[ref] = state
        if plan.net is not None:
            try:
                await self._attach_net(state)
            except Exception:
                # Never leave a half-plumbed child running: kill, unplumb, surface.
                await self._terminate(state)
                await self._detach_net(state)
                self._runs.pop(ref, None)
                if owns_scratch:
                    shutil.rmtree(scratch, ignore_errors=True)
                raise
        return RunHandle(runner_ref=ref)

    async def _attach_net(self, state: _RunState) -> None:
        """Parent side of the per-run egress (sec-18): once the child has entered
        its own netns, create a veth pair with the peer moved INTO it, address our
        end, and allow exactly `child_ip . egress_ip` in the forward allowlist.
        The worker owns the child's user namespace, so moving the peer needs no
        capability over the child; creating the pair and editing the ruleset need
        CAP_NET_ADMIN in the worker's netns."""
        if state.net is None:
            return
        pid = state.proc.pid
        await self._await_child_netns(pid)
        ifname = f"{_VETH_PREFIX}{pid}"
        state.ifname = ifname
        await _priv(
            "ip", "link", "add", ifname, "type", "veth", "peer", "name", "eth0", "netns", str(pid)
        )
        await _priv(
            "ip", "addr", "add", f"{state.net.gateway_ip}/{state.net.prefixlen}", "dev", ifname
        )
        await _priv("ip", "link", "set", ifname, "up")
        await self._ensure_nft_base()
        for ip in state.net.egress_ips:
            await _priv(
                "nft",
                "add",
                "element",
                "ip",
                _NFT_TABLE,
                _NFT_SET,
                f"{{ {state.net.child_ip} . {ip} }}",
            )

    async def _ensure_nft_base(self) -> None:
        # Idempotent-enough: two workers racing here can each append the base
        # rules once more (duplicate accept/masquerade rules are harmless).
        rc, _out, _err = await _run("nft", "list", "table", "ip", _NFT_TABLE)
        if rc != 0:
            await _priv("nft", "-f", "-", stdin=_nft_base_ruleset(str(self._sandbox_net)))

    async def _detach_net(self, state: _RunState) -> None:
        if state.net is None:
            return
        for ip in state.net.egress_ips:
            rc, _out, err = await _run(
                "nft",
                "delete",
                "element",
                "ip",
                _NFT_TABLE,
                _NFT_SET,
                f"{{ {state.net.child_ip} . {ip} }}",
            )
            if rc != 0:
                rc2, out2, _ = await _run("nft", "list", "set", "ip", _NFT_TABLE, _NFT_SET)
                if rc2 == 0 and f"{state.net.child_ip} . {ip}" in out2:
                    raise ExecutionTeardownError(
                        f"sandbox egress allow {state.net.child_ip}->{ip} still present: {err}"
                    )
        if state.ifname is not None:
            rc, _out, _err = await _run("ip", "link", "show", state.ifname)
            if rc == 0:
                await _priv("ip", "link", "del", state.ifname)

    async def _await_child_netns(
        self, pid: int, *, attempts: int = 250, delay: float = 0.02
    ) -> None:
        own = os.readlink("/proc/self/ns/net")
        for _ in range(attempts):
            try:
                if os.readlink(f"/proc/{pid}/ns/net") != own:
                    return
            except OSError as exc:  # child died before unsharing
                raise ExecutionError(
                    f"sandbox child {pid} vanished before entering its netns"
                ) from exc
            await asyncio.sleep(delay)
        raise ExecutionError(f"sandbox child {pid} never entered its own network namespace")

    # ── completion / cancel / teardown ───────────────────────────────────────
    async def _drain_capped(self, state: "_RunState", name: str, stream, out: dict) -> None:
        """Read a child pipe into a FIXED-SIZE buffer (sec-9). `communicate()`
        accumulates the whole stream in memory before any ceiling applies, so a
        scanner emitting gigabytes of JSON exhausts the worker before the 32 MiB
        slice ever runs. This stops reading at the cap and kills the process group
        immediately, so peak capture memory is bounded (≤ cap per stream)."""
        cap = _MAX_CAPTURED_STREAM_BYTES
        buf = bytearray()
        while len(buf) < cap:
            chunk = await stream.read(min(65536, cap - len(buf)))
            if not chunk:
                out[name] = (bytes(buf), False)  # clean EOF within the cap
                return
            buf.extend(chunk)
        out[name] = (bytes(buf), True)  # hit the cap → overflow
        # Kill now so the child stops writing and the sibling pipe reaches EOF.
        await self._terminate(state)

    async def await_completion(self, handle: RunHandle) -> RunOutcome:
        state = self._runs.get(handle.runner_ref)
        if state is None:
            return RunOutcome(ok=False, detail="run not found")
        captured: dict[str, tuple[bytes, bool]] = {}
        try:
            await asyncio.wait_for(
                asyncio.gather(
                    self._drain_capped(state, "out", state.proc.stdout, captured),
                    self._drain_capped(state, "err", state.proc.stderr, captured),
                ),
                timeout=state.spec.timeout_s,
            )
        except TimeoutError:
            await self._terminate(state)
            return RunOutcome(ok=False, detail=f"timeout after {state.spec.timeout_s}s")
        stdout, over_out = captured["out"]
        stderr, over_err = captured["err"]
        # Reap the child (it may already be dead from an overflow kill).
        try:
            code = await state.proc.wait()
        except ProcessLookupError:
            code = state.proc.returncode
        if over_out or over_err:
            return RunOutcome(
                ok=False,
                detail=f"scanner output exceeded {_MAX_CAPTURED_STREAM_BYTES} bytes; terminated",
                stdout=stdout,
                stderr=stderr,
                exit_code=code,
            )
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
        # Reap the killed child and drain its pipes to EOF. Without this, a run
        # torn down without a preceding await_completion (cancel → teardown) leaves
        # the transport's stream readers waiting on a dead pipe, and the abandoned
        # reader surfaces later as a stray CancelledError. Bounded and suppressed:
        # the process is already confirmed gone, so this only closes bookkeeping.
        with contextlib.suppress(Exception):
            await asyncio.wait_for(state.proc.communicate(), timeout=2.0)
        # The run's egress allow must not outlive the run (sec-18) — fail loud.
        await self._detach_net(state)
        if state.owns_scratch:
            shutil.rmtree(state.scratch, ignore_errors=False)

    async def _terminate(self, state: _RunState) -> None:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(state.pgid, sig)
            except ProcessLookupError:
                return  # group already gone
            except PermissionError:
                return  # recycled pgid owned by another uid — ours is gone (see _confirm_gone)
            if await self._confirm_gone(state.pgid):
                return

    async def _confirm_gone(self, pgid: int, attempts: int = 20, delay: float = 0.05) -> bool:
        for _ in range(attempts):
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                return True
            except PermissionError:
                # EPERM means a group with this id exists but belongs to another
                # uid — so it is NOT the group we spawned (our child always shares
                # our uid, which never yields EPERM). The id was recycled after our
                # leader was reaped, i.e. our group IS gone. Letting EPERM escape
                # instead turned an emergency stop into an exception out of
                # teardown/await_completion, which could leave a killed scan
                # finalizing as failed — or not finalizing at all (§2.10).
                return True
            await asyncio.sleep(delay)
        return False


async def _run(*argv: str, stdin: str | None = None) -> tuple[int, str, str]:
    """Run a fixed iproute2/nftables command in the worker (never target input)."""
    binary = shutil.which(argv[0]) or argv[0]
    proc = await asyncio.create_subprocess_exec(  # noqa: S603  # nosemgrep
        binary,
        *argv[1:],
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin is not None else None), timeout=15
        )
    except TimeoutError:
        proc.kill()
        raise ExecutionError(f"{argv[0]} timed out") from None
    return proc.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


async def _priv(*argv: str, stdin: str | None = None) -> None:
    rc, _out, err = await _run(*argv, stdin=stdin)
    if rc != 0:
        raise ExecutionError(f"sandbox network setup failed: {' '.join(argv[:4])}: {err.strip()}")


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
