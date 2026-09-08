"""sec-15 / sec-18 live proof: the per-run scanner sandbox actually contains a
compromised scanner child — secrets, files AND network.

Runs INSIDE the `scanner-worker` container as the worker user through the compose
entrypoint (capsh → appuser with ambient CAP_NET_ADMIN; vendored seccomp profile,
cap_drop ALL, no-new-privileges, SCANNER_SANDBOX=required), playing a scanner
child that has been fully compromised (arbitrary code execution) and attempts
exactly what the findings describe: read the secret-bearing worker's
/proc/<pid>/environ, read another scan's temp files, and pivot to the control
plane (postgres/valkey/minio/zap).

Proves, through the real SubprocessOwner launch path:
  1. the sandbox AND its egress plumbing are SUPPORTED here;
  2. WITHOUT the sandbox the attack works — the same-UID child reads the parent's
     environ, a sibling scan's /tmp files, and reaches the control plane (the
     confirmed vulnerable behavior, kept as the control);
  3. WITH ISOLATE (network scanners) the child cannot read the parent's environ,
     cannot see the sibling's /tmp files (its own workdir IS visible and its
     result comes back through it), resolves ONLY the pinned target name, can
     reach the authorized target IP, and CANNOT reach postgres/valkey/minio/zap
     or any other address;
  4. WITH ISOLATE_NO_NET (offline SAST tools) the child has NO network at all;
  5. teardown removes the run's veth + allowlist entry;
  6. a network scanner with no authorized destination is refused; required-mode
     fails CLOSED when the host cannot sandbox.

Run (from the repo root; needs the `scanners` profile services up for the
control-plane reachability control):
  docker compose --profile scanners up -d postgres valkey minio zap vuln-target
  docker compose --profile scanners run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" scanner-worker \
    "cd /app && PYTHONPATH=/app python scripts/verify_scanner_sandbox.py"
"""

import asyncio
import os
import socket
import sys
import tempfile
from pathlib import Path

from app.workers import execution as ex
from app.workers.execution import RunSpec, SandboxPolicy, SubprocessOwner

FAILURES: list[str] = []
PARENT_PID = os.getpid()
CONTROL_PLANE = ("postgres", "valkey", "minio", "zap")
ALLOWED_TARGET = "vuln-target"  # the sandbox lab target (targets network)
OTHER_TARGET = "tls-target"  # another lab host: in the same network, NOT authorized

# The attack payload: read the parent's environ, list a sibling scan's scratch,
# resolve names, and report reachability of every service. Runs as the child.
ATTACK = r"""
import os, socket, sys
out = {}
try:
    data = open("/proc/%(ppid)d/environ", "rb").read()
    out["environ"] = "READ %%d bytes" %% len(data)
except OSError as exc:
    out["environ"] = "DENIED %%s" %% type(exc).__name__
out["sibling"] = "VISIBLE" if os.path.exists(%(sibling)r) else "HIDDEN"
out["own_workdir"] = "VISIBLE" if os.path.isdir(os.getcwd()) else "MISSING"
try:
    out["resolve_target"] = socket.gethostbyname(%(target_name)r)
except OSError as exc:
    out["resolve_target"] = "FAIL %%s" %% type(exc).__name__
try:
    out["resolve_other"] = socket.gethostbyname("postgres")
except OSError as exc:
    out["resolve_other"] = "FAIL"
for name, host, port in %(probes)r:
    s = socket.socket(); s.settimeout(3)
    try:
        rc = s.connect_ex((host, port))
        out[name] = "connect_ex=%%d" %% rc
    except OSError as exc:
        out[name] = "ERR %%s" %% type(exc).__name__
    finally:
        s.close()
open("result.txt", "w").write("ok")
print("|".join(f"{k}={v}" for k, v in out.items()))
"""


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not ok:
        FAILURES.append(name)


def _resolve(host: str) -> str:
    """Resolve services in the PARENT (the sandbox has no DNS), so the child attacks
    concrete addresses — no resolution excuse."""
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError:
        return "127.0.0.1"  # not up in this stack — loopback still proves no-net


async def _run_attack(
    policy: SandboxPolicy, mode: str, *, sibling: str, egress: tuple[str, ...] = ()
) -> tuple[dict[str, str], Path]:
    probes = [
        (n, _resolve(n), p) for n, p in zip(CONTROL_PLANE, (5432, 6379, 9000, 8090), strict=True)
    ]
    probes.append(("allowed_target", _resolve(ALLOWED_TARGET), 8000))
    probes.append(("other_target", _resolve(OTHER_TARGET), 443))
    probes.append(("internet", "1.1.1.1", 443))
    code = (
        ATTACK
        % {
            "ppid": PARENT_PID,
            "sibling": sibling,
            "target_name": ALLOWED_TARGET,
            "probes": probes,
        }
    ).strip()
    workdir = tempfile.mkdtemp(prefix="dassscan-proof-")
    owner = SubprocessOwner(sandbox_mode=mode)
    hosts = tuple((ip, ALLOWED_TARGET) for ip in egress if ip == _resolve(ALLOWED_TARGET))
    spec = RunSpec(
        label=f"sandbox-proof-{policy.value}",
        argv=[sys.executable, "-c", code],
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        timeout_s=90.0,
        sandbox=policy,
        workdir=workdir,
        egress_ips=egress,
        hosts=hosts,
        keep_paths=(workdir,),
    )
    handle = await owner.launch(spec)
    ifname = f"{ex._VETH_PREFIX}{handle.runner_ref}"
    outcome = await owner.await_completion(handle)
    await owner.teardown(handle)
    if not outcome.ok:
        raise RuntimeError(f"attack child failed to run: {outcome.detail!r}")
    result = dict(kv.split("=", 1) for kv in outcome.stdout.decode().strip().split("|"))
    result["_ifname"] = ifname
    return result, Path(workdir)


async def _nft_has(entry: str) -> bool:
    rc, out, _ = await ex._run("nft", "list", "set", "ip", ex._NFT_TABLE, ex._NFT_SET)
    return rc == 0 and entry in out


async def main() -> int:
    sibling_dir = tempfile.mkdtemp(prefix="dassscan-sibling-")
    sibling = str(Path(sibling_dir) / "evidence.json")
    Path(sibling).write_text('{"other": "scan"}')

    # 1. The shipped confinement supports the sandbox + egress plumbing.
    check("sandbox supported under the shipped seccomp/cap_drop", ex.sandbox_supported())
    check(
        "egress plumbing supported (ambient CAP_NET_ADMIN + ip + nft)",
        ex.network_sandbox_supported(),
    )

    # 2. Control: unsandboxed, the attack WORKS (this is the reported finding).
    bare, _ = await _run_attack(SandboxPolicy.NONE, "off", sibling=sibling)
    check(
        "control: unsandboxed child CAN read the parent's environ",
        bare["environ"].startswith("READ"),
        bare["environ"],
    )
    check(
        "control: unsandboxed child CAN read a sibling scan's /tmp files",
        bare["sibling"] == "VISIBLE",
    )
    check(
        "control: unsandboxed child CAN reach a control-plane service",
        any(bare[s] == "connect_ex=0" for s in CONTROL_PLANE),
        str({k: bare[k] for k in CONTROL_PLANE}),
    )

    # 3. ISOLATE (network scanners): target-only egress.
    target_ip = _resolve(ALLOWED_TARGET)
    iso, workdir = await _run_attack(
        SandboxPolicy.ISOLATE, "required", sibling=sibling, egress=(target_ip,)
    )
    check(
        "ISOLATE: child CANNOT read the parent's environ",
        iso["environ"].startswith("DENIED"),
        iso["environ"],
    )
    check("ISOLATE: sibling scan's /tmp files are HIDDEN", iso["sibling"] == "HIDDEN")
    check(
        "ISOLATE: the run's own workdir IS visible (results channel)",
        iso["own_workdir"] == "VISIBLE",
    )
    check(
        "ISOLATE: result file came back through the bind-mounted workdir",
        (workdir / "result.txt").read_text() == "ok",
    )
    check(
        "ISOLATE: pinned target name resolves to the vetted IP (hosts pin)",
        iso["resolve_target"] == target_ip,
        iso["resolve_target"],
    )
    check(
        "ISOLATE: no DNS — an unpinned name does not resolve",
        iso["resolve_other"].startswith("FAIL"),
        iso["resolve_other"],
    )
    check(
        "ISOLATE: authorized target IS reachable",
        iso["allowed_target"] == "connect_ex=0",
        iso["allowed_target"],
    )
    for svc in CONTROL_PLANE:
        check(f"ISOLATE: {svc} UNREACHABLE from the sandbox", iso[svc] != "connect_ex=0", iso[svc])
    check(
        "ISOLATE: another lab host on the SAME network is unreachable",
        iso["other_target"] != "connect_ex=0",
        iso["other_target"],
    )
    check(
        "ISOLATE: the internet is unreachable", iso["internet"] != "connect_ex=0", iso["internet"]
    )
    # 5. teardown removed the plumbing
    rc, _, _ = await ex._run("ip", "link", "show", iso["_ifname"])
    check("teardown: run's veth removed", rc != 0)
    check("teardown: run's allowlist entry removed", not await _nft_has(f". {target_ip}"))

    # 4. ISOLATE_NO_NET (offline SAST tools): no network at all.
    nonet, _ = await _run_attack(SandboxPolicy.ISOLATE_NO_NET, "required", sibling=sibling)
    check(
        "ISOLATE_NO_NET: child CANNOT read the parent's environ",
        nonet["environ"].startswith("DENIED"),
    )
    check("ISOLATE_NO_NET: sibling scan's /tmp files are HIDDEN", nonet["sibling"] == "HIDDEN")
    for svc in (*CONTROL_PLANE, "allowed_target", "internet"):
        check(f"ISOLATE_NO_NET: {svc} unreachable", nonet[svc] != "connect_ex=0", nonet[svc])

    # 6. Fail closed.
    refused = False
    try:
        SubprocessOwner(sandbox_mode="required")._plan(
            RunSpec(label="x", argv=["/bin/true"], sandbox=SandboxPolicy.ISOLATE)
        )
    except ex.SandboxUnavailableError:
        refused = True
    check("network scanner with NO authorized destination is refused", refused)
    ex.sandbox_supported.cache_clear()
    real_wrapper = ex._sandbox_wrapper
    ex._sandbox_wrapper = lambda policy, **kw: ["/nonexistent-unshare", "--"]
    try:
        refused = False
        try:
            SubprocessOwner(sandbox_mode="required")._plan(
                RunSpec(label="x", argv=["/bin/true"], sandbox=SandboxPolicy.ISOLATE_NO_NET)
            )
        except ex.SandboxUnavailableError:
            refused = True
        check("required mode refuses to launch when userns is unavailable", refused)
    finally:
        ex._sandbox_wrapper = real_wrapper
        ex.sandbox_supported.cache_clear()

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): {FAILURES}")
        return 1
    print("ALL CHECKS PASSED — sec-15/sec-18 sandbox verified live")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
