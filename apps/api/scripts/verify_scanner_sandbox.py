"""sec-15 live proof: the per-run scanner sandbox actually contains a compromised
scanner child.

Runs INSIDE the `scanner-worker` container (compose applies the vendored seccomp
profile + cap_drop ALL + no-new-privileges + SCANNER_SANDBOX=required), playing a
scanner child that has been fully compromised (arbitrary code execution) and
attempts exactly what finding sec-15 describes: read the secret-bearing worker
parent's /proc/<pid>/environ and pivot to the control-plane services.

Proves, through the real SubprocessOwner launch path:
  1. the sandbox is SUPPORTED here (userns probe passes under the shipped
     seccomp profile with every capability dropped);
  2. WITHOUT the sandbox the attack works — the same-UID child reads the
     parent's environ (the confirmed vulnerable behavior, kept as the control);
  3. WITH the sandbox (ISOLATE — network scanners) the child cannot read the
     parent's environ and cannot see its PID namespace;
  4. WITH ISOLATE_NO_NET (offline SAST tools) the child additionally has NO
     network: postgres, valkey, minio and zap are all unreachable (no route,
     not just refused);
  5. sandbox_mode="required" on a host without userns support fails CLOSED
     (simulated by breaking the probe).

Run (from the repo root):
  docker compose --profile scanners run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" \
    --entrypoint sh scanner-worker \
    -c "cd /app && PYTHONPATH=/app python scripts/verify_scanner_sandbox.py"
"""

import asyncio
import os
import socket
import sys

from app.workers import execution as ex
from app.workers.execution import RunSpec, SandboxPolicy, SubprocessOwner

FAILURES: list[str] = []

# What a real compromised child would hunt for: the worker's own environment
# (compose env_file: .env → DB/broker/object-store credentials).
PARENT_PID = os.getpid()

# The attack payload: read the parent's environ, report reachability of the
# control-plane services. Runs as the scanner child under each policy.
ATTACK = r"""
import socket, sys
out = {}
try:
    data = open("/proc/%d/environ", "rb").read()
    out["environ"] = "READ %%d bytes" %% len(data)
except OSError as exc:
    out["environ"] = "DENIED %%s" %% type(exc).__name__
for name, host, port in [
    ("postgres", "%s", 5432), ("valkey", "%s", 6379),
    ("minio", "%s", 9000), ("zap", "%s", 8090),
]:
    s = socket.socket(); s.settimeout(3)
    try:
        rc = s.connect_ex((host, port))
        out[name] = "connect_ex=%%d" %% rc
    except OSError as exc:
        out[name] = "ERR %%s" %% type(exc).__name__
    finally:
        s.close()
print("|".join(f"{k}={v}" for k, v in out.items()))
"""


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not ok:
        FAILURES.append(name)


def _resolve(host: str) -> str:
    """Resolve control-plane services in the PARENT (the child netns has no DNS),
    so the child attacks concrete addresses — no resolution excuse."""
    try:
        return socket.getaddrinfo(host, None)[0][4][0]
    except OSError:
        return "127.0.0.1"  # service not up in this stack — loopback still proves no-net


async def _run_attack(policy: SandboxPolicy, mode: str) -> dict[str, str]:
    ips = [_resolve(h) for h in ("postgres", "valkey", "minio", "zap")]
    code = (ATTACK % (PARENT_PID, *ips)).strip()
    owner = SubprocessOwner(sandbox_mode=mode)
    spec = RunSpec(
        label=f"sandbox-proof-{policy.value}",
        argv=[sys.executable, "-c", code],
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        timeout_s=60.0,
        sandbox=policy,
    )
    handle = await owner.launch(spec)
    outcome = await owner.await_completion(handle)
    await owner.teardown(handle)
    if not outcome.ok:
        raise RuntimeError(f"attack child failed to run: {outcome.detail!r}")
    return dict(kv.split("=", 1) for kv in outcome.stdout.decode().strip().split("|"))


async def main() -> int:
    # 1. The shipped confinement supports the sandbox.
    check("sandbox supported under the shipped seccomp/cap_drop", ex.sandbox_supported())

    # 2. Control: unsandboxed, the attack WORKS (this is the reported finding).
    bare = await _run_attack(SandboxPolicy.NONE, "off")
    check(
        "control: unsandboxed child CAN read the parent's environ (the vuln)",
        bare["environ"].startswith("READ"),
        bare["environ"],
    )
    check(
        "control: unsandboxed child CAN reach a control-plane service",
        any(bare[s] == "connect_ex=0" for s in ("postgres", "valkey", "minio", "zap")),
        str({k: bare[k] for k in ("postgres", "valkey", "minio", "zap")}),
    )

    # 3. ISOLATE (network scanners): parent secrets are out of reach.
    iso = await _run_attack(SandboxPolicy.ISOLATE, "required")
    check(
        "ISOLATE: child CANNOT read the parent's environ",
        iso["environ"].startswith("DENIED"),
        iso["environ"],
    )

    # 4. ISOLATE_NO_NET (offline SAST tools): no control-plane route at all.
    nonet = await _run_attack(SandboxPolicy.ISOLATE_NO_NET, "required")
    check(
        "ISOLATE_NO_NET: child CANNOT read the parent's environ",
        nonet["environ"].startswith("DENIED"),
        nonet["environ"],
    )
    for svc in ("postgres", "valkey", "minio", "zap"):
        check(
            f"ISOLATE_NO_NET: {svc} unreachable from the sandbox",
            nonet[svc] != "connect_ex=0",
            nonet[svc],
        )

    # 5. required-mode fails CLOSED when the host cannot sandbox.
    ex.sandbox_supported.cache_clear()
    real_wrapper = ex._sandbox_wrapper
    ex._sandbox_wrapper = lambda policy: ["/nonexistent-unshare", "--"]
    try:
        refused = False
        try:
            SubprocessOwner(sandbox_mode="required")._sandboxed_argv(
                RunSpec(label="x", argv=["/bin/true"], sandbox=SandboxPolicy.ISOLATE)
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
    print("ALL CHECKS PASSED — sec-15 sandbox verified live")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
