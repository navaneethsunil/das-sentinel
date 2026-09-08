"""SubprocessOwner unit tests (M2-W3). These spawn real short-lived child
processes (Unix; CI runs Linux, dev runs macOS) but no DB and no network — the
DB-integrated orchestration path is exercised live in scripts/verify_execution.py.

The security-relevant guarantee pinned here is env isolation: the child must NOT
inherit the worker's ambient environment (no leaked secrets).
"""

import os
import sys

import pytest

from app.workers import execution as ex
from app.workers.execution import RunSpec, SubprocessOwner


def _spec(code: str, *, env: dict | None = None, timeout_s: float = 30.0) -> RunSpec:
    return RunSpec(label="t", argv=[sys.executable, "-c", code], env=env or {}, timeout_s=timeout_s)


async def test_runs_to_completion_and_records_pid() -> None:
    owner = SubprocessOwner()
    handle = await owner.launch(_spec("import sys; sys.exit(0)"))
    assert handle.runner_ref.isdigit()  # runner_ref is the group-leader PID
    outcome = await owner.await_completion(handle)
    await owner.teardown(handle)  # verified teardown must not raise
    assert outcome.ok is True


async def test_nonzero_exit_is_failure_with_detail() -> None:
    owner = SubprocessOwner()
    handle = await owner.launch(_spec("import sys; sys.stderr.write('boom'); sys.exit(2)"))
    outcome = await owner.await_completion(handle)
    await owner.teardown(handle)
    assert outcome.ok is False
    assert "boom" in (outcome.detail or "")


async def test_child_does_not_inherit_ambient_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # A secret in the worker's environment must NOT reach the child (env={}).
    monkeypatch.setenv("DASS_AMBIENT_SENTINEL", "super-secret")
    assert "DASS_AMBIENT_SENTINEL" in os.environ
    owner = SubprocessOwner()
    handle = await owner.launch(
        _spec("import os, sys; sys.exit(3 if 'DASS_AMBIENT_SENTINEL' in os.environ else 0)")
    )
    outcome = await owner.await_completion(handle)
    await owner.teardown(handle)
    assert outcome.ok is True  # exit 0 ⇒ the sentinel was absent in the child


async def test_timeout_is_reported_and_torn_down() -> None:
    owner = SubprocessOwner()
    handle = await owner.launch(_spec("import time; time.sleep(30)", timeout_s=0.2))
    outcome = await owner.await_completion(handle)  # exceeds the 0.2s budget
    await owner.teardown(handle)  # confirms the tree is gone (else raises)
    assert outcome.ok is False
    assert "timeout" in (outcome.detail or "")


async def test_cancel_then_teardown_confirms_gone() -> None:
    owner = SubprocessOwner()
    handle = await owner.launch(_spec("import time; time.sleep(30)"))
    await owner.cancel(handle)
    await owner.teardown(handle)  # raises if the process group survived SIGKILL
    # After teardown the group must be gone.
    with pytest.raises(ProcessLookupError):
        os.killpg(int(handle.runner_ref), 0)


async def test_overflow_output_is_capped_and_terminated(monkeypatch: pytest.MonkeyPatch) -> None:
    # sec-9: a child emitting far more than the capture ceiling must be killed and
    # its capture bounded — NOT buffered whole in memory first. Shrink the cap so
    # the test is fast, then emit ~50x it.
    import app.workers.execution as execution

    cap = 64 * 1024
    monkeypatch.setattr(execution, "_MAX_CAPTURED_STREAM_BYTES", cap)
    owner = SubprocessOwner()
    # Write ~3.2 MiB of output in a tight loop; the drain must stop at the cap.
    handle = await owner.launch(
        _spec(
            "import sys\n"
            "chunk = b'A' * 65536\n"
            "for _ in range(50):\n"
            "    sys.stdout.buffer.write(chunk)\n"
            "sys.stdout.flush()\n",
            timeout_s=30.0,
        )
    )
    outcome = await owner.await_completion(handle)
    await owner.teardown(handle)
    assert outcome.ok is False
    assert "exceeded" in (outcome.detail or "")
    # Capture is bounded at the cap, not the ~3.2 MiB the child tried to emit.
    assert len(outcome.stdout) <= cap


async def test_confirm_gone_treats_eperm_as_gone(monkeypatch: pytest.MonkeyPatch) -> None:
    """A recycled pgid owned by another uid answers EPERM to signal 0. Our own
    child never does (same uid), so EPERM means our group is gone — it must not
    escape and break an emergency stop's teardown."""
    owner = SubprocessOwner()

    def _eperm(pgid: int, sig: int) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "killpg", _eperm)
    assert await owner._confirm_gone(12345, attempts=1, delay=0) is True


async def test_terminate_treats_eperm_as_gone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same reasoning for the kill itself: EPERM on killpg means the id was
    recycled, so terminate must return quietly instead of raising out of
    cancel()/teardown() and derailing the stop."""
    owner = SubprocessOwner()
    handle = await owner.launch(_spec("import sys; sys.exit(0)"))
    await owner.await_completion(handle)

    def _eperm(pgid: int, sig: int) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "killpg", _eperm)
    await owner.teardown(handle)  # must not raise


# ── Per-run namespace sandbox (sec-15 / sec-18) ────────────────────────────────


def _isolate_spec(**kw) -> RunSpec:
    fields = dict(
        label="t",
        argv=["/bin/scanner", "--x"],
        env={"PATH": "/usr/bin"},
        sandbox=ex.SandboxPolicy.ISOLATE,
        egress_ips=("93.184.216.34",),
        hosts=(("93.184.216.34", "app.example.com"),),
        keep_paths=("/tmp/dassscan-1",),  # noqa: S108 — literal path in an argv contract test
    )
    return RunSpec(**{**fields, **kw})


def test_sandbox_wraps_argv_in_all_namespaces_via_the_entry_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ex, "sandbox_supported", lambda: True)
    monkeypatch.setattr(ex, "network_sandbox_supported", lambda: True)
    owner = SubprocessOwner(sandbox_mode="required")
    plan = owner._plan(_isolate_spec(), scratch="/tmp/dassrun-9")  # noqa: S108
    argv = plan.argv
    assert argv[0].endswith("unshare")
    for flag in ("--user", "--map-root-user", "--pid", "--fork", "--mount", "--net"):
        assert flag in argv
    assert argv[argv.index("--") + 1].endswith("sandbox_entry.sh")
    assert argv[-2:] == ["/bin/scanner", "--x"]
    # the entry script's contract: own dirs, pinned names, veth addressing
    assert plan.env["PATH"] == "/usr/bin"  # the tool's env is untouched otherwise
    assert plan.env["DAS_SANDBOX_KEEP"] == "/tmp/dassscan-1:/tmp/dassrun-9"  # noqa: S108
    assert plan.env["DAS_SANDBOX_HOSTS"] == "93.184.216.34 app.example.com"
    assert plan.net is not None
    assert plan.env["DAS_SANDBOX_NET"] == f"{plan.net.child_ip}/30 {plan.net.gateway_ip}"
    assert plan.net.egress_ips == ("93.184.216.34",)
    # child/gateway are the two hosts of one /30 inside the sandbox block
    import ipaddress

    block = ipaddress.ip_network("10.200.0.0/16")
    assert ipaddress.ip_address(plan.net.child_ip) in block
    assert ipaddress.ip_address(plan.net.gateway_ip) in block
    assert (
        int(ipaddress.ip_address(plan.net.child_ip))
        - int(ipaddress.ip_address(plan.net.gateway_ip))
        == 1
    )


def test_offline_tool_gets_an_empty_network_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ex, "sandbox_supported", lambda: True)
    monkeypatch.setattr(ex, "network_sandbox_supported", lambda: True)
    owner = SubprocessOwner(sandbox_mode="required")
    plan = owner._plan(
        RunSpec(label="t", argv=["/bin/sast"], sandbox=ex.SandboxPolicy.ISOLATE_NO_NET)
    )
    assert "--net" in plan.argv  # own (empty) netns…
    assert plan.net is None  # …and no veth is ever attached
    assert plan.env["DAS_SANDBOX_NET"] == ""


def test_network_scanner_without_an_authorized_destination_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sec-18: no vetted egress IP → no launch, in EVERY mode that sandboxes."""
    monkeypatch.setattr(ex, "sandbox_supported", lambda: True)
    monkeypatch.setattr(ex, "network_sandbox_supported", lambda: True)
    for mode in ("required", "best_effort"):
        with pytest.raises(ex.SandboxUnavailableError, match="no vetted egress"):
            SubprocessOwner(sandbox_mode=mode)._plan(_isolate_spec(egress_ips=()))


def test_sandbox_required_fails_closed_when_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    """SCANNER_SANDBOX=required on a host without userns (or without the egress
    plumbing) must refuse to launch — never fall back to the worker's namespace."""
    owner = SubprocessOwner(sandbox_mode="required")
    monkeypatch.setattr(ex, "sandbox_supported", lambda: False)
    with pytest.raises(ex.SandboxUnavailableError, match="user/mount namespaces"):
        owner._plan(_isolate_spec())
    monkeypatch.setattr(ex, "sandbox_supported", lambda: True)
    monkeypatch.setattr(ex, "network_sandbox_supported", lambda: False)
    with pytest.raises(ex.SandboxUnavailableError, match="CAP_NET_ADMIN"):
        owner._plan(_isolate_spec())


def test_sandbox_best_effort_degrades_and_off_never_wraps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _isolate_spec()
    monkeypatch.setattr(ex, "sandbox_supported", lambda: False)
    assert SubprocessOwner(sandbox_mode="best_effort")._plan(spec).argv == spec.argv
    monkeypatch.setattr(ex, "sandbox_supported", lambda: True)
    monkeypatch.setattr(ex, "network_sandbox_supported", lambda: True)
    assert SubprocessOwner(sandbox_mode="off")._plan(spec).argv == spec.argv
    # best_effort without the egress plumbing keeps the container netns (dev only)
    monkeypatch.setattr(ex, "network_sandbox_supported", lambda: False)
    plan = SubprocessOwner(sandbox_mode="best_effort")._plan(spec)
    assert "--net" not in plan.argv and plan.net is None and "--mount" in plan.argv
    # an unsandboxed policy is never wrapped regardless of support
    monkeypatch.setattr(ex, "network_sandbox_supported", lambda: True)
    none_spec = RunSpec(label="t", argv=["/bin/true"])
    assert SubprocessOwner(sandbox_mode="required")._plan(none_spec).argv == ["/bin/true"]


def test_sandbox_cidr_must_be_a_usable_ipv4_block() -> None:
    with pytest.raises(ValueError):
        SubprocessOwner(sandbox_cidr="fd00::/64")
    with pytest.raises(ValueError):
        SubprocessOwner(sandbox_cidr="10.200.0.0/28")


def test_nft_base_ruleset_drops_everything_but_the_allowlist() -> None:
    rules = ex._nft_base_ruleset("10.200.0.0/16")
    assert "hook forward priority filter; policy drop;" in rules
    assert "ip saddr . ip daddr @allowed accept" in rules
    assert "ip saddr 10.200.0.0/16 masquerade" in rules
    assert 'iifname "das*" drop' in rules  # the worker itself is not a target either
