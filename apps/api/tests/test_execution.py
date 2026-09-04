"""SubprocessOwner unit tests (M2-W3). These spawn real short-lived child
processes (Unix; CI runs Linux, dev runs macOS) but no DB and no network — the
DB-integrated orchestration path is exercised live in scripts/verify_execution.py.

The security-relevant guarantee pinned here is env isolation: the child must NOT
inherit the worker's ambient environment (no leaked secrets).
"""

import os
import sys

import pytest

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


# ── Per-run namespace sandbox (sec-15) ─────────────────────────────────────────


def test_sandbox_wraps_argv_when_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.workers import execution as ex

    monkeypatch.setattr(ex, "sandbox_supported", lambda: True)
    owner = SubprocessOwner(sandbox_mode="best_effort")
    spec = RunSpec(label="t", argv=["/bin/scanner", "--x"], sandbox=ex.SandboxPolicy.ISOLATE)
    argv = owner._sandboxed_argv(spec)
    assert argv[0].endswith("unshare")
    assert {"--user", "--map-current-user", "--pid", "--fork"} <= set(argv)
    assert "--net" not in argv  # network tool keeps the container netns
    assert argv[-2:] == ["/bin/scanner", "--x"]

    no_net = RunSpec(label="t", argv=["/bin/sast"], sandbox=ex.SandboxPolicy.ISOLATE_NO_NET)
    assert "--net" in owner._sandboxed_argv(no_net)  # offline tool loses ALL network


def test_sandbox_required_fails_closed_when_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.workers import execution as ex

    monkeypatch.setattr(ex, "sandbox_supported", lambda: False)
    owner = SubprocessOwner(sandbox_mode="required")
    spec = RunSpec(label="t", argv=["/bin/scanner"], sandbox=ex.SandboxPolicy.ISOLATE_NO_NET)
    with pytest.raises(ex.SandboxUnavailableError):
        owner._sandboxed_argv(spec)


def test_sandbox_best_effort_degrades_and_off_never_wraps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.workers import execution as ex

    spec = RunSpec(label="t", argv=["/bin/scanner"], sandbox=ex.SandboxPolicy.ISOLATE)
    monkeypatch.setattr(ex, "sandbox_supported", lambda: False)
    assert SubprocessOwner(sandbox_mode="best_effort")._sandboxed_argv(spec) == ["/bin/scanner"]
    monkeypatch.setattr(ex, "sandbox_supported", lambda: True)
    assert SubprocessOwner(sandbox_mode="off")._sandboxed_argv(spec) == ["/bin/scanner"]
    # an unsandboxed policy is never wrapped regardless of support
    none_spec = RunSpec(label="t", argv=["/bin/true"])
    assert SubprocessOwner(sandbox_mode="required")._sandboxed_argv(none_spec) == ["/bin/true"]
