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
