"""Uniform execution owner — the launch/cancel/teardown contract (M2-W1 seam).

Every run (scanner or PyRIT suite) is launched, watched, cancelled, and torn
down through one `ExecutionOwner`. M2-W1 ships the contract plus a `StubOwner`
so the orchestration slice — envelope re-derivation, approval consume, status
machine, runner-ref recording, heartbeat, cancel checks — is exercisable end to
end now. **M2-W3 replaces `StubOwner` with the real rootless-sandbox owner**
(all caps dropped, no-new-privileges, seccomp, scoped creds, egress only via the
engagement shaper, verified teardown); the real PyRIT suites plug in at M2-B3.
The contract is deliberately small and provider-neutral so both land behind it
without touching the orchestrator.
"""

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class RunHandle:
    """Identifies a launched run. `runner_ref` is the child PID / container id
    recorded on the scan so emergency stop can terminate that exact process
    tree (M2-W2)."""

    runner_ref: str


@dataclass(frozen=True)
class RunOutcome:
    ok: bool
    detail: str | None = None


class ExecutionOwner(Protocol):
    async def launch(self, *, scan_id: Any, envelope: Any) -> RunHandle:
        """Start the run in its sandbox and return a handle (records runner_ref)."""
        ...

    async def await_completion(self, handle: RunHandle) -> RunOutcome:
        """Block until the run finishes; report success/failure."""
        ...

    async def cancel(self, handle: RunHandle) -> None:
        """Terminate the run's process tree (SIGTERM→SIGKILL) — used by M2-W2."""
        ...

    async def teardown(self, handle: RunHandle) -> None:
        """Verified teardown: sandbox + process tree gone, transient creds revoked."""
        ...


class StubOwner:
    """Placeholder for M2-W1: records a deterministic runner ref and completes
    immediately without doing work or touching the network. No containment and
    no real suite — those arrive with M2-W3 / M2-B3. It exists only so the
    orchestration guarantees around it can be verified today."""

    async def launch(self, *, scan_id: Any, envelope: Any) -> RunHandle:
        return RunHandle(runner_ref=f"stub:{scan_id}")

    async def await_completion(self, handle: RunHandle) -> RunOutcome:
        return RunOutcome(ok=True)

    async def cancel(self, handle: RunHandle) -> None:
        return None

    async def teardown(self, handle: RunHandle) -> None:
        return None
