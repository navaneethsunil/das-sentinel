# Scanner adapter contract

> Moved out of the root `CLAUDE.md` §6 so it loads only when working on scanners/workers.
> The safety invariants it depends on stay in the root file (§2.1, §2.2, §2.10).

Every scanner is a self-contained module implementing a common interface so tools can be added/removed without touching orchestration. The interface lives in `apps/api/app/scanners/base.py` (`ScannerAdapter` / `ApiScannerAdapter` Protocols) — read it there, not from a copy.

Rules:
- **Scope is validated before `run()` is ever called** — the adapter trusts nothing.
- **Raw output and normalized findings are stored separately** — raw evidence goes to MinIO (hashed, immutable), normalized findings to Postgres. Never mutate raw.
- Record scanner **version and configuration** on every run.
- Enforce **timeouts and rate limits** inside the worker; respect the engagement's rate-limit setting.
- Scanner **and PyRIT** runs launch through one **uniform execution owner** in a **rootless per-run sandbox** — minimal read-only mounts, all capabilities dropped + `no-new-privileges` + seccomp, short-lived scoped credentials (no ambient worker secrets), egress only through the engagement egress shaper — with **verified teardown**. Killability is lifecycle control, not compromise containment; the sandbox provides the containment. All target traffic is rate-shaped in aggregate at the egress choke point (across concurrent runs and inside opaque tool daemons), not just per-tool.

## Worker cancellation (emergency stop) — root CLAUDE.md §6a

Emergency stop is a hard safety invariant (root §2.10), and Celery is architecturally fire-and-forget — cancelling an in-flight subprocess is not a first-class primitive. So:

- Each scanner task must launch its tool in a **child process/container whose PID/container ID is recorded** with the scan record. Cancellation = terminate that process group (SIGTERM → SIGKILL) **and confirm the process tree is gone**, not just Celery `revoke` (which won't stop an already-running task's subprocess).
- **In-process suites have no process-group identity.** PyRIT is a native Python library embedded in the worker with no subprocess, so `killpg` cannot selectively stop it. Every suite must therefore get either its **own child execution owner** (killable like a scanner) or a **fully propagated bounded cooperative cancellation token checked between prompts/turns** — an emergency stop that can't actually halt a running suite is a safety-invariant failure (root §2.10).
- Tasks must **heartbeat** progress and check a cancellation flag between steps.
- Reassess if orchestration grows to multi-step, resumable, long-running pipelines: **Dramatiq** (simpler, more reliable actor model) or **Temporal** (durable execution + first-class cancellation) become better fits than Celery. Not an MVP change — noted so we don't over-invest in Celery-specific retry plumbing.
