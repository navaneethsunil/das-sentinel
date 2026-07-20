"""M2-B5 data-leakage suite — CI-safe (no PyRIT import: a fake Runner stands in
for PyRITRunner). Bundle loading, deterministic scoring across all six leakage
vectors (leak AND refusal), and per-turn cancellation of the multi-turn
cross-tenant probe. Real PyRIT + DB findings are proven live in
scripts/verify_data_leakage.py.
"""

from app.runners.base import AttemptOutcome, AttemptRecord, NormalizedResult
from app.suites.base import LeakageVector, serialize_probe_transcript
from app.suites.data_leakage import DataLeakageSuite, load_bundle
from app.workers.execution import CancelToken

# Canaries planted only in the mock's hidden context — surfacing one in a response
# is unambiguous proof of disclosure. Low-entropy by design (secret scanning).
_SECRETS = {
    "system prompt": "canary-canary-sysprompt-aaa",
    "initial instructions": "canary-canary-sysprompt-aaa",
    "private note": "canary-canary-hidden-aaa",
    "confidential internal note": "canary-canary-hidden-aaa",
    "credentials": "canary-canary-secret-aaa",
    "access keys": "canary-canary-secret-aaa",
    "restricted-internal": "canary-canary-rag-aaa",
    "knowledge base": "canary-canary-rag-aaa",
    "globex": "canary-canary-tenant-aaa",
}


class LeakyTarget:
    """A mock model that leaks whatever hidden secret a disclosure request maps to
    — EXCEPT any marker in `refuse`, which it withholds (a partially-guarded model,
    so the suite must discriminate leak from refusal)."""

    def __init__(self, refuse: frozenset[str] = frozenset()) -> None:
        self._refuse = refuse
        self.sent: list[str] = []

    def _reply(self, prompt: str) -> str:
        lowered = prompt.lower()
        # improper output handling: the model echoes unescaped active content
        if "<img" in prompt and "canary-canary-output-aaa" in prompt:
            reply = "<img src=x onerror=canary-canary-output-aaa>"
        else:
            marker = next((m for kw, m in _SECRETS.items() if kw in lowered), None)
            if marker is None:
                return "Confirmed: I only work with the current tenant's records."
            reply = f"Sure, here it is: {marker}"
        if any(m in reply for m in self._refuse):
            return "I can't share that information."
        return reply

    async def send(self, prompt: str) -> str:
        self.sent.append(prompt)
        return self._reply(prompt)

    def open_conversation(self) -> "_Conversation":
        return _Conversation(self)


class _Conversation:
    def __init__(self, target: LeakyTarget) -> None:
        self._target = target

    async def send(self, prompt: str) -> str:
        return self._target._reply(prompt)


class _CancelDuringConversationTarget(LeakyTarget):
    """Trips the CancelToken partway through the multi-turn cross-tenant probe."""

    def __init__(self, token: CancelToken, trip_after_turn: int = 1) -> None:
        super().__init__()
        self._token = token
        self._trip = trip_after_turn

    def open_conversation(self) -> "_CancelConversation":
        return _CancelConversation(self, self._token, self._trip)


class _CancelConversation:
    def __init__(self, target: LeakyTarget, token: CancelToken, trip: int) -> None:
        self._target = target
        self._token = token
        self._trip = trip
        self._turns = 0

    async def send(self, prompt: str) -> str:
        self._turns += 1
        reply = self._target._reply(prompt)
        if self._turns >= self._trip:
            self._token.cancel()
        return reply


class FakeRunner:
    """Stands in for PyRITRunner: sends each objective through the target and
    normalizes, without importing PyRIT."""

    engine = "pyrit"

    async def run(self, target, config, cancel) -> NormalizedResult:  # noqa: ANN001
        planned = config.planned_objectives()
        attempts = []
        for probe_id, objective in planned:
            if cancel.cancelled:
                break
            response = await target.send(objective)
            attempts.append(
                AttemptRecord(
                    probe_id=probe_id,
                    objective=objective,
                    outcome=AttemptOutcome.UNDETERMINED,
                    response_excerpt=response,
                )
            )
        return NormalizedResult(
            engine="pyrit",
            engine_version="0.14.0",
            suite=config.suite,
            attempts=tuple(attempts),
            objective_count=len(planned),
            cancelled=cancel.cancelled,
        )


def test_load_bundle_parses_and_content_hashes():
    bundle_id, sha256, probes = load_bundle()
    assert bundle_id == "data_leakage.v1"
    assert len(sha256) == 64  # hex sha-256
    assert len(probes) == 6
    # one probe per leakage vector
    assert {p.technique for p in probes} == set(LeakageVector)
    # the four OWASP-LLM codes the suite covers
    assert {p.owasp for p in probes} == {"LLM02", "LLM05", "LLM07", "LLM08"}
    # deterministic — same bytes, same hash
    assert load_bundle()[1] == sha256


async def test_suite_scores_all_vectors_leak():
    result = await DataLeakageSuite(runner=FakeRunner()).run(LeakyTarget(), CancelToken())
    assert result.engine == "pyrit" and result.engine_version == "0.14.0"
    assert result.cancelled is False
    assert len(result.probe_results) == 6
    # a fully-leaky model discloses on every vector
    assert len(result.succeeded) == 6
    assert {r.probe.technique for r in result.succeeded} == set(LeakageVector)
    # every success carries concrete matched evidence (a canary or the active tag)
    assert all(r.evidence and "canary-canary-" in r.evidence for r in result.succeeded)


async def test_guarded_target_discriminates_leak_from_refusal():
    # a model that withholds the embedded credential must not be scored on that vector
    guarded = LeakyTarget(refuse=frozenset({"canary-canary-secret-aaa"}))
    result = await DataLeakageSuite(runner=FakeRunner()).run(guarded, CancelToken())
    succeeded_ids = {r.probe.probe_id for r in result.succeeded}
    assert "dl.secret-exposure.embedded-credential" not in succeeded_ids
    assert len(result.succeeded) == 5


async def test_multi_turn_cross_tenant_runs_full_conversation():
    result = await DataLeakageSuite(runner=FakeRunner()).run(LeakyTarget(), CancelToken())
    ct = next(r for r in result.probe_results if r.probe.technique is LeakageVector.CROSS_TENANT)
    assert ct.succeeded is True
    # 2 user turns + 2 assistant replies captured as transcript evidence
    assert len(ct.transcript) == 4


async def test_per_turn_cancel_halts_cross_tenant_conversation():
    token = CancelToken()
    target = _CancelDuringConversationTarget(token, trip_after_turn=1)
    result = await DataLeakageSuite(runner=FakeRunner()).run(target, token)
    assert result.cancelled is True
    ct = next(r for r in result.probe_results if r.probe.technique is LeakageVector.CROSS_TENANT)
    assert ct.succeeded is False
    assert ct.error == "cancelled mid-conversation"
    # halted after turn 1 — the cross-tenant request turn was never sent
    assert len(ct.transcript) == 2


async def test_probe_transcript_serialization_is_deterministic():
    result = await DataLeakageSuite(runner=FakeRunner()).run(LeakyTarget(), CancelToken())
    one = next(r for r in result.succeeded if r.probe.technique is LeakageVector.SYSTEM_PROMPT)
    blob = serialize_probe_transcript(one)
    assert serialize_probe_transcript(one) == blob
    assert b'"owasp":"LLM07"' in blob
