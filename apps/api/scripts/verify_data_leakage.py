"""Live verification for M2-B5 — data-leakage suite → findings, end to end.

Runs INSIDE the `redteam` image (real PyRIT 0.14.0) against real Postgres + MinIO
and an in-process mock 'leaky' target (no network egress). Proves:

  1. The suite runs the vendored data-leakage probes through the real PyRITRunner
     (single-turn) + a scripted multi-turn cross-tenant conversation, and the
     deterministic detectors score disclosure correctly across all six vectors
     (system-prompt/hidden-instruction → LLM07, secret + cross-tenant → LLM02,
     RAG boundary → LLM08, improper output → LLM05).
  2. Successful probes become `automated`, `open` findings mapped to the right
     OWASP-LLM code, each with transcript EVIDENCE stored in MinIO
     (hash-verifiable) and linked + an append-only OPEN status-history row.
  3. Re-running is idempotent (same findings, no duplicates).
  4. Per-turn cancellation halts the multi-turn cross-tenant probe (a stop between
     turns leaves the cross-tenant request turn unsent and never scores it).

Run:
  DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose --profile redteam build redteam-worker
  docker compose up -d postgres valkey minio migrate
  docker compose --profile redteam run --rm --no-deps \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh redteam-worker \
    -c "cd /app && PYTHONPATH=/app python scripts/verify_data_leakage.py"
"""

import asyncio
import json
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text

from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.models.engagement import Engagement, EngagementStatus, ScanIntensity
from app.models.evidence import Evidence
from app.models.finding import (
    Finding,
    FindingEvidence,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
)
from app.models.identity import Organization, User
from app.models.scan import Scan, ScanStatus, TestRun, TestSuite
from app.models.target import Target, TargetType
from app.services.findings import create_findings_from_suite
from app.storage import create_evidence_store, load_evidence
from app.suites.data_leakage import DataLeakageSuite
from app.workers.execution import CancelToken

NOW = datetime(2026, 7, 20, tzinfo=UTC)

# Canaries planted only in the mock's hidden context; surfacing one proves leakage.
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

failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


def _reply(prompt: str) -> str:
    """Mock behaviour: a fully-leaky model that discloses whatever hidden secret a
    disclosure request maps to (echoes unescaped active content for the improper-
    output probe)."""
    if "<img" in prompt and "canary-canary-output-aaa" in prompt:
        return "<img src=x onerror=canary-canary-output-aaa>"
    lowered = prompt.lower()
    marker = next((m for kw, m in _SECRETS.items() if kw in lowered), None)
    if marker is None:
        return "Confirmed: I only work with the current tenant's records."
    return f"Sure, here it is: {marker}"


class LeakyTarget:
    """SuiteTarget mock. `send` is the single-shot seam (PyRITRunner drives it);
    `open_conversation` yields a stateful conversation that can trip a CancelToken
    partway through, to exercise per-turn cancellation of the cross-tenant probe."""

    def __init__(self, cancel: CancelToken | None = None, trip_after_turn: int = 0) -> None:
        self._cancel = cancel
        self._trip = trip_after_turn

    async def send(self, prompt: str) -> str:
        return _reply(prompt)

    def open_conversation(self) -> "_MockConversation":
        return _MockConversation(self._cancel, self._trip)


class _MockConversation:
    def __init__(self, cancel: CancelToken | None, trip_after_turn: int) -> None:
        self._cancel = cancel
        self._trip = trip_after_turn
        self._turns = 0

    async def send(self, prompt: str) -> str:
        self._turns += 1
        reply = _reply(prompt)
        if self._cancel is not None and self._trip and self._turns >= self._trip:
            self._cancel.cancel()
        return reply


async def _seed(session, *, org_id, user_id):  # noqa: ANN001
    eng = Engagement(
        organization_id=org_id,
        name="b5-eng",
        client_system_name="acme",
        status=EngagementStatus.ACTIVE,
        test_window_start=NOW - timedelta(days=1),
        test_window_end=NOW + timedelta(days=1),
        rate_limit_rps=5,
        max_intensity=ScanIntensity.SAFE_ACTIVE,
        created_by=user_id,
    )
    session.add(eng)
    await session.flush()
    target = Target(
        engagement_id=eng.id,
        name="chatbot",
        target_type=TargetType.AI_CHATBOT,
        primary_value="https://chatbot.example.com/",
    )
    session.add(target)
    await session.flush()
    scan = Scan(
        engagement_id=eng.id,
        target_id=target.id,
        intensity=ScanIntensity.SAFE_ACTIVE,
        initiated_by=user_id,
        status=ScanStatus.COMPLETED,
        queued_at=NOW,
    )
    session.add(scan)
    await session.flush()
    test_run = TestRun(
        scan_id=scan.id,
        suite=TestSuite.DATA_LEAKAGE,
        engine="pyrit",
        config={"bundle": "data_leakage.v1"},
        status=ScanStatus.COMPLETED,
    )
    session.add(test_run)
    await session.flush()
    return eng, target, scan, test_run


async def _cleanup(sm, org_id) -> None:  # noqa: ANN001
    async with sm() as s:
        await s.execute(text("SET session_replication_role = replica"))
        eng_ids = (
            (await s.execute(select(Engagement.id).where(Engagement.organization_id == org_id)))
            .scalars()
            .all()
        )
        for table in (FindingEvidence, FindingStatusHistory):
            await s.execute(
                delete(table).where(
                    table.finding_id.in_(
                        select(Finding.id).where(Finding.engagement_id.in_(eng_ids))
                    )
                )
            )
        await s.execute(delete(Finding).where(Finding.engagement_id.in_(eng_ids)))
        await s.execute(delete(Evidence).where(Evidence.organization_id == org_id))
        await s.execute(
            delete(TestRun).where(
                TestRun.scan_id.in_(select(Scan.id).where(Scan.engagement_id.in_(eng_ids)))
            )
        )
        await s.execute(delete(Scan).where(Scan.engagement_id.in_(eng_ids)))
        await s.execute(delete(Target).where(Target.engagement_id.in_(eng_ids)))
        await s.execute(
            text("DELETE FROM scope_items WHERE engagement_id = ANY(:e)"), {"e": eng_ids}
        )
        await s.execute(
            text("DELETE FROM roe_acknowledgements WHERE engagement_id = ANY(:e)"), {"e": eng_ids}
        )
        await s.execute(delete(Engagement).where(Engagement.organization_id == org_id))
        await s.execute(delete(User).where(User.organization_id == org_id))
        await s.execute(delete(Organization).where(Organization.id == org_id))
        await s.commit()


async def main() -> int:  # noqa: C901
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_sessionmaker(engine)
    store = create_evidence_store(settings)
    store.ensure_bucket()

    async with sm() as s:
        org = Organization(name="verify-b5-org")
        s.add(org)
        await s.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-b5@example.com",
            password_hash=pw.hash("verify-b5-throwaway"),
            display_name="Verify B5",
        )
        s.add(user)
        await s.flush()
        user_id = user.id
        await s.commit()

    try:
        # (1) run the suite with REAL PyRIT against the leaky mock, persist findings
        async with sm() as s:
            eng, target, scan, test_run = await _seed(s, org_id=org_id, user_id=user_id)
            await s.commit()
            eng_id, target_id, scan_id, test_run_id = eng.id, target.id, scan.id, test_run.id

        suite = DataLeakageSuite()  # real PyRITRunner
        result = await suite.run(LeakyTarget(), CancelToken())
        check("suite ran real PyRIT engine", result.engine == "pyrit")
        check("engine_version is 0.14.0 (pinned)", result.engine_version == "0.14.0")
        check("all 6 probes scored", len(result.probe_results) == 6)
        check("6 leakage vectors disclosed", len(result.succeeded) == 6)
        vectors = {r.probe.technique.value for r in result.succeeded}
        check(
            "every leakage vector represented",
            vectors
            == {
                "system_prompt",
                "hidden_instruction",
                "secret_exposure",
                "rag_boundary",
                "improper_output",
                "cross_tenant",
            },
        )

        async with sm() as s:
            eng = await s.get(Engagement, eng_id)
            target = await s.get(Target, target_id)
            scan = await s.get(Scan, scan_id)
            test_run = await s.get(TestRun, test_run_id)
            findings = await create_findings_from_suite(
                s,
                store,
                engagement=eng,
                target=target,
                scan=scan,
                test_run=test_run,
                suite_result=result,
                now=NOW,
            )
            await s.commit()
        check("one finding per successful probe", len(findings) == 6)

        # (2) assert persisted findings + OWASP mapping + evidence
        async with sm() as s:
            rows = (
                (await s.execute(select(Finding).where(Finding.engagement_id == eng_id)))
                .scalars()
                .all()
            )
            check("findings persisted", len(rows) == 6)
            check(
                "all findings automated + open",
                all(
                    r.provenance is FindingProvenance.AUTOMATED
                    and r.status is FindingStatus.OPEN
                    and r.location["engine_version"] == "0.14.0"
                    for r in rows
                ),
            )
            codes = {r.location["owasp"]["code"] for r in rows}
            check(
                "findings map to LLM02/LLM05/LLM07/LLM08",
                codes == {"LLM02", "LLM05", "LLM07", "LLM08"},
            )
            # sample a finding: evidence linked + hash-verifiable + is the transcript
            sample = rows[0]
            links = (
                (
                    await s.execute(
                        select(FindingEvidence).where(FindingEvidence.finding_id == sample.id)
                    )
                )
                .scalars()
                .all()
            )
            check("finding links transcript evidence", len(links) == 1)
            check(
                "evidence caption is suite-neutral", links[0].caption == "data_leakage transcript"
            )
            blob = await load_evidence(s, store, links[0].evidence_id)  # re-verifies sha256
            doc = json.loads(blob)
            check("evidence is the probe transcript", doc["probe_id"] == sample.rule_id)
            check("evidence marks probe succeeded", doc["succeeded"] is True)
            hist = (
                (
                    await s.execute(
                        select(FindingStatusHistory).where(
                            FindingStatusHistory.finding_id == sample.id
                        )
                    )
                )
                .scalars()
                .all()
            )
            check(
                "append-only OPEN status history",
                len(hist) == 1 and hist[0].to_status is FindingStatus.OPEN,
            )

        # (3) re-run is idempotent — no duplicate findings
        async with sm() as s:
            eng = await s.get(Engagement, eng_id)
            target = await s.get(Target, target_id)
            scan = await s.get(Scan, scan_id)
            test_run = await s.get(TestRun, test_run_id)
            again = await create_findings_from_suite(
                s,
                store,
                engagement=eng,
                target=target,
                scan=scan,
                test_run=test_run,
                suite_result=result,
                now=NOW,
            )
            await s.commit()
        async with sm() as s:
            total = (
                (await s.execute(select(Finding.id).where(Finding.engagement_id == eng_id)))
                .scalars()
                .all()
            )
        check("re-run created no duplicate findings", len(again) == 6 and len(total) == 6)

        # (4) per-turn cancellation halts the multi-turn cross-tenant probe
        token = CancelToken()
        cancel_target = LeakyTarget(cancel=token, trip_after_turn=1)
        cancelled = await DataLeakageSuite().run(cancel_target, token)
        ct = next(r for r in cancelled.probe_results if r.probe.technique.value == "cross_tenant")
        check("cross-tenant probe cancelled mid-conversation", cancelled.cancelled is True)
        check("cancelled cross-tenant not scored a success", ct.succeeded is False)
        check("cross-tenant request turn never sent (halted after turn 1)", len(ct.transcript) == 2)
    finally:
        await _cleanup(sm, org_id)

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
