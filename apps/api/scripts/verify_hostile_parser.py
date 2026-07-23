"""Live verification of the M2-SEC3 hostile-parser hardening (TM-8) against real
Postgres + MinIO. Runs in the BASE api image (no PyRIT needed):

    docker compose up -d --build api minio   # needs postgres, valkey, minio, migrate
    docker compose run --rm --no-deps \
      -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
      -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_hostile_parser.py"

Two hostile surfaces, both driven end to end:

  A. Hostile TOOL OUTPUT over real HTTP. A malicious in-scope target (a local mock
     on 127.0.0.1, legitimately reachable only because loopback is explicitly in
     scope) is driven through the REAL `HttpLLMTargetConnector` over real TCP and
     returns pathological bodies: a valid reply (control), non-JSON, a truncated
     document, a deeply-nested document, and an oversized body. Every hostile case
     fails safe as a `TargetConnectorError` — never a crash, never an OOM — and the
     valid case still works after the streaming refactor.

  B. Hostile TRANSCRIPT blobs re-read for triage. A finding is linked to three
     evidence blobs in MinIO: a normal transcript, an oversized one, and one with
     invalid UTF-8. `gather_finding_evidence` loads the normal blob, decodes the
     malformed one losslessly (no crash), and refuses to READ the oversized blob at
     all — it gates on the recorded `size_bytes` and notes it as omitted, so a
     pathological blob can never exhaust worker memory.

Cleans up via the dev-superuser trigger bypass (evidence / status history are
insert-only).
"""

import asyncio
import json
import sys
import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sqlalchemy import delete, select, text

import app.connectors.llm_target as llm_target
import app.services.triage as triage
from app.connectors import (
    TargetConnectorError,
    build_llm_target_connector,
    system_dns_resolver,
)
from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.security import PasswordService
from app.models.engagement import (
    Engagement,
    ScanIntensity,
    ScopeItem,
    ScopeKind,
    ScopeMatcher,
)
from app.models.evidence import Evidence, EvidenceKind
from app.models.finding import (
    Finding,
    FindingEvidence,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
    Severity,
)
from app.models.identity import Organization, User
from app.models.scan import Scan, ScanStatus, TestRun, TestSuite
from app.models.target import Target, TargetType
from app.services.triage import gather_finding_evidence
from app.storage.evidence import create_evidence_store, store_evidence

NOW = datetime(2026, 7, 23, tzinfo=UTC)

failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


# ── Part A: hostile tool output over real HTTP ────────────────────────────────
class _HostileHandler(BaseHTTPRequestHandler):
    """Returns a pathological body chosen by the user prompt. Writes raw bytes so
    malformed/truncated/oversized cases are exactly as hostile as the wire allows."""

    def log_message(self, *_args) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        length = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        user_turns = [m for m in body.get("messages", []) if m.get("role") == "user"]
        prompt = user_turns[-1]["content"] if user_turns else ""

        if prompt == "ok":
            payload = json.dumps({"choices": [{"message": {"content": "pong"}}]}).encode()
        elif prompt == "malformed":
            payload = b"this is definitely not json"
        elif prompt == "truncated":
            payload = b'{"choices": [{"message":'  # cut off mid-document
        elif prompt == "nested":
            payload = b"[" * 100_000 + b"]" * 100_000  # valid but stack-blowing
        elif prompt == "oversize":
            payload = json.dumps({"choices": [{"pad": "x" * 4000}]}).encode()
        else:
            payload = b"{}"

        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _hostile_target(endpoint: str) -> Target:
    # Transient (unsaved) ORM objects — the connector needs no DB row.
    return Target(
        name="hostile-mock",
        target_type=TargetType.AI_CHATBOT,
        primary_value=endpoint,
    )


_LOOPBACK_SCOPE = [
    ScopeItem(kind=ScopeKind.ALLOW, matcher_type=ScopeMatcher.IP_CIDR, value="127.0.0.0/8")
]


async def _send(target: Target, prompt: str) -> str:
    connector = build_llm_target_connector(target, _LOOPBACK_SCOPE, resolve=system_dns_resolver)
    try:
        return await connector.send(prompt)
    finally:
        await connector.aclose()


async def _fails_safe(target: Target, prompt: str) -> bool:
    """True iff the send raised TargetConnectorError and nothing else (no crash)."""
    try:
        await _send(target, prompt)
    except TargetConnectorError:
        return True
    except BaseException as exc:  # noqa: BLE001 — any other exception is a TM-8 failure
        print(f"    unexpected {type(exc).__name__}: {exc}")
        return False
    return False


async def part_a() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HostileHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    target = _hostile_target(endpoint)
    try:
        # Control: the streaming-bounded read still returns a valid reply.
        reply = await _send(target, "ok")
        check("A: valid tool output still parses (streaming happy path)", reply == "pong")

        check("A: non-JSON tool output fails safe", await _fails_safe(target, "malformed"))
        check("A: truncated tool output fails safe", await _fails_safe(target, "truncated"))
        check(
            "A: deeply-nested tool output fails safe (no RecursionError crash)",
            await _fails_safe(target, "nested"),
        )

        # Oversized body: lower the cap so the streaming reader aborts a body far
        # larger than the ceiling instead of buffering it all.
        original = llm_target.MAX_RESPONSE_BYTES
        llm_target.MAX_RESPONSE_BYTES = 512
        try:
            check("A: oversized tool output fails safe", await _fails_safe(target, "oversize"))
        finally:
            llm_target.MAX_RESPONSE_BYTES = original

        # And the unit-level parser guard, exercised directly.
        raised = False
        try:
            llm_target.parse_target_json(b'{"x":1}', max_bytes=4)
        except TargetConnectorError:
            raised = True
        check("A: parse_target_json rejects an oversized body", raised)
    finally:
        server.shutdown()


# ── Part B: hostile transcript blobs re-read for triage ───────────────────────
async def part_b() -> None:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    store = create_evidence_store(settings)
    store.ensure_bucket()

    org_id = finding_id = None
    normal_id = oversized_id = malformed_id = None

    async with sessionmaker() as session:
        org = Organization(name="verify-hostile-org")
        session.add(org)
        await session.flush()
        org_id = org.id
        pw = PasswordService(settings.password_hash_scheme)
        user = User(
            organization_id=org.id,
            email="verify-hostile@example.com",
            password_hash=pw.hash("verify-hostile-throwaway"),
            display_name="Verify Hostile",
        )
        session.add(user)
        await session.flush()
        eng = Engagement(
            organization_id=org.id,
            name="hostile-eng",
            client_system_name="acme",
            max_intensity=ScanIntensity.SAFE_ACTIVE,
            created_by=user.id,
            test_window_start=NOW - timedelta(days=1),
            test_window_end=NOW + timedelta(days=1),
        )
        session.add(eng)
        await session.flush()
        target = Target(
            engagement_id=eng.id,
            name="bot",
            target_type=TargetType.AI_CHATBOT,
            primary_value="https://bot.example.com/v1/chat",
        )
        session.add(target)
        await session.flush()
        scan = Scan(
            engagement_id=eng.id,
            target_id=target.id,
            status=ScanStatus.COMPLETED,
            intensity=ScanIntensity.SAFE_ACTIVE,
            initiated_by=user.id,
        )
        session.add(scan)
        await session.flush()
        test_run = TestRun(scan_id=scan.id, suite=TestSuite.PROMPT_INJECTION, config={})
        session.add(test_run)
        await session.flush()

        # Three linked blobs: a normal transcript, an oversized one, and one with
        # invalid UTF-8 bytes. Distinct content → three rows (no content dedup).
        normal = await store_evidence(
            session,
            store,
            organization_id=org.id,
            content=b'{"role":"assistant","content":"normal captured transcript"}',
            kind=EvidenceKind.LLM_TRANSCRIPT,
            content_type="application/json",
        )
        oversized = await store_evidence(
            session,
            store,
            organization_id=org.id,
            content=b"OVERSIZED-" + b"z" * 400,  # 410 bytes, > the lowered gate below
            kind=EvidenceKind.LLM_TRANSCRIPT,
            content_type="application/json",
        )
        malformed = await store_evidence(
            session,
            store,
            organization_id=org.id,
            content=b"\xff\xfe\x00 not valid utf-8 \x80\x81",
            kind=EvidenceKind.LLM_TRANSCRIPT,
            content_type="application/octet-stream",
        )
        normal_id, oversized_id, malformed_id = normal.id, oversized.id, malformed.id

        finding = Finding(
            engagement_id=eng.id,
            target_id=target.id,
            scan_id=scan.id,
            test_run_id=test_run.id,
            rule_id="pi.direct.override",
            title="Hostile transcript re-read",
            message="triage must bound the evidence it loads",
            severity=Severity.HIGH,
            provenance=FindingProvenance.AUTOMATED,
            status=FindingStatus.OPEN,
            hash_code=uuid.uuid4().bytes + uuid.uuid4().bytes,
            created_at=NOW,
            updated_at=NOW,
        )
        session.add(finding)
        await session.flush()
        finding_id = finding.id
        for ev in (normal, oversized, malformed):
            session.add(FindingEvidence(finding_id=finding.id, evidence_id=ev.id, caption="t"))
        session.add(
            FindingStatusHistory(
                finding_id=finding.id, to_status=FindingStatus.OPEN, changed_at=NOW
            )
        )
        await session.commit()

    # Gather with a lowered size gate so the 410-byte blob counts as "oversized".
    original = triage.MAX_EVIDENCE_BYTES
    triage.MAX_EVIDENCE_BYTES = 64
    try:
        async with sessionmaker() as session:
            items = await gather_finding_evidence(session, store, finding_id)
    finally:
        triage.MAX_EVIDENCE_BYTES = original

    by_id = {item.evidence_id: item for item in items}
    check("B: all three evidence records are represented", len(items) == 3)
    check(
        "B: normal transcript is loaded and decoded",
        normal_id in by_id and "normal captured transcript" in by_id[normal_id].text,
    )
    check(
        "B: oversized blob is NOT read — noted as omitted",
        oversized_id in by_id
        and "exceeds the" in by_id[oversized_id].text
        and "OVERSIZED" not in by_id[oversized_id].text,
    )
    check(
        "B: malformed (invalid UTF-8) blob decodes losslessly, no crash",
        malformed_id in by_id and isinstance(by_id[malformed_id].text, str),
    )

    # ── cleanup (trigger bypass: evidence / status history are insert-only) ──
    async with engine.begin() as conn:
        await conn.execute(text("SET session_replication_role = replica"))
        if finding_id is not None:
            await conn.execute(
                delete(FindingEvidence).where(FindingEvidence.finding_id == finding_id)
            )
            await conn.execute(
                delete(FindingStatusHistory).where(FindingStatusHistory.finding_id == finding_id)
            )
            await conn.execute(delete(Finding).where(Finding.id == finding_id))
        for ev_id in (normal_id, oversized_id, malformed_id):
            if ev_id is not None:
                await conn.execute(delete(Evidence).where(Evidence.id == ev_id))
        if org_id is not None:
            org_scan = select(Scan.id).join(Engagement).where(Engagement.organization_id == org_id)
            await conn.execute(delete(TestRun).where(TestRun.scan_id.in_(org_scan)))
            await conn.execute(
                delete(Scan).where(
                    Scan.engagement_id.in_(
                        select(Engagement.id).where(Engagement.organization_id == org_id)
                    )
                )
            )
            await conn.execute(
                delete(Target).where(
                    Target.engagement_id.in_(
                        select(Engagement.id).where(Engagement.organization_id == org_id)
                    )
                )
            )
            await conn.execute(delete(Engagement).where(Engagement.organization_id == org_id))
            await conn.execute(delete(User).where(User.organization_id == org_id))
            await conn.execute(delete(Organization).where(Organization.id == org_id))
    await engine.dispose()


async def main() -> None:
    print("== Part A: hostile tool output over real HTTP ==")
    await part_a()
    print("== Part B: hostile transcript blobs re-read for triage ==")
    await part_b()
    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    asyncio.run(main())
