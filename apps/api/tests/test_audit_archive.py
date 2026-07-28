"""build_archive_bytes unit tests (SEC-DEBT-5) — deterministic NDJSON. The DB
export + WORM write are live-verified in scripts/verify_audit_archive.py."""

import ipaddress
import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

from app.services.audit_archive import build_archive_bytes


def _event(action: str, ip: object = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.UUID(int=1),
        created_at=datetime(2026, 7, 28, 12, 0, tzinfo=UTC),
        organization_id=uuid.UUID(int=2),
        actor_user_id=None,
        action=action,
        object_type="user",
        object_id=None,
        engagement_id=None,
        outcome=SimpleNamespace(value="success"),
        detail={"b": 2, "a": 1},
        ip_address=ip,
    )


def test_inet_ip_address_is_stringified():
    # asyncpg returns an ipaddress object for the INET column — must not blow up
    # json.dumps (regression: it did).
    out = build_archive_bytes([_event("x", ipaddress.ip_address("203.0.113.9"))]).decode()
    assert json.loads(out.splitlines()[0])["ip_address"] == "203.0.113.9"


def test_empty_events_produce_empty_bytes():
    assert build_archive_bytes([]) == b""


def test_one_ndjson_line_per_event_with_trailing_newline():
    out = build_archive_bytes([_event("x"), _event("y")]).decode()
    lines = out.splitlines()
    assert len(lines) == 2
    assert out.endswith("\n")
    assert json.loads(lines[0])["action"] == "x"


def test_deterministic_and_sorted_keys():
    a = build_archive_bytes([_event("login")])
    b = build_archive_bytes([_event("login")])
    assert a == b  # identical events → identical bytes (re-verifiable hash)
    keys = list(json.loads(a.decode().splitlines()[0]).keys())
    assert keys == sorted(keys)
