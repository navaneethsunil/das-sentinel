"""M3-B2 + M3-T2: SARIF 2.1.0 export/import + reimport dedup. CI-safe (no infra).

Covers the pure export/parse logic and the round-trip hash-stability property
(a DAS-exported log re-imports to the same identity), plus fail-closed parsing
of malformed/oversized/wrong-version SARIF (TM-8).

M3-T2 adds coverage of the `import_sarif_findings` DB path itself over a fake
session: a reimport of the same finding links `duplicate_of` the canonical
original, and a full export→import→export round-trip preserves finding identity.
The same path against a real Postgres + MinIO is proven in scripts/verify_sarif.py.
"""

import json
import uuid
from datetime import UTC, datetime

import pytest

from app.models.engagement import Engagement
from app.models.evidence import Evidence
from app.models.finding import (
    Finding,
    FindingEvidence,
    FindingProvenance,
    FindingStatus,
    SarifLevel,
    Severity,
)
from app.models.target import Target
from app.services.finding_hash import (
    PF_FINGERPRINT,
    PF_SOURCE,
    compute_hash_code,
    location_fingerprint,
)
from app.services.sarif import (
    MAX_SARIF_RESULTS,
    SARIF_VERSION,
    SarifError,
    build_sarif_log,
    import_sarif_findings,
    iter_results,
    parse_sarif,
)

ENG = uuid.uuid4()
TGT = uuid.uuid4()
NOW = datetime(2026, 7, 24, tzinfo=UTC)


def _finding(**kw) -> Finding:  # noqa: ANN003
    base = {
        "id": uuid.uuid4(),
        "engagement_id": ENG,
        "target_id": TGT,
        "rule_id": "python.lang.security.eval",
        "title": "eval-detected",
        "message": "arbitrary code execution",
        "sarif_level": SarifLevel.ERROR,
        "location": {"file": "pkg/a.py", "start_line": 12, "end_line": 12},
        "severity": Severity.HIGH,
        "provenance": FindingProvenance.AUTOMATED,
        "status": FindingStatus.OPEN,
        "hash_code": compute_hash_code(ENG, TGT, "semgrep", "fp-1"),
        "partial_fingerprints": {PF_SOURCE: "semgrep", PF_FINGERPRINT: "fp-1", "rule_id": "x"},
    }
    base.update(kw)
    return Finding(**base)


# ── hash identity ────────────────────────────────────────────────────────────
def test_hash_code_is_stable_and_32_bytes() -> None:
    h1 = compute_hash_code(ENG, TGT, "semgrep", "fp-1")
    h2 = compute_hash_code(ENG, TGT, "semgrep", "fp-1")
    assert h1 == h2
    assert len(h1) == 32


def test_hash_code_distinguishes_source_and_fingerprint() -> None:
    base = compute_hash_code(ENG, TGT, "semgrep", "fp-1")
    assert base != compute_hash_code(ENG, TGT, "zap", "fp-1")
    assert base != compute_hash_code(ENG, TGT, "semgrep", "fp-2")
    assert base != compute_hash_code(ENG, uuid.uuid4(), "semgrep", "fp-1")


def test_location_fingerprint_composes_rule_and_location() -> None:
    fp = location_fingerprint("rule.x", {"file": "a.py", "start_line": 9})
    assert fp == "rule.x:a.py:9"


# ── export shape ─────────────────────────────────────────────────────────────
def test_export_is_valid_sarif_210() -> None:
    log = build_sarif_log([_finding()])
    assert log["version"] == SARIF_VERSION
    assert log["$schema"].endswith("sarif-2.1.0.json")
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"]
    result = run["results"][0]
    assert result["ruleId"] == "python.lang.security.eval"
    assert result["level"] == "error"
    assert result["message"]["text"] == "arbitrary code execution"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "pkg/a.py"
    assert loc["region"]["startLine"] == 12
    # exact identity embedded for round-trip dedup
    assert result["partialFingerprints"]["dasHash/v1"]


def test_export_is_json_serializable() -> None:
    json.dumps(build_sarif_log([_finding(), _finding(rule_id="other", hash_code=b"\x01" * 32)]))


# ── round-trip: exported → parsed carries the same identity ──────────────────
def test_round_trip_preserves_hash_identity() -> None:
    f = _finding()
    log = build_sarif_log([f])
    parsed = iter_results(parse_sarif(json.dumps(log).encode()))
    assert len(parsed) == 1
    pr = parsed[0]
    # the exported hash is recovered exactly (→ dedup will link duplicate_of)
    assert pr.exported_hash == f.hash_code
    assert pr.source == "semgrep"
    assert pr.fingerprint == "fp-1"
    assert pr.location["file"] == "pkg/a.py"


def test_foreign_sarif_hash_derived_from_source_and_fingerprint() -> None:
    # A foreign log (no dasHash) → hash derived deterministically; recompute matches.
    log = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "acme-linter"}},
                "results": [
                    {
                        "ruleId": "ACME001",
                        "level": "warning",
                        "message": {"text": "smell"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "x.py"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    pr = iter_results(parse_sarif(json.dumps(log).encode()))[0]
    assert pr.exported_hash is None
    assert pr.source == "acme-linter"
    assert pr.fingerprint == location_fingerprint("ACME001", {"file": "x.py", "start_line": 3})


# ── fail-closed parsing (TM-8) ───────────────────────────────────────────────
def test_parse_rejects_non_json() -> None:
    with pytest.raises(SarifError):
        parse_sarif(b"not json")


def test_parse_rejects_non_object_root() -> None:
    with pytest.raises(SarifError):
        parse_sarif(b"[1,2,3]")


def test_parse_rejects_wrong_version() -> None:
    with pytest.raises(SarifError):
        parse_sarif(json.dumps({"version": "1.0.0", "runs": []}).encode())


def test_parse_rejects_missing_runs() -> None:
    with pytest.raises(SarifError):
        parse_sarif(json.dumps({"version": "2.1.0"}).encode())


def test_parse_rejects_oversized() -> None:
    with pytest.raises(SarifError):
        parse_sarif(b"x" * (16 * 1024 * 1024 + 1))


def test_iter_results_skips_malformed_entries() -> None:
    log = {
        "version": "2.1.0",
        "runs": [
            "not-a-run",
            {"tool": {"driver": {"name": "t"}}, "results": ["bad", {"ruleId": "ok"}]},
            {"no": "results"},
        ],
    }
    parsed = iter_results(parse_sarif(json.dumps(log).encode()))
    assert len(parsed) == 1
    assert parsed[0].rule_id == "ok"


def test_iter_results_enforces_result_cap() -> None:
    results = [{"ruleId": f"r{i}", "message": {"text": "m"}} for i in range(MAX_SARIF_RESULTS + 1)]
    log = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": results}]}
    with pytest.raises(SarifError):
        iter_results(parse_sarif(json.dumps(log).encode()))


# ── import DB path: dedup → duplicate_of + round-trip (M3-T2) ─────────────────
class _FakeBlobStore:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_object(self, key, data, content_type, retain_until) -> None:  # noqa: ANN001
        self.objects[key] = data


class _Result:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _FakeSession:
    """Returns queued scalar results in call order: store_evidence's
    evidence-dedup lookup first, then one `_existing_canonical` lookup per SARIF
    result. Assigns ids on flush (mirrors test_findings.py)."""

    def __init__(self, scalar_returns: list[object]) -> None:
        self._scalars = list(scalar_returns)
        self.added: list[object] = []

    async def execute(self, _stmt: object) -> _Result:
        return _Result(self._scalars.pop(0) if self._scalars else None)

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        for obj in self.added:
            if getattr(obj, "id", "unset") is None:
                obj.id = uuid.uuid4()


def _import_context() -> tuple[Engagement, Target]:
    eng = Engagement()
    eng.id = ENG  # matches _finding()'s hash_code inputs → round-trip identity holds
    eng.organization_id = uuid.uuid4()
    tgt = Target()
    tgt.id = TGT
    return eng, tgt


async def test_import_creates_fresh_finding_when_no_canonical_exists() -> None:
    eng, tgt = _import_context()
    # no existing evidence, no existing canonical finding
    session = _FakeSession([None, None])
    store = _FakeBlobStore()
    raw = json.dumps(build_sarif_log([_finding()])).encode()

    summary = await import_sarif_findings(
        session, store, engagement=eng, target=tgt, raw=raw, now=NOW
    )

    assert len(summary.created) == 1
    assert summary.duplicates == []
    created = summary.created[0]
    assert created.duplicate_of is None
    # the exact hash survives export → import (round-trip identity)
    assert created.hash_code == _finding().hash_code
    assert created.provenance is FindingProvenance.AUTOMATED
    assert created.status is FindingStatus.OPEN
    # raw SARIF stored once as immutable evidence; finding cites it
    assert len(store.objects) == 1
    assert any(isinstance(o, FindingEvidence) for o in session.added)


async def test_reimport_links_duplicate_of_canonical() -> None:
    """The dedup guarantee: reimporting a finding that already exists for the
    target links the new row `duplicate_of` the canonical original (TR-20)."""
    eng, tgt = _import_context()
    canonical = _finding()
    canonical.id = uuid.uuid4()
    existing_evidence = Evidence()
    existing_evidence.id = uuid.uuid4()
    # reimport: identical SARIF bytes dedup to the existing evidence blob;
    # the canonical-finding lookup hits.
    session = _FakeSession([existing_evidence, canonical])
    store = _FakeBlobStore()
    raw = json.dumps(build_sarif_log([canonical])).encode()

    summary = await import_sarif_findings(
        session, store, engagement=eng, target=tgt, raw=raw, now=NOW
    )

    assert summary.created == []
    assert len(summary.duplicates) == 1
    dup = summary.duplicates[0]
    assert dup.duplicate_of == canonical.id
    assert dup.hash_code == canonical.hash_code  # same identity → deduped
    assert store.objects == {}  # content-addressed evidence deduped, no new blob


async def test_round_trip_export_import_export_preserves_identity() -> None:
    """export → import (fresh) → re-export: the hash_code survives both hops, so a
    log can leave DAS, come back, and dedup to the same finding identity."""
    eng, tgt = _import_context()
    session = _FakeSession([None, None])
    store = _FakeBlobStore()
    original = _finding()

    raw = json.dumps(build_sarif_log([original])).encode()
    summary = await import_sarif_findings(
        session, store, engagement=eng, target=tgt, raw=raw, now=NOW
    )
    imported = summary.created[0]

    reexported = build_sarif_log([imported])
    result = reexported["runs"][0]["results"][0]
    assert result["partialFingerprints"]["dasHash/v1"] == original.hash_code.hex()
    assert result["partialFingerprints"][PF_SOURCE] == "semgrep"
    assert result["partialFingerprints"][PF_FINGERPRINT] == "fp-1"
