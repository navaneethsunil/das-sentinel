"""M3-B4 compliance KB + mapping — CI-safe unit tests (no DB).

Validates that the shipped KB (packages/compliance/*.json) parses and has the
expected framework/control shape, that load_kb fails loud on malformed input, and
that auto/manual mapping behaves correctly via a fake session. The full seed +
HTTP + real-DB path is proven in scripts/verify_compliance.py.
"""

import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.models.compliance import ComplianceControl, FindingComplianceMapping
from app.models.finding import FindingProvenance
from app.services.compliance import (
    ComplianceKBError,
    ComplianceMappingError,
    add_mapping,
    auto_map_finding,
    load_kb,
)

KB_DIR = Path(__file__).resolve().parents[3] / "packages" / "compliance"


def test_real_kb_parses_with_expected_frameworks() -> None:
    frameworks = {f.key: f for f in load_kb(KB_DIR)}
    assert set(frameworks) == {
        "owasp_llm_2025",
        "owasp_wstg_4_2",
        "nist_ai_rmf",
        "nist_ai_600_1",
        "nist_800_53_r5",
        "nist_800_115",
    }
    llm = frameworks["owasp_llm_2025"]
    codes = {c.code for c in llm.controls}
    assert {"LLM01", "LLM05", "LLM07", "LLM08", "LLM10"} <= codes
    assert len(llm.controls) == 10
    assert len(frameworks["owasp_wstg_4_2"].controls) == 12
    assert len(frameworks["nist_ai_rmf"].controls) == 19
    assert len(frameworks["nist_ai_600_1"].controls) == 12
    # every control has a title; version is recorded per framework
    assert all(c.title for f in frameworks.values() for c in f.controls)
    assert frameworks["nist_800_53_r5"].version == "Rev 5.2.0"


def test_load_kb_missing_dir(tmp_path: Path) -> None:
    with pytest.raises(ComplianceKBError):
        load_kb(tmp_path / "does-not-exist")


def test_load_kb_empty_dir(tmp_path: Path) -> None:
    with pytest.raises(ComplianceKBError):
        load_kb(tmp_path)


def test_load_kb_rejects_bad_json(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ComplianceKBError):
        load_kb(tmp_path)


def test_load_kb_rejects_missing_fields(tmp_path: Path) -> None:
    (tmp_path / "f.json").write_text(
        json.dumps({"key": "x", "name": "X", "version": "1", "controls": [{"code": "A"}]}),
        encoding="utf-8",
    )
    with pytest.raises(ComplianceKBError):  # control missing 'title'
        load_kb(tmp_path)


def test_load_kb_rejects_duplicate_control_code(tmp_path: Path) -> None:
    (tmp_path / "f.json").write_text(
        json.dumps(
            {
                "key": "x",
                "name": "X",
                "version": "1",
                "controls": [
                    {"code": "A", "title": "a"},
                    {"code": "A", "title": "dup"},
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ComplianceKBError):
        load_kb(tmp_path)


class _FakeResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _FakeSession:
    """Stand-in for auto_map_finding / add_mapping (no DB)."""

    def __init__(self, control: object = None, existing: object = None) -> None:
        self._control = control
        self._existing = existing
        self.added: list[object] = []
        self.flushed = False

    async def execute(self, stmt: object) -> _FakeResult:
        return _FakeResult(self._control)

    async def get(self, model: object, key: object) -> object:
        if model is ComplianceControl:
            return self._control
        if model is FindingComplianceMapping:
            return self._existing
        return None

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushed = True


def _finding(location: dict | None) -> SimpleNamespace:
    return SimpleNamespace(id=uuid.uuid4(), location=location)


@pytest.mark.asyncio
async def test_auto_map_owasp_llm_finding() -> None:
    control = SimpleNamespace(id=uuid.uuid4())
    session = _FakeSession(control=control, existing=None)
    finding = _finding({"owasp": {"framework": "OWASP-LLM-2025", "code": "LLM01"}})
    created = await auto_map_finding(session, finding)  # type: ignore[arg-type]
    assert created == [control.id]
    assert len(session.added) == 1
    mapping = session.added[0]
    assert isinstance(mapping, FindingComplianceMapping)
    assert mapping.control_id == control.id
    assert mapping.mapped_by is FindingProvenance.AUTOMATED


@pytest.mark.asyncio
async def test_auto_map_skips_when_already_mapped() -> None:
    control = SimpleNamespace(id=uuid.uuid4())
    session = _FakeSession(control=control, existing=object())  # mapping exists
    finding = _finding({"owasp": {"framework": "OWASP-LLM-2025", "code": "LLM01"}})
    assert await auto_map_finding(session, finding) == []  # type: ignore[arg-type]
    assert session.added == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "location",
    [
        None,
        {},
        {"owasp": "not-a-dict"},
        {"owasp": {"framework": "acme-linter", "code": "X"}},  # non-LLM framework
        {"owasp": {"framework": "OWASP-LLM-2025"}},  # no code
    ],
)
async def test_auto_map_no_signal(location: dict | None) -> None:
    session = _FakeSession(control=SimpleNamespace(id=uuid.uuid4()))
    assert await auto_map_finding(session, _finding(location)) == []  # type: ignore[arg-type]
    assert session.added == []


@pytest.mark.asyncio
async def test_auto_map_control_not_seeded() -> None:
    session = _FakeSession(control=None)  # KB not seeded / unknown code
    finding = _finding({"owasp": {"framework": "OWASP-LLM-2025", "code": "LLM99"}})
    assert await auto_map_finding(session, finding) == []  # type: ignore[arg-type]
    assert session.added == []


@pytest.mark.asyncio
async def test_add_mapping_unknown_control_raises() -> None:
    session = _FakeSession(control=None)
    with pytest.raises(ComplianceMappingError):
        await add_mapping(session, _finding({}), uuid.uuid4())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_add_mapping_human_default_validated() -> None:
    control = SimpleNamespace(id=uuid.uuid4())
    session = _FakeSession(control=control, existing=None)
    finding = _finding({})
    row = await add_mapping(session, finding, control.id)  # type: ignore[arg-type]
    assert row.mapped_by is FindingProvenance.VALIDATED
    assert session.added == [row]
