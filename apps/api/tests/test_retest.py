"""M4-B3: the deterministic reimport/retest transition table (schema §9).

Pure, infra-free coverage of `next_status` — the rescan-presence → status rule.
The DB wiring (population query, history + retest rows, per-source scoping) is
proven against real Postgres in scripts/verify_retest.py.
"""

from app.models.finding import FindingStatus as S
from app.services.retest import next_status


def test_absent_active_findings_auto_mitigate() -> None:
    for prior in (S.OPEN, S.IN_TRIAGE, S.CONFIRMED):
        assert next_status(prior, present=False) is S.MITIGATED


def test_reappearing_resolved_findings_auto_reopen() -> None:
    for prior in (S.MITIGATED, S.FIXED):
        assert next_status(prior, present=True) is S.OPEN


def test_present_active_and_absent_resolved_are_no_ops() -> None:
    assert next_status(S.OPEN, present=True) is None  # still there, already open
    assert next_status(S.MITIGATED, present=False) is None  # still gone


def test_automation_never_sets_fixed() -> None:
    # No (prior, present) input yields FIXED — §2.9, fixed is human-only.
    for prior in S:
        for present in (True, False):
            assert next_status(prior, present) is not S.FIXED


def test_human_risk_decisions_are_never_overridden() -> None:
    for prior in (S.ACCEPTED_RISK, S.FALSE_POSITIVE, S.OUT_OF_SCOPE):
        assert next_status(prior, present=True) is None
        assert next_status(prior, present=False) is None
