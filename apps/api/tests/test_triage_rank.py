"""Deterministic triage rank/group unit tests (M4-B2) — CI-safe, pure (no DB/LLM).

The ranking key is fixed: severity band, then current CVSS base score (unscored
last within a band), then recency. Grouping keys on rule_id (else discovery
source). No LLM and no mutation are involved.
"""

import uuid
from datetime import UTC, datetime, timedelta

from app.models.finding import Finding, FindingProvenance, FindingStatus, Severity
from app.services.finding_hash import PF_SOURCE
from app.services.triage_rank import (
    group_key_for,
    group_ranked,
    rank_findings,
)

BASE = datetime(2026, 7, 24, tzinfo=UTC)


def _f(sev: Severity, *, rule_id="r", source=None, age_s=0, fid=None) -> Finding:
    pf = {PF_SOURCE: source} if source else {}
    return Finding(
        id=fid or uuid.uuid4(),
        engagement_id=uuid.uuid4(),
        target_id=uuid.uuid4(),
        rule_id=rule_id,
        title=f"{rule_id} finding",
        message="m",
        severity=sev,
        provenance=FindingProvenance.AUTOMATED,
        status=FindingStatus.OPEN,
        hash_code=b"\x00" * 32,
        partial_fingerprints=pf,
        created_at=BASE - timedelta(seconds=age_s),
    )


# ── group_key_for ────────────────────────────────────────────────────────────
def test_group_key_prefers_rule_id_then_source_then_ungrouped() -> None:
    assert group_key_for(_f(Severity.HIGH, rule_id="sqli")) == "sqli"
    f_no_rule = _f(Severity.HIGH, rule_id=None, source="zap")
    assert group_key_for(f_no_rule) == "zap"
    f_bare = _f(Severity.HIGH, rule_id=None)
    assert group_key_for(f_bare) == "ungrouped"


# ── rank_findings ────────────────────────────────────────────────────────────
def test_rank_orders_by_severity_first() -> None:
    high = _f(Severity.HIGH, fid=uuid.uuid4())
    crit = _f(Severity.CRITICAL, fid=uuid.uuid4())
    low = _f(Severity.LOW, fid=uuid.uuid4())
    ranked = rank_findings([high, low, crit], cvss_scores={})
    assert [r.severity for r in ranked] == [Severity.CRITICAL, Severity.HIGH, Severity.LOW]
    assert [r.rank for r in ranked] == [1, 2, 3]


def test_rank_uses_cvss_within_a_band_unscored_last() -> None:
    a = _f(Severity.HIGH, fid=uuid.uuid4())
    b = _f(Severity.HIGH, fid=uuid.uuid4())
    c = _f(Severity.HIGH, fid=uuid.uuid4())
    scores = {a.id: 7.5, b.id: 8.9, c.id: None}  # c unscored
    ranked = rank_findings([a, b, c], scores)
    assert [r.finding_id for r in ranked] == [b.id, a.id, c.id]
    assert ranked[0].cvss_base_score == 8.9
    assert ranked[2].cvss_base_score is None


def test_rank_recency_breaks_ties() -> None:
    newer = _f(Severity.MEDIUM, age_s=0, fid=uuid.uuid4())
    older = _f(Severity.MEDIUM, age_s=100, fid=uuid.uuid4())
    ranked = rank_findings([older, newer], cvss_scores={})
    assert [r.finding_id for r in ranked] == [newer.id, older.id]


# ── group_ranked ─────────────────────────────────────────────────────────────
def test_group_aggregates_by_key_with_max_severity_and_top_rank() -> None:
    # Two rules; "sqli" has a CRITICAL member so it ranks first and represents CRITICAL.
    xss1 = _f(Severity.MEDIUM, rule_id="xss", fid=uuid.uuid4())
    xss2 = _f(Severity.LOW, rule_id="xss", fid=uuid.uuid4())
    sqli1 = _f(Severity.CRITICAL, rule_id="sqli", fid=uuid.uuid4())
    sqli2 = _f(Severity.HIGH, rule_id="sqli", fid=uuid.uuid4())
    ranked = rank_findings([xss1, xss2, sqli1, sqli2], cvss_scores={})
    groups = group_ranked(ranked)
    assert [g.group_key for g in groups] == ["sqli", "xss"]  # sqli's top_rank is best
    sqli = groups[0]
    assert sqli.severity is Severity.CRITICAL
    assert sqli.count == 2
    assert sqli.top_rank == 1
    assert set(sqli.finding_ids) == {sqli1.id, sqli2.id}
    xss = groups[1]
    assert xss.severity is Severity.MEDIUM  # most severe member of the group
    assert xss.count == 2
