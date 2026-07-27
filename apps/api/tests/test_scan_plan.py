"""M4 scan-plan generation: the deterministic recommendation logic (pure).

CI-safe (no DB): covers the target-type → scanners mapping, the recon-signal
extraction (httpx tech + katana endpoints), reason refinement, and the
already_run flagging. The DB wiring (loading a target's findings + completed
runs) is proven live in scripts/verify_scan_plan.py.
"""

import uuid

from app.models.finding import Finding
from app.models.target import TargetType
from app.services.scan_plan import build_recommendations, recon_signals


def _finding(rule_id: str, location: dict) -> Finding:
    f = Finding()
    f.id = uuid.uuid4()
    f.rule_id = rule_id
    f.location = location
    return f


def test_recon_signals_extracts_techs_and_endpoint_count() -> None:
    findings = [
        _finding("httpx-tech", {"technology": "nginx"}),
        _finding("httpx-tech", {"technology": "PHP"}),
        _finding("httpx-tech", {"technology": "nginx"}),  # dup tech
        _finding("katana-endpoint", {"url": "http://t/a"}),
        _finding("katana-endpoint", {"url": "http://t/b"}),
        _finding("httpx-fingerprint", {"url": "http://t"}),  # not a tech/endpoint
    ]
    techs, endpoints = recon_signals(findings)
    assert techs == ["PHP", "nginx"]  # sorted, deduped
    assert endpoints == 2


def test_source_target_plan() -> None:
    recs = build_recommendations(
        TargetType.SOURCE_REPO, detected_techs=[], endpoint_count=0, ran_sources=set()
    )
    assert [r.scanner for r in recs] == ["semgrep", "gitleaks", "osv-scanner"]
    assert {r.category for r in recs} == {"sast", "secrets", "sca"}
    assert all(not r.already_run for r in recs)


def test_web_target_plan_recon_first_then_dast() -> None:
    recs = build_recommendations(
        TargetType.WEB_APP, detected_techs=[], endpoint_count=0, ran_sources=set()
    )
    assert [r.scanner for r in recs] == ["httpx", "katana", "nuclei", "zap"]


def test_llm_target_plan() -> None:
    recs = build_recommendations(
        TargetType.AI_CHATBOT, detected_techs=[], endpoint_count=0, ran_sources=set()
    )
    assert [r.scanner for r in recs] == ["prompt_injection", "data_leakage"]
    assert all(r.category == "llm" for r in recs)


def test_already_run_flag_reflects_completed_scans() -> None:
    recs = build_recommendations(
        TargetType.WEB_APP,
        detected_techs=[],
        endpoint_count=0,
        ran_sources={"httpx", "zap"},
    )
    by = {r.scanner: r for r in recs}
    assert by["httpx"].already_run and by["zap"].already_run
    assert not by["katana"].already_run and not by["nuclei"].already_run


def test_recon_signals_refine_reasons() -> None:
    recs = build_recommendations(
        TargetType.WEB_APP,
        detected_techs=["nginx", "PHP"],
        endpoint_count=7,
        ran_sources=set(),
    )
    by = {r.scanner: r for r in recs}
    assert "7 endpoint(s) mapped by recon" in by["nuclei"].reason
    assert "Recon detected: nginx, PHP" in by["nuclei"].reason
    assert "7 endpoint(s) mapped by recon" in by["zap"].reason
    # recon scanners themselves are not refined by these signals
    assert "endpoint(s) mapped" not in by["httpx"].reason


def test_unknown_target_type_has_no_recommendations() -> None:
    assert build_recommendations(
        TargetType.AI_AGENT, detected_techs=[], endpoint_count=0, ran_sources=set()
    ) == build_recommendations(
        TargetType.LLM_API_WRAPPER, detected_techs=[], endpoint_count=0, ran_sources=set()
    )  # both map to the LLM plan
