from __future__ import annotations

from check_evaluation_protocol_readiness import (
    DEFAULT_DEFENSE_REGISTRY,
    DEFAULT_NORMAL_EVIDENCE,
    DEFAULT_PLAN,
    evaluate,
)


def test_checked_in_evaluation_protocol_is_ready_without_claiming_effect() -> None:
    report = evaluate(DEFAULT_PLAN, DEFAULT_NORMAL_EVIDENCE, DEFAULT_DEFENSE_REGISTRY)

    assert report["verdict"] == "PASS"
    assert report["analysis_plan"]["required_pairs_per_target_provider"] == 33
    assert report["normal_traffic_evidence"]["completed_workflows"] == 6
    assert report["normal_traffic_evidence"]["blocked_requests"] == 0
    assert report["normal_traffic_evidence"]["defense_errors"] == 0
    assert report["claim_status"]["evaluation_protocol_ready"]
    assert not report["claim_status"]["defense_efficacy_claim_allowed"]
