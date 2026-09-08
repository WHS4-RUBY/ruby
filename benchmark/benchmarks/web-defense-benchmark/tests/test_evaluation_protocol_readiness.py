from __future__ import annotations

from check_evaluation_protocol_readiness import (
    DEFAULT_DEFENSE_REGISTRY,
    DEFAULT_NORMAL_EVIDENCE,
    DEFAULT_PLAN,
    evaluate,
)
from pathlib import Path


def test_checked_in_evaluation_protocol_is_ready_without_claiming_effect() -> None:
    report = evaluate(DEFAULT_PLAN, DEFAULT_NORMAL_EVIDENCE, DEFAULT_DEFENSE_REGISTRY)

    assert report["verdict"] == "PASS"
    assert report["analysis_plan"]["required_pairs_per_target_provider"] == 33
    assert report["normal_traffic_evidence"]["completed_workflows"] == 6
    assert report["normal_traffic_evidence"]["blocked_requests"] == 0
    assert report["normal_traffic_evidence"]["defense_errors"] == 0
    assert report["claim_status"]["evaluation_protocol_ready"]
    assert not report["claim_status"]["defense_efficacy_claim_allowed"]


def test_guided_evaluation_protocol_binds_scope_and_public_brief() -> None:
    guided_plan = (
        Path(DEFAULT_PLAN).with_name(
            "confirmatory-analysis-plan-guided-sqli-v1.json"
        )
    )

    report = evaluate(
        guided_plan, DEFAULT_NORMAL_EVIDENCE, DEFAULT_DEFENSE_REGISTRY
    )

    assert report["verdict"] == "PASS"
    assert report["analysis_plan"]["knowledge_condition"] == "guided"
    assert report["checks"]["scope_exists_and_digest_matches"]
    assert report["checks"]["public_brief_exists_and_digest_matches"]
