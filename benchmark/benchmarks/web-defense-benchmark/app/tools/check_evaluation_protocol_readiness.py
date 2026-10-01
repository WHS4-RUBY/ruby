from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from analyze_confirmatory_campaign import load_json, paired_sample_size, validate_plan


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLAN = PROJECT_ROOT / "app" / "configs" / "confirmatory-analysis-plan-v1.json"
DEFAULT_NORMAL_EVIDENCE = (
    PROJECT_ROOT
    / "evidence"
    / "20260909"
    / "static-guard-v3-sql-regression.json"
)
DEFAULT_DEFENSE_REGISTRY = (
    PROJECT_ROOT / "app" / "configs" / "stage3a-defense-runtime-registry-v2.json"
)
BASELINE_SCOPE = (
    PROJECT_ROOT / "app" / "configs" / "stage3a-autonomous-baseline-scope-v1.json"
)
OFFICIAL_MODEL_CALLS_PER_TRIAL = 45


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def evaluate(
    plan_path: Path,
    normal_evidence_path: Path,
    defense_registry_path: Path,
) -> dict[str, object]:
    plan = load_json(plan_path)
    normal_evidence = load_json(normal_evidence_path)
    defense_registry = load_json(defense_registry_path)
    validate_plan(plan)
    required_pairs = paired_sample_size(plan)

    execution = plan["execution"]
    qualification = plan["qualification"]
    comparison = plan["primary_comparison"]
    normal_policy = plan["normal_traffic"]
    assert isinstance(execution, dict)
    assert isinstance(qualification, dict)
    assert isinstance(comparison, dict)
    assert isinstance(normal_policy, dict)
    scope_input = execution.get("scope_sealed_input")
    scope_path = (
        PROJECT_ROOT / "app" / str(scope_input)
        if isinstance(scope_input, str)
        else BASELINE_SCOPE
    )
    baseline_scope = load_json(scope_path)
    trial_limits = execution["trial_limits"]
    scope_limits = baseline_scope["trial_budget"]
    scope_execution = baseline_scope["execution"]
    scope_comparison = baseline_scope["comparison_policy"]
    assert isinstance(trial_limits, dict)
    assert isinstance(scope_limits, dict)
    assert isinstance(scope_execution, dict)
    assert isinstance(scope_comparison, dict)
    profile_path = PROJECT_ROOT / "app" / str(
        execution["attacker_profile_sealed_input"]
    )
    public_brief_input = execution.get("public_brief_sealed_input")
    public_brief_path = (
        PROJECT_ROOT / "app" / str(public_brief_input)
        if isinstance(public_brief_input, str)
        else None
    )
    scope_digest = execution.get("scope_sha256")
    public_brief_digest = execution.get("public_brief_sha256")
    scope_knowledge = baseline_scope.get("knowledge", {})

    registered = defense_registry.get("conditions", {})
    registered_conditions = set(registered) if isinstance(registered, dict) else set()
    evidence_row = normal_evidence
    results = normal_evidence.get("results")
    if isinstance(results, list):
        matching = [
            item
            for item in results
            if isinstance(item, dict) and item.get("condition") == "static-guard"
        ]
        if len(matching) != 1:
            raise ValueError("normal evidence needs exactly one static-guard result")
        evidence_row = matching[0]
    probe = evidence_row.get("normal_traffic_through_gateway", {})
    normal_metrics = evidence_row.get("normal_traffic_defense", {})
    if not isinstance(probe, dict):
        probe = {}
    if not isinstance(normal_metrics, dict):
        normal_metrics = {}

    expected_workflows = int(probe.get("expected_workflows") or 0)
    completed_workflows = probe.get("completed_workflows", [])
    failed_workflows = probe.get("failed_workflows", [])
    checks = {
        "analysis_plan_valid": True,
        "attacker_profile_exists": profile_path.is_file(),
        "attacker_profile_digest_matches": profile_path.is_file()
        and digest(profile_path).removeprefix("sha256:")
        == execution["attacker_profile_sha256"],
        "scope_exists_and_digest_matches": scope_path.is_file()
        and (
            scope_digest is None
            or digest(scope_path).removeprefix("sha256:") == scope_digest
        ),
        "knowledge_condition_matches_scope": isinstance(scope_knowledge, dict)
        and scope_knowledge.get("mode")
        == execution.get("knowledge_condition", "hidden-black-box"),
        "public_brief_exists_and_digest_matches": (
            public_brief_path is None
            and public_brief_digest is None
            or public_brief_path is not None
            and public_brief_path.is_file()
            and digest(public_brief_path).removeprefix("sha256:")
            == public_brief_digest
        ),
        "official_trial_budget_matches_scope": (
            trial_limits["wall_clock_seconds"] == scope_limits["wall_clock_seconds"]
            and trial_limits["active_http_requests"] == scope_limits["http_requests"]
            and trial_limits["agent_decisions"] == scope_limits["agent_decisions"]
            and trial_limits["model_calls_per_trial"]
            == OFFICIAL_MODEL_CALLS_PER_TRIAL
        ),
        "official_qualification_rule_matches_scope": (
            qualification["minimum_trials"]
            == scope_execution["repetitions_per_scenario"]
            and qualification["minimum_success_rate"]
            == scope_comparison["minimum_qualification_success_rate"]
        ),
        "reference_target_and_provider_fixed": execution["target_ids"]
        == ["ruby-web:sql-injection.product-search"]
        and execution["providers"] == ["codex"],
        "control_is_proxy_only": comparison.get("control_condition") == "proxy-only",
        "treatment_is_registered": comparison.get("treatment_condition")
        in registered_conditions,
        "sample_size_exceeds_qualification_pilot": required_pairs
        > int(qualification["minimum_trials"]),
        "post_attachment_normal_probe_present": probe.get("all_workflows_completed")
        is True,
        "all_normal_workflows_completed": expected_workflows > 0
        and isinstance(completed_workflows, list)
        and len(completed_workflows) == expected_workflows
        and failed_workflows == [],
        "limited_concurrent_normal_workflow_completed": int(
            probe.get("concurrent_workflows") or 0
        )
        >= 1
        and int(probe.get("concurrent_requests") or 0) >= 2,
        "normal_requests_not_blocked": int(
            normal_metrics.get("blocked_requests") or 0
        )
        <= int(normal_policy["maximum_blocked_requests"]),
        "normal_probe_has_no_defense_errors": int(
            normal_metrics.get("defense_errors") or 0
        )
        <= int(normal_policy["maximum_defense_errors"]),
    }
    return {
        "report_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "verdict": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "analysis_plan": {
            "path": plan_path.relative_to(PROJECT_ROOT).as_posix(),
            "sha256": digest(plan_path),
            "required_pairs_per_target_provider": required_pairs,
            "qualification_minimum_trials": qualification["minimum_trials"],
            "qualification_minimum_success_rate": qualification[
                "minimum_success_rate"
            ],
            "control_condition": comparison["control_condition"],
            "treatment_condition": comparison["treatment_condition"],
            "attacker_profile_id": execution["attacker_profile_id"],
            "target_ids": execution["target_ids"],
            "providers": execution["providers"],
            "schedule_seed": execution["schedule_seed"],
            "trial_limits": trial_limits,
            "knowledge_condition": execution.get(
                "knowledge_condition", "hidden-black-box"
            ),
            "scope": {
                "path": scope_path.relative_to(PROJECT_ROOT).as_posix(),
                "sha256": digest(scope_path),
            },
            "public_brief": (
                {
                    "path": public_brief_path.relative_to(PROJECT_ROOT).as_posix(),
                    "sha256": digest(public_brief_path),
                }
                if public_brief_path is not None
                else None
            ),
        },
        "normal_traffic_evidence": {
            "path": normal_evidence_path.relative_to(PROJECT_ROOT).as_posix(),
            "sha256": digest(normal_evidence_path),
            "expected_workflows": expected_workflows,
            "completed_workflows": len(completed_workflows)
            if isinstance(completed_workflows, list)
            else 0,
            "http_requests": probe.get("http_requests"),
            "blocked_requests": normal_metrics.get("blocked_requests"),
            "defense_errors": normal_metrics.get("defense_errors"),
        },
        "claim_status": {
            "evaluation_protocol_ready": all(checks.values()),
            "confirmatory_campaign_completed": False,
            "independent_review_completed": False,
            "defense_efficacy_claim_allowed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis-plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--normal-evidence", type=Path, default=DEFAULT_NORMAL_EVIDENCE)
    parser.add_argument(
        "--defense-registry", type=Path, default=DEFAULT_DEFENSE_REGISTRY
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite report: {output}")
    report = evaluate(
        args.analysis_plan.resolve(),
        args.normal_evidence.resolve(),
        args.defense_registry.resolve(),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"verdict": report["verdict"], "report": str(output)}))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
