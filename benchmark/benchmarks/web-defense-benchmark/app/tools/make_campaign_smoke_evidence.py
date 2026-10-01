from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Callable

from analyze_confirmatory_campaign import DEFAULT_PLAN, validate_plan


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BASELINE_SCOPE = (
    PROJECT_ROOT / "app" / "configs" / "stage3a-autonomous-baseline-scope-v1.json"
)
OFFICIAL_MODEL_CALLS_PER_TRIAL = 45
INFRASTRUCTURE_FAILURES = {
    "setup-error",
    "model-error",
    "runner-error",
    "isolation-error",
    "verifier-error",
    "invalid-defense-error",
}
def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def docker_project_resources(project: str) -> dict[str, list[str]]:
    containers = subprocess.run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    ).stdout.splitlines()
    networks = subprocess.run(
        [
            "docker",
            "network",
            "ls",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    ).stdout.splitlines()
    return {"containers": containers, "networks": networks}


def make_evidence(
    run_dir: Path,
    resource_lookup: Callable[[str], dict[str, list[str]]] = docker_project_resources,
    analysis_plan_path: Path = DEFAULT_PLAN,
) -> dict[str, object]:
    run_dir = run_dir.resolve()
    seal_path = run_dir / "run-seal.json"
    schedule_path = run_dir / "schedule.json"
    summary_path = run_dir / "campaign-summary.json"
    seal = load_json(seal_path)
    schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
    summary = load_json(summary_path)
    plan = load_json(analysis_plan_path.resolve())
    execution = plan["execution"]
    assert isinstance(execution, dict)
    scope_input = execution.get("scope_sealed_input")
    scope_path = (
        PROJECT_ROOT / "app" / str(scope_input)
        if isinstance(scope_input, str)
        else BASELINE_SCOPE
    )
    baseline_scope = load_json(scope_path)
    validate_plan(plan)
    qualification = plan["qualification"]
    assert isinstance(execution, dict)
    assert isinstance(qualification, dict)
    if not isinstance(schedule, list):
        raise ValueError("schedule must be a list")
    trial_paths = sorted(
        path
        for path in (run_dir / "trials").glob("*.json")
        if not path.name.endswith((".checkpoint.json", ".running.json"))
    )
    trials = [load_json(path) for path in trial_paths]
    schedule_keys = [
        str(item.get("trial_key", "")) if isinstance(item, dict) else ""
        for item in schedule
    ]
    trial_keys = [str(item.get("trial_key", "")) for item in trials]

    project_resources: dict[str, dict[str, list[str]]] = {}
    for trial in trials:
        isolation = trial.get("isolation")
        if not isinstance(isolation, dict):
            continue
        project = isolation.get("compose_project")
        if isinstance(project, str) and project:
            project_resources[project] = resource_lookup(project)

    trial_rows = []
    for path, trial in zip(trial_paths, trials, strict=True):
        normal_probe = trial.get("normal_traffic_through_gateway")
        metrics = trial.get("metrics")
        normal_metrics = (
            metrics.get("normal_traffic_defense", {})
            if isinstance(metrics, dict)
            else {}
        )
        invocations = trial.get("model_invocations", [])
        prohibited = [
            event
            for invocation in invocations
            if isinstance(invocations, list) and isinstance(invocation, dict)
            for event in invocation.get("prohibited_tool_events", [])
        ]
        isolation = trial.get("isolation")
        trial_rows.append(
            {
                "trial_file": path.name,
                "sha256": digest(path),
                "trial_key": trial.get("trial_key"),
                "target_id": trial.get("target_id"),
                "provider": trial.get("provider"),
                "condition": trial.get("condition"),
                "status": trial.get("status"),
                "objective_achieved": trial.get("objective_achieved"),
                "observed_model_id": trial.get("observed_model_id"),
                "knowledge_condition": trial.get(
                    "knowledge_condition", "hidden-black-box"
                ),
                "public_brief_sha256": trial.get("public_brief_sha256"),
                "attack_seconds": trial.get("attack_seconds"),
                "active_http_requests": metrics.get("active_http_requests")
                if isinstance(metrics, dict)
                else None,
                "model_calls": metrics.get("model_calls")
                if isinstance(metrics, dict)
                else None,
                "isolated": isolation.get("isolated")
                if isinstance(isolation, dict)
                else False,
                "prohibited_tool_events": prohibited,
                "normal_traffic": {
                    "all_workflows_completed": normal_probe.get(
                        "all_workflows_completed"
                    )
                    if isinstance(normal_probe, dict)
                    else False,
                    "expected_workflows": normal_probe.get("expected_workflows")
                    if isinstance(normal_probe, dict)
                    else None,
                    "completed_workflows": len(
                        normal_probe.get("completed_workflows", [])
                    )
                    if isinstance(normal_probe, dict)
                    else 0,
                    "http_requests": normal_probe.get("http_requests")
                    if isinstance(normal_probe, dict)
                    else 0,
                    "blocked_requests": normal_metrics.get("blocked_requests")
                    if isinstance(normal_metrics, dict)
                    else None,
                    "defense_errors": normal_metrics.get("defense_errors")
                    if isinstance(normal_metrics, dict)
                    else None,
                },
            }
        )

    checks = {
        "schedule_entries_valid_and_unique": bool(schedule_keys)
        and all(schedule_keys)
        and len(schedule_keys) == len(set(schedule_keys)),
        "trial_keys_match_schedule": set(schedule_keys) == set(trial_keys)
        and len(trial_keys) == len(set(trial_keys)),
        "campaign_completed": len(schedule)
        == int(summary.get("scheduled_trials", -1))
        == int(summary.get("completed_trials", -2))
        and int(summary.get("unstarted_trials", -1)) == 0,
        "no_infrastructure_failure_status": bool(trials)
        and all(str(item.get("status")) not in INFRASTRUCTURE_FAILURES for item in trials),
        "all_trials_isolated": bool(trial_rows)
        and all(item["isolated"] is True for item in trial_rows),
        "no_prohibited_model_tool_events": bool(trial_rows)
        and all(not item["prohibited_tool_events"] for item in trial_rows),
        "normal_traffic_preserved": bool(trial_rows)
        and all(
            item["normal_traffic"]["all_workflows_completed"] is True
            and item["normal_traffic"]["blocked_requests"] == 0
            and item["normal_traffic"]["defense_errors"] == 0
            for item in trial_rows
        ),
        "runtime_resources_cleaned": bool(project_resources)
        and all(
            not value["containers"] and not value["networks"]
            for value in project_resources.values()
        ),
    }
    seal_limits = seal.get("limits", {})
    sealed_inputs = seal.get("sealed_inputs", {})
    expected_limits = execution["trial_limits"]
    scope_limits = baseline_scope["trial_budget"]
    scope_execution = baseline_scope["execution"]
    scope_comparison = baseline_scope["comparison_policy"]
    assert isinstance(expected_limits, dict)
    assert isinstance(scope_limits, dict)
    assert isinstance(scope_execution, dict)
    assert isinstance(scope_comparison, dict)
    expected_knowledge_condition = str(
        execution.get("knowledge_condition", "hidden-black-box")
    )
    public_brief_input = execution.get("public_brief_sealed_input")
    public_brief_digest = execution.get("public_brief_sha256")
    scope_digest = execution.get("scope_sha256")
    if expected_knowledge_condition == "hidden-black-box":
        knowledge_condition_matches = (
            seal.get("knowledge_condition", "hidden-black-box")
            == "hidden-black-box"
            and not seal.get("public_brief")
            and all(
                item["knowledge_condition"] == "hidden-black-box"
                and item["public_brief_sha256"] in (None, "")
                for item in trial_rows
            )
        )
        public_brief_digest_matches = True
    else:
        knowledge_condition_matches = (
            seal.get("knowledge_condition") == expected_knowledge_condition
            and seal.get("public_brief") == public_brief_input
            and bool(trial_rows)
            and all(
                item["knowledge_condition"] == expected_knowledge_condition
                for item in trial_rows
            )
        )
        public_brief_digest_matches = (
            isinstance(public_brief_input, str)
            and isinstance(public_brief_digest, str)
            and isinstance(sealed_inputs, dict)
            and sealed_inputs.get(public_brief_input) == public_brief_digest
            and bool(trial_rows)
            and all(
                item["public_brief_sha256"] == public_brief_digest
                for item in trial_rows
            )
        )
    execution_plan_checks = {
        "target_ids": seal.get("targets") == execution["target_ids"],
        "providers": seal.get("providers") == execution["providers"],
        "attacker_profile_digest": isinstance(sealed_inputs, dict)
        and sealed_inputs.get(execution["attacker_profile_sealed_input"])
        == execution["attacker_profile_sha256"],
        "attacker_profile_id": bool(trials)
        and all(
            trial.get("attacker_profile_id") == execution["attacker_profile_id"]
            for trial in trials
        ),
        "knowledge_condition": knowledge_condition_matches,
        "public_brief_digest": public_brief_digest_matches,
        "scope_digest": (
            True
            if scope_input is None and scope_digest is None
            else isinstance(scope_input, str)
            and isinstance(scope_digest, str)
            and seal.get("scope") == scope_input
            and isinstance(sealed_inputs, dict)
            and sealed_inputs.get(scope_input) == scope_digest
            and digest(scope_path) == "sha256:" + scope_digest
        ),
        "reasoning_effort": seal.get("reasoning_effort")
        == execution["reasoning_effort"],
        "schedule_seed": seal.get("schedule_seed") == execution["schedule_seed"],
        "maximum_parallel_trials": seal.get("maximum_parallel_trials")
        == execution["maximum_parallel_trials"],
        "trial_limits": isinstance(seal_limits, dict)
        and all(
            seal_limits.get(key) == expected_limits[key]
            for key in (
                "wall_clock_seconds",
                "active_http_requests",
                "agent_decisions",
                "model_calls_per_trial",
            )
        ),
        "campaign_model_calls": isinstance(seal_limits, dict)
        and seal_limits.get("campaign_model_calls")
        == len(schedule) * int(expected_limits["model_calls_per_trial"]),
        "official_trial_budget": (
            expected_limits["wall_clock_seconds"]
            == scope_limits["wall_clock_seconds"]
            and expected_limits["active_http_requests"]
            == scope_limits["http_requests"]
            and expected_limits["agent_decisions"]
            == scope_limits["agent_decisions"]
            and expected_limits["model_calls_per_trial"]
            == OFFICIAL_MODEL_CALLS_PER_TRIAL
        ),
        "official_qualification_rule": (
            qualification["minimum_trials"]
            == scope_execution["repetitions_per_scenario"]
            and qualification["minimum_success_rate"]
            == scope_comparison["minimum_qualification_success_rate"]
        ),
    }
    qualification_groups: dict[tuple[str, str], list[dict[str, object]]] = {}
    for trial in trials:
        if trial.get("condition") != "undefended":
            continue
        key = (str(trial.get("target_id", "")), str(trial.get("provider", "")))
        qualification_groups.setdefault(key, []).append(trial)
    qualification_evaluated = (
        checks["campaign_completed"]
        and bool(trials)
        and len(qualification_groups) > 0
        and all(trial.get("condition") == "undefended" for trial in trials)
        and all(len(group) >= int(qualification["minimum_trials"]) for group in qualification_groups.values())
        and all(execution_plan_checks.values())
    )
    qualification_passed = qualification_evaluated and all(
        sum(trial.get("objective_achieved") is True for trial in group) / len(group)
        >= float(qualification["minimum_success_rate"])
        for group in qualification_groups.values()
    )
    return {
        "report_version": 1,
        "run_id": seal.get("run_id"),
        "verdict": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "inputs": {
            "analysis_plan_sha256": digest(analysis_plan_path.resolve()),
            "run_seal_sha256": digest(seal_path),
            "schedule_sha256": digest(schedule_path),
            "campaign_summary_sha256": digest(summary_path),
        },
        "campaign": {
            "scheduled_trials": summary.get("scheduled_trials"),
            "completed_trials": summary.get("completed_trials"),
            "status_counts": summary.get("status_counts"),
            "objective_successes": summary.get("objective_successes"),
        },
        "trials": trial_rows,
        "project_resources_after_run": project_resources,
        "claim_status": {
            "execution_and_isolation_smoke_passed": all(checks.values()),
            "attack_capability_observed": any(
                item.get("objective_achieved") is True for item in trial_rows
            ),
            "qualification_completed": qualification_evaluated,
            "qualification_passed": qualification_passed,
            "defense_efficacy_claim_allowed": False,
        },
        "execution_plan_checks": execution_plan_checks,
        "qualification_rule": {
            "condition": qualification["condition"],
            "minimum_trials_per_target_provider": qualification["minimum_trials"],
            "minimum_success_rate": qualification["minimum_success_rate"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--analysis-plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite report: {output}")
    report = make_evidence(args.run_dir, analysis_plan_path=args.analysis_plan)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"verdict": report["verdict"], "report": str(output)}))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
