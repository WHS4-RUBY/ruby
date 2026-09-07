from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from statistics import median

from audit_attacker_v11_sources import audit_v11_sources


APP_ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON document is not an object: {path}")
    return value


def _rate(wins: int, trials: int) -> float:
    return wins / trials if trials else 0.0


def _seal_mismatches(seal: dict[str, object]) -> list[str]:
    sealed = seal.get("sealed_inputs")
    if not isinstance(sealed, dict):
        return ["run seal has no sealed_inputs object"]
    mismatches: list[str] = []
    for relative, expected in sealed.items():
        path = (APP_ROOT / str(relative)).resolve()
        if not path.is_file():
            mismatches.append(f"missing:{relative}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != str(expected):
            mismatches.append(f"sha256:{relative}")
    return sorted(mismatches)


def evaluate_qualification(
    cohort: dict[str, object],
    run_seal: dict[str, object],
    reports: list[dict[str, object]],
    *,
    retry_artifacts: list[str],
) -> dict[str, object]:
    targets = cohort["targets"]
    gates = cohort["qualification_gate"]
    conditions = cohort["fixed_conditions"]
    if not isinstance(targets, list) or not isinstance(gates, dict) or not isinstance(conditions, dict):
        raise ValueError("invalid v11 cohort document")
    providers = tuple(str(item) for item in conditions["providers"])
    repetitions = int(conditions["repetitions_per_target_provider"])
    target_rows = {str(item["target_id"]): item for item in targets if isinstance(item, dict)}
    expected = {
        (target_id, provider, repetition)
        for target_id in target_rows
        for provider in providers
        for repetition in range(repetitions)
    }
    observed: dict[tuple[str, str, int], dict[str, object]] = {}
    duplicates: list[str] = []
    for report in reports:
        key = (
            str(report.get("target_id")),
            str(report.get("provider")),
            int(report.get("repetition", -1)),
        )
        if key in observed:
            duplicates.append("|".join(map(str, key)))
        observed[key] = report
    selected = [observed[key] for key in sorted(expected & set(observed))]
    missing = sorted("|".join(map(str, key)) for key in expected - set(observed))
    unexpected = sorted("|".join(map(str, key)) for key in set(observed) - expected)

    target_provider: dict[str, dict[str, dict[str, object]]] = {}
    target_summary: dict[str, dict[str, object]] = {}
    both_provider_qualified = 0
    zero_success_targets = 0
    for target_id, metadata in target_rows.items():
        target_provider[target_id] = {}
        target_trials = [item for item in selected if item.get("target_id") == target_id]
        target_wins = sum(bool(item.get("objective_achieved")) for item in target_trials)
        if target_wins == 0:
            zero_success_targets += 1
        provider_rates = []
        for provider in providers:
            rows = [item for item in target_trials if item.get("provider") == provider]
            wins = sum(bool(item.get("objective_achieved")) for item in rows)
            rate = _rate(wins, len(rows))
            provider_rates.append(rate)
            target_provider[target_id][provider] = {
                "trials": len(rows),
                "successes": wins,
                "success_rate": rate,
            }
        qualified = all(
            rate >= float(gates["minimum_target_provider_success_rate"])
            for rate in provider_rates
        )
        both_provider_qualified += int(qualified)
        target_summary[target_id] = {
            "family": metadata["family"],
            "trials": len(target_trials),
            "successes": target_wins,
            "success_rate": _rate(target_wins, len(target_trials)),
            "both_providers_qualified": qualified,
        }

    successes = [item for item in selected if bool(item.get("objective_achieved"))]
    provider_summary: dict[str, dict[str, object]] = {}
    for provider in providers:
        rows = [item for item in selected if item.get("provider") == provider]
        wins = sum(bool(item.get("objective_achieved")) for item in rows)
        provider_summary[provider] = {
            "trials": len(rows),
            "successes": wins,
            "success_rate": _rate(wins, len(rows)),
        }

    terminal_errors = sum(
        bool(item.get("metrics", {}).get("terminal_policy_contract_error"))
        for item in selected
    )
    model_calls = sum(int(item.get("metrics", {}).get("model_calls", 0)) for item in selected)
    decision_rejections = sum(
        int(item.get("metrics", {}).get("decision_contract_rejections", 0))
        for item in selected
    )
    isolation_violations = sum(
        not isinstance(item.get("isolation"), dict)
        or not bool(item.get("isolation", {}).get("isolated"))
        for item in selected
    )
    prohibited_tool_events = sum(
        len(invocation.get("prohibited_tool_events", []))
        for item in selected
        for invocation in item.get("model_invocations", [])
        if isinstance(invocation, dict)
    )
    invalid_trials = [
        str(item.get("trial_key", item.get("trial_id")))
        for item in selected
        if str(item.get("status")) in {"runner-error", "isolation-error", "verifier-error"}
    ]

    high_retention_failures: list[str] = []
    improved_baseline_families: list[str] = []
    for target_id, metadata in target_rows.items():
        baseline = metadata.get("v10_baseline_success_rate")
        if not isinstance(baseline, (int, float)):
            continue
        current = float(target_summary[target_id]["success_rate"])
        family = str(metadata["family"])
        if current > float(baseline):
            improved_baseline_families.append(family)
        if float(baseline) >= 0.80 and (
            current < 0.80 or float(baseline) - current > 0.10
        ):
            high_retention_failures.append(target_id)

    variant_failures: list[str] = []
    for target_id in target_rows:
        if not target_id.startswith("ruby-web:"):
            continue
        for provider in providers:
            rows = [
                item
                for item in selected
                if item.get("target_id") == target_id and item.get("provider") == provider
            ]
            prefixes = {
                item.get("isolation", {}).get("public_api_prefix")
                for item in rows
                if isinstance(item.get("isolation"), dict)
            }
            states = {
                item.get("metrics", {}).get("initial_state_sha256") for item in rows
            }
            accounts = {
                item.get("isolation", {}).get("account_namespace_sha256")
                for item in rows
                if isinstance(item.get("isolation"), dict)
            }
            if len(prefixes - {None}) != repetitions:
                variant_failures.append(f"prefix:{target_id}|{provider}")
            if len(states - {None}) != repetitions:
                variant_failures.append(f"state:{target_id}|{provider}")
            if len(accounts - {None}) != repetitions:
                variant_failures.append(f"accounts:{target_id}|{provider}")

    request_values = [int(item["metrics"]["active_http_requests"]) for item in successes]
    call_values = [int(item["metrics"]["model_calls"]) for item in successes]
    request_median = median(request_values) if request_values else None
    call_median = median(call_values) if call_values else None
    total_rate = _rate(len(successes), len(selected))
    contract_error_rate = _rate(terminal_errors, len(selected))
    decision_rejection_rate = _rate(decision_rejections, model_calls)
    source_audit = audit_v11_sources()
    frozen_mismatches = _seal_mismatches(run_seal)
    profile_mismatches = [
        str(item.get("trial_key", item.get("trial_id")))
        for item in selected
        if item.get("attacker_profile_id") != cohort["profile_id"]
    ]
    checks = {
        "exact_schedule": not missing
        and not unexpected
        and not duplicates
        and len(selected) == int(gates["expected_trials"]),
        "no_selective_retries": not retry_artifacts,
        "valid_infrastructure": not invalid_trials,
        "frozen_inputs_unchanged": not frozen_mismatches,
        "correct_profile": not profile_mismatches,
        "total_success_rate": total_rate >= float(gates["minimum_total_success_rate"]),
        "provider_success_rates": all(
            float(item["success_rate"]) >= float(gates["minimum_provider_success_rate"])
            for item in provider_summary.values()
        ),
        "target_provider_coverage": both_provider_qualified
        >= int(gates["minimum_targets_qualified_for_both_providers"]),
        "zero_success_targets": zero_success_targets
        <= int(gates["maximum_zero_success_targets"]),
        "high_baseline_retention": not high_retention_failures,
        "cross_family_improvement": len(set(improved_baseline_families))
        >= int(gates["minimum_improved_baseline_families"]),
        "successful_request_median": request_median is not None
        and request_median <= int(gates["maximum_successful_request_median"]),
        "successful_model_call_median": call_median is not None
        and call_median <= int(gates["maximum_successful_model_call_median"]),
        "terminal_contract_error_rate": contract_error_rate
        <= float(gates["maximum_terminal_policy_contract_error_rate"]),
        "decision_contract_rejection_rate": decision_rejection_rate
        <= float(gates["maximum_decision_contract_rejection_rate"]),
        "isolation_and_tool_safety": isolation_violations + prohibited_tool_events == 0,
        "target_specific_rule_audit": bool(source_audit["passed"]),
        "hidden_variant_coverage": not variant_failures,
    }
    return {
        "schema_version": 1,
        "cohort_id": cohort["cohort_id"],
        "passed": all(checks.values()),
        "checks": checks,
        "scheduled_trials": len(expected),
        "observed_trials": len(selected),
        "status_counts": dict(Counter(str(item.get("status")) for item in selected)),
        "successes": len(successes),
        "success_rate": total_rate,
        "providers": provider_summary,
        "targets": target_summary,
        "target_provider_results": target_provider,
        "targets_qualified_for_both_providers": both_provider_qualified,
        "zero_success_targets": zero_success_targets,
        "improved_baseline_families": sorted(set(improved_baseline_families)),
        "high_baseline_retention_failures": high_retention_failures,
        "successful_request_median": request_median,
        "successful_model_call_median": call_median,
        "terminal_policy_contract_error_rate": contract_error_rate,
        "decision_contract_rejection_rate": decision_rejection_rate,
        "isolation_violations": isolation_violations,
        "prohibited_tool_events": prohibited_tool_events,
        "missing_trials": missing,
        "unexpected_trials": unexpected,
        "duplicate_trials": duplicates,
        "retry_artifacts": retry_artifacts,
        "invalid_trials": invalid_trials,
        "variant_failures": variant_failures,
        "frozen_file_mismatches": frozen_mismatches,
        "profile_mismatches": profile_mismatches,
        "target_specific_rule_audit": source_audit,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate frozen generic attacker v11")
    parser.add_argument("--cohort", required=True, type=Path)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    reports = [
        _load(path)
        for path in sorted((args.run_dir / "trials").glob("*.json"))
        if not path.name.endswith((".running.json", ".checkpoint.json"))
    ]
    retries = [
        str(path.relative_to(args.run_dir)).replace("\\", "/")
        for path in sorted((args.run_dir / "attempts").glob("**/*"))
        if path.is_file()
    ] if (args.run_dir / "attempts").exists() else []
    result = evaluate_qualification(
        _load(args.cohort),
        _load(args.run_dir / "run-seal.json"),
        reports,
        retry_artifacts=retries,
    )
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
