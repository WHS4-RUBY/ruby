from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from statistics import median


APP_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_ROOT.parent


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON document is not an object: {path}")
    return value


def _frozen_mismatches(seal: dict[str, object]) -> list[str]:
    frozen = seal.get("frozen_files")
    if not isinstance(frozen, dict):
        raise ValueError("seal has no frozen_files object")
    mismatches: list[str] = []
    for relative, expected in sorted(frozen.items()):
        path = (PROJECT_ROOT / str(relative)).resolve()
        if not path.is_relative_to(PROJECT_ROOT.resolve()) or not path.is_file():
            mismatches.append(f"missing:{relative}")
        elif _sha256(path) != str(expected):
            mismatches.append(f"sha256:{relative}")
    return mismatches


def evaluate_cohort(
    cohort: dict[str, object],
    seal: dict[str, object],
    reports: list[dict[str, object]],
) -> dict[str, object]:
    conditions = cohort["fixed_conditions"]
    gate = cohort["completion_gate"]
    targets = cohort["targets"]
    if not isinstance(conditions, dict) or not isinstance(gate, dict):
        raise ValueError("cohort conditions and gate must be objects")
    if not isinstance(targets, list):
        raise ValueError("cohort targets must be a list")
    target_family = {
        str(item["target_id"]): str(item["family"])
        for item in targets
        if isinstance(item, dict)
    }
    providers = [str(item) for item in conditions["providers"]]
    repetitions = int(conditions["repetitions_per_provider_family"])
    expected = {
        (target_id, provider, repetition)
        for target_id in target_family
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
    missing = sorted("|".join(map(str, key)) for key in expected - set(observed))
    unexpected = sorted("|".join(map(str, key)) for key in set(observed) - expected)
    selected = [observed[key] for key in sorted(expected & set(observed))]

    invalid_statuses = {"runner-error", "isolation-error", "verifier-error"}
    invalid = [
        str(item.get("trial_key", item.get("trial_id", "unknown")))
        for item in selected
        if str(item.get("status")) in invalid_statuses
    ]
    successes = [item for item in selected if bool(item.get("objective_achieved"))]
    provider_counts: dict[str, dict[str, object]] = {}
    for provider in providers:
        rows = [item for item in selected if str(item.get("provider")) == provider]
        won = sum(bool(item.get("objective_achieved")) for item in rows)
        provider_counts[provider] = {
            "trials": len(rows),
            "successes": won,
            "success_rate": won / len(rows) if rows else 0.0,
        }

    family_successes = {
        target_family[str(item["target_id"])]
        for item in successes
        if str(item.get("target_id")) in target_family
    }
    terminal_contract_errors = sum(
        bool(item.get("metrics", {}).get("terminal_policy_contract_error"))
        for item in selected
        if isinstance(item.get("metrics"), dict)
    )
    decision_contract_rejections = sum(
        int(item.get("metrics", {}).get("decision_contract_rejections", 0))
        for item in selected
        if isinstance(item.get("metrics"), dict)
    )
    strategy_deviations = sum(
        int(item.get("metrics", {}).get("strategy_policy_deviations", 0))
        for item in selected
        if isinstance(item.get("metrics"), dict)
    )

    isolation_violations = 0
    prohibited_tool_events = 0
    for item in selected:
        isolation = item.get("isolation")
        if not isinstance(isolation, dict) or not bool(isolation.get("isolated")):
            isolation_violations += 1
        for invocation in item.get("model_invocations", []):
            if isinstance(invocation, dict):
                events = invocation.get("prohibited_tool_events", [])
                if isinstance(events, list):
                    prohibited_tool_events += len(events)

    variant_failures: list[str] = []
    expected_prefixes = set(str(item) for item in conditions["route_prefixes_by_repetition"])
    for target_id in target_family:
        for provider in providers:
            rows = [
                observed[key]
                for key in expected
                if key[0] == target_id and key[1] == provider and key in observed
            ]
            prefixes = {
                str(item.get("isolation", {}).get("public_api_prefix"))
                for item in rows
                if isinstance(item.get("isolation"), dict)
            }
            states = {
                str(item.get("metrics", {}).get("initial_state_sha256"))
                for item in rows
                if isinstance(item.get("metrics"), dict)
                and item.get("metrics", {}).get("initial_state_sha256")
            }
            accounts = {
                str(item.get("isolation", {}).get("account_namespace_sha256"))
                for item in rows
                if isinstance(item.get("isolation"), dict)
                and item.get("isolation", {}).get("account_namespace_sha256")
            }
            label = f"{target_id}|{provider}"
            if prefixes != expected_prefixes:
                variant_failures.append(f"route-prefix:{label}")
            if len(states) < int(gate["minimum_distinct_initial_states_per_provider_family"]):
                variant_failures.append(f"initial-state:{label}")
            if len(accounts) < int(
                gate["minimum_distinct_account_namespaces_per_provider_family"]
            ):
                variant_failures.append(f"account-namespace:{label}")

    successful_requests = [
        int(item["metrics"]["active_http_requests"])
        for item in successes
        if isinstance(item.get("metrics"), dict)
    ]
    successful_calls = [
        int(item["metrics"]["model_calls"])
        for item in successes
        if isinstance(item.get("metrics"), dict)
    ]
    request_median = median(successful_requests) if successful_requests else None
    call_median = median(successful_calls) if successful_calls else None
    total_rate = len(successes) / len(selected) if selected else 0.0
    contract_rate = terminal_contract_errors / len(selected) if selected else 0.0
    frozen_mismatches = _frozen_mismatches(seal)
    checks = {
        "complete_schedule": not missing
        and not unexpected
        and not duplicates
        and len(selected) == int(gate["expected_trials"]),
        "valid_infrastructure": not invalid,
        "frozen_inputs_unchanged": not frozen_mismatches,
        "total_success_rate": total_rate >= float(gate["minimum_total_success_rate"]),
        "provider_success_rates": all(
            float(value["success_rate"]) >= float(gate["minimum_provider_success_rate"])
            for value in provider_counts.values()
        ),
        "family_coverage": len(family_successes)
        >= int(gate["minimum_families_with_success"]),
        "terminal_policy_contract_error_rate": contract_rate
        <= float(gate["maximum_terminal_policy_contract_error_rate"]),
        "successful_request_median": request_median is not None
        and request_median <= int(gate["maximum_successful_request_median"]),
        "successful_model_call_median": call_median is not None
        and call_median <= int(gate["maximum_successful_model_call_median"]),
        "isolation_and_tool_safety": isolation_violations + prohibited_tool_events
        <= int(gate["maximum_isolation_or_prohibited_tool_violations"]),
        "variant_coverage": not variant_failures,
    }
    return {
        "schema_version": 1,
        "cohort_id": cohort["cohort_id"],
        "passed": all(checks.values()),
        "checks": checks,
        "scheduled_trials": len(expected),
        "observed_trials": len(selected),
        "missing_trials": missing,
        "unexpected_trials": unexpected,
        "duplicate_trials": duplicates,
        "invalid_trials": invalid,
        "status_counts": dict(Counter(str(item.get("status")) for item in selected)),
        "successes": len(successes),
        "success_rate": total_rate,
        "providers": provider_counts,
        "families_with_success": sorted(family_successes),
        "successful_request_median": request_median,
        "successful_model_call_median": call_median,
        "terminal_policy_contract_errors": terminal_contract_errors,
        "terminal_policy_contract_error_rate": contract_rate,
        "decision_contract_rejections": decision_contract_rejections,
        "strategy_policy_deviations": strategy_deviations,
        "isolation_violations": isolation_violations,
        "prohibited_tool_events": prohibited_tool_events,
        "variant_failures": variant_failures,
        "frozen_file_mismatches": frozen_mismatches,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the frozen attacker v10 cohort")
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--seal", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reports = [
        _load(path)
        for path in sorted((args.run_dir / "trials").glob("*.json"))
        if not path.name.endswith((".running.json", ".checkpoint.json"))
    ]
    result = evaluate_cohort(_load(args.cohort), _load(args.seal), reports)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
