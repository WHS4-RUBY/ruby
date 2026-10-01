from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = PROJECT_ROOT / "app"
POLICY_PATH = APP_ROOT / "configs" / "main-experiment-target-policy-v1.json"
POLICY_SCHEMA_PATH = (
    PROJECT_ROOT / "contracts" / "main-experiment-target-policy.schema.json"
)
REGISTRY_PATH = APP_ROOT / "configs" / "stage3a-autonomous-target-registry-v2.json"
LEGACY_EFFECT_EXCLUSIONS_PATH = (
    APP_ROOT / "configs" / "defense-effect-exclusions-v1.json"
)


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def registered_target_ids(registry_path: Path = REGISTRY_PATH) -> list[str]:
    registry = load_json(registry_path)
    rows = [
        *registry.get("ruby_web_targets", []),
        *registry.get("original_cve_targets", []),
    ]
    if not all(isinstance(item, dict) and item.get("target_id") for item in rows):
        raise ValueError("target registry contains an invalid row")
    target_ids = [str(item["target_id"]) for item in rows]
    if len(target_ids) != len(set(target_ids)):
        raise ValueError("target registry contains duplicate target ids")
    return target_ids


def load_main_experiment_policy(
    policy_path: Path = POLICY_PATH,
    registry_path: Path = REGISTRY_PATH,
    legacy_exclusions_path: Path = LEGACY_EFFECT_EXCLUSIONS_PATH,
) -> dict[str, object]:
    policy = load_json(policy_path)
    schema = load_json(POLICY_SCHEMA_PATH)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(policy),
        key=lambda item: list(item.path),
    )
    if errors:
        raise ValueError(
            "invalid main experiment target policy: "
            + "; ".join(error.message for error in errors)
        )

    registered = registered_target_ids(registry_path)
    eligible = [str(item) for item in policy["eligible_target_ids"]]
    excluded_rows = policy["excluded_targets"]
    assert isinstance(excluded_rows, list)
    excluded = [str(item["target_id"]) for item in excluded_rows]
    if len(excluded) != len(set(excluded)):
        raise ValueError("main experiment target policy contains duplicate exclusions")
    if set(eligible) & set(excluded):
        raise ValueError("main experiment eligible and excluded targets overlap")
    if set(eligible) | set(excluded) != set(registered):
        raise ValueError("main experiment target policy does not partition the registry")
    if int(policy["implemented_target_count"]) != len(registered):
        raise ValueError("implemented target count does not match the registry")

    legacy = load_json(legacy_exclusions_path)
    legacy_rows = legacy.get("blocked_targets")
    if not isinstance(legacy_rows, list):
        raise ValueError("legacy defense-effect exclusions have no target list")
    legacy_ids = {
        str(item.get("target_id"))
        for item in legacy_rows
        if isinstance(item, dict)
    }
    if set(excluded) != legacy_ids:
        raise ValueError(
            "main experiment exclusions differ from defense-effect exclusions"
        )
    return policy


def main_experiment_target_gate(target_ids: list[str]) -> dict[str, object]:
    policy = load_main_experiment_policy()
    registered = set(registered_target_ids())
    unknown = sorted(set(target_ids) - registered)
    excluded_rows = policy["excluded_targets"]
    assert isinstance(excluded_rows, list)
    selected = [
        item
        for item in excluded_rows
        if isinstance(item, dict) and item.get("target_id") in set(target_ids)
    ]
    return {
        "policy": POLICY_PATH.relative_to(PROJECT_ROOT).as_posix(),
        "blocked_targets": selected,
        "unknown_targets": unknown,
        "passed": not selected and not unknown,
    }


def assert_main_experiment_targets(target_ids: list[str]) -> None:
    gate = main_experiment_target_gate(target_ids)
    if gate["unknown_targets"]:
        raise ValueError(
            f"unregistered main experiment targets: {gate['unknown_targets']}"
        )
    if gate["blocked_targets"]:
        blocked = [
            str(item["target_id"])
            for item in gate["blocked_targets"]
            if isinstance(item, dict)
        ]
        raise ValueError(
            "targets excluded from the main experiment by the 2026-09-17 "
            f"decision: {blocked}"
        )


def target_policy_metadata() -> dict[str, dict[str, object]]:
    policy = load_main_experiment_policy()
    metadata = {
        str(target_id): {
            "main_experiment_eligible": True,
            "main_experiment_status": "eligible",
            "main_experiment_reason": None,
            "success_judgment": None,
            "request_identification": None,
            "blocking": None,
        }
        for target_id in policy["eligible_target_ids"]
    }
    excluded_rows = policy["excluded_targets"]
    assert isinstance(excluded_rows, list)
    for item in excluded_rows:
        assert isinstance(item, dict)
        metadata[str(item["target_id"])] = {
            "main_experiment_eligible": False,
            "main_experiment_status": item["main_experiment_status"],
            "main_experiment_reason": item["reason"],
            "success_judgment": item["success_judgment"],
            "request_identification": item["request_identification"],
            "blocking": item["blocking"],
        }
    return metadata
