from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
from datetime import UTC, datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = PROJECT_ROOT / "app" / "configs" / "stage3a-autonomous-target-registry-v2.json"


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def interaction_classes(capabilities: list[str]) -> set[str]:
    classes = {item for item in ("browser", "concurrency", "multipart", "smtp", "victim-session", "multi-account") if item in capabilities}
    if not classes:
        classes.add("http-only")
    return classes


def qualified_strata(
    qualification: dict[str, object], registry: dict[str, object]
) -> list[dict[str, object]]:
    checks = qualification.get("checks")
    execution_checks = qualification.get("execution_plan_checks")
    claim_status = qualification.get("claim_status")
    inputs = qualification.get("inputs")
    rule = qualification.get("qualification_rule")
    source_rows = qualification.get("trials")
    if (
        qualification.get("verdict") != "PASS"
        or not isinstance(checks, dict)
        or not checks
        or not all(value is True for value in checks.values())
        or not isinstance(execution_checks, dict)
        or not execution_checks
        or not all(value is True for value in execution_checks.values())
        or not isinstance(claim_status, dict)
        or claim_status.get("qualification_completed") is not True
        or not isinstance(inputs, dict)
        or not isinstance(inputs.get("analysis_plan_sha256"), str)
        or not isinstance(rule, dict)
        or not isinstance(source_rows, list)
    ):
        raise ValueError(
            "qualification input must be a completed campaign evidence report "
            "with passing runtime and execution-plan checks"
        )
    qualification_condition = str(rule.get("condition", ""))
    minimum_trials = int(rule.get("minimum_trials_per_target_provider", 0))
    minimum_success_rate = float(rule.get("minimum_success_rate", -1.0))
    if (
        not qualification_condition
        or minimum_trials < 1
        or not 0.0 <= minimum_success_rate <= 1.0
    ):
        raise ValueError("qualification input contains an invalid qualification rule")

    capabilities = {}
    for group in ("ruby_web_targets", "original_cve_targets"):
        for item in registry.get(group, []):
            if isinstance(item, dict):
                capabilities[str(item["target_id"])] = [str(value) for value in item.get("required_capabilities", [])]
    grouped: dict[tuple[str, str], list[dict[str, object]]] = {}
    for item in source_rows:
        if not isinstance(item, dict) or item.get("condition") != qualification_condition:
            continue
        key = (str(item.get("target_id", "")), str(item.get("provider", "")))
        grouped.setdefault(key, []).append(item)

    rows = []
    for (target_id, provider), items in sorted(grouped.items()):
        successes = sum(item.get("objective_achieved") is True for item in items)
        if len(items) < minimum_trials or successes / len(items) < minimum_success_rate:
            continue
        if target_id not in capabilities:
            raise ValueError(f"qualified target is absent from registry: {target_id}")
        rows.append(
            {
                "target_id": target_id,
                "provider": provider,
                "interaction_classes": sorted(interaction_classes(capabilities[target_id])),
            }
        )
    unique = {(item["target_id"], item["provider"]): item for item in rows}
    return [unique[key] for key in sorted(unique)]


def select_holdout(
    strata: list[dict[str, object]], secret: bytes
) -> tuple[list[dict[str, object]], dict[str, object]]:
    if len(secret) < 32:
        raise ValueError("holdout secret must contain at least 32 bytes")
    all_classes = sorted(
        {str(value) for item in strata for value in item["interaction_classes"]}
    )
    requested = max(math.ceil(len(strata) * 0.2), 6, len(all_classes))
    if len(strata) < requested:
        raise ValueError(
            f"not enough qualified strata for holdout: have {len(strata)}, need {requested}"
        )
    ranked = []
    for item in strata:
        identity = f"{item['target_id']}|{item['provider']}"
        score = hmac.new(secret, identity.encode("utf-8"), hashlib.sha256).hexdigest()
        ranked.append({**item, "selection_score": score})
    ranked.sort(key=lambda item: (str(item["selection_score"]), str(item["target_id"]), str(item["provider"])))
    selected: list[dict[str, object]] = []
    selected_keys: set[tuple[str, str]] = set()
    uncovered = set(all_classes)
    while uncovered:
        candidate = min(
            (
                item
                for item in ranked
                if (str(item["target_id"]), str(item["provider"])) not in selected_keys
                and uncovered.intersection(str(value) for value in item["interaction_classes"])
            ),
            key=lambda item: str(item["selection_score"]),
            default=None,
        )
        if candidate is None:
            raise ValueError(f"could not cover interaction classes: {sorted(uncovered)}")
        selected.append(candidate)
        selected_keys.add((str(candidate["target_id"]), str(candidate["provider"])))
        uncovered.difference_update(str(value) for value in candidate["interaction_classes"])
    for item in ranked:
        if len(selected) >= requested:
            break
        key = (str(item["target_id"]), str(item["provider"]))
        if key not in selected_keys:
            selected.append(item)
            selected_keys.add(key)
    selected.sort(key=lambda item: (str(item["target_id"]), str(item["provider"])))
    policy = {
        "eligible_strata": len(strata),
        "twenty_percent_ceiling": math.ceil(len(strata) * 0.2),
        "minimum_count": 6,
        "interaction_classes": all_classes,
        "selected_count": requested,
    }
    return selected, policy


def create_commitment(
    qualification_path: Path,
    secret_path: Path,
    public_path: Path,
    private_path: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    for path in (public_path, private_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite holdout file: {path}")
    qualification = load_json(qualification_path)
    registry = load_json(REGISTRY_PATH)
    strata = qualified_strata(qualification, registry)
    selected, policy = select_holdout(strata, secret_path.read_bytes())
    private = {
        "manifest_version": 1,
        "qualification_id": qualification.get("analysis_id")
        or qualification.get("run_id")
        or qualification.get("run_dir"),
        "qualification_sha256": sha256_bytes(qualification_path.read_bytes()),
        "selection_algorithm": "hmac-sha256-stratified-v1",
        "policy": policy,
        "selected": selected,
    }
    private_digest = sha256_bytes(canonical(private))
    public = {
        "commitment_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "qualification_id": private["qualification_id"],
        "qualification_sha256": private["qualification_sha256"],
        "selection_algorithm": private["selection_algorithm"],
        "policy": policy,
        "private_manifest_commitment_sha256": private_digest,
        "selected_identities_disclosed": False,
    }
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(json.dumps(private, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    public_path.write_text(json.dumps(public, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return public, private


def verify_commitment(public_path: Path, private_path: Path) -> bool:
    public = load_json(public_path)
    private = load_json(private_path)
    expected = sha256_bytes(canonical(private))
    selected = private.get("selected", [])
    covered = {
        str(value)
        for item in selected
        if isinstance(item, dict)
        for value in item.get("interaction_classes", [])
    }
    public_policy = public.get("policy", {})
    private_policy = private.get("policy", {})
    keys = [
        (str(item.get("target_id", "")), str(item.get("provider", "")))
        for item in selected
        if isinstance(item, dict)
    ]
    return bool(
        expected == public.get("private_manifest_commitment_sha256")
        and isinstance(public_policy, dict)
        and public_policy == private_policy
        and len(selected) == int(public_policy.get("selected_count", -1))
        and len(keys) == len(set(keys)) == len(selected)
        and covered == set(public_policy.get("interaction_classes", []))
        and public.get("qualification_sha256")
        == private.get("qualification_sha256")
        and public.get("qualification_id") == private.get("qualification_id")
        and public.get("selection_algorithm")
        == private.get("selection_algorithm")
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--qualification", type=Path, required=True)
    create.add_argument("--secret-file", type=Path, required=True)
    create.add_argument("--public-output", type=Path, required=True)
    create.add_argument("--private-output", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--public", type=Path, required=True)
    verify.add_argument("--private", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "create":
        public, _ = create_commitment(
            args.qualification.resolve(),
            args.secret_file.resolve(),
            args.public_output.resolve(),
            args.private_output.resolve(),
        )
        print(json.dumps(public, ensure_ascii=False))
        return 0
    passed = verify_commitment(args.public.resolve(), args.private.resolve())
    print(json.dumps({"verified": passed}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
