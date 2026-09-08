from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from make_holdout_commitment import (
    REGISTRY_PATH,
    load_json,
    qualified_strata,
    verify_commitment,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "contracts" / "independent-review-record.schema.json"
REQUIRED_INPUT_KINDS = {
    "qualification-analysis-plan",
    "confirmatory-analysis-plan",
    "qualification-evidence",
    "confirmatory-run-seal",
    "statistical-analysis",
    "holdout-commitment",
    "holdout-private-manifest",
}


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def validate_review(path: Path, input_root: Path) -> dict[str, object]:
    record = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    schema_errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(record),
        key=lambda item: list(item.path),
    )
    input_results = []
    resolved_inputs: dict[str, Path] = {}
    if isinstance(record, dict):
        for item in record.get("inputs", []):
            if not isinstance(item, dict):
                continue
            candidate = (input_root / str(item.get("path", ""))).resolve()
            inside = candidate == input_root or input_root in candidate.parents
            exists = inside and candidate.is_file()
            observed = digest(candidate) if exists else None
            input_results.append(
                {
                    "kind": item.get("kind"),
                    "path": item.get("path"),
                    "inside_input_root": inside,
                    "exists": exists,
                    "expected_sha256": item.get("sha256"),
                    "observed_sha256": observed,
                    "passed": exists and observed == item.get("sha256"),
                }
            )
            kind = str(item.get("kind", ""))
            if exists and observed == item.get("sha256") and kind not in resolved_inputs:
                resolved_inputs[kind] = candidate
    findings = record.get("findings", []) if isinstance(record, dict) else []
    record_inputs = record.get("inputs", []) if isinstance(record, dict) else []
    input_paths = [
        str(item.get("path", ""))
        for item in record_inputs
        if isinstance(item, dict)
    ]
    input_kinds = [
        str(item.get("kind", ""))
        for item in record_inputs
        if isinstance(item, dict)
    ]
    unresolved_high = [
        item
        for item in findings
        if isinstance(item, dict)
        and item.get("severity") == "high"
        and item.get("resolved") is not True
    ]
    semantic_errors = []
    evidence_links_valid = False
    evidence_link_checks: dict[str, bool] = {}
    required_kinds_present_once = all(
        input_kinds.count(kind) == 1 for kind in REQUIRED_INPUT_KINDS
    )
    if required_kinds_present_once and REQUIRED_INPUT_KINDS.issubset(resolved_inputs):
        try:
            qualification_plan_path = resolved_inputs["qualification-analysis-plan"]
            confirmatory_plan_path = resolved_inputs["confirmatory-analysis-plan"]
            qualification_path = resolved_inputs["qualification-evidence"]
            run_seal_path = resolved_inputs["confirmatory-run-seal"]
            analysis_path = resolved_inputs["statistical-analysis"]
            public_holdout_path = resolved_inputs["holdout-commitment"]
            private_holdout_path = resolved_inputs["holdout-private-manifest"]
            qualification = load_json(qualification_path)
            analysis = load_json(analysis_path)
            private_holdout = load_json(private_holdout_path)
            analysis_inputs = analysis.get("run_inputs", {})
            analysis_claim = analysis.get("claim_status", {})
            analysis_integrity = analysis.get("integrity_checks", {})
            qualification_claim = qualification.get("claim_status", {})
            qualification_inputs = qualification.get("inputs", {})
            qualification_checks = qualification.get("checks", {})
            execution_checks = qualification.get("execution_plan_checks", {})
            primary_comparisons = analysis.get("primary_comparisons", [])
            selected = private_holdout.get("selected", [])
            selected_keys = {
                (str(item.get("target_id", "")), str(item.get("provider", "")))
                for item in selected
                if isinstance(item, dict)
            }
            comparison_keys = {
                (str(item.get("target_id", "")), str(item.get("provider", "")))
                for item in primary_comparisons
                if isinstance(item, dict)
                and item.get("positive_effect_claim_ready") is True
            }
            eligible_keys = {
                (str(item["target_id"]), str(item["provider"]))
                for item in qualified_strata(qualification, load_json(REGISTRY_PATH))
            }
            run_seal_input = (
                analysis_inputs.get("run_seal", {})
                if isinstance(analysis_inputs, dict)
                else {}
            )
            evidence_link_checks = {
                "confirmatory_plan_hash_matches_analysis": analysis.get(
                    "analysis_plan_sha256"
                )
                == digest(confirmatory_plan_path),
                "qualification_plan_hash_matches_evidence": isinstance(
                    qualification_inputs, dict
                )
                and qualification_inputs.get("analysis_plan_sha256")
                == digest(qualification_plan_path),
                "run_seal_hash_matches_analysis": isinstance(run_seal_input, dict)
                and run_seal_input.get("sha256") == digest(run_seal_path),
                "analysis_integrity_checks_pass": isinstance(
                    analysis_integrity, dict
                )
                and bool(analysis_integrity)
                and all(value is True for value in analysis_integrity.values()),
                "positive_effect_claim_ready": isinstance(analysis_claim, dict)
                and analysis_claim.get("analysis_complete") is True
                and analysis_claim.get("positive_effect_claim_allowed") is True,
                "qualification_runtime_checks_pass": isinstance(
                    qualification_checks, dict
                )
                and bool(qualification_checks)
                and all(value is True for value in qualification_checks.values()),
                "qualification_execution_checks_pass": isinstance(
                    execution_checks, dict
                )
                and bool(execution_checks)
                and all(value is True for value in execution_checks.values()),
                "qualification_completed": isinstance(qualification_claim, dict)
                and qualification_claim.get("qualification_completed") is True,
                "holdout_commitment_verifies": verify_commitment(
                    public_holdout_path, private_holdout_path
                ),
                "holdout_qualification_hash_matches": private_holdout.get(
                    "qualification_sha256"
                )
                == digest(qualification_path),
                "positive_comparison_present": bool(comparison_keys),
                "comparisons_are_in_holdout": comparison_keys.issubset(selected_keys),
                "holdout_strata_are_qualified": selected_keys.issubset(eligible_keys),
            }
            evidence_links_valid = all(evidence_link_checks.values())
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            semantic_errors.append(str(error))

    checks = {
        "schema_valid": not schema_errors,
        "all_input_hashes_match": bool(input_results)
        and all(item["passed"] for item in input_results),
        "input_paths_are_distinct": len(input_paths) >= len(REQUIRED_INPUT_KINDS)
        and len(input_paths) == len(set(input_paths)),
        "required_input_kinds_present_once": required_kinds_present_once,
        "evidence_links_valid": evidence_links_valid,
        "no_unresolved_high_findings": not unresolved_high,
    }
    return {
        "review": str(path),
        "schema_errors": [error.message for error in schema_errors],
        "input_results": input_results,
        "unresolved_high_findings": unresolved_high,
        "semantic_errors": semantic_errors,
        "evidence_link_checks": evidence_link_checks,
        "checks": checks,
        "passed": all(checks.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--input-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate_review(args.review.resolve(), args.input_root.resolve())
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        output = args.output.resolve()
        if output.exists():
            raise FileExistsError(f"refusing to overwrite report: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    print(json.dumps({"passed": report["passed"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
