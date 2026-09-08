from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from run_all_pair_checks import CHECKERS


PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = PROJECT_ROOT / "app"
CATALOG_PATH = APP_ROOT / "configs" / "stage3-vulnerability-module-catalog-v1.json"
REGISTRY_PATH = APP_ROOT / "configs" / "stage3a-autonomous-target-registry-v2.json"
ISOLATION_PATH = PROJECT_ROOT / "evidence" / "20260908" / "runtime-isolation-gate.json"
DEFENSE_PATH = PROJECT_ROOT / "evidence" / "20260908" / "generic-defense-attachment.json"
RUBY_CHECKERS = tuple(item for item in CHECKERS if item[0].startswith("ruby-"))
CVE_CHECKERS = tuple(item for item in CHECKERS if item[0].startswith("cve-"))
PAIR_REPORT_GLOB = "*report.json"


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def report_passed(report: dict[str, object]) -> bool:
    return bool(
        report.get("status") == "passed"
        or report.get("passed") is True
        or report.get("all_checks_passed") is True
    )


def result_passed(result: dict[str, object]) -> bool:
    if "passed" in result:
        return result["passed"] is True
    if "all_checks_passed" in result:
        return result["all_checks_passed"] is True
    checks = result.get("checks")
    return isinstance(checks, dict) and bool(checks) and all(checks.values())


def source_module_ids(script: Path, catalog_ids: set[str]) -> set[str]:
    tree = ast.parse(script.read_text(encoding="utf-8"), filename=str(script))
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    return catalog_ids.intersection(literals)


def one_report(directory: Path) -> Path:
    reports = sorted(directory.glob(PAIR_REPORT_GLOB))
    if len(reports) != 1:
        raise ValueError(f"expected one pair report under {directory}, found {len(reports)}")
    return reports[0]


def result_rows(report: dict[str, object]) -> list[dict[str, object]]:
    rows = report.get("results", report.get("conditions"))
    if not isinstance(rows, list) or not all(isinstance(item, dict) for item in rows):
        raise ValueError("pair report does not contain a result list")
    return rows  # type: ignore[return-value]


def objective_value(row: dict[str, object]) -> bool | None:
    direct = row.get("objective_achieved")
    if isinstance(direct, bool):
        return direct
    evaluator = row.get("evaluator")
    if isinstance(evaluator, dict) and isinstance(evaluator.get("objective_achieved"), bool):
        return bool(evaluator["objective_achieved"])
    return None


def validate_ruby_report(
    label: str, modules: set[str], report_path: Path
) -> dict[str, object]:
    report = load_json(report_path)
    rows = result_rows(report)
    conditions = [str(item.get("condition")) for item in rows]
    objective_checks = []
    for item in rows:
        observed = objective_value(item)
        if observed is not None:
            objective_checks.append(
                observed is (str(item.get("condition")) == "vulnerable")
            )
    reported_modules = {
        str(item["module_id"]) for item in rows if isinstance(item.get("module_id"), str)
    }
    checks = {
        "overall_passed": report_passed(report),
        "two_conditions_per_module": len(rows) == len(modules) * 2,
        "condition_balance": (
            conditions.count("secure") == len(modules)
            and conditions.count("vulnerable") == len(modules)
        ),
        "every_result_passed": all(result_passed(item) for item in rows),
        "available_objectives_match_condition": all(objective_checks),
        "reported_module_ids_match_source": (
            not reported_modules or reported_modules == modules
        ),
    }
    return {
        "label": label,
        "modules": sorted(modules),
        "conditions": len(rows),
        "report": report_path.relative_to(PROJECT_ROOT).as_posix(),
        "sha256": sha256(report_path),
        "checks": checks,
        "passed": all(checks.values()),
    }


def cve_from_report(report: dict[str, object]) -> str | None:
    direct = report.get("cve_id")
    if isinstance(direct, str):
        return direct
    pair = report.get("pair")
    if isinstance(pair, dict) and isinstance(pair.get("cve_id"), str):
        return str(pair["cve_id"])
    return None


def validate_cve_report(label: str, report_path: Path) -> dict[str, object]:
    report = load_json(report_path)
    rows = result_rows(report)
    conditions = [str(item.get("condition")) for item in rows]
    objective_checks = []
    for item in rows:
        observed = objective_value(item)
        if observed is not None:
            objective_checks.append(
                observed is (str(item.get("condition")) == "vulnerable")
            )
    cve_id = cve_from_report(report)
    expected_cve = "CVE-" + label.removeprefix("cve-")
    checks = {
        "overall_passed": report_passed(report),
        "cve_identity": cve_id == expected_cve,
        "vulnerable_and_fixed": sorted(conditions) == ["fixed", "vulnerable"],
        "every_explicit_result_passed": all(
            result_passed(item) if ("passed" in item or "all_checks_passed" in item) else True
            for item in rows
        ),
        "available_objectives_match_condition": all(objective_checks),
    }
    return {
        "label": label,
        "cve_id": cve_id,
        "conditions": len(rows),
        "report": report_path.relative_to(PROJECT_ROOT).as_posix(),
        "sha256": sha256(report_path),
        "checks": checks,
        "passed": all(checks.values()),
    }


def pytest_result() -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    output = "\n".join(item for item in (completed.stdout, completed.stderr) if item)
    match = re.search(r"(?P<passed>\d+) passed(?:, (?P<warnings>\d+) warnings)?", output)
    subtests = re.search(r"(?P<subtests>\d+) subtests passed", output)
    return {
        "command": f"{sys.executable} -m pytest -q",
        "returncode": completed.returncode,
        "passed_tests": int(match.group("passed")) if match else None,
        "warnings": int(match.group("warnings") or 0) if match else None,
        "passed_subtests": int(subtests.group("subtests")) if subtests else 0,
        "summary_found": match is not None,
        "passed": completed.returncode == 0 and match is not None,
        "output_tail": output.strip()[-2000:],
    }


def check_isolation(registry_cves: set[str], path: Path) -> dict[str, object]:
    report = load_json(path)
    target_rows = report.get("target_results", [])
    static_rows = report.get("static_compose_results", [])
    defense_rows = report.get("defense_results", [])
    target_pairs = {
        (str(item.get("target_id")), str(item.get("release")))
        for item in target_rows
        if isinstance(item, dict)
    }
    expected_pairs = {
        (f"cve-original:{cve}", release)
        for cve in registry_cves
        for release in ("vulnerable", "fixed")
    }
    static_ids = {
        str(item.get("target_id")) for item in static_rows if isinstance(item, dict)
    }
    checks = {
        "overall_passed": report.get("passed") is True,
        "all_target_release_pairs": target_pairs == expected_pairs,
        "every_target_passed": all(
            isinstance(item, dict) and item.get("passed") is True for item in target_rows
        ),
        "all_compose_targets": static_ids
        == {f"cve-original:{cve}" for cve in registry_cves},
        "every_compose_check_passed": all(
            isinstance(item, dict) and item.get("passed") is True for item in static_rows
        ),
        "managed_defense_checked": len(defense_rows) >= 1
        and all(isinstance(item, dict) and item.get("passed") is True for item in defense_rows),
    }
    return {
        "report": path.relative_to(PROJECT_ROOT).as_posix(),
        "sha256": sha256(path),
        "target_release_conditions": len(target_rows),
        "compose_targets": len(static_rows),
        "managed_defenses": len(defense_rows),
        "checks": checks,
        "passed": all(checks.values()),
    }


def check_defense_attachment(path: Path) -> dict[str, object]:
    report = load_json(path)
    replaceability = report.get("replaceability", {})
    pair = report.get("managed_static_guard_pair", {})
    cleanup = report.get("cleanup", {})
    checks = {
        "overall_passed": report.get("verdict") == "PASS",
        "source_independent_registration": isinstance(replaceability, dict)
        and replaceability.get("custom_external_adapter_registered_without_runner_source_change") is True,
        "identity_and_reset_checked": isinstance(replaceability, dict)
        and replaceability.get("identity_mismatch_rejected") is True
        and replaceability.get("reset_before_each_trial") is True,
        "normal_request_preserved": isinstance(pair, dict)
        and isinstance(pair.get("defended"), dict)
        and pair["defended"].get("normal_status") == 200,
        "reference_attack_blocked": isinstance(pair, dict)
        and isinstance(pair.get("defended"), dict)
        and pair["defended"].get("attack_status") == 403
        and pair["defended"].get("private_objective_achieved") is False,
        "runtime_cleaned": isinstance(cleanup, dict)
        and cleanup.get("managed_containers_remaining") == 0
        and cleanup.get("managed_networks_remaining") == 0,
    }
    return {
        "report": path.relative_to(PROJECT_ROOT).as_posix(),
        "sha256": sha256(path),
        "checks": checks,
        "passed": all(checks.values()),
    }


def check_documentation() -> dict[str, object]:
    required = (
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "docs" / "benchmarking.md",
        PROJECT_ROOT / "docs" / "defense-integration.md",
        PROJECT_ROOT / "docs" / "runtime-isolation-gate-20260908.md",
        PROJECT_ROOT / "docs" / "benchmark-audit-20260908.md",
    )
    readme = required[0].read_text(encoding="utf-8") if required[0].is_file() else ""
    checks = {
        "required_files_exist": all(path.is_file() for path in required),
        "quick_start_commands_present": "benchmark.ps1 start -Mode normal" in readme
        and "benchmark.sh start normal" in readme
        and "RUBY benchmark is ready" in readme,
        "pair_and_isolation_commands_present": "run_all_pair_checks.py" in readme
        and "check_runtime_isolation_gate.py" in readme,
        "defense_registration_documented": "defense-integration.md" in readme
        and "defense.ps1" in readme
        and "defense.sh" in readme,
        "honeyval_not_claimed_complete": "Honeyval 방어는 개발 중" in readme,
    }
    return {
        "files": [path.relative_to(PROJECT_ROOT).as_posix() for path in required],
        "checks": checks,
        "passed": all(checks.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pair-run-root", type=Path, required=True)
    parser.add_argument("--isolation-report", type=Path, default=ISOLATION_PATH)
    parser.add_argument("--defense-report", type=Path, default=DEFENSE_PATH)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()

    pair_root = args.pair_run_root.resolve()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite report: {output}")

    catalog = load_json(CATALOG_PATH)
    registry = load_json(REGISTRY_PATH)
    catalog_ids = {
        str(item["module_id"])
        for item in catalog.get("modules", [])
        if isinstance(item, dict)
    }
    registry_ruby_ids = {
        str(item["module_id"])
        for item in registry.get("ruby_web_targets", [])
        if isinstance(item, dict)
    }
    registry_cves = {
        str(item["cve_id"])
        for item in registry.get("original_cve_targets", [])
        if isinstance(item, dict)
    }

    orchestration_path = pair_root / "all-pair-checks.json"
    orchestration = load_json(orchestration_path)
    orchestration_rows = orchestration.get("results", [])
    expected_labels = {item[0] for item in CHECKERS}
    observed_labels = {
        str(item.get("label")) for item in orchestration_rows if isinstance(item, dict)
    }
    orchestration_checks = {
        "overall_passed": orchestration.get("passed") is True,
        "all_checkers_present": observed_labels == expected_labels,
        "every_checker_passed": all(
            isinstance(item, dict)
            and item.get("status") == "passed"
            and item.get("returncode") == 0
            for item in orchestration_rows
        ),
    }

    ruby_results = []
    module_owners: dict[str, list[str]] = {}
    for label, script_name, _ in RUBY_CHECKERS:
        modules = source_module_ids(APP_ROOT / "tools" / f"{script_name}.py", catalog_ids)
        for module in modules:
            module_owners.setdefault(module, []).append(label)
        ruby_results.append(validate_ruby_report(label, modules, one_report(pair_root / label)))

    cve_results = [
        validate_cve_report(label, one_report(pair_root / label))
        for label, _, _ in CVE_CHECKERS
    ]
    catalog_checks = {
        "catalog_has_29_modules": len(catalog_ids) == 29,
        "registry_matches_catalog": registry_ruby_ids == catalog_ids,
        "five_original_cves_registered": len(registry_cves) == 5,
        "every_ruby_module_has_one_pair_checker": set(module_owners) == catalog_ids
        and all(len(owners) == 1 for owners in module_owners.values()),
        "every_ruby_pair_report_passed": all(item["passed"] for item in ruby_results),
        "every_cve_pair_report_passed": len(cve_results) == 5
        and all(item["passed"] for item in cve_results),
    }

    isolation_path = args.isolation_report.resolve()
    defense_path = args.defense_report.resolve()
    isolation = check_isolation(registry_cves, isolation_path)
    defense = check_defense_attachment(defense_path)
    documentation = check_documentation()
    tests = (
        {"skipped": True, "passed": False}
        if args.skip_tests
        else pytest_result()
    )
    checks = {
        "catalog_and_registry": all(catalog_checks.values()),
        "pair_orchestration": all(orchestration_checks.values()),
        "all_29_ruby_pairs": all(item["passed"] for item in ruby_results)
        and len(module_owners) == 29,
        "all_5_original_cve_pairs": len(cve_results) == 5
        and all(item["passed"] for item in cve_results),
        "runtime_isolation": isolation["passed"] is True,
        "pluggable_defense": defense["passed"] is True,
        "operator_documentation": documentation["passed"] is True,
        "full_regression": tests["passed"] is True,
    }
    report = {
        "report_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": {
            "ruby_web_modules": len(catalog_ids),
            "original_cve_targets": len(registry_cves),
            "total_targets": len(catalog_ids) + len(registry_cves),
            "honeyval_efficacy_in_scope": False,
        },
        "verdict": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "catalog_checks": catalog_checks,
        "orchestration": {
            "report": orchestration_path.relative_to(PROJECT_ROOT).as_posix(),
            "sha256": sha256(orchestration_path),
            "checks": orchestration_checks,
        },
        "ruby_pair_results": ruby_results,
        "original_cve_pair_results": cve_results,
        "isolation": isolation,
        "defense_attachment": defense,
        "documentation": documentation,
        "tests": tests,
        "limitations": [
            "Pair checks prove the intended vulnerable and secure behaviors; they do not estimate autonomous attacker success rates.",
            "The 29 RUBY modules are synthetic or derived and do not represent the prevalence of vulnerabilities on the public web.",
            "Honeyval efficacy is excluded because the defense is incomplete and was excluded from this release decision.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "report": str(output)}))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
