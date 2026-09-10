from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = PROJECT_ROOT / "app" / "tools"
sys.path.insert(0, str(TOOLS_ROOT))

import check_release_readiness  # noqa: E402
from check_release_readiness import (  # noqa: E402
    RUBY_CHECKERS,
    report_passed,
    result_passed,
    source_module_ids,
    validate_cve_report,
    validate_ruby_report,
)


def test_every_catalog_module_has_exactly_one_pair_checker() -> None:
    catalog = json.loads(
        (
            PROJECT_ROOT
            / "app"
            / "configs"
            / "stage3-vulnerability-module-catalog-v1.json"
        ).read_text(encoding="utf-8")
    )
    catalog_ids = {item["module_id"] for item in catalog["modules"]}
    owners: dict[str, list[str]] = {}
    for label, script_name, _ in RUBY_CHECKERS:
        for module_id in source_module_ids(TOOLS_ROOT / f"{script_name}.py", catalog_ids):
            owners.setdefault(module_id, []).append(label)
    assert len(catalog_ids) == 29
    assert set(owners) == catalog_ids
    assert all(len(labels) == 1 for labels in owners.values())


def test_report_pass_checks_only_explicit_success_forms() -> None:
    assert report_passed({"status": "passed"})
    assert report_passed({"passed": True})
    assert report_passed({"all_checks_passed": True})
    assert not report_passed({"status": "failed", "passed": False})


def test_result_pass_rejects_missing_or_failed_checks() -> None:
    assert result_passed({"passed": True})
    assert result_passed({"all_checks_passed": True})
    assert result_passed({"checks": {"one": True, "two": True}})
    assert not result_passed({"checks": {"one": True, "two": False}})
    assert not result_passed({})


def _write_report(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_ruby_report_requires_module_and_objective_on_every_row(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(check_release_readiness, "PROJECT_ROOT", tmp_path)
    report = {
        "passed": True,
        "results": [
            {
                "module_id": "sql-injection.product-search",
                "condition": "secure",
                "objective_achieved": False,
                "passed": True,
            },
            {
                "module_id": "sql-injection.product-search",
                "condition": "vulnerable",
                "objective_achieved": True,
                "passed": True,
            },
        ],
    }
    path = tmp_path / "ruby-report.json"
    _write_report(path, report)
    valid = validate_ruby_report(
        "ruby-test", {"sql-injection.product-search"}, path
    )
    assert valid["passed"] is True

    del report["results"][0]["module_id"]
    del report["results"][1]["objective_achieved"]
    _write_report(path, report)
    invalid = validate_ruby_report(
        "ruby-test", {"sql-injection.product-search"}, path
    )
    assert invalid["passed"] is False
    assert invalid["checks"]["reported_module_ids_match_source"] is False
    assert invalid["checks"]["objectives_present_and_match_condition"] is False


def test_cve_report_requires_explicit_results_and_objectives(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(check_release_readiness, "PROJECT_ROOT", tmp_path)
    report = {
        "cve_id": "CVE-2024-23897",
        "passed": True,
        "results": [
            {
                "condition": "fixed",
                "objective_achieved": False,
                "passed": True,
            },
            {
                "condition": "vulnerable",
                "objective_achieved": True,
                "passed": True,
            },
        ],
    }
    path = tmp_path / "cve-report.json"
    _write_report(path, report)
    valid = validate_cve_report("cve-2024-23897", path)
    assert valid["passed"] is True

    del report["results"][0]["passed"]
    del report["results"][1]["objective_achieved"]
    _write_report(path, report)
    invalid = validate_cve_report("cve-2024-23897", path)
    assert invalid["passed"] is False
    assert invalid["checks"]["every_result_passed"] is False
    assert invalid["checks"]["objectives_present_and_match_condition"] is False
