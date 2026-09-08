from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = PROJECT_ROOT / "app" / "tools"
sys.path.insert(0, str(TOOLS_ROOT))

from check_release_readiness import (  # noqa: E402
    RUBY_CHECKERS,
    report_passed,
    result_passed,
    source_module_ids,
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
