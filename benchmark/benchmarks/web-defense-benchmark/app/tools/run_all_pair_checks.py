# -*- coding: utf-8 -*-
"""표준 쌍 검사기를 한 번에 돌려 한 표로 낸다.

각 검사기는 api 컨테이너를 재생성하므로 반드시 차례로 돌린다. 다른 실험이 같은
기계에서 도는 동안에는 결과가 자원 경합에 흔들릴 수 있다.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable

# 결과 이름, 검사기 이름, 추가 인자
CHECKERS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("ruby-common", "check_stage3_vulnerability_pairs", ()),
    ("ruby-derived", "check_stage3a_derived_pairs", ("--run-id", "all-pairs")),
    ("ruby-second-synthetic", "check_stage3a_second_synthetic_pairs", ("--run-id", "all-pairs")),
    ("ruby-archive-execution", "check_stage3a_archive_execution_pair", ()),
    ("ruby-support-role-csrf", "check_stage3a_support_role_csrf_pair", ()),
    ("ruby-search-takeover", "check_stage3a_search_takeover_pair", ()),
    ("ruby-remembered-session", "check_stage3a_remembered_session_role_pair", ()),
    ("ruby-support-diagnostic", "check_stage3a_support_error_diagnostic_pair", ()),
    ("ruby-image-credential", "check_stage3a_image_credential_chain_pair", ()),
    ("ruby-seller-document", "check_stage3a_seller_document_pair", ("--run-id", "all-pairs")),
    ("ruby-cross-shop-refund", "check_stage3a_cross_shop_refund_pair", ()),
    ("ruby-inventory-race", "check_stage3a_inventory_race_pair", ()),
    ("ruby-refund-workflow", "check_stage3a_refund_workflow_pair", ()),
    ("cve-2024-23897", "check_stage3_jenkins_cve_pair", ()),
    (
        "cve-2024-36401",
        "check_stage3a_geoserver_cve_pair",
        ("--run-id", "all-pairs-geoserver-2024"),
    ),
    (
        "cve-2024-42009",
        "check_stage3a_roundcube_cve_pair",
        ("--run-id", "all-pairs-roundcube-2024"),
    ),
    ("cve-2025-3248", "check_stage3a_langflow_cve_pair", ()),
    (
        "cve-2026-54433",
        "check_stage3a_roundcube_cve_pair",
        (
            "--run-id",
            "all-pairs-roundcube-2026",
            "--pair",
            str(APP_ROOT / "configs" / "stage3a-cve-roundcube-2026-54433-v1.json"),
        ),
    ),
)


def build_current_images(skip: bool) -> dict[str, object]:
    started = time.time()
    build = (
        subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        if skip
        else subprocess.run(
            ["docker", "compose", "build"],
            cwd=APP_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    )
    return {
        "command": "docker compose build",
        "skipped": skip,
        "returncode": build.returncode,
        "seconds": round(time.time() - started, 1),
        "stderr_tail": (build.stderr or "").strip()[-1000:],
        "passed": build.returncode == 0 and not skip,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="reuse local images for debugging; do not use for release evidence",
    )
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to reuse output directory: {output_dir}")
    output_dir.mkdir(parents=True)

    build_result = build_current_images(args.skip_build)
    if build_result["returncode"] != 0:
        report = {
            "report_version": 2,
            "image_build": build_result,
            "results": [],
            "passed": False,
        }
        path = output_dir / "all-pair-checks.json"
        path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"passed": False, "report": str(path)}))
        return 1

    rows: list[dict[str, object]] = []
    for label, name, extra in CHECKERS:
        target = output_dir / label
        started = time.time()
        completed = subprocess.run(
            [
                PYTHON,
                str(APP_ROOT / "tools" / f"{name}.py"),
                "--output-dir",
                str(target),
                *extra,
            ],
            cwd=APP_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={**__import__("os").environ, "PYTHONPATH": str(APP_ROOT / "tools")},
        )
        tail = (completed.stdout or "").strip().splitlines()
        rows.append(
            {
                "label": label,
                "checker": name,
                "returncode": completed.returncode,
                "status": "passed" if completed.returncode == 0 else "failed",
                "seconds": round(time.time() - started, 1),
                "last_line": tail[-1][:300] if tail else "",
                "stderr_tail": (completed.stderr or "").strip()[-400:],
            }
        )
        print(
            "%-46s %-8s %6.0f초"
            % (name, rows[-1]["status"], rows[-1].get("seconds", 0)),
            flush=True,
        )

    report = {
        "report_version": 2,
        "image_build": build_result,
        "results": rows,
        "passed": build_result["passed"]
        and all(item.get("status") == "passed" for item in rows),
    }
    path = output_dir / "all-pair-checks.json"
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"passed": report["passed"], "report": str(path)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
