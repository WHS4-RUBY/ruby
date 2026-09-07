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
PYTHON = str(APP_ROOT / ".venv" / "Scripts" / "python.exe")

# 이름, 추가 인자
CHECKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("check_stage3_vulnerability_pairs", ()),
    ("check_stage3a_derived_pairs", ("--run-id", "all-pairs")),
    ("check_stage3a_second_synthetic_pairs", ("--run-id", "all-pairs")),
    ("check_stage3a_archive_execution_pair", ()),
    ("check_stage3a_support_role_csrf_pair", ()),
    ("check_stage3a_search_takeover_pair", ()),
    ("check_stage3a_remembered_session_role_pair", ()),
    ("check_stage3a_support_error_diagnostic_pair", ()),
    ("check_stage3a_image_credential_chain_pair", ()),
    ("check_stage3a_seller_document_pair", ("--run-id", "all-pairs")),
    ("check_stage3a_cross_shop_refund_pair", ()),
    ("check_stage3a_inventory_race_pair", ()),
    ("check_stage3a_refund_workflow_pair", ()),
    ("check_stage3a_langflow_cve_pair", ()),
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, object]] = []
    for name, extra in CHECKERS:
        target = args.output_dir / name
        if target.exists():
            rows.append({"checker": name, "status": "skipped-existing"})
            continue
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
        "report_version": 1,
        "results": rows,
        "passed": all(item.get("status") == "passed" for item in rows),
    }
    path = args.output_dir / "all-pair-checks.json"
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"passed": report["passed"], "report": str(path)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
