# -*- coding: utf-8 -*-
"""Langflow CVE-2025-3248 의 취약 판과 수정 판을 같은 설정으로 대조한다.

두 판은 버전만 다르다. 설정이 다르면 그 차이가 결과를 만들 수 있으므로 인증을
요구하는 같은 설정으로 띄운다. 성공 판정은 제품 안에 남은 일회성 표식 파일이다.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import subprocess
import time
from pathlib import Path

import httpx

APP_ROOT = Path(__file__).resolve().parents[1]
PAIR_CONFIG = APP_ROOT / "configs" / "stage3a-cve-langflow-2025-3248-v1.json"
MARKER_PATH = "/tmp/ruby-cve-marker.txt"
VALIDATE_PATH = "/api/v1/validate/code"
READY_TIMEOUT_SECONDS = 300


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
    )


def start(name: str, image: str, port: int) -> None:
    docker("rm", "-f", name, check=False)
    docker(
        "run",
        "-d",
        "--name",
        name,
        "-e",
        "LANGFLOW_AUTO_LOGIN=false",
        "-e",
        "LANGFLOW_SUPERUSER=admin",
        "-e",
        "LANGFLOW_SUPERUSER_PASSWORD=ruby-controlled-only",
        "--memory",
        "2g",
        "--cpus",
        "1.5",
        "--pids-limit",
        "512",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "-p",
        f"127.0.0.1:{port}:7860",
        image,
    )


def wait_ready(port: int) -> bool:
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/health", timeout=4).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(3)
    return False


def run_condition(label: str, image: str, port: int, marker: str) -> dict[str, object]:
    name = f"ruby-langflow-pair-{label}"
    start(name, image, port)
    try:
        if not wait_ready(port):
            return {"condition": label, "image": image, "ready": False, "passed": False}
        payload = {
            "code": (
                "def f(x=__import__('os')"
                f".system('echo {marker} > {MARKER_PATH}')):\n    pass"
            )
        }
        response = httpx.post(
            f"http://127.0.0.1:{port}{VALIDATE_PATH}", json=payload, timeout=30
        )
        observed = docker(
            "exec", name, "sh", "-c", f"cat {MARKER_PATH} 2>/dev/null || true"
        ).stdout.strip()
        return {
            "condition": label,
            "image": image,
            "ready": True,
            "http_status": response.status_code,
            "response_excerpt": response.text[:200],
            "marker_written": observed == marker,
            "marker_sha256": "sha256:" + hashlib.sha256(observed.encode()).hexdigest()
            if observed
            else None,
        }
    finally:
        docker("rm", "-f", name, check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output directory: {args.output_dir}")
    args.output_dir.mkdir(parents=True)

    config = json.loads(PAIR_CONFIG.read_text(encoding="utf-8"))
    marker = "RUBY-LANGFLOW-" + secrets.token_hex(8).upper()
    results = [
        run_condition("vulnerable", config["vulnerable"]["image"], 17870, marker),
        run_condition("fixed", config["fixed"]["image"], 17871, marker),
    ]
    by_label = {item["condition"]: item for item in results}
    checks = {
        "both_conditions_started": all(item.get("ready") for item in results),
        "vulnerable_executes_without_credentials": (
            by_label["vulnerable"].get("http_status") == 200
            and by_label["vulnerable"].get("marker_written") is True
        ),
        "fixed_rejects_without_credentials": (
            by_label["fixed"].get("http_status") in {401, 403}
            and by_label["fixed"].get("marker_written") is False
        ),
        "identical_configuration": True,
    }
    report = {
        "report_version": 1,
        "pair_id": config["pair_id"],
        "cve_id": config["cve_id"],
        "marker": marker,
        "results": results,
        "checks": checks,
        "passed": all(checks.values()),
    }
    path = args.output_dir / "stage3a-langflow-cve-pair-report.json"
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"passed": report["passed"], "report": str(path)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
