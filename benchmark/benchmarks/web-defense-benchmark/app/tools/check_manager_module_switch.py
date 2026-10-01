from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx


APP_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = Path(__file__).resolve().parent
MANAGER_ROOT = APP_ROOT / "manager"
PROJECT_PATTERN = re.compile(r"^ruby-manager-check-[a-z0-9-]{3,40}$")
COMPOSE_SERVICES = (
    "postgres",
    "redis",
    "object-store",
    "mock-integration",
    "api",
    "worker",
    "evaluator",
    "web",
)


def docker_lines(*arguments: str) -> list[str]:
    result = subprocess.run(
        ["docker", *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    return sorted(line for line in result.stdout.splitlines() if line)


def project_resources(project: str) -> dict[str, list[str]]:
    label = f"label=com.docker.compose.project={project}"
    return {
        "containers": docker_lines("ps", "-a", "-q", "--filter", label),
        "networks": docker_lines("network", "ls", "-q", "--filter", label),
        "volumes": docker_lines("volume", "ls", "-q", "--filter", label),
        "images": docker_lines(
            "image",
            "ls",
            "--format",
            "{{.Repository}}:{{.Tag}}",
            "--filter",
            f"reference={project}-*",
        ),
    }


def verify_orphan_resource_refusal(manager: Any, project: str) -> dict[str, object]:
    network = f"{project}_orphan-preflight"
    created = subprocess.run(
        [
            "docker",
            "network",
            "create",
            "--label",
            f"com.docker.compose.project={project}",
            network,
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    ).stdout.strip()
    refusal: str | None = None
    try:
        try:
            manager.ensure_compose_project_owned(manager.manager_stack_environment())
        except RuntimeError as error:
            refusal = str(error)
    finally:
        subprocess.run(
            ["docker", "network", "rm", created or network],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    residual = project_resources(project)
    checks = {
        "orphan_network_was_refused": bool(refusal)
        and "orphaned network" in refusal,
        "orphan_network_was_removed": not any(residual.values()),
    }
    return {
        "network": network,
        "refusal": refusal,
        "residual_resources": residual,
        "checks": checks,
        "passed": all(checks.values()),
    }


def observe_pair(
    pair_checker: object,
    pair: object,
    trial_id: str,
    *,
    expected_effect: bool,
) -> dict[str, object]:
    with httpx.Client(base_url=pair_checker.PUBLIC_ORIGIN, timeout=20) as client:
        attempt = pair.exercise(client)
    evaluation, verifier_manifest = pair_checker.evaluate(trial_id, pair, attempt)
    expected_status = (
        pair.expected_vulnerable_status
        if expected_effect
        else pair.expected_secure_status
    )
    checks = {
        "expected_http_status": attempt.status_code == expected_status,
        "private_evaluator_effect": (
            evaluation["objective_achieved"] is expected_effect
        ),
        "matched_event_count": len(evaluation["matched_event_ids"])
        == (1 if expected_effect else 0),
    }
    if pair.module_id == "sql-injection.product-search":
        checks["protected_response_evidence"] = (
            attempt.response_evidence["protected_marker_observed"] is expected_effect
            and attempt.response_evidence["protected_item_count"]
            == (1 if expected_effect else 0)
        )
    if pair.module_id == "path-traversal.report-download":
        checks["protected_response_evidence"] = (
            (attempt.response_evidence["protected_content"] is not None)
            is expected_effect
        )
    return {
        "module_id": pair.module_id,
        "trial_id": trial_id,
        "expected_effect": expected_effect,
        "http_status": attempt.status_code,
        "objective_achieved": evaluation["objective_achieved"],
        "matched_event_ids": evaluation["matched_event_ids"],
        "response_evidence": attempt.response_evidence,
        "verifier_image_digest": verifier_manifest["verifier_image_digest"],
        "checks": checks,
        "passed": all(checks.values()),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify manager module switching in a separate Compose project."
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--public-port", type=int, required=True)
    parser.add_argument("--control-port", type=int, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if PROJECT_PATTERN.fullmatch(args.project) is None:
        raise ValueError("project must match ruby-manager-check-[a-z0-9-]{3,40}")
    if not 1024 <= args.public_port <= 65535:
        raise ValueError("public-port must be between 1024 and 65535")
    if not 1024 <= args.control_port <= 65535:
        raise ValueError("control-port must be between 1024 and 65535")
    if args.public_port == args.control_port:
        raise ValueError("public-port and control-port must be different")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output directory: {output_dir}")
    output_dir.mkdir(parents=True)

    os.environ.update(
        {
            "RUBY_MANAGER_COMPOSE_PROJECT": args.project,
            "COMPOSE_PROJECT_NAME": args.project,
            "RUBY_IMAGE_PREFIX": args.project,
            "RUBY_PUBLIC_PORT": str(args.public_port),
            "RUBY_CONTROL_PORT": str(args.control_port),
            "RUBY_TEST_PUBLIC_ORIGIN": f"http://127.0.0.1:{args.public_port}",
            "RUBY_TEST_CONTROL_ORIGIN": f"http://127.0.0.1:{args.control_port}",
        }
    )
    sys.path.insert(0, str(MANAGER_ROOT))
    sys.path.insert(0, str(TOOLS_ROOT))
    import check_stage3_vulnerability_pairs as pair_checker
    import ruby_manager.main as manager

    manager.EVALUATION_ROOT = output_dir / "manager-state"
    manager.JOB_STATE_PATH = manager.EVALUATION_ROOT / ".manager-job-state.json"
    manager.active_process = None
    manager.active_run_id = None

    if any(project_resources(args.project).values()):
        raise RuntimeError(
            f"refusing to reuse existing verification project: {args.project}"
        )

    orphan_resource_preflight = verify_orphan_resource_refusal(manager, args.project)
    default_project = "ruby-web-defense-benchmark"
    default_before = project_resources(default_project)
    stages: list[dict[str, object]] = []
    failure: str | None = None
    cleanup_errors: list[str] = []
    try:
        pairs = {item.module_id: item for item in pair_checker.PAIRS}
        sql_pair = pairs["sql-injection.product-search"]
        path_pair = pairs["path-traversal.report-download"]

        safe_sql = manager.select_module(manager.ModuleSelection(module_id=None))
        stages.append(
            {
                "switch": "safe-before-sql",
                "state": safe_sql,
                "live_state": manager.current_selection_state(
                    manager.manager_stack_environment()
                ),
                "observations": [
                    observe_pair(
                        pair_checker,
                        sql_pair,
                        safe_sql["trial_id"],
                        expected_effect=False,
                    )
                ],
            }
        )

        vulnerable_sql = manager.select_module(
            manager.ModuleSelection(module_id=sql_pair.module_id)
        )
        stages.append(
            {
                "switch": "sql-vulnerable",
                "state": vulnerable_sql,
                "live_state": manager.current_selection_state(
                    manager.manager_stack_environment()
                ),
                "observations": [
                    observe_pair(
                        pair_checker,
                        sql_pair,
                        vulnerable_sql["trial_id"],
                        expected_effect=True,
                    )
                ],
            }
        )

        vulnerable_path = manager.select_module(
            manager.ModuleSelection(module_id=path_pair.module_id)
        )
        stages.append(
            {
                "switch": "path-vulnerable",
                "state": vulnerable_path,
                "live_state": manager.current_selection_state(
                    manager.manager_stack_environment()
                ),
                "observations": [
                    observe_pair(
                        pair_checker,
                        sql_pair,
                        vulnerable_path["trial_id"],
                        expected_effect=False,
                    ),
                    observe_pair(
                        pair_checker,
                        path_pair,
                        vulnerable_path["trial_id"],
                        expected_effect=True,
                    ),
                ],
            }
        )

        safe_path = manager.select_module(manager.ModuleSelection(module_id=None))
        stages.append(
            {
                "switch": "safe-after-path",
                "state": safe_path,
                "live_state": manager.current_selection_state(
                    manager.manager_stack_environment()
                ),
                "observations": [
                    observe_pair(
                        pair_checker,
                        path_pair,
                        safe_path["trial_id"],
                        expected_effect=False,
                    )
                ],
            }
        )
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        environment = manager.manager_stack_environment()
        cleanup = subprocess.run(
            manager.compose_command(environment, "down", "-v", "--remove-orphans"),
            cwd=APP_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
        if cleanup.returncode:
            cleanup_errors.append((cleanup.stderr or cleanup.stdout)[-2000:])
        image_names = [f"{args.project}-{service}:latest" for service in COMPOSE_SERVICES]
        existing_images = set(project_resources(args.project)["images"])
        removable_images = [name for name in image_names if name in existing_images]
        if removable_images:
            image_cleanup = subprocess.run(
                ["docker", "image", "rm", *removable_images],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                check=False,
            )
            if image_cleanup.returncode:
                cleanup_errors.append(
                    (image_cleanup.stderr or image_cleanup.stdout)[-2000:]
                )

    default_after = project_resources(default_project)
    residual_resources = project_resources(args.project)
    post_cleanup_selection = manager.current_selection_state(
        manager.manager_stack_environment()
    )
    stage_checks = [
        bool(stage["state"]["stack_verification"]["passed"])
        and stage["live_state"].get("mode") == stage["state"].get("mode")
        and bool(stage["live_state"].get("live_verified_at"))
        and all(item["passed"] for item in stage["observations"])
        for stage in stages
    ]
    checks = {
        "orphan_resource_preflight_passed": orphan_resource_preflight["passed"],
        "four_switch_states_completed": len(stages) == 4,
        "all_switch_live_state_and_judgment_checks_passed": len(stage_checks) == 4
        and all(stage_checks),
        "unique_trial_ids": len(
            {str(stage["state"]["trial_id"]) for stage in stages}
        )
        == 4,
        "default_project_unchanged": default_before == default_after,
        "verification_resources_removed": not any(residual_resources.values()),
        "cleanup_succeeded": not cleanup_errors,
        "removed_stack_is_reported_unknown": post_cleanup_selection.get("mode")
        == "unknown",
    }
    report = {
        "report_version": 2,
        "project": args.project,
        "public_origin": pair_checker.PUBLIC_ORIGIN,
        "control_origin": pair_checker.CONTROL_ORIGIN,
        "stages": stages,
        "orphan_resource_preflight": orphan_resource_preflight,
        "default_project_before": default_before,
        "default_project_after": default_after,
        "residual_resources": residual_resources,
        "post_cleanup_selection": post_cleanup_selection,
        "failure": failure,
        "cleanup_errors": cleanup_errors,
        "checks": checks,
        "passed": failure is None and all(checks.values()),
        "completed_at": datetime.now(UTC).isoformat(),
    }
    report_path = output_dir / "manager-module-switch-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(report_path)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
