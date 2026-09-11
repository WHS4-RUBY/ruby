from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


MANAGER_ROOT = Path(__file__).resolve().parents[1] / "app" / "manager"
sys.path.insert(0, str(MANAGER_ROOT))

import ruby_manager.main as manager  # noqa: E402
from ruby_manager.main import (  # noqa: E402
    ModuleSelection,
    RunRequest,
    build_campaign_command,
    campaign_environment,
    registered_conditions,
    registered_modules,
    registered_targets,
    run_directory,
    update_process,
    write_json_atomic,
)


def test_catalog_only_exposes_registered_modules() -> None:
    modules = registered_modules()
    assert len(modules) == 29
    assert all(str(item["target_id"]).startswith("ruby-web:") for item in modules)
    assert registered_conditions() == ["proxy-only", "static-guard", "undefended"]


def test_target_catalog_includes_isolated_original_cves() -> None:
    targets = registered_targets()
    originals = [item for item in targets if item["target_kind"] == "original-cve"]
    assert len(targets) == 34
    assert len(originals) == 5
    assert {item["target_id"] for item in originals} == {
        "cve-original:CVE-2024-23897",
        "cve-original:CVE-2024-36401",
        "cve-original:CVE-2024-42009",
        "cve-original:CVE-2025-3248",
        "cve-original:CVE-2026-54433",
    }
    assert all(item["switchable"] is False for item in originals)


def test_campaign_command_uses_registered_values_and_computes_budget(tmp_path: Path) -> None:
    payload = RunRequest(
        module_id="sql-injection.product-search",
        providers=["codex"],
        conditions=["undefended", "static-guard"],
        repetitions=2,
        max_model_calls_per_trial=5,
    )
    command = build_campaign_command(payload, "manager-20260909T000000Z-1234abcd", tmp_path)
    assert "ruby-web:sql-injection.product-search" in command
    assert command[command.index("--max-model-calls") + 1] == "20"
    assert command[command.index("--conditions") + 1 : command.index("--repetitions")] == [
        "undefended",
        "static-guard",
    ]

    cve_command = build_campaign_command(
        RunRequest(target_id="cve-original:CVE-2024-23897"),
        "manager-20260909T000000Z-1234abcd",
        tmp_path,
    )
    assert "cve-original:CVE-2024-23897" in cve_command


def test_unknown_provider_and_module_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="providers"):
        build_campaign_command(
            RunRequest(module_id="sql-injection.product-search", providers=["shell"]),
            "manager-20260909T000000Z-1234abcd",
            tmp_path,
        )
    with pytest.raises(ValueError, match="unknown"):
        build_campaign_command(
            RunRequest(module_id="../../outside"),
            "manager-20260909T000000Z-1234abcd",
            tmp_path,
        )


def test_run_directory_rejects_unmanaged_paths() -> None:
    with pytest.raises(ValueError, match="invalid"):
        run_directory("../outside")


def test_module_switch_waits_for_health_and_resets(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[object] = []

    class Response:
        def __init__(self, status: int) -> None:
            self.status = status

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_: object) -> None:
            return None

    def fake_urlopen(request: object, timeout: int) -> Response:
        requests.append(request)
        return Response(204 if len(requests) == 2 else 200)

    monkeypatch.setattr(manager, "urlopen", fake_urlopen)
    manager.wait_for_stack_and_reset({"RUBY_WEB_RESET_TOKEN": "test-reset"})

    assert requests[0] == "http://127.0.0.1:18081/health/live"
    assert requests[1].full_url == "http://127.0.0.1:18081/internal/reset"
    assert requests[1].get_header("X-ruby-reset-token") == "test-reset"


def test_module_switch_builds_current_source_before_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[tuple[list[str], dict[str, object]]] = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(command: list[str], **options: object) -> Result:
        commands.append((command, options))
        return Result()

    monkeypatch.setattr(manager, "EVALUATION_ROOT", tmp_path)
    monkeypatch.setattr(manager, "JOB_STATE_PATH", tmp_path / ".manager-job-state.json")
    monkeypatch.setattr(manager, "active_process", None)
    monkeypatch.setattr(manager, "active_run_id", None)
    monkeypatch.setenv("RUBY_MANAGER_COMPOSE_PROJECT", "ruby-manager-test")
    monkeypatch.setattr(manager.subprocess, "run", fake_run)
    monkeypatch.setattr(manager, "ensure_new_stack_ports_available", lambda _: None)
    monkeypatch.setattr(manager, "wait_for_stack_and_reset", lambda _: None)
    monkeypatch.setattr(
        manager,
        "inspect_active_stack",
        lambda _: {"passed": True, "compose_project": "ruby-manager-test"},
    )

    state = manager.select_module(ModuleSelection(module_id="sql-injection.product-search"))

    assert state["module_id"] == "sql-injection.product-search"
    assert commands[0][0][:3] == ["docker", "ps", "-a"]
    assert commands[1][0][1:3] == ["network", "ls"]
    assert commands[2][0][1:3] == ["volume", "ls"]
    assert commands[3][0][-1] == "build"
    assert commands[3][0][2:4] == ["-p", "ruby-manager-test"]
    assert commands[3][1]["env"]["RUBY_IMAGE_PREFIX"] == "ruby-manager-test"
    assert commands[4][0][-3:] == ["up", "-d", "--no-build"]
    assert state["stack_verification"]["passed"] is True
    assert state["compose_project"] == "ruby-manager-test"


def test_module_switch_rejects_a_project_owned_by_another_checkout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Result:
        returncode = 0
        stdout = "container-id|C:\\other-checkout\\app\\compose.yaml\n"
        stderr = ""

    monkeypatch.setattr(manager.subprocess, "run", lambda *_args, **_kwargs: Result())
    environment = manager.manager_stack_environment()

    with pytest.raises(RuntimeError, match="another checkout"):
        manager.ensure_compose_project_owned(environment)


def test_manager_rejects_orphaned_project_networks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Result:
        returncode = 0
        stderr = ""

        def __init__(self, stdout: str = "") -> None:
            self.stdout = stdout

    def fake_run(command: list[str], **_options: object) -> Result:
        if command[1:3] == ["network", "ls"]:
            return Result("network-id\n")
        return Result()

    monkeypatch.setattr(manager.subprocess, "run", fake_run)
    environment = manager.manager_stack_environment()

    with pytest.raises(RuntimeError, match="orphaned network"):
        manager.ensure_compose_project_owned(environment)


def test_manager_stack_uses_configured_project_images_and_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RUBY_MANAGER_COMPOSE_PROJECT", "ruby-manager-review")
    monkeypatch.setenv("RUBY_PUBLIC_PORT", "28080")
    monkeypatch.setenv("RUBY_CONTROL_PORT", "28081")
    monkeypatch.setattr(
        manager,
        "current_selection_state",
        lambda _: {
            "mode": "stopped",
            "module_id": None,
            "trial_id": None,
            "changed_at": None,
        },
    )

    environment = manager.manager_stack_environment()
    overview = manager.overview()

    assert environment["COMPOSE_PROJECT_NAME"] == "ruby-manager-review"
    assert environment["RUBY_IMAGE_PREFIX"] == "ruby-manager-review"
    assert overview["stack"] == {
        "compose_project": "ruby-manager-review",
        "public_origin": "http://127.0.0.1:28080",
        "control_origin": "http://127.0.0.1:28081",
    }


def test_manager_stack_default_project_is_checkout_specific(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("RUBY_MANAGER_COMPOSE_PROJECT", raising=False)

    environment = manager.manager_stack_environment()

    assert environment["COMPOSE_PROJECT_NAME"] == manager.default_compose_project()
    assert environment["COMPOSE_PROJECT_NAME"].startswith("ruby-web-defense-")


def test_manager_stack_rejects_invalid_or_duplicate_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RUBY_PUBLIC_PORT", "70000")
    with pytest.raises(ValueError, match="RUBY_PUBLIC_PORT"):
        manager.manager_stack_environment()

    monkeypatch.setenv("RUBY_PUBLIC_PORT", "28080")
    monkeypatch.setenv("RUBY_CONTROL_PORT", "28080")
    with pytest.raises(ValueError, match="must be different"):
        manager.manager_stack_environment()


def test_manager_stack_rejects_an_invalid_project_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RUBY_MANAGER_COMPOSE_PROJECT", "../shared")

    with pytest.raises(ValueError, match="RUBY_MANAGER_COMPOSE_PROJECT"):
        manager.manager_stack_environment()


def test_active_stack_inspection_checks_module_trial_image_and_networks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = {
        "COMPOSE_PROJECT_NAME": "ruby-manager-test",
        "RUBY_IMAGE_PREFIX": "ruby-manager-test",
        "RUBY_WEB_VULNERABILITY_MODULES": "sql-injection.product-search",
        "RUBY_WEB_TRIAL_ID": "a" * 32,
    }
    compose_path = str(manager.APP_ROOT / "compose.yaml")
    container = {
        "Image": "sha256:api-image",
        "Config": {
            "Labels": {
                "com.docker.compose.project": "ruby-manager-test",
                "com.docker.compose.project.config_files": compose_path,
            },
            "Env": [
                "RUBY_WEB_VULNERABILITY_MODULES=sql-injection.product-search",
                f"RUBY_WEB_TRIAL_ID={'a' * 32}",
            ],
        },
        "NetworkSettings": {
            "Networks": {
                "ruby-manager-test_data": {},
                "ruby-manager-test_edge": {},
            }
        },
    }

    class Result:
        def __init__(self, stdout: str) -> None:
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ""

    results = iter(
        [
            Result("container-id\n"),
            Result(__import__("json").dumps([container])),
            Result(__import__("json").dumps([{"Id": "sha256:api-image"}])),
        ]
    )
    monkeypatch.setattr(
        manager.subprocess,
        "run",
        lambda *_args, **_kwargs: next(results),
    )

    verification = manager.inspect_active_stack(environment)

    assert verification["passed"] is True
    assert all(verification["checks"].values())


def test_missing_stack_is_reported_as_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(manager, "EVALUATION_ROOT", tmp_path)
    monkeypatch.setattr(manager, "ensure_compose_project_owned", lambda _: False)

    state = manager.current_selection_state(manager.manager_stack_environment())

    assert state["mode"] == "stopped"
    assert state["module_id"] is None


def test_saved_selection_drift_is_reported_as_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(manager, "EVALUATION_ROOT", tmp_path)
    environment = manager.manager_stack_environment()
    manager.write_json_atomic(
        tmp_path / ".manager-module-selection.json",
        {
            "mode": "vulnerable",
            "module_id": "sql-injection.product-search",
            "trial_id": "a" * 32,
            "compose_project": environment["COMPOSE_PROJECT_NAME"],
            "changed_at": "2026-09-12T00:00:00+00:00",
        },
    )
    monkeypatch.setattr(
        manager,
        "inspect_active_stack",
        lambda _: (_ for _ in ()).throw(RuntimeError("container missing")),
    )

    state = manager.current_selection_state(environment)

    assert state["mode"] == "unknown"
    assert state["stored_mode"] == "vulnerable"
    assert "container missing" in str(state["error"])


def test_failed_post_switch_verification_records_unknown_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(manager, "EVALUATION_ROOT", tmp_path)
    monkeypatch.setattr(manager, "JOB_STATE_PATH", tmp_path / ".manager-job-state.json")
    monkeypatch.setattr(manager, "active_process", None)
    monkeypatch.setattr(manager, "active_run_id", None)
    monkeypatch.setenv("RUBY_MANAGER_COMPOSE_PROJECT", "ruby-manager-test")
    monkeypatch.setattr(manager.subprocess, "run", lambda *_args, **_kwargs: Result())
    monkeypatch.setattr(manager, "ensure_new_stack_ports_available", lambda _: None)
    monkeypatch.setattr(manager, "wait_for_stack_and_reset", lambda _: None)
    monkeypatch.setattr(
        manager,
        "inspect_active_stack",
        lambda _: (_ for _ in ()).throw(RuntimeError("wrong active module")),
    )

    with pytest.raises(manager.HTTPException, match="wrong active module") as raised:
        manager.select_module(ModuleSelection(module_id="sql-injection.product-search"))

    assert raised.value.status_code == 400
    state = __import__("json").loads(
        (tmp_path / ".manager-module-selection.json").read_text(encoding="utf-8")
    )
    assert state["mode"] == "unknown"
    assert state["module_id"] == "sql-injection.product-search"
    assert state["error"] == "wrong active module"
    assert state["compose_project"] == "ruby-manager-test"


def test_failed_build_records_unknown_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Result:
        def __init__(self, returncode: int = 0, stderr: str = "") -> None:
            self.returncode = returncode
            self.stdout = ""
            self.stderr = stderr

    def fake_run(command: list[str], **_options: object) -> Result:
        if command[-1] == "build":
            return Result(1, "build failed")
        return Result()

    monkeypatch.setattr(manager, "EVALUATION_ROOT", tmp_path)
    monkeypatch.setattr(manager, "JOB_STATE_PATH", tmp_path / ".manager-job-state.json")
    monkeypatch.setattr(manager, "active_process", None)
    monkeypatch.setattr(manager, "active_run_id", None)
    monkeypatch.setenv("RUBY_MANAGER_COMPOSE_PROJECT", "ruby-manager-test")
    monkeypatch.setattr(manager.subprocess, "run", fake_run)
    monkeypatch.setattr(manager, "ensure_new_stack_ports_available", lambda _: None)

    with pytest.raises(manager.HTTPException, match="build failed"):
        manager.select_module(ModuleSelection(module_id="sql-injection.product-search"))

    state = __import__("json").loads(
        (tmp_path / ".manager-module-selection.json").read_text(encoding="utf-8")
    )
    assert state["mode"] == "unknown"
    assert state["module_id"] == "sql-injection.product-search"
    assert state["error"] == "build failed"
    assert state["compose_project"] == "ruby-manager-test"


def test_manager_rejects_non_loopback_clients_and_untrusted_hosts() -> None:
    headers = {"X-Ruby-Manager-Token": manager.MANAGER_TOKEN}
    local = TestClient(
        manager.app,
        base_url="http://127.0.0.1:18083",
        client=("127.0.0.1", 51000),
    )
    assert local.get("/api/overview", headers=headers).status_code == 200
    assert local.get("/api/overview").status_code == 401
    assert local.get("/assets/app.js").status_code == 200

    remote = TestClient(
        manager.app,
        base_url="http://127.0.0.1:18083",
        client=("172.20.0.10", 51000),
    )
    assert remote.get("/api/overview", headers=headers).status_code == 403
    assert local.get(
        "/api/overview",
        headers={**headers, "host": "manager.attacker.example"},
    ).status_code == 400


def test_static_shell_has_security_headers_without_a_cookie() -> None:
    client = TestClient(
        manager.app,
        base_url="http://127.0.0.1:18083",
        client=("127.0.0.1", 51000),
    )
    page = client.get("/")
    assert page.status_code == 200
    assert "set-cookie" not in page.headers
    assert page.headers["Cache-Control"] == "no-store"
    assert page.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
    assert client.get("/assets/app.js").status_code == 200
    assert client.get(
        "/openapi.json", headers={"X-Ruby-Manager-Token": manager.MANAGER_TOKEN}
    ).status_code == 404


def test_static_shell_exposes_operational_workflows() -> None:
    client = TestClient(
        manager.app,
        base_url="http://127.0.0.1:18083",
        client=("127.0.0.1", 51000),
    )
    page = client.get("/").text
    script = client.get("/assets/app.js").text

    for control in (
        'id="module-search"',
        'id="family-filter"',
        'id="safe-mode"',
        'id="run-dialog"',
        'id="run-search"',
        'id="auto-refresh"',
        'rel="icon"',
        'id="target-web-link"',
    ):
        assert control in page
    assert client.get("/assets/favicon.svg").status_code == 200
    for endpoint in (
        '"/api/overview"',
        '"/api/module-selection"',
        '"/api/runs"',
    ):
        assert endpoint in script
    assert "public_origin" in script
    assert 'selectionMode === "unknown"' in script
    assert "상태 확인 필요:" in script
    assert "window.history.replaceState" in script
    assert "스택 미실행" in script


def test_static_shell_marks_xss_and_csrf_claim_limits() -> None:
    client = TestClient(
        manager.app,
        base_url="http://127.0.0.1:18083",
        client=("127.0.0.1", 51000),
    )
    script = client.get("/assets/app.js").text

    for target_id in (
        "ruby-web:unsafe-file-upload.seller-document-preview",
        "ruby-web:roundcube-derived.support-ticket-html-postprocess",
        "ruby-web:cross-site-request-forgery.support-role-change",
        "cve-original:CVE-2024-42009",
        "cve-original:CVE-2026-54433",
    ):
        assert target_id in script
    for label in (
        '["판정", "검증됨"',
        '["식별", "미채택"',
        '["차단", "미구현"',
        '"방어 효과 집계 제외"',
    ):
        assert label in script


def test_campaign_environment_drops_manager_control_values_and_keeps_image_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RUBY_MANAGER_TOKEN", "must-not-reach-campaign")
    monkeypatch.setenv("RUBY_MANAGER_COMPOSE_PROJECT", "must-not-reach-campaign")
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "must-not-reach-campaign")
    monkeypatch.setenv("RUBY_IMAGE_PREFIX", "must-not-reach-campaign")

    environment = campaign_environment()

    assert "RUBY_MANAGER_TOKEN" not in environment
    assert "RUBY_MANAGER_COMPOSE_PROJECT" not in environment
    assert "COMPOSE_PROJECT_NAME" not in environment
    assert environment["RUBY_IMAGE_PREFIX"] == "must-not-reach-campaign"


def test_job_state_recovers_running_and_completed_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = "manager-20260911T000000Z-1234abcd"
    state_path = tmp_path / ".manager-job-state.json"
    monkeypatch.setattr(manager, "EVALUATION_ROOT", tmp_path)
    monkeypatch.setattr(manager, "JOB_STATE_PATH", state_path)
    monkeypatch.setattr(manager, "active_process", None)
    monkeypatch.setattr(manager, "active_run_id", None)
    write_json_atomic(
        state_path,
        {"run_id": run_id, "status": "running", "pid": __import__("os").getpid()},
    )

    recovered = update_process()
    assert recovered["status"] == "running-unmanaged"
    assert recovered["recovery"] == "process-still-running-after-manager-restart"

    run = tmp_path / run_id
    run.mkdir()
    (run / "campaign-summary.json").write_text("{}", encoding="utf-8")
    completed = update_process()
    assert completed["status"] == "completed"
    assert completed["recovery"] == "campaign-summary-found-after-manager-restart"


def test_runs_preserves_failed_status_without_a_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = "manager-20260911T010000Z-abcdef12"
    monkeypatch.setattr(manager, "EVALUATION_ROOT", tmp_path)
    monkeypatch.setattr(manager, "JOB_STATE_PATH", tmp_path / ".manager-job-state.json")
    monkeypatch.setattr(manager, "active_process", None)
    monkeypatch.setattr(manager, "active_run_id", None)
    (tmp_path / run_id).mkdir()
    write_json_atomic(
        manager.JOB_STATE_PATH,
        {"run_id": run_id, "status": "failed", "return_code": 2},
    )

    assert manager.runs() == [
        {"run_id": run_id, "status": "failed", "summary": None}
    ]
