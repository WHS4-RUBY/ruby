from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request as HttpRequest, urlopen

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response


PACKAGE_ROOT = Path(__file__).resolve().parent
APP_ROOT = Path(os.getenv("RUBY_MANAGER_APP_ROOT", PACKAGE_ROOT.parents[1])).resolve()
EVALUATION_ROOT = APP_ROOT / "evaluation"
CONFIG_ROOT = APP_ROOT / "configs"
JOB_STATE_PATH = EVALUATION_ROOT / ".manager-job-state.json"
RUN_PATTERN = re.compile(r"^manager-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$")
COMPOSE_PROJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
ALLOWED_PROVIDERS = {"codex", "claude"}
MANAGER_TOKEN = os.getenv("RUBY_MANAGER_TOKEN") or secrets.token_urlsafe(32)
lock = threading.Lock()
active_process: subprocess.Popen[bytes] | None = None
active_run_id: str | None = None
active_log = None


def default_compose_project() -> str:
    checkout = str(APP_ROOT).replace("\\", "/").casefold().encode("utf-8")
    return f"ruby-web-defense-{hashlib.sha256(checkout).hexdigest()[:12]}"


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def manager_stack_environment() -> dict[str, str]:
    environment = os.environ.copy()
    project = environment.get(
        "RUBY_MANAGER_COMPOSE_PROJECT", default_compose_project()
    ).strip()
    if COMPOSE_PROJECT_PATTERN.fullmatch(project) is None:
        raise ValueError(
            "RUBY_MANAGER_COMPOSE_PROJECT must use lowercase letters, digits, "
            "hyphens or underscores"
        )
    environment["COMPOSE_PROJECT_NAME"] = project
    environment["RUBY_IMAGE_PREFIX"] = project
    ports: dict[str, int] = {}
    for name, default in (
        ("RUBY_PUBLIC_PORT", "18080"),
        ("RUBY_CONTROL_PORT", "18081"),
    ):
        raw = environment.get(name, default).strip()
        if not raw.isdecimal() or not 1 <= int(raw) <= 65535:
            raise ValueError(f"{name} must be an integer from 1 through 65535")
        ports[name] = int(raw)
        environment[name] = str(ports[name])
    if ports["RUBY_PUBLIC_PORT"] == ports["RUBY_CONTROL_PORT"]:
        raise ValueError("RUBY_PUBLIC_PORT and RUBY_CONTROL_PORT must be different")
    return environment


def compose_command(environment: dict[str, str], *arguments: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-p",
        environment["COMPOSE_PROJECT_NAME"],
        "-f",
        str(APP_ROOT / "compose.yaml"),
        *arguments,
    ]


def normalized_checkout_path(value: str) -> str:
    return str(Path(value).resolve()).replace("\\", "/").casefold()


def compose_project_resources(project: str) -> dict[str, list[str]]:
    resources: dict[str, list[str]] = {}
    for kind in ("network", "volume"):
        result = subprocess.run(
            [
                "docker",
                kind,
                "ls",
                "-q",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout)[-2000:])
        resources[kind] = [
            line.strip() for line in result.stdout.splitlines() if line.strip()
        ]
    return resources


def ensure_compose_project_owned(environment: dict[str, str]) -> bool:
    project = environment["COMPOSE_PROJECT_NAME"]
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            '{{.ID}}|{{.Label "com.docker.compose.project.config_files"}}',
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout)[-2000:])
    expected = normalized_checkout_path(str(APP_ROOT / "compose.yaml"))
    records = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    owners: set[str] = set()
    missing_sources: list[str] = []
    for record in records:
        container_id, separator, sources = record.partition("|")
        if not separator or not sources.strip():
            missing_sources.append(container_id or "unknown")
            continue
        owners.update(
            normalized_checkout_path(path.strip())
            for path in sources.split(",")
            if path.strip()
        )
    foreign = sorted(owner for owner in owners if owner != expected)
    if foreign or missing_sources:
        details = foreign + [
            f"container {item} has no source label" for item in missing_sources
        ]
        raise RuntimeError(
            f"Compose project {project!r} is already controlled by another checkout: "
            f"{', '.join(details)}. Set RUBY_MANAGER_COMPOSE_PROJECT and unused "
            "RUBY_PUBLIC_PORT and RUBY_CONTROL_PORT values for an isolated stack."
        )
    if not records:
        orphaned = compose_project_resources(project)
        occupied = [kind for kind, identifiers in orphaned.items() if identifiers]
        if occupied:
            raise RuntimeError(
                f"Compose project {project!r} has orphaned {', '.join(occupied)} "
                "resources without containers; clean that exact project or choose a new "
                "RUBY_MANAGER_COMPOSE_PROJECT value."
            )
    return bool(records)


def ensure_new_stack_ports_available(environment: dict[str, str]) -> None:
    for name in ("RUBY_PUBLIC_PORT", "RUBY_CONTROL_PORT"):
        port = int(environment[name])
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
                candidate.bind(("127.0.0.1", port))
        except OSError as error:
            raise RuntimeError(
                f"{name}={port} is already in use; choose an unused loopback port"
            ) from error


def inspect_active_stack(environment: dict[str, str]) -> dict[str, object]:
    project = environment["COMPOSE_PROJECT_NAME"]
    container_result = subprocess.run(
        compose_command(environment, "ps", "-q", "api"),
        cwd=APP_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    container_id = container_result.stdout.strip()
    if container_result.returncode or not container_id:
        raise RuntimeError(
            "RUBY API container was not found after module switch: "
            + (container_result.stderr or container_result.stdout)[-2000:]
        )
    expected_image = f"{environment['RUBY_IMAGE_PREFIX']}-api:latest"
    container_inspect = subprocess.run(
        ["docker", "inspect", container_id],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    image_inspect = subprocess.run(
        ["docker", "image", "inspect", expected_image],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    if container_inspect.returncode or image_inspect.returncode:
        detail = (
            container_inspect.stderr
            or image_inspect.stderr
            or container_inspect.stdout
            or image_inspect.stdout
        )
        raise RuntimeError(f"RUBY stack inspection failed: {detail[-2000:]}")
    containers = json.loads(container_inspect.stdout)
    images = json.loads(image_inspect.stdout)
    if len(containers) != 1 or len(images) != 1:
        raise RuntimeError("RUBY stack inspection returned an ambiguous result")
    container = containers[0]
    image = images[0]
    labels = container.get("Config", {}).get("Labels") or {}
    variables = {
        item.split("=", 1)[0]: item.split("=", 1)[1]
        for item in container.get("Config", {}).get("Env") or []
        if "=" in item
    }
    networks = sorted((container.get("NetworkSettings", {}).get("Networks") or {}))
    expected_networks = sorted([f"{project}_data", f"{project}_edge"])
    checks = {
        "compose_project": labels.get("com.docker.compose.project") == project,
        "compose_source": normalized_checkout_path(
            str(labels.get("com.docker.compose.project.config_files", ""))
        )
        == normalized_checkout_path(str(APP_ROOT / "compose.yaml")),
        "image_id": container.get("Image") == image.get("Id"),
        "module_id": variables.get("RUBY_WEB_VULNERABILITY_MODULES", "")
        == environment.get("RUBY_WEB_VULNERABILITY_MODULES", ""),
        "trial_id": variables.get("RUBY_WEB_TRIAL_ID", "")
        == environment.get("RUBY_WEB_TRIAL_ID", ""),
        "networks": networks == expected_networks,
    }
    if not all(checks.values()):
        raise RuntimeError(f"RUBY stack verification failed: {checks}")
    return {
        "passed": True,
        "compose_project": project,
        "image": expected_image,
        "image_id": image.get("Id"),
        "networks": networks,
        "checks": checks,
    }


def unknown_selection(
    message: str,
    selection: dict[str, object] | None = None,
) -> dict[str, object]:
    value = dict(selection or {})
    previous_mode = value.get("mode")
    value.update(mode="unknown", error=message)
    if previous_mode and previous_mode != "unknown":
        value["stored_mode"] = previous_mode
    value.setdefault("module_id", None)
    value.setdefault("trial_id", None)
    value.setdefault("changed_at", None)
    return value


def current_selection_state(environment: dict[str, str]) -> dict[str, object]:
    selection_path = EVALUATION_ROOT / ".manager-module-selection.json"
    if not selection_path.is_file():
        try:
            project_exists = ensure_compose_project_owned(environment)
        except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as error:
            return unknown_selection(str(error))
        if project_exists:
            return unknown_selection(
                "a stack exists without a saved manager selection state"
            )
        return {
            "mode": "stopped",
            "module_id": None,
            "trial_id": None,
            "changed_at": None,
            "compose_project": environment["COMPOSE_PROJECT_NAME"],
        }

    try:
        loaded = read_json(selection_path)
    except (OSError, ValueError) as error:
        return unknown_selection(f"saved selection state cannot be read: {error}")
    if not isinstance(loaded, dict):
        return unknown_selection("saved selection state is not a JSON object")
    selection = dict(loaded)
    mode = selection.get("mode")
    if mode == "unknown":
        return selection
    if mode == "switching":
        return unknown_selection(
            "the previous module switch did not record a completed state",
            selection,
        )
    if mode not in {"safe", "vulnerable"}:
        return unknown_selection(f"saved selection mode is invalid: {mode!r}", selection)

    verification = selection.get("stack_verification")
    verified_project = (
        verification.get("compose_project")
        if isinstance(verification, dict)
        else None
    )
    stored_project = selection.get("compose_project") or verified_project
    if stored_project != environment["COMPOSE_PROJECT_NAME"]:
        return unknown_selection(
            "saved selection belongs to a different Compose project",
            selection,
        )
    module_id = selection.get("module_id")
    trial_id = selection.get("trial_id")
    if mode == "safe" and module_id is not None:
        return unknown_selection("safe selection contains a module id", selection)
    if mode == "vulnerable" and not isinstance(module_id, str):
        return unknown_selection("vulnerable selection has no module id", selection)
    if not isinstance(trial_id, str) or re.fullmatch(r"[0-9a-f]{32}", trial_id) is None:
        return unknown_selection("saved selection has an invalid trial id", selection)

    inspection_environment = environment.copy()
    inspection_environment["RUBY_WEB_TRIAL_ID"] = trial_id
    inspection_environment["RUBY_WEB_VULNERABILITY_MODULES"] = module_id or ""
    try:
        current = inspect_active_stack(inspection_environment)
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as error:
        return unknown_selection(
            f"saved selection does not match the current stack: {error}",
            selection,
        )
    selection["stack_verification"] = current
    selection["live_verified_at"] = datetime.now(UTC).isoformat()
    return selection


def saved_job_state() -> dict[str, object] | None:
    if not JOB_STATE_PATH.is_file():
        return None
    try:
        value = read_json(JOB_STATE_PATH)
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def process_exists(pid: object) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except (OSError, PermissionError):
        return False
    return True


def registered_modules() -> list[dict[str, object]]:
    catalog = read_json(CONFIG_ROOT / "stage3-vulnerability-module-catalog-v1.json")
    registry = read_json(CONFIG_ROOT / "stage3a-autonomous-target-registry-v2.json")
    target_ids = {
        item["module_id"]: item["target_id"] for item in registry["ruby_web_targets"]
    }
    return sorted(
        [
            {
                "module_id": item["module_id"],
                "target_id": target_ids[item["module_id"]],
                "target_kind": "ruby-web",
                "switchable": True,
                "family": item.get("family"),
                "required_role": item.get("required_role"),
                "request": item.get("request"),
                "secure_outcome": item.get("secure_outcome"),
                "vulnerable_outcome": item.get("vulnerable_outcome"),
            }
            for item in catalog["modules"]
            if item["module_id"] in target_ids
        ],
        key=lambda item: str(item["module_id"]),
    )


def registered_targets() -> list[dict[str, object]]:
    registry = read_json(CONFIG_ROOT / "stage3a-autonomous-target-registry-v2.json")
    originals = [
        {
            "module_id": item["target_id"],
            "target_id": item["target_id"],
            "target_kind": "original-cve",
            "switchable": False,
            "family": "original-cve",
            "cve_id": item["cve_id"],
            "product": item["product"],
            "required_role": None,
            "request": None,
            "secure_outcome": None,
            "vulnerable_outcome": None,
        }
        for item in registry["original_cve_targets"]
    ]
    return sorted(
        [*registered_modules(), *originals], key=lambda item: str(item["target_id"])
    )


def registered_conditions() -> list[str]:
    registry = read_json(CONFIG_ROOT / "stage3a-defense-runtime-registry-v2.json")
    return sorted({"undefended", "proxy-only", *registry.get("conditions", {}).keys()})


def module_record(module_id: str) -> dict[str, object]:
    for item in registered_modules():
        if item["module_id"] == module_id:
            return item
    raise ValueError(f"unknown or unregistered module: {module_id}")


def target_record(target_id: str | None, legacy_module_id: str | None) -> dict[str, object]:
    identifier = target_id or legacy_module_id
    for item in registered_targets():
        if item["target_id"] == identifier or item["module_id"] == identifier:
            return item
    raise ValueError(f"unknown or unregistered target: {identifier}")


def wait_for_stack_and_reset(environment: dict[str, str], timeout: int = 120) -> None:
    port = environment.get("RUBY_CONTROL_PORT", "18081")
    origin = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(f"{origin}/health/live", timeout=2) as response:
                if response.status == 200:
                    break
        except (HTTPError, URLError, TimeoutError) as error:
            last_error = error
        time.sleep(1)
    else:
        raise RuntimeError(f"RUBY control API did not become healthy: {last_error}")

    token = environment.get("RUBY_WEB_RESET_TOKEN", "development-reset-only")
    request = HttpRequest(
        f"{origin}/internal/reset",
        method="POST",
        headers={"X-Ruby-Reset-Token": token},
    )
    try:
        with urlopen(request, timeout=20) as response:
            if response.status != 204:
                raise RuntimeError(f"RUBY reset returned HTTP {response.status}")
    except (HTTPError, URLError, TimeoutError) as error:
        raise RuntimeError(f"RUBY reset failed: {error}") from error


def build_campaign_command(payload: "RunRequest", run_id: str, output: Path) -> list[str]:
    target = target_record(payload.target_id, payload.module_id)
    providers = list(dict.fromkeys(payload.providers))
    conditions = list(dict.fromkeys(payload.conditions))
    if not providers or not set(providers) <= ALLOWED_PROVIDERS:
        raise ValueError("providers must contain codex or claude")
    if not conditions or not set(conditions) <= set(registered_conditions()):
        raise ValueError("one or more defense conditions are not registered")
    if payload.reasoning_effort not in {"medium", "high"}:
        raise ValueError("reasoning_effort must be medium or high")
    limits = {
        "repetitions": (payload.repetitions, 20),
        "max_seconds": (payload.max_seconds, 3600),
        "max_requests": (payload.max_requests, 500),
        "max_decisions": (payload.max_decisions, 200),
        "max_model_calls_per_trial": (payload.max_model_calls_per_trial, 200),
        "max_parallel": (payload.max_parallel, 8),
    }
    for name, (value, maximum) in limits.items():
        if value < 1 or value > maximum:
            raise ValueError(f"{name} must be between 1 and {maximum}")
    trials = len(providers) * len(conditions) * payload.repetitions
    total_calls = trials * payload.max_model_calls_per_trial
    return [
        sys.executable,
        str(APP_ROOT / "tools" / "run_autonomous_campaign_v3.py"),
        "--run-id", run_id,
        "--output-dir", str(output),
        "--targets", str(target["target_id"]),
        "--providers", *providers,
        "--conditions", *conditions,
        "--repetitions", str(payload.repetitions),
        "--max-seconds", str(payload.max_seconds),
        "--max-requests", str(payload.max_requests),
        "--max-decisions", str(payload.max_decisions),
        "--max-model-calls", str(total_calls),
        "--max-model-calls-per-trial", str(payload.max_model_calls_per_trial),
        "--max-parallel", str(payload.max_parallel),
        "--reasoning-effort", payload.reasoning_effort,
    ]


def campaign_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "RUBY_MANAGER_TOKEN",
        "RUBY_MANAGER_COMPOSE_PROJECT",
        "COMPOSE_PROJECT_NAME",
        "RUBY_IMAGE_PREFIX",
        "RUBY_PUBLIC_PORT",
        "RUBY_CONTROL_PORT",
        "RUBY_TEST_PUBLIC_ORIGIN",
        "RUBY_TEST_CONTROL_ORIGIN",
    ):
        environment.pop(name, None)
    return environment


def update_process() -> dict[str, object] | None:
    global active_process, active_run_id, active_log
    if active_process is None or active_run_id is None:
        state = saved_job_state()
        if state is None or state.get("status") not in {
            "starting",
            "running",
            "running-unmanaged",
        }:
            return state
        run_id = state.get("run_id")
        if not isinstance(run_id, str) or not RUN_PATTERN.fullmatch(run_id):
            return state
        summary = EVALUATION_ROOT / run_id / "campaign-summary.json"
        if summary.is_file():
            state.update(
                status="completed",
                completed_at=datetime.now(UTC).isoformat(),
                recovery="campaign-summary-found-after-manager-restart",
            )
            write_json_atomic(JOB_STATE_PATH, state)
        elif process_exists(state.get("pid")):
            state.update(
                status="running-unmanaged",
                recovery="process-still-running-after-manager-restart",
            )
            write_json_atomic(JOB_STATE_PATH, state)
        else:
            state.update(
                status="interrupted",
                completed_at=datetime.now(UTC).isoformat(),
                recovery="process-missing-and-no-campaign-summary",
            )
            write_json_atomic(JOB_STATE_PATH, state)
        return state
    code = active_process.poll()
    saved = saved_job_state()
    result = (
        dict(saved)
        if isinstance(saved, dict) and saved.get("run_id") == active_run_id
        else {"run_id": active_run_id}
    )
    result.update(status="running", pid=active_process.pid)
    if code is not None:
        if active_log is not None:
            active_log.close()
        result.update(status="completed" if code == 0 else "failed", return_code=code)
        result["completed_at"] = datetime.now(UTC).isoformat()
        write_json_atomic(JOB_STATE_PATH, result)
        active_process = None
        active_run_id = None
        active_log = None
    return result


def run_directory(run_id: str) -> Path:
    if not RUN_PATTERN.fullmatch(run_id):
        raise ValueError("invalid manager run id")
    path = (EVALUATION_ROOT / run_id).resolve()
    if path.parent != EVALUATION_ROOT.resolve():
        raise ValueError("run path leaves the evaluation root")
    return path


def run_documents(run_id: str) -> dict[str, object]:
    directory = run_directory(run_id)
    state = saved_job_state()
    known_job = isinstance(state, dict) and state.get("run_id") == run_id
    if not directory.is_dir() and not known_job:
        raise ValueError("run does not exist")
    documents = {}
    for name in (
        "campaign-summary.json", "run-seal.json", "schedule.json",
        "confirmatory-analysis.json", "qualification-analysis.json",
        "runtime-capacity.json", "startup-resource-recovery.json",
    ):
        path = directory / name
        if path.is_file():
            documents[name] = read_json(path)
    log_path = EVALUATION_ROOT / ".manager-logs" / f"{run_id}.log"
    log = ""
    if log_path.is_file():
        data = log_path.read_bytes()
        log = data[-32768:].decode("utf-8", errors="replace")
    return {"run_id": run_id, "documents": documents, "log_tail": log}


class ModuleSelection(BaseModel):
    module_id: str | None = None


class RunRequest(BaseModel):
    target_id: str | None = None
    module_id: str | None = None
    providers: list[str] = Field(default_factory=lambda: ["codex"])
    conditions: list[str] = Field(default_factory=lambda: ["undefended"])
    repetitions: int = 1
    max_seconds: int = 600
    max_requests: int = 50
    max_decisions: int = 20
    max_model_calls_per_trial: int = 20
    max_parallel: int = 1
    reasoning_effort: str = "medium"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    port = os.getenv("RUBY_MANAGER_PORT", "18083")
    print(
        f"RUBY manager URL: http://127.0.0.1:{port}/#token={MANAGER_TOKEN}",
        flush=True,
    )
    yield


app = FastAPI(
    title="RUBY benchmark manager",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "[::1]"],
)


def valid_manager_token(candidate: str | None) -> bool:
    return bool(candidate) and secrets.compare_digest(candidate, MANAGER_TOKEN)


@app.middleware("http")
async def require_loopback_client(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    host = request.client.host if request.client else ""
    try:
        allowed = ip_address(host).is_loopback
    except ValueError:
        allowed = False
    if not allowed:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "benchmark manager accepts loopback clients only"},
        )
    return await call_next(request)


@app.middleware("http")
async def require_manager_token(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    if request.url.path.startswith("/api/") and not valid_manager_token(
        request.headers.get("X-Ruby-Manager-Token")
    ):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "valid benchmark manager token required"},
        )
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


def bad_request(error: Exception) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, str(error))


@app.get("/api/overview")
def overview() -> dict[str, object]:
    stack_environment = manager_stack_environment()
    selection = current_selection_state(stack_environment)
    with lock:
        process = update_process()
    active = (
        process
        if isinstance(process, dict)
        and process.get("status") in {"starting", "running", "running-unmanaged"}
        else None
    )
    return {
        "modules": registered_modules(),
        "targets": registered_targets(),
        "conditions": registered_conditions(),
        "selection": selection,
        "active_job": active,
        "stack": {
            "compose_project": stack_environment["COMPOSE_PROJECT_NAME"],
            "public_origin": (
                "http://127.0.0.1:"
                + stack_environment.get("RUBY_PUBLIC_PORT", "18080")
            ),
            "control_origin": (
                "http://127.0.0.1:"
                + stack_environment.get("RUBY_CONTROL_PORT", "18081")
            ),
        },
    }


@app.post("/api/module-selection")
def select_module(payload: ModuleSelection) -> dict[str, object]:
    try:
        if payload.module_id:
            module_record(payload.module_id)
        with lock:
            current = update_process()
            if active_process is not None or (
                isinstance(current, dict)
                and current.get("status")
                in {"starting", "running", "running-unmanaged"}
            ):
                raise HTTPException(status.HTTP_409_CONFLICT, "cannot switch modules during an experiment")
            trial_id = secrets.token_hex(16)
            env = manager_stack_environment()
            env["RUBY_WEB_TRIAL_ID"] = trial_id or ""
            env["RUBY_WEB_VULNERABILITY_MODULES"] = payload.module_id or ""
            project_exists = ensure_compose_project_owned(env)
            if not project_exists:
                ensure_new_stack_ports_available(env)
            selection_path = EVALUATION_ROOT / ".manager-module-selection.json"
            write_json_atomic(
                selection_path,
                {
                    "mode": "switching",
                    "module_id": payload.module_id,
                    "trial_id": trial_id,
                    "compose_project": env["COMPOSE_PROJECT_NAME"],
                    "changed_at": datetime.now(UTC).isoformat(),
                },
            )
            try:
                build = subprocess.run(
                    compose_command(env, "build"),
                    cwd=APP_ROOT, env=env, capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=1800, check=False,
                )
                if build.returncode:
                    raise RuntimeError((build.stderr or build.stdout)[-2000:])
                result = subprocess.run(
                    compose_command(env, "up", "-d", "--no-build"),
                    cwd=APP_ROOT, env=env, capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=600, check=False,
                )
                if result.returncode:
                    raise RuntimeError((result.stderr or result.stdout)[-2000:])
                wait_for_stack_and_reset(env)
                stack_verification = inspect_active_stack(env)
            except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as error:
                write_json_atomic(
                    selection_path,
                    {
                        "mode": "unknown",
                        "module_id": payload.module_id,
                        "trial_id": trial_id,
                        "compose_project": env["COMPOSE_PROJECT_NAME"],
                        "changed_at": datetime.now(UTC).isoformat(),
                        "error": str(error),
                    },
                )
                raise
            state = {
                "mode": "vulnerable" if payload.module_id else "safe",
                "module_id": payload.module_id, "trial_id": trial_id,
                "compose_project": env["COMPOSE_PROJECT_NAME"],
                "changed_at": datetime.now(UTC).isoformat(),
                "stack_verification": stack_verification,
            }
            write_json_atomic(selection_path, state)
            return state
    except HTTPException:
        raise
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as error:
        raise bad_request(error) from error


@app.post("/api/runs", status_code=status.HTTP_202_ACCEPTED)
def start_run(payload: RunRequest) -> dict[str, object]:
    global active_process, active_run_id, active_log
    try:
        with lock:
            current = update_process()
            if active_process is not None or (
                isinstance(current, dict)
                and current.get("status")
                in {"starting", "running", "running-unmanaged"}
            ):
                raise HTTPException(status.HTTP_409_CONFLICT, "an experiment is already running")
            run_id = datetime.now(UTC).strftime("manager-%Y%m%dT%H%M%SZ-") + secrets.token_hex(4)
            EVALUATION_ROOT.mkdir(exist_ok=True)
            logs = EVALUATION_ROOT / ".manager-logs"
            logs.mkdir(exist_ok=True)
            command = build_campaign_command(payload, run_id, EVALUATION_ROOT / run_id)
            target = target_record(payload.target_id, payload.module_id)
            write_json_atomic(
                JOB_STATE_PATH,
                {
                    "run_id": run_id,
                    "status": "starting",
                    "target_id": target["target_id"],
                    "started_at": datetime.now(UTC).isoformat(),
                },
            )
            try:
                active_log = (logs / f"{run_id}.log").open("wb")
                active_process = subprocess.Popen(
                    command,
                    cwd=APP_ROOT,
                    stdout=active_log,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    env=campaign_environment(),
                )
            except OSError:
                if active_log is not None:
                    active_log.close()
                active_log = None
                write_json_atomic(
                    JOB_STATE_PATH,
                    {
                        "run_id": run_id,
                        "status": "failed",
                        "return_code": None,
                        "completed_at": datetime.now(UTC).isoformat(),
                        "failure_kind": "process-start",
                    },
                )
                raise
            active_run_id = run_id
            state = {
                "run_id": run_id,
                "status": "running",
                "pid": active_process.pid,
                "target_id": target["target_id"],
                "started_at": datetime.now(UTC).isoformat(),
            }
            write_json_atomic(JOB_STATE_PATH, state)
            return state
    except HTTPException:
        raise
    except (OSError, ValueError) as error:
        raise bad_request(error) from error


@app.get("/api/runs")
def runs() -> list[dict[str, object]]:
    with lock:
        process = update_process()
    values = []
    process_run_id = process.get("run_id") if isinstance(process, dict) else None
    if EVALUATION_ROOT.is_dir():
        for directory in EVALUATION_ROOT.iterdir():
            if not directory.is_dir() or not RUN_PATTERN.fullmatch(directory.name):
                continue
            summary_path = directory / "campaign-summary.json"
            summary = read_json(summary_path) if summary_path.is_file() else None
            state = (
                str(process.get("status"))
                if isinstance(process, dict) and process_run_id == directory.name
                else None
            )
            values.append(
                {
                    "run_id": directory.name,
                    "status": state or ("completed" if summary else "incomplete"),
                    "summary": summary,
                }
            )
    if isinstance(process_run_id, str) and not any(
        item["run_id"] == process_run_id for item in values
    ):
        values.append(
            {
                "run_id": process_run_id,
                "status": process.get("status"),
                "summary": None,
            }
        )
    return sorted(values, key=lambda item: item["run_id"], reverse=True)


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str) -> dict[str, object]:
    try:
        return run_documents(run_id)
    except ValueError as error:
        raise bad_request(error) from error


@app.post("/api/runs/{run_id}/drain", status_code=status.HTTP_202_ACCEPTED)
def drain(run_id: str) -> dict[str, object]:
    try:
        directory = run_directory(run_id)
        if not directory.is_dir():
            raise ValueError("run directory does not exist yet")
        (directory / "DRAIN").write_text(datetime.now(UTC).isoformat() + "\n", encoding="utf-8")
        return {"run_id": run_id, "drain_requested": True}
    except ValueError as error:
        raise bad_request(error) from error


@app.get("/")
def index() -> FileResponse:
    return FileResponse(PACKAGE_ROOT / "static" / "index.html")


app.mount("/assets", StaticFiles(directory=PACKAGE_ROOT / "static"), name="assets")
