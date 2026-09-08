from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from uuid import uuid4

from jsonschema import Draft202012Validator

from inline_defense_gateway_v2 import (
    HttpDefenseAdapter,
    InlineDefenseGateway,
    InlineGatewayError,
)


APP_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_ROOT.parent
REGISTRY_PATH = APP_ROOT / "configs" / "stage3a-defense-runtime-registry-v2.json"
REGISTRY_SCHEMA = PROJECT_ROOT / "contracts" / "defense-runtime-registry.schema.json"
DEFENSE_SCHEMA = PROJECT_ROOT / "contracts" / "defense-capability.schema.json"
LIFECYCLE_SCHEMA = PROJECT_ROOT / "contracts" / "attachment-lifecycle.schema.json"
_IMAGE_LOCK = threading.Lock()
_BUILT_SOURCE_DIGESTS: set[str] = set()
CONTROL_RELAY_IMAGE = "ruby-defense-control-relay:1.0.0"


class DefenseRuntimeError(RuntimeError):
    pass


def _repository_root() -> Path:
    for candidate in (PROJECT_ROOT, *PROJECT_ROOT.parents):
        if (candidate / ".git").exists():
            return candidate.resolve()
    return PROJECT_ROOT.resolve()


REPOSITORY_ROOT = _repository_root()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _inside(root: Path, relative: str) -> Path:
    if Path(relative).is_absolute():
        raise DefenseRuntimeError(f"defense path must be relative: {relative}")
    resolved = (root / relative).resolve()
    if resolved != root and root not in resolved.parents:
        raise DefenseRuntimeError(f"defense path escapes its allowed root: {relative}")
    return resolved


def _registry_path(path: Path | str | None = None) -> Path:
    resolved = Path(path or REGISTRY_PATH).expanduser().resolve()
    if resolved != REPOSITORY_ROOT and REPOSITORY_ROOT not in resolved.parents:
        raise DefenseRuntimeError("defense registry must remain inside the repository")
    if not resolved.is_file():
        raise DefenseRuntimeError(f"defense registry is missing: {resolved}")
    return resolved


def _json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DefenseRuntimeError(f"{label} could not be read: {error}") from error
    if not isinstance(value, dict):
        raise DefenseRuntimeError(f"{label} must be a JSON object")
    return value


def _validate(value: dict[str, object], schema_path: Path, label: str) -> None:
    schema = _json(schema_path, f"{label} schema")
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=str)
    if errors:
        path = "/".join(str(item) for item in errors[0].absolute_path)
        suffix = f" at {path}" if path else ""
        raise DefenseRuntimeError(f"{label} validation failed{suffix}: {errors[0].message}")


def load_defense_registry(path: Path | str | None = None) -> tuple[Path, dict[str, object]]:
    selected = _registry_path(path)
    registry = _json(selected, "defense runtime registry")
    _validate(registry, REGISTRY_SCHEMA, "defense runtime registry")
    reserved = sorted(set(registry["conditions"]) & {"undefended", "proxy-only"})
    if reserved:
        raise DefenseRuntimeError(f"defense registry uses reserved conditions: {reserved}")
    return selected, registry


def _scope_root(registration: dict[str, object]) -> Path:
    scope = registration.get("path_scope")
    if scope == "benchmark":
        return PROJECT_ROOT
    if scope == "repository":
        return REPOSITORY_ROOT
    raise DefenseRuntimeError(f"unsupported defense path scope: {scope}")


def _source_files(root: Path, names: list[str]) -> tuple[Path, ...]:
    selected = tuple(_inside(root, name) for name in names)
    missing = [str(path) for path in selected if not path.is_file()]
    if missing:
        raise DefenseRuntimeError(f"defense source files are missing: {missing}")
    return tuple(sorted(set(selected), key=lambda path: path.as_posix()))


def _source_digest(root: Path, files: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(root).as_posix().encode()
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _registration_files(
    registration: dict[str, object],
) -> tuple[Path, Path, Path | None, tuple[Path, ...]]:
    root = _scope_root(registration)
    manifest_path = _inside(root, str(registration["manifest_path"]))
    lifecycle_path = _inside(root, str(registration["lifecycle_path"]))
    model_path = (
        _inside(root, str(registration["model_config_path"]))
        if registration.get("model_config_path")
        else None
    )
    build = registration.get("build")
    source_files: tuple[Path, ...] = ()
    if isinstance(build, dict):
        source_files = _source_files(root, [str(item) for item in build["source_files"]])
    return manifest_path, lifecycle_path, model_path, source_files


def _validated_registration(
    condition: str,
    registry_path: Path | str | None = None,
) -> dict[str, object]:
    selected_registry, registry = load_defense_registry(registry_path)
    registration = registry["conditions"].get(condition)
    if not isinstance(registration, dict):
        raise DefenseRuntimeError(f"unregistered defense condition: {condition}")
    manifest_path, lifecycle_path, model_path, source_files = _registration_files(
        registration
    )
    manifest = _json(manifest_path, "defense capability")
    lifecycle = _json(lifecycle_path, "attachment lifecycle")
    _validate(manifest, DEFENSE_SCHEMA, "defense capability")
    _validate(lifecycle, LIFECYCLE_SCHEMA, "attachment lifecycle")
    if lifecycle["profile"] != "inline-http" or lifecycle["transport"] != "openapi-http":
        raise DefenseRuntimeError("campaign only supports the inline-http OpenAPI lifecycle")
    lifecycle_digest = _digest(lifecycle_path.read_bytes())
    inline = [
        item
        for item in manifest["attachment_contracts"]
        if item["profile"] == "inline-http"
    ]
    if len(inline) != 1 or inline[0]["lifecycle_contract_digest"] != lifecycle_digest:
        raise DefenseRuntimeError("inline lifecycle digest does not match capability manifest")
    actual_source = None
    if source_files:
        actual_source = _source_digest(_scope_root(registration), source_files)
        if manifest["source"]["source_digest"] != actual_source:
            raise DefenseRuntimeError("defense source digest does not match capability manifest")
    model_config = None
    if manifest["model_use"]["enabled"]:
        if model_path is None:
            raise DefenseRuntimeError("model-enabled defense has no registered model config")
        if _digest(model_path.read_bytes()) != manifest["model_use"]["parameter_digest"]:
            raise DefenseRuntimeError("defense model parameter digest does not match")
        model_config = _json(model_path, "defense model config")
        if model_config.get("requested_model_id") != manifest["model_use"].get(
            "requested_model_id"
        ):
            raise DefenseRuntimeError("defense requested model does not match model config")
    return {
        **registration,
        "condition_id": condition,
        "registry_path": selected_registry,
        "manifest": manifest,
        "manifest_path_resolved": manifest_path,
        "manifest_digest": _digest(manifest_path.read_bytes()),
        "lifecycle": lifecycle,
        "lifecycle_path_resolved": lifecycle_path,
        "model_config": model_config,
        "model_config_path_resolved": model_path,
        "source_files_resolved": source_files,
        "source_digest": actual_source or manifest["source"]["source_digest"],
        "request_timeout_seconds": float(lifecycle["timeout_ms"]) / 1000.0,
    }


def _mapped_origin(container_id: str, container_port: int) -> str:
    result = subprocess.run(
        ["docker", "port", container_id, f"{container_port}/tcp"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
    ).stdout.strip()
    match = re.search(r"127\.0\.0\.1:(\d+)$", result, flags=re.MULTILINE)
    if match is None:
        raise DefenseRuntimeError(f"defense container has no loopback mapping: {result}")
    return f"http://127.0.0.1:{match.group(1)}"


def _remove_containers_and_network(
    container_ids: tuple[str | None, ...], network: str | None
) -> None:
    errors: list[str] = []
    for container_id in container_ids:
        if not container_id:
            continue
        result = subprocess.run(
            ["docker", "rm", "-f", container_id],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0 and "No such container" not in result.stderr:
            errors.append(result.stderr.strip() or "container removal failed")
    if network:
        result = subprocess.run(
            ["docker", "network", "rm", network],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0 and "not found" not in result.stderr.lower():
            errors.append(result.stderr.strip() or "network removal failed")
    if errors:
        raise DefenseRuntimeError("; ".join(errors))


def _build_control_relay() -> None:
    context = APP_ROOT / "defense-control-relay"
    files = (context / "Dockerfile", context / "relay.py")
    source_digest = _source_digest(PROJECT_ROOT, files)
    with _IMAGE_LOCK:
        if source_digest in _BUILT_SOURCE_DIGESTS:
            return
        subprocess.run(
            [
                "docker",
                "build",
                "-q",
                "-t",
                CONTROL_RELAY_IMAGE,
                "-f",
                str(context / "Dockerfile"),
                str(context),
            ],
            check=True,
            capture_output=True,
            timeout=300,
        )
        _BUILT_SOURCE_DIGESTS.add(source_digest)


def _start_managed_adapter(
    registration: dict[str, object],
) -> tuple[HttpDefenseAdapter, dict[str, object]]:
    root = _scope_root(registration)
    image = str(registration["image"])
    build = registration.get("build")
    if isinstance(build, dict):
        context = _inside(root, str(build["context"]))
        dockerfile = _inside(context, str(build["dockerfile"]))
        source_digest = str(registration["source_digest"])
        with _IMAGE_LOCK:
            if source_digest not in _BUILT_SOURCE_DIGESTS:
                subprocess.run(
                    ["docker", "build", "-q", "-t", image, "-f", str(dockerfile), str(context)],
                    check=True,
                    capture_output=True,
                    timeout=300,
                )
                _BUILT_SOURCE_DIGESTS.add(source_digest)
    elif re.search(r"@sha256:[a-f0-9]{64}$", image) is None:
        raise DefenseRuntimeError("managed defense image must be digest-pinned")

    limits = registration["resource_limits"]
    name = "ruby-defense-adapter-" + uuid4().hex
    network = None
    container_id = None
    relay_id = None
    try:
        if registration["network_policy"] == "isolated":
            _build_control_relay()
            network = "ruby-defense-net-" + uuid4().hex[:20]
            subprocess.run(
                [
                    "docker",
                    "network",
                    "create",
                    "--internal",
                    "--label",
                    "ruby.benchmark.managed=true",
                    network,
                ],
                check=True,
                capture_output=True,
                timeout=30,
            )
        command = [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "ruby.benchmark.managed=true",
            "--label",
            "ruby.benchmark.kind=defense-adapter",
            "--read-only",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,size={int(limits['tmpfs_mb'])}m",
            "--memory",
            f"{int(limits['memory_mb'])}m",
            "--cpus",
            str(limits["cpus"]),
            "--pids-limit",
            str(limits["pids"]),
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
        ]
        if network is not None:
            command.extend(
                ["--network", network, "--network-alias", "defense-adapter"]
            )
        else:
            command.extend(
                ["-p", f"127.0.0.1::{int(registration['control_port'])}"]
            )
        command.extend(
            [
                "-e",
                f"RUBY_DEFENSE_MANIFEST_DIGEST={registration['manifest_digest']}",
                "-e",
                "RUBY_DEFENSE_UPSTREAM=http://127.0.0.1:1",
            ]
        )
        for name_from_environment in registration.get("secret_env_names", []):
            if name_from_environment in os.environ:
                command.extend(["--env", str(name_from_environment)])
        command.append(image)
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        container_id = result.stdout.strip()
        if network is None:
            control = _mapped_origin(container_id, int(registration["control_port"]))
        else:
            relay_name = "ruby-defense-relay-" + uuid4().hex
            relay = subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    relay_name,
                    "--label",
                    "ruby.benchmark.managed=true",
                    "--label",
                    "ruby.benchmark.kind=defense-control-relay",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=4m",
                    "--memory",
                    "32m",
                    "--cpus",
                    "0.25",
                    "--pids-limit",
                    "32",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "-p",
                    "127.0.0.1::8080",
                    CONTROL_RELAY_IMAGE,
                ],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
            )
            relay_id = relay.stdout.strip()
            subprocess.run(
                ["docker", "network", "connect", network, relay_id],
                check=True,
                capture_output=True,
                timeout=30,
            )
            control = _mapped_origin(relay_id, 8080)
        image_id = subprocess.run(
            ["docker", "inspect", "--format", "{{.Image}}", container_id],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        ).stdout.strip()
        adapter = HttpDefenseAdapter(
            control_origin=control,
            timeout_seconds=2.0,
            close_callback=lambda: _remove_containers_and_network(
                (relay_id, container_id), network
            ),
        )
        return adapter, {
            "defense_image_id": image_id,
            "defense_network_policy": registration["network_policy"],
            "defense_container_id": container_id,
            "defense_control_relay_id": relay_id,
        }
    except Exception:
        try:
            _remove_containers_and_network((relay_id, container_id), network)
        except Exception:
            pass
        raise


def _external_adapter(registration: dict[str, object]) -> HttpDefenseAdapter:
    if registration.get("endpoint"):
        endpoint = str(registration["endpoint"])
    else:
        variable = str(registration["endpoint_env"])
        endpoint = os.getenv(variable, "").strip()
        if not endpoint:
            raise DefenseRuntimeError(f"external defense endpoint variable is missing: {variable}")
    return HttpDefenseAdapter(control_origin=endpoint, timeout_seconds=2.0)


def _wait_for_identity(
    adapter: HttpDefenseAdapter,
    registration: dict[str, object],
) -> None:
    deadline = time.monotonic() + 30
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            health = adapter.health()
            expected = (
                "ready",
                registration["manifest"]["defense_id"],
                registration["manifest"]["defense_version"],
                registration["manifest_digest"],
            )
            observed = (
                health.get("status"),
                health.get("adapter_id"),
                health.get("version"),
                health.get("manifest_digest"),
            )
            if observed != expected:
                raise DefenseRuntimeError(
                    f"defense adapter identity mismatch: expected {expected}, observed {observed}"
                )
            adapter.timeout_seconds = float(registration["request_timeout_seconds"])
            adapter.reset()
            return
        except DefenseRuntimeError:
            raise
        except Exception as error:
            last_error = error
            time.sleep(0.2)
    raise DefenseRuntimeError(f"defense adapter readiness timed out: {last_error}")


def defense_front(
    condition: str,
    registry_path: Path | str | None = None,
):
    if condition == "undefended":
        return None
    if condition == "proxy-only":
        selected_registry, _ = load_defense_registry(registry_path)

        def build_proxy(
            *,
            upstream_origin: str,
            secrets,
            accounts,
            trial_id: str | None = None,
            listen_port: int = 0,
        ) -> InlineDefenseGateway:
            del secrets, accounts
            return InlineDefenseGateway(
                upstream_origin=upstream_origin,
                trial_id=trial_id or uuid4().hex,
                adapter=None,
                identity={
                    "defense_id": "ruby-proxy-only",
                    "defense_version": "2.0.0",
                    "defense_manifest_digest": None,
                    "defense_source_digest": _digest(Path(__file__).read_bytes()),
                    "defense_runtime_driver": "benchmark-inline-gateway",
                    "defense_image_id": None,
                    "defense_registry_digest": _digest(selected_registry.read_bytes()),
                    "defense_model_requested_id": None,
                },
                request_timeout_seconds=30.0,
                listen_port=listen_port,
            )

        return build_proxy

    registration = _validated_registration(condition, registry_path)

    def build(
        *,
        upstream_origin: str,
        secrets,
        accounts,
        trial_id: str | None = None,
        listen_port: int = 0,
    ) -> InlineDefenseGateway:
        del secrets, accounts
        adapter: HttpDefenseAdapter | None = None
        try:
            runtime_identity: dict[str, object] = {}
            if registration["driver"] == "managed-container":
                adapter, runtime_identity = _start_managed_adapter(registration)
            elif registration["driver"] == "external-http":
                adapter = _external_adapter(registration)
            else:
                raise DefenseRuntimeError(
                    f"unsupported defense runtime driver: {registration['driver']}"
                )
            _wait_for_identity(adapter, registration)
            model_use = registration["manifest"]["model_use"]
            return InlineDefenseGateway(
                upstream_origin=upstream_origin,
                trial_id=trial_id or uuid4().hex,
                adapter=adapter,
                identity={
                    "defense_id": registration["manifest"]["defense_id"],
                    "defense_version": registration["manifest"]["defense_version"],
                    "defense_manifest_digest": registration["manifest_digest"],
                    "defense_source_digest": registration["source_digest"],
                    "defense_runtime_driver": registration["driver"],
                    "defense_registry_digest": _digest(
                        registration["registry_path"].read_bytes()
                    ),
                    "defense_model_requested_id": model_use.get("requested_model_id"),
                    **runtime_identity,
                },
                request_timeout_seconds=float(registration["request_timeout_seconds"]),
                listen_port=listen_port,
            )
        except (DefenseRuntimeError, InlineGatewayError):
            if adapter is not None:
                adapter.close()
            raise
        except Exception as error:
            if adapter is not None:
                adapter.close()
            raise DefenseRuntimeError(f"defense startup failed: {error}") from error

    return build


def registered_conditions(
    registry_path: Path | str | None = None,
) -> tuple[str, ...]:
    _, registry = load_defense_registry(registry_path)
    return ("undefended", "proxy-only", *registry["conditions"].keys())


def registered_defense_source_files(
    conditions: list[str] | tuple[str, ...] | None = None,
    registry_path: Path | str | None = None,
) -> tuple[Path, ...]:
    selected_registry, registry = load_defense_registry(registry_path)
    selected_conditions = (
        tuple(registry["conditions"])
        if conditions is None
        else tuple(
            condition
            for condition in conditions
            if condition not in {"undefended", "proxy-only"}
        )
    )
    unknown = sorted(set(selected_conditions) - set(registry["conditions"]))
    if unknown:
        raise DefenseRuntimeError(f"unregistered defense conditions: {unknown}")
    selected: set[Path] = {selected_registry, REGISTRY_SCHEMA}
    for condition in selected_conditions:
        registration = registry["conditions"][condition]
        manifest, lifecycle, model, sources = _registration_files(registration)
        selected.update((manifest, lifecycle, *sources))
        if model is not None:
            selected.add(model)
    return tuple(sorted(selected, key=lambda path: path.as_posix()))


def validate_defense_registry(
    registry_path: Path | str | None = None,
) -> dict[str, object]:
    selected_registry, registry = load_defense_registry(registry_path)
    validated = [
        _validated_registration(condition, selected_registry)
        for condition in registry["conditions"]
    ]
    return {
        "status": "valid",
        "registry": str(selected_registry),
        "registry_digest": _digest(selected_registry.read_bytes()),
        "conditions": [
            {
                "condition_id": item["condition_id"],
                "driver": item["driver"],
                "defense_id": item["manifest"]["defense_id"],
                "defense_version": item["manifest"]["defense_version"],
                "manifest_digest": item["manifest_digest"],
            }
            for item in validated
        ],
    }


__all__ = [
    "DefenseRuntimeError",
    "REGISTRY_PATH",
    "defense_front",
    "load_defense_registry",
    "registered_conditions",
    "registered_defense_source_files",
    "validate_defense_registry",
]
