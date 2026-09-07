from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from uuid import uuid4

from jsonschema import Draft202012Validator


APP_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_ROOT.parent
SOURCE_ROOT = PROJECT_ROOT.parent
REGISTRY_PATH = APP_ROOT / "configs" / "stage3a-defense-runtime-registry-v1.json"
DEFENSE_SCHEMA = PROJECT_ROOT / "contracts" / "defense-capability.schema.json"
LIFECYCLE_SCHEMA = PROJECT_ROOT / "contracts" / "attachment-lifecycle.schema.json"
_IMAGE_LOCK = threading.Lock()
_BUILT_SOURCE_DIGESTS: set[str] = set()


class DefenseRuntimeError(RuntimeError):
    pass


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _inside(root: Path, relative: str) -> Path:
    resolved = (root / relative).resolve()
    if resolved != root and root not in resolved.parents:
        raise DefenseRuntimeError(f"defense path escapes its allowed root: {relative}")
    return resolved


def _defense_component_root() -> Path:
    configured = os.getenv("RUBY_DEFENSE_COMPONENT_ROOT", "").strip()
    if configured:
        candidate = Path(configured).expanduser().resolve()
        if not (candidate / "honeyval-defense" / "src" / "honeyval").is_dir():
            raise DefenseRuntimeError(
                "RUBY_DEFENSE_COMPONENT_ROOT must contain honeyval-defense/src/honeyval"
            )
        return candidate

    candidates = [PROJECT_ROOT.parent]
    candidates.extend(ancestor / "defense" for ancestor in PROJECT_ROOT.parents)
    checked: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in checked:
            continue
        checked.add(resolved)
        if (resolved / "honeyval-defense" / "src" / "honeyval").is_dir():
            return resolved
    raise DefenseRuntimeError(
        "honeyval defense source is missing; expected defense/honeyval-defense "
        "in the repository"
    )


def _registration_source_root(registration: dict[str, object]) -> Path:
    source_root = str(registration.get("source_root", "benchmark-siblings"))
    if source_root == "benchmark-siblings":
        return SOURCE_ROOT
    if source_root == "defense-component":
        return _defense_component_root()
    raise DefenseRuntimeError(f"unsupported defense source root: {source_root}")


def _source_files(root: Path, patterns: list[str]) -> tuple[Path, ...]:
    selected: list[Path] = []
    for pattern in patterns:
        selected.extend(path for path in root.glob(pattern) if path.is_file())
    selected = sorted(set(selected), key=lambda path: path.as_posix())
    if not selected:
        raise DefenseRuntimeError("defense registration selected no source files")
    return tuple(selected)


def _source_digest(root: Path, patterns: list[str]) -> str:
    selected = _source_files(root, patterns)
    digest = hashlib.sha256()
    for path in selected:
        relative = path.relative_to(root).as_posix().encode()
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _validated_registration(condition: str) -> tuple[dict[str, object], dict[str, object]]:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    registration = registry.get("conditions", {}).get(condition)
    if not isinstance(registration, dict):
        raise DefenseRuntimeError(f"unregistered defense condition: {condition}")
    manifest_path = _inside(APP_ROOT, str(registration["manifest_path"]))
    lifecycle_path = _inside(APP_ROOT, str(registration["lifecycle_path"]))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
    for label, value, schema_path in (
        ("defense capability", manifest, DEFENSE_SCHEMA),
        ("attachment lifecycle", lifecycle, LIFECYCLE_SCHEMA),
    ):
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        errors = sorted(Draft202012Validator(schema).iter_errors(value), key=str)
        if errors:
            raise DefenseRuntimeError(f"{label} validation failed: {errors[0].message}")
    lifecycle_digest = _digest(lifecycle_path.read_bytes())
    inline = [
        item
        for item in manifest["attachment_contracts"]
        if item["profile"] == "inline-http"
    ]
    if len(inline) != 1 or inline[0]["lifecycle_contract_digest"] != lifecycle_digest:
        raise DefenseRuntimeError("inline lifecycle digest does not match capability manifest")
    if lifecycle["profile"] != "inline-http" or lifecycle["transport"] != "openapi-http":
        raise DefenseRuntimeError("campaign requires an inline-http OpenAPI lifecycle")
    source_root = _registration_source_root(registration)
    actual_source = _source_digest(source_root, list(registration["source_files"]))
    if manifest["source"]["source_digest"] != actual_source:
        raise DefenseRuntimeError("defense source digest does not match capability manifest")
    model_config = None
    if manifest["model_use"]["enabled"]:
        configured_path = registration.get("model_config_path")
        if not configured_path:
            raise DefenseRuntimeError("model-enabled defense has no registered model config")
        model_config_path = _inside(APP_ROOT, str(configured_path))
        if _digest(model_config_path.read_bytes()) != manifest["model_use"]["parameter_digest"]:
            raise DefenseRuntimeError("defense model parameter digest does not match")
        if manifest["model_use"]["identity_evidence_policy_digest"] != actual_source:
            raise DefenseRuntimeError("defense model identity policy digest does not match source")
        if manifest["model_use"]["prompt_digest"] != actual_source:
            raise DefenseRuntimeError("defense prompt source digest does not match source")
        model_config = json.loads(model_config_path.read_text(encoding="utf-8"))
        if model_config.get("requested_model_id") != manifest["model_use"]["requested_model_id"]:
            raise DefenseRuntimeError("defense requested model does not match model config")
    registration = {
        **registration,
        "manifest": manifest,
        "manifest_digest": _digest(manifest_path.read_bytes()),
        "source_digest": actual_source,
        "source_root_path": source_root,
        "model_config": model_config,
        "request_timeout_seconds": float(lifecycle["timeout_ms"]) / 1000.0,
    }
    return registration, lifecycle


class ContainerDefenseGateway:
    def __init__(
        self,
        *,
        container_id: str,
        origin: str,
        control_origin: str,
        identity: dict[str, object],
    ) -> None:
        self.container_id = container_id
        self.origin = origin
        self.control_origin = control_origin
        self.identity = identity

    def metrics(self) -> dict[str, object]:
        with urllib.request.urlopen(f"{self.control_origin}/v2/metrics", timeout=5) as response:
            return {**json.loads(response.read()), **self.identity}

    def close(self) -> None:
        subprocess.run(
            ["docker", "rm", "-f", self.container_id],
            check=False,
            capture_output=True,
            timeout=30,
        )


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
    match = re.search(r"127\.0\.0\.1:(\d+)$", result)
    if match is None:
        raise DefenseRuntimeError(f"defense container has no loopback mapping: {result}")
    return f"http://127.0.0.1:{match.group(1)}"


def _container_upstream(origin: str) -> str:
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
        "127.0.0.1",
        "localhost",
    }:
        raise DefenseRuntimeError("container defense requires a loopback HTTP target")
    authority = "host.docker.internal"
    if parsed.port is not None:
        authority += f":{parsed.port}"
    return urllib.parse.urlunsplit((parsed.scheme, authority, parsed.path, "", ""))


def _build_container_gateway(
    registration: dict[str, object],
    *,
    upstream_origin: str,
) -> ContainerDefenseGateway:
    context = _inside(APP_ROOT, str(registration["build_context"]))
    dockerfile = _inside(context, str(registration.get("dockerfile", "Dockerfile")))
    image = str(registration["image"])
    source_digest = str(registration["source_digest"])
    with _IMAGE_LOCK:
        if source_digest not in _BUILT_SOURCE_DIGESTS:
            subprocess.run(
                ["docker", "build", "-q", "-t", image, "-f", str(dockerfile), str(context)],
                check=True,
                capture_output=True,
                timeout=180,
            )
            _BUILT_SOURCE_DIGESTS.add(source_digest)
    name = "ruby-defense-" + uuid4().hex
    result = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--add-host",
            "host.docker.internal:host-gateway",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=8m",
            "--memory",
            "128m",
            "--cpus",
            "0.5",
            "--pids-limit",
            "128",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "-p",
            "127.0.0.1::8080",
            "-p",
            "127.0.0.1::8081",
            "-e",
            f"RUBY_DEFENSE_UPSTREAM={_container_upstream(upstream_origin)}",
            "-e",
            f"RUBY_DEFENSE_MANIFEST_DIGEST={registration['manifest_digest']}",
            image,
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    container_id = result.stdout.strip()
    try:
        origin = _mapped_origin(container_id, 8080)
        control = _mapped_origin(container_id, 8081)
        deadline = time.monotonic() + 30
        while True:
            try:
                with urllib.request.urlopen(f"{control}/v2/health", timeout=2) as response:
                    health = json.loads(response.read())
                break
            except Exception as error:
                if time.monotonic() >= deadline:
                    raise DefenseRuntimeError("defense readiness timed out") from error
                time.sleep(0.2)
        manifest = registration["manifest"]
        expected = (
            manifest["defense_id"],
            manifest["defense_version"],
            registration["manifest_digest"],
        )
        observed = (health.get("adapter_id"), health.get("version"), health.get("manifest_digest"))
        if observed != expected:
            raise DefenseRuntimeError(f"defense identity mismatch: expected={expected}, observed={observed}")
        request = urllib.request.Request(f"{control}/v2/reset", data=b"{}", method="POST")
        with urllib.request.urlopen(request, timeout=5) as response:
            if json.loads(response.read()).get("status") != "reset":
                raise DefenseRuntimeError("defense reset contract failed")
        image_id = subprocess.run(
            ["docker", "inspect", image, "--format", "{{.Id}}"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        ).stdout.strip()
        return ContainerDefenseGateway(
            container_id=container_id,
            origin=origin,
            control_origin=control,
            identity={
                "defense_id": manifest["defense_id"],
                "defense_version": manifest["defense_version"],
                "defense_manifest_digest": registration["manifest_digest"],
                "defense_source_digest": registration["source_digest"],
                "defense_runtime_driver": registration["driver"],
                "defense_image_id": image_id,
                "defense_request_timeout_seconds": registration[
                    "request_timeout_seconds"
                ],
            },
        )
    except Exception:
        subprocess.run(["docker", "rm", "-f", container_id], check=False, capture_output=True)
        raise


def defense_front(condition: str):
    if condition == "undefended":
        return None
    registration, _ = _validated_registration(condition)
    driver = str(registration["driver"])

    def build(*, upstream_origin: str, secrets, accounts):
        try:
            if driver == "honeyval-python":
                honeyval_package = (
                    Path(registration["source_root_path"]) / "honeyval-defense" / "src"
                )
                sys.path.insert(0, str(honeyval_package))
                from honeyval.gateway import GatewayConfig, HoneyvalGateway

                protected = [str(item) for item in secrets if item]
                protected.extend(
                    str(item.get("password"))
                    for item in accounts
                    if isinstance(item, dict) and item.get("password")
                )
                gateway = HoneyvalGateway(
                    GatewayConfig(
                        upstream_origin=upstream_origin,
                        ledger_path=Path(tempfile.mkdtemp()) / "defense-ledger.jsonl",
                        account_secrets=protected,
                        enabled=bool(registration.get("enabled")),
                        model_selector=str(registration["model_config"]["model_selector"]),
                        model_effort=str(registration["model_config"]["effort"]),
                        model_timeout=float(
                            registration["model_config"]["request_timeout_seconds"]
                        ),
                        chain_model_timeout=float(
                            registration["model_config"]["chain_timeout_seconds"]
                        ),
                        max_concurrency=int(
                            registration["model_config"]["maximum_concurrency"]
                        ),
                    )
                )
                gateway.load_spec()
                if registration.get("enabled"):
                    gateway.build_chain()
                wrapped = RegisteredDefenseGateway(gateway, registration)
                evidence = wrapped.metrics()
                if registration.get("enabled") and (
                    int(evidence.get("defense_model_failures") or 0) > 0
                    or evidence.get("defense_model_identity_match") is not True
                ):
                    wrapped.close()
                    raise DefenseRuntimeError(
                        "defense model failed or its observed identity did not match"
                    )
                return wrapped
            if driver == "container-reverse-proxy":
                return _build_container_gateway(registration, upstream_origin=upstream_origin)
            raise DefenseRuntimeError(f"unsupported defense runtime driver: {driver}")
        except DefenseRuntimeError:
            raise
        except Exception as error:
            raise DefenseRuntimeError(f"defense startup failed: {error}") from error

    return build


class RegisteredDefenseGateway:
    def __init__(self, gateway, registration: dict[str, object]) -> None:
        self.gateway = gateway
        self.origin = gateway.origin
        manifest = registration["manifest"]
        self.identity = {
            "defense_id": manifest["defense_id"],
            "defense_version": manifest["defense_version"],
            "defense_manifest_digest": registration["manifest_digest"],
            "defense_source_digest": registration["source_digest"],
            "defense_runtime_driver": registration["driver"],
            "defense_image_id": None,
            "defense_request_timeout_seconds": registration[
                "request_timeout_seconds"
            ],
            "defense_model_requested_id": manifest["model_use"].get(
                "requested_model_id"
            ),
            "defense_model_identity_source": "claude-cli-stream-json:modelUsage",
        }

    def metrics(self) -> dict[str, object]:
        raw = dict(self.gateway.metrics())
        observed = list(raw.get("defense_model_ids") or ())
        requested = self.identity["defense_model_requested_id"]
        if not observed:
            identity_match = None
        elif requested == "haiku":
            identity_match = all("haiku" in str(item).lower() for item in observed)
        else:
            identity_match = all(str(item) == str(requested) for item in observed)
        return {
            **raw,
            **self.identity,
            "defense_model_identity_match": identity_match,
        }

    def close(self) -> None:
        self.gateway.close()


def registered_conditions() -> tuple[str, ...]:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    return ("undefended", *registry["conditions"].keys())


def registered_defense_source_files(
    conditions: list[str] | tuple[str, ...] | None = None,
) -> tuple[Path, ...]:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    selected_conditions = (
        tuple(registry["conditions"])
        if conditions is None
        else tuple(condition for condition in conditions if condition != "undefended")
    )
    unknown = sorted(set(selected_conditions) - set(registry["conditions"]))
    if unknown:
        raise DefenseRuntimeError(f"unregistered defense conditions: {unknown}")
    selected: set[Path] = set()
    for condition in selected_conditions:
        registration = registry["conditions"][condition]
        root = _registration_source_root(registration)
        selected.update(_source_files(root, list(registration["source_files"])))
    return tuple(sorted(selected, key=lambda path: path.as_posix()))


__all__ = [
    "DefenseRuntimeError",
    "defense_front",
    "registered_conditions",
    "registered_defense_source_files",
]
