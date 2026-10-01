from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from jsonschema import Draft202012Validator

from autonomous_cve_target_adapters_v3 import PREPARE_CVE_TARGETS
from defense_runtime_v1 import defense_front


APP_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_ROOT.parent
POLICY_PATH = APP_ROOT / "configs" / "runtime-isolation-policy-v1.json"
POLICY_SCHEMA_PATH = PROJECT_ROOT / "contracts" / "runtime-isolation-policy.schema.json"
CANARY_PORTS = (2375, 5432, 8000, 8080)
COMPOSE_CONTRACTS = {
    "cve-original:CVE-2024-23897": (APP_ROOT / "cve-jenkins" / "compose.yaml", "target", ("relay",)),
    "cve-original:CVE-2024-36401": (APP_ROOT / "cve-geoserver" / "compose.yaml", "target", ("relay",)),
    "cve-original:CVE-2024-42009": (APP_ROOT / "cve-roundcube" / "compose.yaml", "roundcube", ("mail", "relay")),
    "cve-original:CVE-2025-3248": (APP_ROOT / "cve-langflow" / "compose.yaml", "target", ("relay",)),
    "cve-original:CVE-2026-54433": (APP_ROOT / "cve-roundcube" / "compose.yaml", "roundcube", ("mail", "relay")),
}


def docker(*arguments: str, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load_policy(path: Path) -> dict[str, object]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads(POLICY_SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(policy), key=str)
    if errors:
        location = "/".join(str(item) for item in errors[0].absolute_path)
        raise ValueError(f"isolation policy is invalid at {location}: {errors[0].message}")
    ids = [item["target_id"] for item in policy["original_cve_targets"]]
    if len(ids) != len(set(ids)):
        raise ValueError("isolation policy contains duplicate target IDs")
    if set(ids) != set(PREPARE_CVE_TARGETS):
        raise ValueError("isolation policy and autonomous CVE registry do not cover the same targets")
    return policy


def yaml_mapping_block(text: str, key: str, indent: int) -> str:
    lines = text.splitlines()
    marker = " " * indent + key + ":"
    for index, line in enumerate(lines):
        if line.rstrip() != marker:
            continue
        selected = [line]
        for following in lines[index + 1 :]:
            if not following.strip():
                selected.append(following)
                continue
            following_indent = len(following) - len(following.lstrip(" "))
            if following_indent <= indent:
                break
            selected.append(following)
        return "\n".join(selected)
    raise ValueError(f"YAML mapping key is missing: {key}")


def static_compose_contracts(policy: dict[str, object]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for specification in policy["original_cve_targets"]:
        target_id = str(specification["target_id"])
        path, primary_service, auxiliary_services = COMPOSE_CONTRACTS[target_id]
        text = path.read_text(encoding="utf-8")
        primary = yaml_mapping_block(text, primary_service, 2)
        target_network = yaml_mapping_block(yaml_mapping_block(text, "networks", 0), "target", 2)
        allowed = list(specification["allowed_cap_add"])
        expected_cap_add = "cap_add: [" + ", ".join(allowed) + "]" if allowed else None
        checks = {
            "target_capabilities_dropped": "cap_drop: [ALL]" in primary,
            "target_capability_additions_exact": (
                expected_cap_add in primary if expected_cap_add else "cap_add:" not in primary
            ),
            "target_no_new_privileges": "security_opt: [no-new-privileges:true]" in primary,
            "target_memory_limit": "mem_limit:" in primary,
            "target_cpu_limit": "cpus:" in primary,
            "target_pid_limit": "pids_limit:" in primary,
            "target_internal_network_only": "networks: [target]" in primary,
            "target_has_no_ports": "\n    ports:" not in primary,
            "target_has_no_bind_mounts": "\n    volumes:" not in primary,
            "target_not_privileged": "privileged: true" not in primary.lower(),
            "target_no_docker_socket": "docker.sock" not in primary.lower(),
            "target_network_is_internal": "internal: true" in target_network,
        }
        auxiliary: list[dict[str, object]] = []
        for service in auxiliary_services:
            block = yaml_mapping_block(text, service, 2)
            service_checks = {
                "capabilities_dropped": "cap_drop: [ALL]" in block,
                "no_new_privileges": "security_opt: [no-new-privileges:true]" in block,
                "memory_limit": "mem_limit:" in block,
                "cpu_limit": "cpus:" in block,
                "pid_limit": "pids_limit:" in block,
                "no_docker_socket": "docker.sock" not in block.lower(),
                "not_privileged": "privileged: true" not in block.lower(),
            }
            if service == "relay":
                service_checks.update(
                    {
                        "read_only_root": "read_only: true" in block,
                        "loopback_publish": '"127.0.0.1:${' in block,
                        "target_and_browser_networks": "networks: [target, browser]" in block,
                        "bind_mounts_read_only": all(
                            line.strip().endswith(":ro")
                            for line in block.splitlines()
                            if ":/" in line and line.lstrip().startswith("-")
                        ),
                    }
                )
            else:
                service_checks.update(
                    {
                        "internal_network_only": "networks: [target]" in block,
                        "no_published_ports": "\n    ports:" not in block,
                    }
                )
            auxiliary.append(
                {
                    "service": service,
                    "checks": service_checks,
                    "passed": all(service_checks.values()),
                }
            )
        results.append(
            {
                "target_id": target_id,
                "compose_path": str(path.relative_to(PROJECT_ROOT)),
                "checks": checks,
                "auxiliary_services": auxiliary,
                "passed": all(checks.values()) and all(item["passed"] for item in auxiliary),
            }
        )
    return results


def inspect_container(container_id: str) -> dict[str, object]:
    result = json.loads(docker("inspect", container_id).stdout)
    if len(result) != 1:
        raise RuntimeError(f"unexpected inspect result for {container_id}")
    return result[0]


def network_inspect(name: str) -> dict[str, object]:
    result = json.loads(docker("network", "inspect", name).stdout)
    if len(result) != 1:
        raise RuntimeError(f"unexpected network inspect result for {name}")
    return result[0]


def project_container_ids(project: str) -> list[str]:
    return [
        item
        for item in docker(
            "ps",
            "-a",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ).stdout.splitlines()
        if item
    ]


def project_resources(project: str) -> dict[str, list[str]]:
    commands = {
        "containers": ("ps", "-a", "-q"),
        "networks": ("network", "ls", "-q"),
        "volumes": ("volume", "ls", "-q"),
    }
    return {
        kind: [
            item
            for item in docker(
                *command,
                "--filter",
                f"label=com.docker.compose.project={project}",
            ).stdout.splitlines()
            if item
        ]
        for kind, command in commands.items()
    }


def managed_resource_ids() -> dict[str, list[str]]:
    return {
        "containers": sorted(
            item
            for item in docker(
                "ps", "-a", "-q", "--filter", "label=ruby.benchmark.managed=true"
            ).stdout.splitlines()
            if item
        ),
        "networks": sorted(
            item
            for item in docker(
                "network", "ls", "-q", "--filter", "label=ruby.benchmark.managed=true"
            ).stdout.splitlines()
            if item
        ),
    }


def start_canary(image: str, run_id: str) -> tuple[str, str, str]:
    network = f"ruby-isolation-canary-{run_id[:12]}"
    name = f"ruby-isolation-canary-{run_id[:12]}"
    docker(
        "network",
        "create",
        "--internal",
        "--label",
        f"ruby.benchmark.isolation-gate={run_id}",
        network,
    )
    script = (
        "import socket,threading,time;"
        f"ports={CANARY_PORTS!r};"
        "listeners=[];"
        "[(lambda s,p:(s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1),"
        "s.bind(('0.0.0.0',p)),s.listen(),listeners.append(s),"
        "threading.Thread(target=lambda: [s.accept()[0].close() for _ in iter(int,1)],daemon=True).start()))"
        "(socket.socket(),p) for p in ports];"
        "time.sleep(3600)"
    )
    command = [
        "run",
        "-d",
        "--name",
        name,
        "--label",
        f"ruby.benchmark.isolation-gate={run_id}",
        "--network",
        network,
    ]
    for alias in ("api", "control-api", "evaluator", "postgres", "other-target", "docker"):
        command.extend(["--network-alias", alias])
    command.extend(
        [
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=8m",
            "--memory",
            "128m",
            "--cpus",
            "0.5",
            "--pids-limit",
            "64",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            image,
            "python",
            "-B",
            "-c",
            script,
        ]
    )
    container_id = docker(*command).stdout.strip()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        info = inspect_container(container_id)
        if info["State"]["Running"]:
            networks = info["NetworkSettings"]["Networks"]
            address = next(str(item["IPAddress"]) for item in networks.values())
            if address:
                return container_id, network, address
        time.sleep(0.2)
    raise RuntimeError("isolation canary did not start")


def cleanup_canary(container_id: str | None, network: str | None) -> None:
    if container_id:
        docker("rm", "-f", container_id, check=False)
    if network:
        docker("network", "rm", network, check=False)


PROBE_PROGRAM = r'''
import base64
import concurrent.futures
import json
import socket
import sys
from pathlib import Path

payload = json.loads(base64.b64decode(sys.argv[1]))

def resolve(name):
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(name, None)})
        return {"name": name, "resolved": True, "addresses": addresses}
    except OSError as error:
        return {"name": name, "resolved": False, "error_type": type(error).__name__}

def connect(endpoint):
    try:
        connection = socket.create_connection(
            (endpoint["host"], int(endpoint["port"])), timeout=0.8
        )
        connection.close()
        return {**endpoint, "connected": True}
    except OSError as error:
        return {**endpoint, "connected": False, "error_type": type(error).__name__}

with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
    dns = list(executor.map(resolve, payload["dns_names"]))
    connections = list(executor.map(connect, payload["endpoints"]))

ipv4_default = False
route = Path("/proc/net/route")
if route.exists():
    for line in route.read_text(encoding="ascii", errors="replace").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 2:
            ipv4_default = True

ipv6_default = False
route6 = Path("/proc/net/ipv6_route")
if route6.exists():
    for line in route6.read_text(encoding="ascii", errors="replace").splitlines():
        fields = line.split()
        if (
            len(fields) >= 10
            and fields[0] == "0" * 32
            and fields[1] == "00"
            and fields[5].lower() != "ffffffff"
            and fields[9] != "lo"
        ):
            ipv6_default = True

print(json.dumps({
    "dns": dns,
    "connections": connections,
    "ipv4_default_route": ipv4_default,
    "ipv6_default_route": ipv6_default,
}, sort_keys=True))
'''


def network_probe(
    container_id: str,
    *,
    policy: dict[str, object],
    canary_ip: str,
    gateway_ips: list[str],
) -> dict[str, object]:
    endpoints: list[dict[str, object]] = [
        {"label": "dns-api", "host": "api", "port": 8000},
        {"label": "dns-control-api", "host": "control-api", "port": 8000},
        {"label": "dns-evaluator", "host": "evaluator", "port": 8000},
        {"label": "dns-postgres", "host": "postgres", "port": 5432},
        {"label": "dns-other-target", "host": "other-target", "port": 8080},
        {"label": "dns-docker", "host": "docker", "port": 2375},
        {"label": "host-docker-web", "host": "host.docker.internal", "port": 18080},
        {"label": "host-docker-control", "host": "host.docker.internal", "port": 18081},
        {"label": "host-docker-api", "host": "host.docker.internal", "port": 2375},
        {"label": "gateway-docker-api", "host": "gateway.docker.internal", "port": 2375},
    ]
    endpoints.extend(dict(item) for item in policy["direct_network_probes"])
    for port in CANARY_PORTS:
        endpoints.append(
            {"label": f"separate-network-canary-{port}", "host": canary_ip, "port": port}
        )
    for gateway in sorted(set(item for item in gateway_ips if item)):
        for port in (18080, 18081, 2375, 2376):
            endpoints.append(
                {"label": f"bridge-gateway-{port}", "host": gateway, "port": port}
            )
    payload = {
        "dns_names": policy["forbidden_dns_names"],
        "endpoints": endpoints,
    }
    encoded = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    result = docker(
        "run",
        "--rm",
        "--network",
        f"container:{container_id}",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=8m",
        "--memory",
        "128m",
        "--cpus",
        "0.5",
        "--pids-limit",
        "64",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        str(policy["probe_image"]),
        "python",
        "-B",
        "-c",
        PROBE_PROGRAM,
        encoded,
        timeout=90,
    )
    observation = json.loads(result.stdout.strip())
    checks = {
        "no_ipv4_default_route": observation["ipv4_default_route"] is False,
        "no_ipv6_default_route": observation["ipv6_default_route"] is False,
        "forbidden_names_unresolved": not any(item["resolved"] for item in observation["dns"]),
        "forbidden_tcp_connections_failed": not any(
            item["connected"] for item in observation["connections"]
        ),
    }
    return {"observation": observation, "checks": checks, "passed": all(checks.values())}


def security_observation(
    info: dict[str, object],
    *,
    allowed_cap_add: list[str],
    maximum_pids: int,
    require_read_only: bool,
    require_pinned_image: bool,
    require_no_ports: bool,
    require_internal_networks: bool,
) -> dict[str, object]:
    host = info["HostConfig"]
    config = info["Config"]
    mounts = info.get("Mounts") or []
    networks = info["NetworkSettings"]["Networks"]
    network_details = {
        name: network_inspect(name)
        for name in networks
    }
    cap_add = sorted(
        str(item).upper().removeprefix("CAP_") for item in host.get("CapAdd") or []
    )
    cap_drop = [str(item).upper() for item in host.get("CapDrop") or []]
    security_opt = [str(item).lower() for item in host.get("SecurityOpt") or []]
    port_bindings = host.get("PortBindings") or {}
    bind_specs = host.get("Binds") or []
    checks = {
        "not_privileged": host.get("Privileged") is False,
        "all_capabilities_dropped": "ALL" in cap_drop,
        "capability_additions_allowlisted": cap_add == sorted(allowed_cap_add),
        "no_new_privileges": "no-new-privileges:true" in security_opt,
        "pid_limit": 0 < int(host.get("PidsLimit") or 0) <= maximum_pids,
        "memory_limit": int(host.get("Memory") or 0) > 0,
        "cpu_limit": int(host.get("NanoCpus") or 0) > 0,
        "no_host_namespace": all(
            str(host.get(name) or "") not in {"host", "container:host"}
            for name in ("NetworkMode", "PidMode", "IpcMode", "UTSMode")
        ),
        "no_host_device": not bool(host.get("Devices")),
        "no_host_bind_mount": not any(item.get("Type") == "bind" for item in mounts),
        "no_docker_socket": not any(
            "docker.sock" in str(item).lower()
            for item in (*bind_specs, *[item.get("Source", "") for item in mounts])
        ),
        "no_published_ports": (not port_bindings) if require_no_ports else True,
        "read_only_root": bool(host.get("ReadonlyRootfs")) if require_read_only else True,
        "image_digest_pinned": (
            "@sha256:" in str(config.get("Image", "")) if require_pinned_image else True
        ),
        "networks_internal": (
            bool(networks)
            and all(bool(item.get("Internal")) for item in network_details.values())
            if require_internal_networks
            else True
        ),
    }
    return {
        "container_id": str(info["Id"]),
        "service": (config.get("Labels") or {}).get("com.docker.compose.service"),
        "image_id": str(info["Image"]),
        "configured_image": str(config.get("Image", "")),
        "cap_add": cap_add,
        "cap_drop": cap_drop,
        "pids_limit": host.get("PidsLimit"),
        "memory_bytes": host.get("Memory"),
        "nano_cpus": host.get("NanoCpus"),
        "network_names": sorted(networks),
        "network_internal": {
            name: bool(item.get("Internal")) for name, item in network_details.items()
        },
        "checks": checks,
        "passed": all(checks.values()),
    }


def project_boundary_observations(project: str, target_container_id: str) -> dict[str, object]:
    containers = [inspect_container(item) for item in project_container_ids(project)]
    observations: list[dict[str, object]] = []
    checks: dict[str, bool] = {}
    target_networks = set(
        inspect_container(target_container_id)["NetworkSettings"]["Networks"]
    )
    for info in containers:
        host = info["HostConfig"]
        config = info["Config"]
        labels = config.get("Labels") or {}
        service = str(labels.get("com.docker.compose.service", ""))
        bindings = host.get("PortBindings") or {}
        bind_specs = host.get("Binds") or []
        networks = set(info["NetworkSettings"]["Networks"])
        service_checks = {
            "not_privileged": host.get("Privileged") is False,
            "all_capabilities_dropped": "ALL" in [
                str(item).upper() for item in host.get("CapDrop") or []
            ],
            "no_new_privileges": "no-new-privileges:true" in [
                str(item).lower() for item in host.get("SecurityOpt") or []
            ],
            "resource_limits": (
                int(host.get("PidsLimit") or 0) > 0
                and int(host.get("Memory") or 0) > 0
                and int(host.get("NanoCpus") or 0) > 0
            ),
            "no_docker_socket": not any("docker.sock" in str(item).lower() for item in bind_specs),
            "bind_mounts_read_only": all(str(item).endswith(":ro") for item in bind_specs),
            "only_relay_publishes": (service == "relay") if bindings else True,
            "published_ports_loopback": all(
                binding.get("HostIp") == "127.0.0.1"
                for values in bindings.values()
                for binding in values or []
            ),
            "target_network_shared_only_inside_project": bool(networks & target_networks),
        }
        observations.append(
            {
                "container_id": str(info["Id"]),
                "service": service,
                "network_names": sorted(networks),
                "published_ports": bindings,
                "bind_mounts": public_bind_mounts(bind_specs),
                "checks": service_checks,
                "passed": all(service_checks.values()),
            }
        )
        checks[f"service_{service}_hardened"] = all(service_checks.values())
    checks["target_uses_one_internal_project_network"] = (
        len(target_networks) == 1
        and all(bool(network_inspect(name).get("Internal")) for name in target_networks)
    )
    return {"services": observations, "checks": checks, "passed": all(checks.values())}


def public_bind_mounts(bind_specs: list[object]) -> list[dict[str, str]]:
    """Keep the container target and mode without publishing host paths."""
    rows: list[dict[str, str]] = []
    for bind in bind_specs:
        parts = str(bind).rsplit(":", 2)
        if len(parts) == 3:
            rows.append({"target": parts[1], "mode": parts[2]})
        else:
            rows.append({"target": "unparsed", "mode": "unknown"})
    return rows


def gateway_addresses(info: dict[str, object]) -> list[str]:
    return sorted(
        {
            str(item.get("Gateway", ""))
            for item in info["NetworkSettings"]["Networks"].values()
            if item.get("Gateway")
        }
    )


def run_target(
    specification: dict[str, object],
    release: str,
    *,
    policy: dict[str, object],
    canary_ip: str,
) -> dict[str, object]:
    target_id = str(specification["target_id"])
    trial_id = uuid4().hex
    prepared = None
    project = None
    result: dict[str, object] = {
        "target_id": target_id,
        "release": release,
        "trial_id": trial_id,
    }
    try:
        prepared = PREPARE_CVE_TARGETS[target_id](trial_id, 8312026, release_name=release)
        project = prepared.project
        container_id = str(prepared.executor.container_id)
        info = inspect_container(container_id)
        security = security_observation(
            info,
            allowed_cap_add=list(specification["allowed_cap_add"]),
            maximum_pids=int(policy["maximum_pids"]),
            require_read_only=False,
            require_pinned_image=True,
            require_no_ports=True,
            require_internal_networks=True,
        )
        boundary = project_boundary_observations(project, container_id)
        probe = network_probe(
            container_id,
            policy=policy,
            canary_ip=canary_ip,
            gateway_ips=gateway_addresses(info),
        )
        result.update(
            {
                "project": project,
                "normal_traffic": prepared.normal_traffic,
                "security": security,
                "project_boundary": boundary,
                "network_probe": probe,
            }
        )
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if prepared is not None:
            try:
                prepared.close()
            except Exception as error:
                result["cleanup_error"] = f"{type(error).__name__}: {error}"
        if project is not None:
            residue = project_resources(project)
            result["cleanup_residue"] = residue
            result["cleanup_passed"] = not any(residue.values())
        else:
            result["cleanup_residue"] = None
            result["cleanup_passed"] = False
    result["passed"] = (
        "error" not in result
        and "cleanup_error" not in result
        and result.get("cleanup_passed") is True
        and result.get("security", {}).get("passed") is True
        and result.get("project_boundary", {}).get("passed") is True
        and result.get("network_probe", {}).get("passed") is True
    )
    return result


def run_defense(
    specification: dict[str, object],
    *,
    policy: dict[str, object],
    canary_ip: str,
) -> dict[str, object]:
    condition = str(specification["condition_id"])
    before = managed_resource_ids()
    gateway = None
    result: dict[str, object] = {"condition_id": condition}
    try:
        builder = defense_front(condition)
        if builder is None:
            raise RuntimeError("managed defense did not return a runtime builder")
        gateway = builder(
            upstream_origin="http://127.0.0.1:18080",
            secrets=[],
            accounts=[],
            trial_id=uuid4().hex,
            listen_port=0,
        )
        container_ids = [
            str(gateway.identity[key])
            for key in ("defense_container_id", "defense_control_relay_id")
            if gateway.identity.get(key)
        ]
        observations = []
        adapter_id = str(gateway.identity["defense_container_id"])
        adapter_networks = set(
            inspect_container(adapter_id)["NetworkSettings"]["Networks"]
        )
        for container_id in container_ids:
            info = inspect_container(container_id)
            is_adapter = container_id == adapter_id
            observation = security_observation(
                info,
                allowed_cap_add=list(specification["allowed_cap_add"]),
                maximum_pids=int(policy["maximum_pids"]),
                require_read_only=bool(specification["require_read_only"]),
                require_pinned_image=False,
                require_no_ports=is_adapter,
                require_internal_networks=is_adapter,
            )
            if not is_adapter:
                bindings = info["HostConfig"].get("PortBindings") or {}
                relay_networks = set(info["NetworkSettings"]["Networks"])
                observation["checks"]["relay_port_is_loopback_only"] = bool(bindings) and all(
                    binding.get("HostIp") == "127.0.0.1"
                    for values in bindings.values()
                    for binding in values or []
                )
                observation["checks"]["relay_reaches_adapter_internal_network"] = bool(
                    relay_networks & adapter_networks
                )
                observation["passed"] = all(observation["checks"].values())
            observations.append(observation)
        adapter_info = inspect_container(adapter_id)
        probe = network_probe(
            adapter_id,
            policy=policy,
            canary_ip=canary_ip,
            gateway_ips=gateway_addresses(adapter_info),
        )
        result.update(
            {
                "identity": {
                    key: value
                    for key, value in gateway.identity.items()
                    if key not in {"defense_container_id", "defense_control_relay_id"}
                },
                "containers": observations,
                "network_probe": probe,
            }
        )
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if gateway is not None:
            try:
                gateway.close()
            except Exception as error:
                result["cleanup_error"] = f"{type(error).__name__}: {error}"
        after = managed_resource_ids()
        result["cleanup_residue"] = {
            kind: sorted(set(after[kind]) - set(before[kind])) for kind in after
        }
        result["cleanup_passed"] = before == after
    result["passed"] = (
        "error" not in result
        and "cleanup_error" not in result
        and result.get("cleanup_passed") is True
        and bool(result.get("containers"))
        and all(item["passed"] for item in result.get("containers", []))
        and result.get("network_probe", {}).get("passed") is True
    )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the common Docker isolation gate for original CVE targets and managed defenses."
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    parser.add_argument("--targets", nargs="*")
    parser.add_argument(
        "--releases", nargs="+", choices=("vulnerable", "fixed"), default=("vulnerable", "fixed")
    )
    parser.add_argument("--skip-defenses", action="store_true")
    return parser.parse_args()


def gate_checks(
    *,
    static_results: list[dict[str, object]],
    target_results: list[dict[str, object]],
    defense_results: list[dict[str, object]],
    expected_target_runs: int,
    skip_defenses: bool,
    canary_cleanup: bool,
) -> dict[str, bool | None]:
    return {
        "all_compose_contracts_passed": all(
            item["passed"] for item in static_results
        ),
        "all_selected_target_releases_executed": (
            len(target_results) == expected_target_runs
        ),
        "all_target_runs_passed": bool(target_results)
        and all(item["passed"] for item in target_results),
        "managed_defenses_executed": not skip_defenses,
        "all_managed_defenses_passed": (
            None
            if skip_defenses
            else bool(defense_results)
            and all(item["passed"] for item in defense_results)
        ),
        "canary_resources_removed": canary_cleanup,
    }


def required_checks_passed(
    checks: dict[str, bool | None], *, skip_defenses: bool
) -> bool:
    required = [
        "all_compose_contracts_passed",
        "all_selected_target_releases_executed",
        "all_target_runs_passed",
        "canary_resources_removed",
    ]
    if not skip_defenses:
        required.extend(
            ["managed_defenses_executed", "all_managed_defenses_passed"]
        )
    return all(checks[name] is True for name in required)


def main() -> int:
    args = parse_args()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite isolation report: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    policy_path = args.policy.resolve()
    policy = load_policy(policy_path)
    static_results = static_compose_contracts(policy)
    selected = set(args.targets or [item["target_id"] for item in policy["original_cve_targets"]])
    unknown = sorted(selected - set(PREPARE_CVE_TARGETS))
    if unknown:
        raise ValueError(f"unknown isolation targets: {unknown}")
    run_id = uuid4().hex
    canary_id = None
    canary_network = None
    target_results: list[dict[str, object]] = []
    defense_results: list[dict[str, object]] = []
    canary_cleanup = False
    try:
        canary_id, canary_network, canary_ip = start_canary(str(policy["probe_image"]), run_id)
        for specification in policy["original_cve_targets"]:
            if specification["target_id"] not in selected:
                continue
            for release in specification["releases"]:
                if release not in args.releases:
                    continue
                print(f"isolation target start: {specification['target_id']} {release}", flush=True)
                result = run_target(
                    specification,
                    release,
                    policy=policy,
                    canary_ip=canary_ip,
                )
                target_results.append(result)
                print(
                    f"isolation target finish: {specification['target_id']} {release} passed={result['passed']}",
                    flush=True,
                )
        if not args.skip_defenses:
            for specification in policy["managed_defenses"]:
                print(f"isolation defense start: {specification['condition_id']}", flush=True)
                result = run_defense(specification, policy=policy, canary_ip=canary_ip)
                defense_results.append(result)
                print(
                    f"isolation defense finish: {specification['condition_id']} passed={result['passed']}",
                    flush=True,
                )
    finally:
        cleanup_canary(canary_id, canary_network)
        remaining = docker(
            "ps",
            "-a",
            "-q",
            "--filter",
            f"label=ruby.benchmark.isolation-gate={run_id}",
        ).stdout.splitlines()
        remaining_networks = docker(
            "network",
            "ls",
            "-q",
            "--filter",
            f"label=ruby.benchmark.isolation-gate={run_id}",
        ).stdout.splitlines()
        canary_cleanup = not remaining and not remaining_networks

    expected_target_runs = sum(
        1
        for item in policy["original_cve_targets"]
        if item["target_id"] in selected
        for release in item["releases"]
        if release in args.releases
    )
    checks = gate_checks(
        static_results=static_results,
        target_results=target_results,
        defense_results=defense_results,
        expected_target_runs=expected_target_runs,
        skip_defenses=args.skip_defenses,
        canary_cleanup=canary_cleanup,
    )
    report = {
        "report_version": 2,
        "generated_at": datetime.now(UTC).isoformat(),
        "run_id": run_id,
        "policy_path": str(policy_path.relative_to(PROJECT_ROOT)),
        "policy_sha256": sha256_bytes(policy_path.read_bytes()),
        "probe_image": policy["probe_image"],
        "static_compose_results": static_results,
        "docker_server_version": docker("version", "--format", "{{.Server.Version}}").stdout.strip(),
        "target_results": target_results,
        "defense_results": defense_results,
        "checks": checks,
        "passed": required_checks_passed(
            checks, skip_defenses=args.skip_defenses
        ),
    }
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output), "passed": report["passed"]}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
