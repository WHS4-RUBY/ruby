from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import FIRST_COMPLETED, wait
from datetime import UTC, datetime
from pathlib import Path

from autonomous_cli_policy_v2 import SubscriptionCLIPolicy
from autonomous_cve_target_adapters_v3 import CVE_ACTION_SCHEMA, PREPARE_CVE_TARGETS
from autonomous_target_adapters_v2 import prepare_isolated_ruby_target
from defense_runtime_v1 import (
    REGISTRY_PATH as DEFAULT_DEFENSE_REGISTRY_PATH,
    defense_front,
    registered_conditions,
    registered_defense_source_files,
)
from autonomous_trial_v2 import (
    ACTION_SCHEMA,
    ModelCallBudgetExceeded,
    run_autonomous_trial,
)


APP_ROOT = Path(__file__).resolve().parents[1]

# 방어 구현은 별도 패키지에 있다. 무방어 조건에서는 불러오지 않는다.
REGISTRY_PATH = APP_ROOT / "configs" / "stage3a-autonomous-target-registry-v2.json"
SCOPE_PATH = APP_ROOT / "configs" / "stage3a-autonomous-baseline-scope-v1.json"
PROFILE_PATH = APP_ROOT / "configs" / "stage3a-autonomous-web-attacker-profile-v10.json"
CAMPAIGN_LOCK_PATH = APP_ROOT / "evaluation" / ".autonomous-campaign.lock"
ORPHAN_MARKER_PATH = APP_ROOT / "evaluation" / "last-orphan-termination.json"
# Measured isolated stacks peaked at about 349 MiB for RUBY and 769 MiB for
# GeoServer on 2026-08-31. Reserves include space for the subscription CLI.
TRIAL_MEMORY_RESERVE_BYTES = 640 * 1024**2
HOST_MEMORY_HEADROOM_BYTES = 512 * 1024**2
PROVIDER_PARALLEL_LIMIT = 4
SETUP_ADAPTER_MEMORY_RESERVES = {
    "ephemeral-account-pool": TRIAL_MEMORY_RESERVE_BYTES,
    "password-reset-victim": TRIAL_MEMORY_RESERVE_BYTES,
    "support-ticket-and-accounts": TRIAL_MEMORY_RESERVE_BYTES,
    "seller-document-browser": TRIAL_MEMORY_RESERVE_BYTES,
    "csrf-admin-victim": TRIAL_MEMORY_RESERVE_BYTES,
    "paid-order": TRIAL_MEMORY_RESERVE_BYTES,
    "inventory-race-state": TRIAL_MEMORY_RESERVE_BYTES,
    "administrator-reset-victim": TRIAL_MEMORY_RESERVE_BYTES,
    "archive-upload-state": TRIAL_MEMORY_RESERVE_BYTES,
    "cross-shop-paid-order": TRIAL_MEMORY_RESERVE_BYTES,
    "remembered-admin-victim": TRIAL_MEMORY_RESERVE_BYTES,
    "support-ticket-browser": TRIAL_MEMORY_RESERVE_BYTES,
    "jenkins-isolated-product": 768 * 1024**2,
    "roundcube-isolated-product": 768 * 1024**2,
    "geoserver-isolated-product": 1024**3,
    "langflow-isolated-product": 3 * 1024**3,
}
BASE_SEALED_INPUTS = (
    REGISTRY_PATH,
    # 피해자 루프와 방어 구현도 결과를 만든다. 봉인에 없으면 그것들이
    # 바뀌어도 재개 검사를 통과하고, 한 실행 묶음에 다른 피해자 동작이나
    # 다른 방어 판본의 결과가 섞인다.
    APP_ROOT / "tools" / "victim_browser.py",
    SCOPE_PATH,
    ACTION_SCHEMA,
    CVE_ACTION_SCHEMA,
    APP_ROOT / "configs" / "stage3-vulnerability-module-catalog-v1.json",
    APP_ROOT / "configs" / "stage3a-normal-traffic-v1.json",
    APP_ROOT / "configs" / "stage3-cve-jenkins-2024-23897-v1.json",
    APP_ROOT / "configs" / "stage3a-cve-geoserver-2024-36401-v1.json",
    APP_ROOT / "configs" / "stage3a-cve-roundcube-2024-42009-v1.json",
    APP_ROOT / "configs" / "stage3a-cve-roundcube-2026-54433-v1.json",
    APP_ROOT / "configs" / "stage3a-cve-langflow-2025-3248-v1.json",
    APP_ROOT / "configs" / "stage3a-cve-http-relay-v1.json",
    APP_ROOT / "cve-jenkins" / "compose.yaml",
    APP_ROOT / "cve-geoserver" / "compose.yaml",
    APP_ROOT / "cve-roundcube" / "compose.yaml",
    APP_ROOT / "cve-langflow" / "compose.yaml",
    APP_ROOT / "cve-http-relay.nginx.conf",
    APP_ROOT / "cve-langflow-relay.nginx.conf",
    APP_ROOT.parent / "contracts" / "defense-adapter.openapi.yaml",
    APP_ROOT.parent / "contracts" / "defense-capability.schema.json",
    APP_ROOT.parent / "contracts" / "attachment-lifecycle.schema.json",
    APP_ROOT.parent / "contracts" / "defense-runtime-registry.schema.json",
    APP_ROOT / "compose.yaml",
    Path(__file__).resolve(),
    APP_ROOT / "tools" / "autonomous_cli_policy_v2.py",
    APP_ROOT / "tools" / "autonomous_cve_target_adapters_v3.py",
    APP_ROOT / "tools" / "autonomous_target_adapters_v2.py",
    APP_ROOT / "tools" / "autonomous_trial_v2.py",
    APP_ROOT / "tools" / "attacker_strategy_v11.py",
    APP_ROOT / "tools" / "autonomous_experiment_v2.py",
    APP_ROOT / "tools" / "defense_runtime_v1.py",
    APP_ROOT / "tools" / "inline_defense_gateway_v2.py",
    APP_ROOT / "defense-control-relay" / "Dockerfile",
    APP_ROOT / "defense-control-relay" / "relay.py",
)


def _profile_inputs(profile_path: Path) -> tuple[Path, Path]:
    resolved = profile_path.resolve()
    profile = json.loads(resolved.read_text(encoding="utf-8"))
    guide = (resolved.parent / str(profile.get("instruction_document", ""))).resolve()
    repository_root = APP_ROOT.parent.resolve()
    if repository_root not in guide.parents:
        raise ValueError("attacker instruction document must remain inside the repository")
    if not guide.is_file():
        raise FileNotFoundError(f"attacker instruction document is missing: {guide}")
    return resolved, guide
RUBY_IMAGE_REFERENCES = (
    "ruby-web-defense-benchmark-api:latest",
    "ruby-web-defense-benchmark-postgres:latest",
    "ruby-web-defense-benchmark-web:latest",
    "ruby-web-defense-benchmark-worker:latest",
    "ruby-web-defense-benchmark-mock-integration:latest",
    "ruby-web-defense-benchmark-evaluator:latest",
    "ruby-web-defense-benchmark-object-store:latest",
    "ruby-web-defense-benchmark-redis:latest",
)
TERMINAL_STATUSES = {
    "objective-achieved",
    "attack-failed",
    "budget-exhausted",
    "model-error",
    "runner-error",
    "isolation-error",
    "verifier-error",
    "invalid-defense-error",
}


class CampaignProcessLock:
    """Prevent two autonomous campaigns from sharing the Docker address pool."""

    def __init__(self, path: Path, *, run_id: str) -> None:
        self.path = path
        self.run_id = run_id
        self._handle = None

    def __enter__(self) -> "CampaignProcessLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            handle.close()
            try:
                owner = self.path.read_text(
                    encoding="utf-8", errors="replace"
                ).strip("\0\n")
            except OSError:
                owner = "locked owner metadata is unavailable on this platform"
            raise RuntimeError(
                f"another autonomous campaign holds the process lock: {owner or 'unknown'}"
            ) from error
        handle.seek(0)
        handle.truncate()
        handle.write(
            (
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "run_id": self.run_id,
                        "locked_at": datetime.now(UTC).isoformat(),
                    },
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
        )
        handle.flush()
        os.fsync(handle.fileno())
        self._handle = handle
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._handle is None:
            return
        self._handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        self._handle.close()
        self._handle = None


def _managed_docker_projects() -> tuple[str, ...]:
    pattern = re.compile(
        r"(?:ruby-autonomous|ruby-auto-(?:jenkins|geoserver|roundcube|langflow))-[a-f0-9]{32}"
    )
    projects: set[str] = set()
    queries = (
        ["docker", "ps", "-a", "--format", '{{.Label "com.docker.compose.project"}}'],
        ["docker", "network", "ls", "--format", '{{.Label "com.docker.compose.project"}}'],
        ["docker", "volume", "ls", "--format", '{{.Label "com.docker.compose.project"}}'],
    )
    for query in queries:
        output = subprocess.run(
            query,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        ).stdout.splitlines()
        projects.update(value for value in output if pattern.fullmatch(value))
    return tuple(sorted(projects))


def _reconcile_managed_docker_projects() -> tuple[str, ...]:
    projects = _managed_docker_projects()
    for project in projects:
        _remove_abandoned_project(project)
    return projects


def _windows_process_info(pid: int) -> tuple[str, int] | None:
    if os.name != "nt":
        return None
    script = (
        f"$p=Get-CimInstance Win32_Process -Filter 'ProcessId={pid}';"
        "if($null -eq $p){exit 3};"
        "Write-Output ($p.Name + '|' + $p.ParentProcessId)"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
    )
    if result.returncode != 0 or "|" not in result.stdout:
        return None
    name, parent = result.stdout.strip().rsplit("|", 1)
    return name.lower(), int(parent)


def _launcher_shell_pid() -> int | None:
    if os.name != "nt":
        return None
    current = os.getpid()
    for _ in range(6):
        info = _windows_process_info(current)
        if info is None:
            return None
        name, parent = info
        if name not in {"python.exe", "pythonw.exe"}:
            return current
        if parent <= 0 or parent == current:
            return None
        current = parent
    return None


def _start_launcher_watchdog(
    *, run_id: str, launcher_pid: int | None = None
) -> threading.Thread | None:
    launcher_pid = launcher_pid if launcher_pid is not None else _launcher_shell_pid()
    if launcher_pid is None:
        return None

    def watch() -> None:
        import ctypes

        synchronize = 0x00100000
        infinite = 0xFFFFFFFF
        handle = ctypes.windll.kernel32.OpenProcess(synchronize, False, launcher_pid)
        if handle:
            try:
                result = ctypes.windll.kernel32.WaitForSingleObject(handle, infinite)
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
            if result != 0:
                return
        try:
            _write_atomic(
                ORPHAN_MARKER_PATH,
                {
                    "run_id": run_id,
                    "campaign_pid": os.getpid(),
                    "launcher_pid": launcher_pid,
                    "detected_at": datetime.now(UTC).isoformat(),
                    "action": "terminated_campaign_process_tree",
                },
            )
        finally:
            subprocess.run(
                ["taskkill", "/PID", str(os.getpid()), "/T", "/F"],
                check=False,
                capture_output=True,
                timeout=20,
            )

    thread = threading.Thread(
        target=watch,
        name=f"campaign-launcher-watchdog-{run_id}",
        daemon=True,
    )
    thread.start()
    return thread


def _available_memory_bytes() -> int:
    if os.name == "nt":
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB",
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        return int(result.stdout.strip())
    page_size = os.sysconf("SC_PAGE_SIZE")
    available_pages = os.sysconf("SC_AVPHYS_PAGES")
    return int(page_size * available_pages)


def _defense_front(condition: str, defense_registry: Path | None = None):
    """Load and validate the registered defense before attaching it."""
    return defense_front(condition, defense_registry)

def _validate_runtime_capacity(maximum_parallel_trials: int) -> dict[str, int]:
    available = _available_memory_bytes()
    minimum_required = HOST_MEMORY_HEADROOM_BYTES + TRIAL_MEMORY_RESERVE_BYTES
    if available < minimum_required:
        raise RuntimeError(
            "insufficient free memory for one isolated trial: "
            f"available={available}, required={minimum_required}, "
            f"max_parallel={maximum_parallel_trials}"
        )
    usable = available - HOST_MEMORY_HEADROOM_BYTES
    memory_parallel_limit = max(1, usable // TRIAL_MEMORY_RESERVE_BYTES)
    return {
        "available_memory_bytes": available,
        "required_memory_bytes": minimum_required,
        "full_requested_memory_bytes": (
            HOST_MEMORY_HEADROOM_BYTES
            + maximum_parallel_trials * TRIAL_MEMORY_RESERVE_BYTES
        ),
        "usable_trial_memory_bytes": usable,
        "host_headroom_bytes": HOST_MEMORY_HEADROOM_BYTES,
        "per_trial_reserve_bytes": TRIAL_MEMORY_RESERVE_BYTES,
        "maximum_parallel_trials": maximum_parallel_trials,
        "memory_parallel_limit": min(
            maximum_parallel_trials, int(memory_parallel_limit)
        ),
    }


def _trial_memory_reserve_bytes(
    row: dict[str, object], registry: dict[str, dict[str, object]]
) -> int:
    target = registry[str(row["target_id"])]
    adapter = str(target.get("setup_adapter", ""))
    return SETUP_ADAPTER_MEMORY_RESERVES.get(adapter, 1024**3)


def _schedulable_pending_index(
    pending: list[dict[str, object]],
    *,
    registry: dict[str, dict[str, object]],
    reserved_memory_bytes: int,
    usable_memory_bytes: int,
    provider_counts: dict[str, int],
) -> int | None:
    for index, row in enumerate(pending):
        provider = str(row["provider"])
        if provider_counts.get(provider, 0) >= PROVIDER_PARALLEL_LIMIT:
            continue
        reserve = _trial_memory_reserve_bytes(row, registry)
        if reserved_memory_bytes + reserve <= usable_memory_bytes:
            return index
    return None


class CampaignModelCallBudget:
    def __init__(
        self,
        maximum: int,
        used: int = 0,
        *,
        ledger_path: Path | None = None,
    ) -> None:
        if maximum < 1 or not 0 <= used <= maximum:
            raise ValueError("invalid campaign model-call budget")
        self.maximum = maximum
        self.used = used
        self.ledger_path = ledger_path
        self._lock = threading.Lock()
        if ledger_path is not None:
            ledger_path.parent.mkdir(parents=True, exist_ok=True)
            if ledger_path.exists():
                records = [
                    json.loads(line)
                    for line in ledger_path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                indexes = [int(item["call_index"]) for item in records]
                if indexes != list(range(1, len(records) + 1)):
                    raise ValueError("campaign model-call ledger is not contiguous")
                if used not in (0, len(records)):
                    raise ValueError("campaign model-call ledger count mismatch")
                self.used = len(records)
            else:
                ledger_path.touch(exist_ok=False)

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self.used >= self.maximum

    def reserve(
        self, *, trial_key: str | None = None, provider: str | None = None
    ) -> int:
        with self._lock:
            if self.used >= self.maximum:
                raise ModelCallBudgetExceeded("campaign model-call budget exhausted")
            next_index = self.used + 1
            if self.ledger_path is not None:
                record = {
                    "call_index": next_index,
                    "provider": provider,
                    "reserved_at": datetime.now(UTC).isoformat(),
                    "trial_key": trial_key,
                }
                with self.ledger_path.open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            self.used = next_index
            return self.used


class BudgetedPolicy:
    def __init__(
        self,
        policy: SubscriptionCLIPolicy,
        budget: CampaignModelCallBudget,
        maximum_trial_calls: int,
        *,
        trial_key: str | None = None,
        provider: str | None = None,
    ) -> None:
        if maximum_trial_calls < 1:
            raise ValueError("trial model-call budget must be positive")
        self.policy = policy
        self.budget = budget
        self.maximum_trial_calls = maximum_trial_calls
        self.trial_key = trial_key
        self.provider = provider
        self.trial_calls = 0
        self._lock = threading.Lock()

    def __call__(self, payload: dict[str, object]) -> dict[str, object]:
        with self._lock:
            if self.trial_calls >= self.maximum_trial_calls:
                raise ModelCallBudgetExceeded(
                    "trial model-call budget exhausted", scope="trial"
                )
            self.trial_calls += 1
        try:
            self.budget.reserve(trial_key=self.trial_key, provider=self.provider)
        except Exception:
            with self._lock:
                self.trial_calls -= 1
            raise
        return self.policy(payload)

    def __getattr__(self, name: str):
        return getattr(self.policy, name)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _cli_versions(providers: list[str]) -> dict[str, str]:
    commands = {"codex": "codex.cmd", "claude": "claude.exe"}
    versions: dict[str, str] = {}
    for provider in providers:
        executable = shutil.which(commands[provider])
        if executable is None:
            raise FileNotFoundError(f"subscription CLI is unavailable: {provider}")
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            timeout=20,
        )
        versions[provider] = (result.stdout or result.stderr).strip()
    return versions


def _ruby_image_ids() -> dict[str, dict[str, object]]:
    sealed: dict[str, dict[str, object]] = {}
    for reference in RUBY_IMAGE_REFERENCES:
        result = subprocess.run(
            ["docker", "image", "inspect", reference],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            timeout=30,
        )
        values = json.loads(result.stdout)
        if len(values) != 1:
            raise RuntimeError(f"Docker image reference is ambiguous: {reference}")
        image = values[0]
        sealed[reference] = {
            "id": image["Id"],
            "repo_digests": sorted(image.get("RepoDigests") or []),
        }
    return sealed


def _write_atomic(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _safe(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-")


def _runtime_identifier(run_id: str, trial_key: str) -> str:
    return hashlib.sha256(f"{run_id}:{trial_key}".encode("utf-8")).hexdigest()[:32]


def _project_for_row(run_id: str, row: dict[str, object]) -> str:
    runtime_id = _runtime_identifier(run_id, str(row["trial_key"]))
    if row["target_kind"] == "ruby-web":
        return f"ruby-autonomous-{runtime_id}"
    products = {
        "cve-original:CVE-2024-23897": "jenkins",
        "cve-original:CVE-2024-36401": "geoserver",
        "cve-original:CVE-2024-42009": "roundcube",
        "cve-original:CVE-2025-3248": "langflow",
        "cve-original:CVE-2026-54433": "roundcube",
    }
    try:
        product = products[str(row["target_id"])]
    except KeyError as error:
        raise ValueError(f"cannot derive project for target: {row['target_id']}") from error
    return f"ruby-auto-{product}-{runtime_id}"


def _remove_abandoned_project(project: str) -> None:
    if re.fullmatch(
        r"(?:ruby-autonomous|ruby-auto-(?:jenkins|geoserver|roundcube|langflow))-[a-f0-9]{32}",
        project,
    ) is None:
        raise ValueError("refusing to remove an unexpected Docker project")
    commands = (
        ("containers", ["docker", "ps", "-a", "-q"], ["docker", "rm", "-f"]),
        ("networks", ["docker", "network", "ls", "-q"], ["docker", "network", "rm"]),
        ("volumes", ["docker", "volume", "ls", "-q"], ["docker", "volume", "rm"]),
    )
    for resource, query, remove in commands:
        values = subprocess.run(
            query + ["--filter", f"label=com.docker.compose.project={project}"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        ).stdout.splitlines()
        if values:
            subprocess.run(
                remove + values,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
        remaining = subprocess.run(
            query + ["--filter", f"label=com.docker.compose.project={project}"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        ).stdout.splitlines()
        if remaining:
            raise RuntimeError(
                f"abandoned {resource} remain for project {project}: {remaining}"
            )


def _recover_running_trials(
    *,
    run_id: str,
    schedule: list[dict[str, object]],
    trials_dir: Path,
    attempts_dir: Path,
) -> None:
    rows = {str(row["trial_key"]): row for row in schedule}
    for running_path in sorted(trials_dir.glob("*.running.json")):
        value = json.loads(running_path.read_text(encoding="utf-8"))
        trial_key = str(value.get("trial_key", ""))
        if trial_key not in rows:
            raise ValueError(f"running trial is not in sealed schedule: {running_path}")
        _remove_abandoned_project(_project_for_row(run_id, rows[trial_key]))
        attempts_dir.mkdir(exist_ok=True)
        attempt = 1
        while any(
            (
                attempts_dir / f"{trial_key}-abandoned-{attempt:03d}{suffix}"
            ).exists()
            for suffix in (".running.json", ".checkpoint.json")
        ):
            attempt += 1
        running_path.replace(
            attempts_dir / f"{trial_key}-abandoned-{attempt:03d}.running.json"
        )
        checkpoint_path = trials_dir / f"{trial_key}.checkpoint.json"
        if checkpoint_path.exists():
            checkpoint_path.replace(
                attempts_dir / f"{trial_key}-abandoned-{attempt:03d}.checkpoint.json"
            )


def _registry() -> dict[str, dict[str, object]]:
    value = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    result: dict[str, dict[str, object]] = {}
    for item in value["ruby_web_targets"]:
        result[str(item["target_id"])] = {**item, "target_kind": "ruby-web"}
    for item in value["original_cve_targets"]:
        result[str(item["target_id"])] = {**item, "target_kind": "original-cve"}
    return result


def _schedule(
    targets: list[str],
    registry: dict[str, dict[str, object]],
    providers: list[str],
    repetitions: int,
    seed: int,
    variants: list[dict[str, object]] | None = None,
    conditions: list[str] | None = None,
) -> list[dict[str, object]]:
    # 조건이 여럿이면 비교다. 조건을 행에 넣고 함께 섞어야 조건 순서가 결과에
    # 실려 오지 않는다. 조건이 하나면 아무것도 달라지지 않는다.
    conditions = list(conditions or ["undefended"])
    if variants is not None:
        if len(variants) != repetitions:
            raise ValueError("variant manifest must have exactly one row per repetition")
        indexes = [int(item.get("repetition", -1)) for item in variants]
        if indexes != list(range(repetitions)):
            raise ValueError("variant repetitions must be contiguous and ordered from zero")
    def variant(repetition: int) -> dict[str, object]:
        if variants is None:
            return {"normal_traffic_seed": seed + repetition}
        item = variants[repetition]
        prefix = str(item.get("public_api_prefix", ""))
        if re.fullmatch(r"/[a-z][a-z0-9-]{2,20}", prefix) is None:
            raise ValueError(f"invalid public API prefix for repetition {repetition}")
        return {
            "normal_traffic_seed": int(item["normal_traffic_seed"]),
            "public_api_prefix": prefix,
            "variant_id": str(item["variant_id"]),
        }
    rows = [
        {
            "target_id": target_id,
            "target_kind": registry[target_id]["target_kind"],
            "provider": provider,
            "repetition": repetition,
            "condition": condition,
            **variant(repetition),
        }
        for repetition in range(repetitions)
        for target_id in targets
        for provider in providers
        for condition in conditions
    ]
    randomizer = random.Random(seed)
    ruby_rows = [item for item in rows if item["target_kind"] == "ruby-web"]
    cve_rows = [item for item in rows if item["target_kind"] == "original-cve"]
    randomizer.shuffle(ruby_rows)
    randomizer.shuffle(cve_rows)
    rows = ruby_rows + cve_rows
    for index, row in enumerate(rows):
        row["pair_id"] = hashlib.sha256(
            json.dumps(
                {
                    "target_id": row["target_id"],
                    "provider": row["provider"],
                    "repetition": row["repetition"],
                    "normal_traffic_seed": row["normal_traffic_seed"],
                    "variant_id": row.get("variant_id"),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()[:32]
        row["order"] = index
        # 조건이 하나뿐인 실행에서는 열쇠 모양을 바꾸지 않는다. 비교 실행에서만
        # 조건을 넣어 같은 대상의 세 팔이 서로 다른 이름을 갖게 한다.
        condition_part = (
            f"{_safe(str(row['condition']))}-" if len(conditions) > 1 else ""
        )
        row["trial_key"] = (
            f"{index:04d}-{_safe(str(row['provider']))}-"
            f"{_safe(str(row['target_id']))}-"
            f"{condition_part}r{int(row['repetition']) + 1}"
        )
    return rows


def _archive_for_retry(
    result_path: Path, attempts_dir: Path, trial_key: str
) -> None:
    attempts_dir.mkdir(exist_ok=True)
    attempt = 1
    while (attempts_dir / f"{trial_key}-attempt-{attempt:03d}.json").exists():
        attempt += 1
    result_path.replace(attempts_dir / f"{trial_key}-attempt-{attempt:03d}.json")


def _run_one(
    *,
    row: dict[str, object],
    registry: dict[str, dict[str, object]],
    args: argparse.Namespace,
    trials_dir: Path,
    model_call_budget: CampaignModelCallBudget,
) -> dict[str, object]:
    target_id = str(row["target_id"])
    target = registry[target_id]
    result_path = trials_dir / f"{row['trial_key']}.json"
    running_path = result_path.with_suffix(".running.json")
    checkpoint_path = result_path.with_suffix(".checkpoint.json")
    _write_atomic(
        running_path,
        {
            "run_id": args.run_id,
            "trial_key": row["trial_key"],
            "started_at": datetime.now(UTC).isoformat(),
        },
    )
    if target["target_kind"] == "ruby-web":
        module_id = str(target["module_id"])
        schema_path = ACTION_SCHEMA
        prepare = lambda runtime_id, seed: prepare_isolated_ruby_target(
            module_id,
            runtime_id,
            seed,
            public_api_prefix=(
                str(row["public_api_prefix"])
                if "public_api_prefix" in row
                else None
            ),
            account_namespace=str(row["pair_id"]),
        )
    else:
        schema_path = CVE_ACTION_SCHEMA
        prepare = PREPARE_CVE_TARGETS[target_id]
    policy = BudgetedPolicy(
        SubscriptionCLIPolicy(
            str(row["provider"]),
            schema_path=schema_path,
            reasoning_effort=args.reasoning_effort,
        ),
        model_call_budget,
        args.max_model_calls_per_trial,
        trial_key=str(row["trial_key"]),
        provider=str(row["provider"]),
    )
    report = run_autonomous_trial(
        condition=str(row.get("condition", "undefended")),
        defense_front=_defense_front(
            str(row.get("condition", "undefended")), args.defense_registry
        ),
        target_id=target_id,
        target_kind=str(target["target_kind"]),
        prepare_target=prepare,
        policy=policy,
        normal_traffic_seed=int(row["normal_traffic_seed"]),
        trial_id=f"{args.run_id}:{row['trial_key']}",
        action_schema_path=schema_path,
        attacker_profile_path=args.attacker_profile,
        max_seconds=args.max_seconds,
        max_active_requests=args.max_requests,
        max_decisions=args.max_decisions,
        progress_callback=lambda checkpoint: _write_atomic(
            checkpoint_path,
            {
                **checkpoint,
                "run_id": args.run_id,
                "trial_key": row["trial_key"],
                "provider": row["provider"],
                "repetition": row["repetition"],
                "checkpointed_at": datetime.now(UTC).isoformat(),
            },
        ),
    )
    report.update(
        {
            "run_id": args.run_id,
            "trial_key": row["trial_key"],
            "provider": row["provider"],
            "repetition": row["repetition"],
            "condition": row.get("condition", "undefended"),
            "pair_id": row["pair_id"],
            "finished_at": datetime.now(UTC).isoformat(),
        }
    )
    _write_atomic(result_path, report)
    checkpoint_path.unlink(missing_ok=True)
    running_path.unlink(missing_ok=True)
    return report


def run_campaign(args: argparse.Namespace) -> dict[str, object]:
    profile_path, guide_path = _profile_inputs(
        getattr(args, "attacker_profile", PROFILE_PATH)
    )
    args.attacker_profile = profile_path
    recovered_projects = _reconcile_managed_docker_projects()
    registry = _registry()
    targets = args.targets or list(registry)
    unknown = sorted(set(targets) - set(registry))
    if unknown:
        raise ValueError(f"unregistered targets: {unknown}")
    if len(targets) != len(set(targets)):
        raise ValueError("target list contains duplicates")
    # 준비 함수가 없는 표적이 일정에 들어가면 그 순서에 닿았을 때 캠페인 전체가
    # 죽는다. 등록부에 이름만 있고 어댑터가 없는 경우가 실제로 있었다. 시작할 때
    # 걸러 몇 시간 뒤가 아니라 지금 알게 한다.
    unprepared = sorted(
        target_id
        for target_id in targets
        if registry[target_id]["target_kind"] == "original-cve"
        and target_id not in PREPARE_CVE_TARGETS
    )
    if unprepared:
        raise ValueError(
            "these targets are registered but have no prepare adapter, so a run "
            f"would fail when it reached them: {unprepared}"
        )
    variant_manifest_path = getattr(args, "variant_manifest", None)
    variants = None
    if variant_manifest_path is not None:
        variant_manifest_path = Path(variant_manifest_path).resolve()
        variant_document = json.loads(variant_manifest_path.read_text(encoding="utf-8"))
        variants = variant_document.get("variants")
        if not isinstance(variants, list):
            raise ValueError("variant manifest has no variants list")
    conditions = list(getattr(args, "conditions", None) or ["undefended"])
    args.defense_registry = Path(
        getattr(args, "defense_registry", DEFAULT_DEFENSE_REGISTRY_PATH)
    ).resolve()
    available_conditions = set(registered_conditions(args.defense_registry))
    unknown_conditions = sorted(set(conditions) - available_conditions)
    if unknown_conditions:
        raise ValueError(f"unregistered defense conditions: {unknown_conditions}")
    defense_source_inputs = registered_defense_source_files(
        conditions, args.defense_registry
    )
    schedule = _schedule(
        targets,
        registry,
        args.providers,
        args.repetitions,
        args.seed,
        variants=variants,
        conditions=conditions,
    )
    seal = {
        "seal_version": 1,
        "run_id": args.run_id,
        "targets": targets,
        "providers": args.providers,
        "conditions": conditions,
        "defense_registry": os.path.relpath(
            Path(args.defense_registry).resolve(), APP_ROOT
        ).replace("\\", "/"),
        "repetitions": args.repetitions,
        "schedule_seed": args.seed,
        "maximum_parallel_trials": args.max_parallel,
        "reasoning_effort": args.reasoning_effort,
        "parallel_policy": (
            "isolated target-weighted memory reservations, provider concurrency at most "
            f"{PROVIDER_PARALLEL_LIMIT}, total at most max_parallel"
        ),
        "cli_versions": _cli_versions(args.providers),
        "ruby_image_ids": _ruby_image_ids(),
        "limits": {
            "wall_clock_seconds": args.max_seconds,
            "active_http_requests": args.max_requests,
            "agent_decisions": args.max_decisions,
            "campaign_model_calls": args.max_model_calls,
            "model_calls_per_trial": args.max_model_calls_per_trial,
        },
        "sealed_inputs": {
            os.path.relpath(path, APP_ROOT).replace("\\", "/"): _digest(path)
            for path in BASE_SEALED_INPUTS
            + defense_source_inputs
            + (profile_path, guide_path)
            + ((variant_manifest_path,) if variant_manifest_path is not None else ())
        },
    }
    output_dir: Path = args.output_dir
    trials_dir = output_dir / "trials"
    attempts_dir = output_dir / "attempts"
    seal_path = output_dir / "run-seal.json"
    if output_dir.exists():
        if not args.resume:
            raise FileExistsError(f"output directory already exists: {output_dir}")
        if json.loads(seal_path.read_text(encoding="utf-8")) != seal:
            raise ValueError("resume seal does not match current arguments or inputs")
    else:
        if args.resume:
            raise FileNotFoundError("resume output directory does not exist")
        output_dir.mkdir(parents=True)
        trials_dir.mkdir()
        _write_atomic(seal_path, seal)
        _write_atomic(output_dir / "schedule.json", schedule)

    _write_atomic(
        output_dir / "startup-resource-recovery.json",
        {
            "recovered_projects": list(recovered_projects),
            "recovered_at": datetime.now(UTC).isoformat(),
        },
    )
    capacity_evidence = getattr(args, "runtime_capacity_evidence", None)
    if capacity_evidence is not None:
        _write_atomic(output_dir / "runtime-capacity.json", capacity_evidence)

    if args.resume:
        _recover_running_trials(
            run_id=args.run_id,
            schedule=schedule,
            trials_dir=trials_dir,
            attempts_dir=attempts_dir,
        )

    pending: list[dict[str, object]] = []
    for row in schedule:
        result_path = trials_dir / f"{row['trial_key']}.json"
        if result_path.is_file():
            existing = json.loads(result_path.read_text(encoding="utf-8"))
            if existing.get("status") not in TERMINAL_STATUSES:
                raise ValueError(f"non-terminal stored trial: {result_path}")
            if existing.get("status") not in set(args.retry_status):
                continue
            _archive_for_retry(result_path, attempts_dir, str(row["trial_key"]))
        pending.append(row)

    stored_model_calls = 0
    for path in list(trials_dir.glob("*.json")) + list(attempts_dir.glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        stored_model_calls += int(value.get("metrics", {}).get("model_calls", 0))
    ledger_path = output_dir / "model-call-ledger.jsonl"
    model_call_budget = CampaignModelCallBudget(
        args.max_model_calls,
        ledger_path=ledger_path,
    )
    if model_call_budget.used < stored_model_calls:
        raise ValueError(
            "model-call ledger contains fewer reservations than stored trial reports"
        )
    capacity = getattr(args, "runtime_capacity_evidence", None)
    usable_memory_bytes = (
        int(capacity["usable_trial_memory_bytes"])
        if capacity is not None
        else args.max_parallel * 1024**3
    )
    with ThreadPoolExecutor(max_workers=args.max_parallel) as pool:
        futures: dict[object, tuple[dict[str, object], int]] = {}
        reserved_memory_bytes = 0
        provider_counts: dict[str, int] = {}
        automatic_drain_reason: str | None = None

        def submit_available() -> None:
            nonlocal reserved_memory_bytes
            while (
                pending
                and len(futures) < args.max_parallel
                and not model_call_budget.exhausted
                and automatic_drain_reason is None
                and not (output_dir / "DRAIN").is_file()
            ):
                index = _schedulable_pending_index(
                    pending,
                    registry=registry,
                    reserved_memory_bytes=reserved_memory_bytes,
                    usable_memory_bytes=usable_memory_bytes,
                    provider_counts=provider_counts,
                )
                if index is None:
                    break
                row = pending.pop(index)
                reserve = _trial_memory_reserve_bytes(row, registry)
                future = pool.submit(
                    _run_one,
                    row=row,
                    registry=registry,
                    args=args,
                    trials_dir=trials_dir,
                    model_call_budget=model_call_budget,
                )
                futures[future] = (row, reserve)
                reserved_memory_bytes += reserve
                provider = str(row["provider"])
                provider_counts[provider] = provider_counts.get(provider, 0) + 1

        submit_available()
        while futures:
            done, _ = wait(set(futures), return_when=FIRST_COMPLETED)
            for future in done:
                row, reserve = futures.pop(future)
                reserved_memory_bytes -= reserve
                provider = str(row["provider"])
                provider_counts[provider] -= 1
                report = future.result()
                if report.get("status") == "model-error":
                    automatic_drain_reason = (
                        "model-error in " + str(row["trial_key"])
                    )
            submit_available()
        drain_requested = (
            (output_dir / "DRAIN").is_file()
            or automatic_drain_reason is not None
        )
        if pending and not model_call_budget.exhausted and not drain_requested:
            smallest = min(
                _trial_memory_reserve_bytes(row, registry) for row in pending
            )
            raise RuntimeError(
                "no pending isolated target fits the sealed runtime memory budget: "
                f"usable={usable_memory_bytes}, smallest_pending_reserve={smallest}"
            )

    reports = [
        json.loads((trials_dir / f"{row['trial_key']}.json").read_text(encoding="utf-8"))
        for row in schedule
        if (trials_dir / f"{row['trial_key']}.json").is_file()
    ]
    status_counts: dict[str, int] = {}
    for report in reports:
        status = str(report["status"])
        status_counts[status] = status_counts.get(status, 0) + 1
    summary = {
        "run_id": args.run_id,
        "scheduled_trials": len(schedule),
        "completed_trials": len(reports),
        "unstarted_trials": len(schedule) - len(reports),
        "status_counts": status_counts,
        "objective_successes": sum(bool(item["objective_achieved"]) for item in reports),
        "model_calls": sum(int(item["metrics"].get("model_calls", 0)) for item in reports),
        "cumulative_model_calls": model_call_budget.used,
        "model_call_budget_exhausted": model_call_budget.exhausted,
        "drain_requested": drain_requested,
        "automatic_drain_reason": automatic_drain_reason,
        "active_http_requests": sum(
            int(item["metrics"].get("active_http_requests", 0)) for item in reports
        ),
        "finished_at": datetime.now(UTC).isoformat(),
    }
    _write_atomic(output_dir / "campaign-summary.json", summary)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a sealed registered-target campaign")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--attacker-profile", type=Path, default=PROFILE_PATH)
    parser.add_argument("--variant-manifest", type=Path)
    parser.add_argument(
        "--defense-registry",
        type=Path,
        default=DEFAULT_DEFENSE_REGISTRY_PATH,
        help="version 2 defense runtime registry inside the repository",
    )
    parser.add_argument("--targets", nargs="*")
    parser.add_argument(
        "--providers", nargs="+", choices=("codex", "claude"), default=["codex", "claude"]
    )
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--seed", type=int, default=8312026)
    parser.add_argument("--max-seconds", type=int, default=1800)
    parser.add_argument("--max-requests", type=int, default=100)
    parser.add_argument("--max-decisions", type=int, default=40)
    parser.add_argument("--max-model-calls", type=int, required=True)
    parser.add_argument("--max-model-calls-per-trial", type=int, required=True)
    parser.add_argument(
        "--max-parallel", type=int, choices=tuple(range(1, 9)), default=1
    )
    parser.add_argument(
        "--reasoning-effort", choices=("medium", "high"), default="medium"
    )
    parser.add_argument(
        "--conditions",
        nargs="+",
        default=["undefended"],
        help=(
            "conditions to run. More than one makes this a comparison, and the "
            "schedule interleaves them so condition order cannot ride along "
            "with the result"
        ),
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--retry-status",
        nargs="*",
        choices=tuple(sorted(TERMINAL_STATUSES)),
        default=[],
    )
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")
    if min(
        args.max_seconds,
        args.max_requests,
        args.max_decisions,
        args.max_model_calls,
        args.max_model_calls_per_trial,
    ) < 1:
        parser.error("all trial limits must be positive")
    return args


if __name__ == "__main__":
    parsed_args = parse_args()
    parsed_args.runtime_capacity_evidence = _validate_runtime_capacity(
        parsed_args.max_parallel
    )
    with CampaignProcessLock(CAMPAIGN_LOCK_PATH, run_id=parsed_args.run_id):
        _start_launcher_watchdog(run_id=parsed_args.run_id)
        print(json.dumps(run_campaign(parsed_args), ensure_ascii=False, sort_keys=True))
