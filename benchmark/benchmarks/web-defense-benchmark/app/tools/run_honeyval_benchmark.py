"""Honeyval condition runner for the RUBY web defense benchmark.

The runner reproduces the Plain Claude R1 trial procedure exactly and inserts
one change: the attacker reaches a Honeyval deception gateway instead of the
application socket, and the gateway forwards to the application.

Everything else is held fixed against the baseline. Same target registry, same
attacker prompt text, same model selector and reasoning effort, same per target
timeout, same isolation and reset, same private evaluator, and the same
container log HTTP counter.

The defense implementation lives in defense/honeyval-defense and is imported,
not copied, so the benchmark tree holds no defense operational code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any

APP_ROOT = Path(__file__).resolve().parents[1]
DEFENSE_PACKAGE: Path | None = None
GatewayConfig: Any = None
HoneyvalGateway: Any = None

from run_plain_claude_baseline import (  # noqa: E402
    MODEL_SELECTOR,
    REASONING_EFFORT,
    ScopedHTTPProxy,
    _assistant_text,
    _container_http_requests,
    _model_and_usage,
    _prepare,
    _sha256,
    _subscription_environment,
    _tool_audit,
    all_target_ids,
    build_prompt,
    classify_status,
    compact_evaluation,
    REFUSAL_PATTERNS,
    require_legacy_host_tools_acknowledgement,
)

CONDITION = "honeyval"
BASELINE_RUN = "plain-claude-all24-r1-final-20260903"


def _atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)


def _load_legacy_defense() -> None:
    global DEFENSE_PACKAGE, GatewayConfig, HoneyvalGateway
    from defense_runtime_v1 import _defense_component_root

    DEFENSE_PACKAGE = _defense_component_root() / "honeyval-defense" / "src"
    if str(DEFENSE_PACKAGE) not in sys.path:
        sys.path.insert(0, str(DEFENSE_PACKAGE))
    from honeyval.gateway import GatewayConfig as LoadedGatewayConfig
    from honeyval.gateway import HoneyvalGateway as LoadedHoneyvalGateway

    GatewayConfig = LoadedGatewayConfig
    HoneyvalGateway = LoadedHoneyvalGateway


def _failure_reason(
    status: str,
    setup_error: str | None,
    evaluator_error: str | None,
    unblocked: list[str],
    returncode: int | None,
) -> str | None:
    if status == "objective-achieved":
        return None
    if setup_error:
        return f"setup: {setup_error}"[:500]
    if evaluator_error:
        return f"evaluator: {evaluator_error}"[:500]
    if status == "scope-violation":
        return f"out of scope requests: {unblocked[:5]}"
    if status == "timeout":
        return "attacker exceeded the per target time limit"
    if status == "refused":
        return "the attacker model declined or was blocked by provider safeguards"
    if status == "model-error":
        return f"attacker CLI exit code {returncode}"
    return "the attacker stopped without achieving the private objective"


def run_trial(
    *,
    target_id: str,
    repetition: int,
    seed: int,
    timeout_seconds: int,
    output_dir: Path,
    run_id: str,
    defense_options: dict[str, Any],
) -> dict[str, Any]:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", f"{target_id}-r{repetition}")
    trial_dir = output_dir / "trials" / slug
    result_path = trial_dir / "result.json"
    if result_path.is_file():
        return json.loads(result_path.read_text(encoding="utf-8"))
    trial_dir.mkdir(parents=True, exist_ok=True)
    workspace = trial_dir / "workspace"
    workspace.mkdir(exist_ok=True)

    trial_id = uuid.uuid4().hex
    started = time.time()
    target = None
    gateway: HoneyvalGateway | None = None
    scope_proxy: ScopedHTTPProxy | None = None
    events: list[dict[str, Any]] = []
    raw_stdout = ""
    raw_stderr = ""
    returncode: int | None = None
    timed_out = False
    setup_error: str | None = None
    evaluator_error: str | None = None
    evaluation: dict[str, Any] | None = None
    upstream_origin: str | None = None
    attacker_origin: str | None = None
    project: str | None = None
    prompt = ""
    reset_passed = False
    defense_metrics: dict[str, Any] = {}

    gateway_options = dict(defense_options)
    attacker_config_dir = gateway_options.pop("attacker_config_dir", None)
    # Older defense versions do not carry every knob the runner knows about.
    # Passing an unknown one would abort the trial, so keep only the fields the
    # loaded GatewayConfig actually declares and record what was dropped.
    accepted = set(getattr(GatewayConfig, "__dataclass_fields__", {}))
    dropped = sorted(set(gateway_options) - accepted)
    gateway_options = {k: v for k, v in gateway_options.items() if k in accepted}

    try:
        target = _prepare(target_id, trial_id, seed)
        reset_passed = True
        upstream_origin = str(target.executor.target_origin)
        project = str(target.isolation_metadata().get("compose_project"))
        accounts = list(target.accounts)

        # The registry is a rejection list held in memory only. Nothing from it
        # is written to any artifact. It carries the synthetic account
        # credentials and the scenario protected values so a generated response
        # can never reproduce a genuine secret or success marker.
        protected_values = [
            str(item.get("password")) for item in accounts if item.get("password")
        ]
        protected_values.extend(str(item) for item in getattr(target, "secrets", []) or [])

        gateway = HoneyvalGateway(
            GatewayConfig(
                upstream_origin=upstream_origin,
                ledger_path=trial_dir / "defense-ledger.jsonl",
                account_secrets=protected_values,
                **gateway_options,
            )
        )
        gateway.load_spec()
        attacker_origin = gateway.origin

        prompt = build_prompt(attacker_origin, accounts)
        _atomic_write(trial_dir / "prompt.txt", prompt)

        scope_proxy = ScopedHTTPProxy(attacker_origin)
        executable = shutil.which("claude.exe") or shutil.which("claude")
        if executable is None:
            raise FileNotFoundError("claude.exe is not installed")
        command = [
            executable,
            "--print",
            "--model",
            MODEL_SELECTOR,
            "--effort",
            REASONING_EFFORT,
            "--safe-mode",
            "--disable-slash-commands",
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--tools",
            "default",
            "--disallowedTools",
            "WebFetch,WebSearch",
            "--dangerously-skip-permissions",
            "--no-session-persistence",
            "--output-format",
            "stream-json",
            "--verbose",
            prompt,
        ]
        environment = scope_proxy.apply(_subscription_environment())
        if attacker_config_dir:
            environment["CLAUDE_CONFIG_DIR"] = str(attacker_config_dir)
        try:
            process = subprocess.run(
                command,
                cwd=workspace,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=environment,
                timeout=timeout_seconds,
            )
            returncode = process.returncode
            raw_stdout = process.stdout
            raw_stderr = process.stderr
        except subprocess.TimeoutExpired as error:
            timed_out = True
            raw_stdout = (
                error.stdout.decode("utf-8", "replace")
                if isinstance(error.stdout, bytes)
                else (error.stdout or "")
            )
            raw_stderr = (
                error.stderr.decode("utf-8", "replace")
                if isinstance(error.stderr, bytes)
                else (error.stderr or "")
            )
        for line in raw_stdout.splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                events.append(value)
        try:
            evaluation = target.evaluate()
        except Exception as error:
            evaluator_error = f"{type(error).__name__}: {error}"
    except Exception as error:
        setup_error = f"{type(error).__name__}: {error}"
    finally:
        http_requests = _container_http_requests(project) if project else None
        if scope_proxy is not None:
            scope_proxy.close()
        if gateway is not None:
            defense_metrics = gateway.metrics()
            gateway.close()
        if target is not None:
            try:
                target.close()
            except Exception as error:
                suffix = f"cleanup: {type(error).__name__}: {error}"
                setup_error = f"{setup_error}; {suffix}" if setup_error else suffix

    _atomic_write(trial_dir / "events.jsonl", raw_stdout)
    _atomic_write(trial_dir / "stderr.txt", raw_stderr)

    assistant_text = _assistant_text(events)
    refused = any(pattern.search(assistant_text) for pattern in REFUSAL_PATTERNS)
    objective_achieved = bool(evaluation and evaluation.get("objective_achieved"))
    tools = _tool_audit(events, attacker_origin or "")
    blocked = sorted(set(scope_proxy.denied_urls)) if scope_proxy else []
    tools["blocked_out_of_scope_urls"] = blocked
    tools["scope_proxy_active"] = scope_proxy is not None
    unblocked = (
        list(tools["out_of_scope_urls"])
        if not scope_proxy or tools["proxy_bypass_command_sha256"]
        else []
    )
    tools["unblocked_out_of_scope_urls"] = unblocked
    models, usage = _model_and_usage(events)
    status = classify_status(
        setup_error=setup_error,
        evaluator_error=evaluator_error,
        out_of_scope_urls=unblocked,
        objective_achieved=objective_achieved,
        refused=refused,
        timed_out=timed_out,
        returncode=returncode,
    )

    generator_stats = {
        key: defense_metrics.get(key, 0)
        for key in (
            "defense_model_calls",
            "defense_model_failures",
            "defense_input_tokens",
            "defense_output_tokens",
            "defense_latency_seconds_total",
        )
    }
    result = {
        "schema_version": 1,
        "condition": CONDITION,
        "run_id": run_id,
        "target_id": target_id,
        "repetition": repetition,
        "trial_id": trial_id,
        "final_status": status,
        "status": status,
        "objective_achieved": objective_achieved,
        "failure_reason": _failure_reason(
            status, setup_error, evaluator_error, unblocked, returncode
        ),
        "elapsed_seconds": round(time.time() - started, 3),
        "timeout_seconds": timeout_seconds,
        "returncode": returncode,
        "timed_out": timed_out,
        "setup_error": setup_error,
        "evaluator_error": evaluator_error,
        "evaluation": compact_evaluation(evaluation),
        "target_reset_passed": reset_passed,
        "result_evaluator_passed": evaluation is not None and evaluator_error is None,
        "model_selector": MODEL_SELECTOR,
        "reasoning_effort": REASONING_EFFORT,
        "observed_model_ids": models,
        "usage": usage,
        "attacker_input_tokens": usage.get("input_tokens", 0),
        "attacker_cache_creation_input_tokens": usage.get("cache_creation_input_tokens", 0),
        "attacker_cache_read_input_tokens": usage.get("cache_read_input_tokens", 0),
        "attacker_output_tokens": usage.get("output_tokens", 0),
        "attacker_tool_uses": tools.get("tool_uses", 0),
        "http_requests": http_requests,
        "http_requests_from_container_logs": http_requests,
        "gateway_observed_requests": defense_metrics.get("gateway_observed_requests"),
        "decoy_responses": defense_metrics.get("decoy_responses", 0),
        "defense_actions": defense_metrics.get("defense_actions", {}),
        "defense_validation_failures": defense_metrics.get("defense_validation_failures", 0),
        "defense_regenerations": defense_metrics.get("defense_regenerations", 0),
        "defense_passthrough_after_failure": defense_metrics.get(
            "defense_passthrough_after_failure", 0
        ),
        "defense_options_dropped": dropped,
        "defense_openapi_available": defense_metrics.get("openapi_available"),
        "defense_openapi_operation_count": defense_metrics.get("openapi_operation_count"),
        "defense_model_ids": defense_metrics.get("defense_model_ids", []),
        "defense_budget_used": defense_metrics.get("defense_budget_used", 0),
        "defense_budget_limit": defense_metrics.get("defense_budget_limit"),
        "decoy_state": defense_metrics.get("decoy_state", {}),
        "scope_violations": len(unblocked),
        "refused": refused,
        "tool_audit": tools,
        "scope_proxy": {
            "active": scope_proxy is not None,
            "attacker_origin": attacker_origin,
            "blocked_request_count": len(blocked),
        },
        "upstream_origin_recorded": upstream_origin is not None,
        "prompt_sha256": _sha256(prompt.encode("utf-8")),
        "stdout_sha256": _sha256(raw_stdout.encode("utf-8")),
        "stderr_sha256": _sha256(raw_stderr.encode("utf-8")),
        **generator_stats,
    }
    _atomic_write(result_path, json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result


def _compact(result: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "target_id",
        "condition",
        "repetition",
        "run_id",
        "trial_id",
        "objective_achieved",
        "final_status",
        "failure_reason",
        "elapsed_seconds",
        "http_requests",
        "gateway_observed_requests",
        "attacker_tool_uses",
        "attacker_input_tokens",
        "attacker_cache_creation_input_tokens",
        "attacker_cache_read_input_tokens",
        "attacker_output_tokens",
        "defense_model_calls",
        "decoy_responses",
        "defense_input_tokens",
        "defense_output_tokens",
        "defense_latency_seconds_total",
        "defense_validation_failures",
        "defense_regenerations",
        "defense_passthrough_after_failure",
        "scope_violations",
        "target_reset_passed",
        "result_evaluator_passed",
    )
    compact = {key: result.get(key) for key in keys}
    compact["defense_actions"] = result.get("defense_actions", {})
    return compact


def write_summary(output_dir: Path, run_id: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(results, key=lambda item: (str(item.get("target_id")), item.get("repetition", 1)))
    statuses: dict[str, int] = {}
    for item in ordered:
        key = str(item.get("final_status"))
        statuses[key] = statuses.get(key, 0) + 1
    successes = sum(1 for item in ordered if item.get("objective_achieved"))
    def total(key: str) -> int:
        return sum(int(item.get(key) or 0) for item in ordered)

    summary = {
        "schema_version": 1,
        "run_id": run_id,
        "condition": CONDITION,
        "baseline_run": BASELINE_RUN,
        "trials": len(ordered),
        "unique_targets": len({str(item.get("target_id")) for item in ordered}),
        "objective_successes": successes,
        "attack_success_rate": round(successes / len(ordered), 6) if ordered else 0.0,
        "status_counts": statuses,
        "elapsed_seconds_sum": round(sum(float(item.get("elapsed_seconds") or 0) for item in ordered), 3),
        "http_requests_container_logs_sum": total("http_requests"),
        "gateway_observed_requests_sum": total("gateway_observed_requests"),
        "attacker_tool_uses_sum": total("attacker_tool_uses"),
        "attacker_tokens": {
            "input": total("attacker_input_tokens"),
            "cache_creation_input": total("attacker_cache_creation_input_tokens"),
            "cache_read_input": total("attacker_cache_read_input_tokens"),
            "output": total("attacker_output_tokens"),
        },
        "defense": {
            "model_calls": total("defense_model_calls"),
            "decoy_responses": total("decoy_responses"),
            "input_tokens": total("defense_input_tokens"),
            "output_tokens": total("defense_output_tokens"),
            "latency_seconds_total": round(
                sum(float(item.get("defense_latency_seconds_total") or 0) for item in ordered), 3
            ),
            "validation_failures": total("defense_validation_failures"),
            "regenerations": total("defense_regenerations"),
            "passthrough_after_failure": total("defense_passthrough_after_failure"),
        },
        "results": [_compact(item) for item in ordered],
    }
    _atomic_write(output_dir / "summary.json", json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--targets", nargs="*", default=None)
    parser.add_argument("--repetition", type=int, default=1)
    parser.add_argument("--seed", type=int, default=20260903)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--parallel", type=int, default=2)
    parser.add_argument("--max-defense-calls", type=int, default=60)
    parser.add_argument("--max-calls-per-template", type=int, default=10)
    parser.add_argument("--max-deceived-templates", type=int, default=8)
    parser.add_argument("--min-refused-identities", dest="min_refused_identities", type=int, default=2)
    parser.add_argument("--state-scope", default="actor", choices=["actor", "session"])
    parser.add_argument("--deceive-undeclared-not-found", action="store_true")
    parser.add_argument("--max-attempts", type=int, default=2)
    parser.add_argument("--defense-model", default="haiku")
    parser.add_argument("--defense-effort", default="low")
    parser.add_argument("--defense-timeout", type=float, default=90.0)
    parser.add_argument("--defense-config-dir", default=None)
    parser.add_argument("--attacker-config-dir", default=None)
    parser.add_argument("--defense-concurrency", type=int, default=2)
    parser.add_argument("--disable-defense", action="store_true")
    parser.add_argument(
        "--allow-host-tools",
        action="store_true",
        help="allow this legacy runner only to reproduce historical results",
    )
    parsed = parser.parse_args()
    require_legacy_host_tools_acknowledgement(parsed.allow_host_tools)
    _load_legacy_defense()
    assert DEFENSE_PACKAGE is not None

    output_dir = Path(parsed.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    targets = parsed.targets if parsed.targets else all_target_ids()

    defense_options: dict[str, Any] = {
        "max_defense_calls": parsed.max_defense_calls,
        "max_calls_per_template": parsed.max_calls_per_template,
        "max_deceived_templates": parsed.max_deceived_templates,
        "min_refused_identities": parsed.min_refused_identities,
        "state_scope": parsed.state_scope,
        "deceive_undeclared_not_found": parsed.deceive_undeclared_not_found,
        "max_attempts_per_request": parsed.max_attempts,
        "model_selector": parsed.defense_model,
        "model_effort": parsed.defense_effort,
        "model_timeout": parsed.defense_timeout,
        "model_config_dir": parsed.defense_config_dir,
        "max_concurrency": parsed.defense_concurrency,
        "enabled": not parsed.disable_defense,
    }
    seal = {
        "run_id": parsed.run_id,
        "condition": CONDITION,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "baseline_run": BASELINE_RUN,
        "attacker": {
            "provider": "claude-code",
            "model_selector": MODEL_SELECTOR,
            "reasoning_effort": REASONING_EFFORT,
            "timeout_seconds_per_target": parsed.timeout,
            "attacker_config_dir_set": bool(parsed.attacker_config_dir),
        },
        "defense": {key: value for key, value in defense_options.items()},
        "targets": list(targets),
        "repetition": parsed.repetition,
        "seed": parsed.seed,
        "parallel": parsed.parallel,
        "defense_source_sha256": {
            path.name: _sha256(path.read_bytes())
            for path in sorted((DEFENSE_PACKAGE / "honeyval").glob("*.py"))
        },
        "runner_sha256": _sha256(Path(__file__).read_bytes()),
    }
    _atomic_write(output_dir / "run-seal.json", json.dumps(seal, ensure_ascii=False, indent=2) + "\n")

    # The defense source is edited in place across iterations and this tree
    # is not under version control, so the seal hashes alone cannot bring a
    # past version back. Keep the actual sources next to the run they made.
    snapshot = output_dir / "defense-source"
    snapshot.mkdir(parents=True, exist_ok=True)
    for path in sorted((DEFENSE_PACKAGE / "honeyval").glob("*.py")):
        (snapshot / path.name).write_bytes(path.read_bytes())

    trial_options = dict(defense_options)
    trial_options["attacker_config_dir"] = parsed.attacker_config_dir

    results: list[dict[str, Any]] = []
    pending: dict[Future[dict[str, Any]], str] = {}
    remaining = list(targets)
    with ThreadPoolExecutor(max_workers=max(1, parsed.parallel)) as pool:
        while remaining or pending:
            while remaining and len(pending) < max(1, parsed.parallel):
                target_id = remaining.pop(0)
                future = pool.submit(
                    run_trial,
                    target_id=target_id,
                    repetition=parsed.repetition,
                    seed=parsed.seed,
                    timeout_seconds=parsed.timeout,
                    output_dir=output_dir,
                    run_id=parsed.run_id,
                    defense_options=dict(trial_options),
                )
                pending[future] = target_id
            done, _ = wait(list(pending), return_when=FIRST_COMPLETED)
            for future in done:
                target_id = pending.pop(future)
                try:
                    result = future.result()
                except Exception as error:
                    result = {
                        "schema_version": 1,
                        "condition": CONDITION,
                        "run_id": parsed.run_id,
                        "target_id": target_id,
                        "repetition": parsed.repetition,
                        "trial_id": None,
                        "final_status": "runner-error",
                        "objective_achieved": False,
                        "failure_reason": f"{type(error).__name__}: {error}",
                        "elapsed_seconds": 0.0,
                    }
                results.append(result)
                print(
                    f"[{len(results)}/{len(targets)}] {target_id} -> "
                    f"{result.get('final_status')} "
                    f"decoys={result.get('decoy_responses')} "
                    f"defense_calls={result.get('defense_model_calls')} "
                    f"elapsed={result.get('elapsed_seconds')}s",
                    flush=True,
                )
                write_summary(output_dir, parsed.run_id, results)

    summary = write_summary(output_dir, parsed.run_id, results)
    print(json.dumps({key: summary[key] for key in ("trials", "objective_successes", "attack_success_rate", "status_counts")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
