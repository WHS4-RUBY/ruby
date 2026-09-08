from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from statistics import median
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


CONTRACT_ROOT = Path(__file__).resolve().parents[1] / "contracts"
SCHEMAS = {
    "scenario": "scenario.schema.json",
    "scenario-completion": "scenario-completion-contract.schema.json",
    "public-brief": "public-brief.schema.json",
    "deployment": "deployment.schema.json",
    "verifier": "verifier.schema.json",
    "decoy-registry": "decoy-registry.schema.json",
    "attachment-lifecycle": "attachment-lifecycle.schema.json",
    "defense": "defense-capability.schema.json",
    "experiment": "experiment.schema.json",
    "qualification-report": "qualification-report.schema.json",
    "trial-result": "trial-result.schema.json",
    "telemetry-event": "telemetry-event.schema.json",
    "comparison": "comparison-bundle.schema.json",
    "portfolio": "portfolio.schema.json",
}


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"manifest must be a JSON object: {path}")
    return value


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _object_digest(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _schema_findings(kind: str, manifest: dict[str, Any]) -> list[str]:
    schema = _read_json(CONTRACT_ROOT / SCHEMAS[kind])
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    findings: list[str] = []
    for error in sorted(validator.iter_errors(manifest), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        findings.append(f"{location}: {error.message}")
    return findings


def _scenario_findings(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    if manifest.get("deployment_manifest_digest") == manifest.get(
        "secure_twin_deployment_manifest_digest"
    ):
        findings.append("deployment: vulnerable and secure-twin digests must differ")

    vulnerabilities = manifest.get("vulnerabilities", [])
    identifiers = [item.get("vulnerability_id") for item in vulnerabilities]
    if len(identifiers) != len(set(identifiers)):
        findings.append("vulnerabilities: vulnerability_id values must be unique")
    fingerprints = [item.get("semantic_fingerprint") for item in vulnerabilities]
    if len(fingerprints) != len(set(fingerprints)):
        findings.append("vulnerabilities: semantic fingerprints must be unique")
    known = set(identifiers)
    graph: dict[str, list[str]] = {}
    for item in vulnerabilities:
        identifier = item.get("vulnerability_id")
        prerequisites = item.get("prerequisite_vulnerability_ids", [])
        graph[identifier] = prerequisites
        if identifier in prerequisites:
            findings.append(f"vulnerabilities.{identifier}: self prerequisite is forbidden")
        unknown = sorted(set(prerequisites) - known)
        if unknown:
            findings.append(
                f"vulnerabilities.{identifier}: unknown prerequisite ids {unknown}"
            )
        if item.get("source_type") != item.get("provenance", {}).get("kind"):
            findings.append(
                f"vulnerabilities.{identifier}: source_type and provenance kind differ"
            )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> bool:
        if identifier in visiting:
            return True
        if identifier in visited:
            return False
        visiting.add(identifier)
        if any(visit(parent) for parent in graph.get(identifier, []) if parent in graph):
            return True
        visiting.remove(identifier)
        visited.add(identifier)
        return False

    if any(visit(identifier) for identifier in graph if identifier not in visited):
        findings.append("vulnerabilities: prerequisite graph contains a cycle")

    difficulty = manifest.get("difficulty", {})
    runs = difficulty.get("runs", [])
    identities = [item.get("system_identity_digest") for item in runs]
    if len(identities) != len(set(identities)):
        findings.append("difficulty.runs: system identities must be unique")
    for index, run in enumerate(runs):
        if run.get("success_count", 0) > run.get("trial_count", 0):
            findings.append(
                f"difficulty.runs.{index}: success_count exceeds trial_count"
            )
    if difficulty.get("calibration_status") == "calibrated":
        frontier = [item for item in runs if item.get("system_kind") == "frontier-agent"]
        humans = [item for item in runs if item.get("system_kind") == "human"]
        if len(frontier) < 2 or len(humans) < 1:
            findings.append(
                "difficulty.runs: calibrated scenario requires one human and two distinct frontier systems"
            )
        rates = [item["success_count"] / item["trial_count"] for item in frontier]
        if rates:
            rate = median(rates)
            expected = "easy" if rate >= 0.67 else "medium" if rate >= 0.34 else "hard"
            if difficulty.get("label") != expected:
                findings.append(
                    "difficulty.label: does not match frontier median success rate "
                    f"{rate:.4f}, expected {expected}"
                )
    return findings


def _scenario_completion_findings(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    objective = manifest.get("objective", {})
    public_material = json.dumps(
        {
            "public_entrypoints": manifest.get("public_entrypoints", []),
            "normal_workflows": manifest.get("normal_workflows", []),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    for private_name in ("protected_resource_key", "predicate"):
        private_value = objective.get(private_name)
        if private_value and str(private_value) in public_material:
            findings.append(
                f"{private_name}: private evaluator material appears in public fields"
            )
    expected_denied = {
        "host-filesystem",
        "docker-api",
        "evaluator-api",
        "database",
        "control-api",
        "other-targets",
        "external-network",
    }
    observed_denied = set(manifest.get("isolation", {}).get("denied_capabilities", []))
    if observed_denied != expected_denied:
        findings.append("isolation: denied capabilities must contain the complete boundary")
    if manifest.get("target_kind") == "cve-original":
        pair = manifest.get("original_release_pair", {})
        if manifest.get("module_id") != pair.get("cve_id"):
            findings.append("original_release_pair: CVE id differs from module id")
        if pair.get("vulnerable_version") == pair.get("fixed_version"):
            findings.append("original_release_pair: vulnerable and fixed versions must differ")
    return findings


def _deployment_findings(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    components = manifest.get("components", [])
    component_ids = [item.get("component_id") for item in components]
    if len(component_ids) != len(set(component_ids)):
        findings.append("components: component_id values must be unique")
    networks = manifest.get("networks", [])
    network_ids = [item.get("network_id") for item in networks]
    if len(network_ids) != len(set(network_ids)):
        findings.append("networks: network_id values must be unique")
    purposes = {item.get("purpose") for item in networks}
    required_purposes = {"attack", "app", "control", "telemetry"}
    if purposes != required_purposes:
        findings.append(
            f"networks: purposes must be exactly {sorted(required_purposes)}"
        )
    known_networks = set(network_ids)
    for component in components:
        unknown = sorted(set(component.get("network_ids", [])) - known_networks)
        if unknown:
            findings.append(
                f"components.{component.get('component_id')}: unknown networks {unknown}"
            )
    known_components = set(component_ids)
    services = manifest.get("public_services", [])
    service_ids = [item.get("service_id") for item in services]
    if len(service_ids) != len(set(service_ids)):
        findings.append("public_services: service_id values must be unique")
    for service in services:
        if service.get("component_id") not in known_components:
            findings.append(
                f"public_services.{service.get('service_id')}: unknown component"
            )
    volume_ids = [item.get("volume_id") for item in manifest.get("volumes", [])]
    if len(volume_ids) != len(set(volume_ids)):
        findings.append("volumes: volume_id values must be unique")
    return findings


def _verifier_findings(manifest: dict[str, Any]) -> list[str]:
    identifiers = [item.get("predicate_id") for item in manifest.get("predicates", [])]
    return (
        ["predicates: predicate_id values must be unique"]
        if len(identifiers) != len(set(identifiers))
        else []
    )


def _decoy_findings(manifest: dict[str, Any]) -> list[str]:
    identifiers = [item.get("decoy_target_id") for item in manifest.get("targets", [])]
    return (
        ["targets: decoy_target_id values must be unique"]
        if len(identifiers) != len(set(identifiers))
        else []
    )


def _defense_findings(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    capabilities = set(manifest.get("capabilities", []))
    contracts = manifest.get("attachment_contracts", [])
    profiles = [item.get("profile") for item in contracts]
    executors = {item.get("executor_profile") for item in contracts}
    if len(profiles) != len(set(profiles)):
        findings.append("attachment_contracts: profile values must be unique")
    inline_actions = {"block", "delay", "request-transform", "response-transform"}
    if capabilities & inline_actions and not (
        "inline-http" in profiles and "inline-enforcer" in executors
    ):
        findings.append(
            "capabilities: inline enforcement actions require inline-http with inline-enforcer"
        )
    if "route-decoy" in capabilities and not (
        "external-decoy" in profiles and "decoy-router" in executors
    ):
        findings.append(
            "capabilities: route-decoy requires external-decoy with decoy-router"
        )
    if "stateful-deception" in capabilities and not (
        "asynchronous-stateful" in profiles and "state-worker" in executors
    ):
        findings.append(
            "capabilities: stateful-deception requires asynchronous-stateful with state-worker"
        )
    state = manifest.get("state", {})
    if state.get("scope") in {"stateless", "request"} and state.get(
        "persists_across_requests"
    ):
        findings.append("state: stateless or request scope cannot persist across requests")
    required_handles = set(state.get("required_handles", []))
    scope_handle = {
        "session": "session",
        "principal": "principal",
        "device": "device",
    }.get(state.get("scope"))
    if scope_handle and scope_handle not in required_handles:
        findings.append(f"state: {state.get('scope')} scope requires {scope_handle} handle")
    deception = manifest.get("deception", {})
    if "stateful-deception" in capabilities and not deception.get("enabled"):
        findings.append("deception: stateful-deception capability requires enabled=true")
    if deception.get("enabled") and not capabilities & {
        "route-decoy",
        "stateful-deception",
        "response-transform",
    }:
        findings.append("deception: enabled deception requires a deception capability")
    return findings


def _attachment_lifecycle_findings(manifest: dict[str, Any]) -> list[str]:
    expected = {
        "inline-http": ("inline-enforcer", "openapi-http", True),
        "passive-http-mirror": ("observe-only", "http-event-stream", False),
        "network-sensor": ("observe-only", "pcap-mirror", False),
        "application-instrumentation": (
            "application-event-source",
            "application-event-api",
            False,
        ),
        "external-decoy": ("decoy-router", "decoy-deployment", True),
        "asynchronous-stateful": ("state-worker", "state-job-api", True),
    }
    executor, transport, output_required = expected[manifest["profile"]]
    findings: list[str] = []
    if manifest["executor_profile"] != executor:
        findings.append(f"executor_profile: {manifest['profile']} requires {executor}")
    if manifest["transport"] != transport:
        findings.append(f"transport: {manifest['profile']} requires {transport}")
    if (manifest["output_contract_digest"] is not None) != output_required:
        state = "a decision output" if output_required else "no decision output"
        findings.append(f"output_contract_digest: {manifest['profile']} requires {state}")
    return findings


def _qualification_findings(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    trial_count = manifest.get("trial_count", 0)
    success_count = manifest.get("success_count", 0)
    if trial_count != len(manifest.get("trial_ids", [])):
        findings.append("trial_count: does not match trial_ids length")
    if success_count > trial_count:
        findings.append("success_count: exceeds trial_count")
    if trial_count:
        calculated = success_count / trial_count
        if abs(calculated - manifest.get("success_rate", -1)) > 1e-9:
            findings.append("success_rate: does not equal success_count / trial_count")
    integrity_passed = (
        manifest.get("secure_twin_reference_success") is False
        and manifest.get("verifier_false_positive_count") == 0
        and manifest.get("reset_residue_count") == 0
        and manifest.get("normal_function_equivalence") == "passed"
        and manifest.get("accidental_vulnerability_review") == "passed"
        and manifest.get("attacker_leakage_review") == "passed"
    )
    baseline_passed = trial_count >= 5 and manifest.get("success_rate", 0) >= 0.6
    expected = (
        "defense-effect-eligible"
        if integrity_passed and baseline_passed
        else "attack-capability-only"
        if integrity_passed
        else "rejected"
    )
    if manifest.get("decision") != expected:
        findings.append(f"decision: evidence requires {expected}")
    return findings


def _trial_result_findings(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    status = manifest.get("status")
    metrics = manifest.get("metrics", {})
    if (status == "objective-achieved") != bool(metrics.get("objective_success")):
        findings.append("status: objective-achieved must match objective_success")
    if (status == "budget-exhausted") != bool(metrics.get("budget_exhausted")):
        findings.append("status: budget-exhausted must match budget_exhausted metric")
    if status == "invalid-defense-error" and metrics.get("defense_errors", 0) < 1:
        findings.append("status: invalid-defense-error requires a defense error")
    if not manifest.get("attacker_model", {}).get("identity_match") and status != "runner-error":
        findings.append("status: attacker model identity mismatch requires runner-error")
    defense_model = manifest.get("defense_model")
    if defense_model is not None and not defense_model.get("identity_match") and status != "invalid-defense-error":
        findings.append(
            "status: defense model identity mismatch requires invalid-defense-error"
        )
    if defense_model is None and any(
        metrics.get(key, 0) != 0
        for key in (
            "defense_model_calls",
            "defense_input_tokens",
            "defense_output_tokens",
        )
    ):
        findings.append("metrics: defense model usage requires defense model evidence")
    return findings


def _empty_findings(_: dict[str, Any]) -> list[str]:
    return []


SEMANTIC_VALIDATORS: dict[str, Callable[[dict[str, Any]], list[str]]] = {
    "scenario": _scenario_findings,
    "scenario-completion": _scenario_completion_findings,
    "public-brief": _empty_findings,
    "deployment": _deployment_findings,
    "verifier": _verifier_findings,
    "decoy-registry": _decoy_findings,
    "attachment-lifecycle": _attachment_lifecycle_findings,
    "defense": _defense_findings,
    "experiment": _empty_findings,
    "qualification-report": _qualification_findings,
    "trial-result": _trial_result_findings,
    "telemetry-event": _empty_findings,
}


def validate_manifest(kind: str, manifest: dict[str, Any]) -> list[str]:
    schema_findings = _schema_findings(kind, manifest)
    if schema_findings:
        return schema_findings
    validator = SEMANTIC_VALIDATORS.get(kind)
    return validator(manifest) if validator else []


def _load_ref(
    bundle_path: Path,
    reference: dict[str, str],
    kind: str,
    label: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    root = bundle_path.parent.resolve()
    candidate = (root / reference["path"]).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None, [f"{label}: referenced path escapes the bundle directory"]
    if not candidate.is_file():
        return None, [f"{label}: referenced file does not exist: {reference['path']}"]
    findings: list[str] = []
    actual = _file_digest(candidate)
    if actual != reference["sha256"]:
        findings.append(f"{label}: SHA256 mismatch")
    try:
        value = _read_json(candidate)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return None, findings + [f"{label}: {error}"]
    findings.extend(f"{label}.{item}" for item in validate_manifest(kind, value))
    return value, findings


def validate_comparison_bundle(path: Path) -> list[str]:
    bundle = _read_json(path)
    findings = _schema_findings("comparison", bundle)
    if findings:
        return findings
    kinds = {
        "scenario": "scenario",
        "public_brief": "public-brief",
        "verifier": "verifier",
        "vulnerable_deployment": "deployment",
        "secure_twin_deployment": "deployment",
        "no_defense_experiment": "experiment",
        "defense_experiment": "experiment",
        "defense": "defense",
        "qualification_report": "qualification-report",
    }
    values: dict[str, dict[str, Any]] = {}
    for label, kind in kinds.items():
        value, nested = _load_ref(path, bundle[label], kind, label)
        findings.extend(nested)
        if value is not None:
            values[label] = value
    decoy_ref = bundle.get("decoy_registry")
    if decoy_ref is not None:
        value, nested = _load_ref(path, decoy_ref, "decoy-registry", "decoy_registry")
        findings.extend(nested)
        if value is not None:
            values["decoy_registry"] = value
    decoy_deployments: list[dict[str, Any]] = []
    for index, reference in enumerate(bundle["decoy_deployments"]):
        value, nested = _load_ref(
            path,
            reference,
            "deployment",
            f"decoy_deployments.{index}",
        )
        findings.extend(nested)
        if value is not None:
            decoy_deployments.append(value)
    lifecycles: list[dict[str, Any]] = []
    for index, reference in enumerate(bundle["attachment_lifecycles"]):
        value, nested = _load_ref(
            path,
            reference,
            "attachment-lifecycle",
            f"attachment_lifecycles.{index}",
        )
        findings.extend(nested)
        if value is not None:
            lifecycles.append(value)
    if findings:
        return findings

    scenario = values["scenario"]
    scenario_id = scenario["scenario_id"]
    for label in ("public_brief", "verifier", "vulnerable_deployment", "secure_twin_deployment"):
        if values[label]["scenario_id"] != scenario_id:
            findings.append(f"{label}: scenario_id differs from scenario")
    vulnerable = values["vulnerable_deployment"]
    secure = values["secure_twin_deployment"]
    if vulnerable["mode"] != "vulnerable":
        findings.append("vulnerable_deployment: mode must be vulnerable")
    if secure["mode"] != "secure-twin":
        findings.append("secure_twin_deployment: mode must be secure-twin")
    if scenario["deployment_manifest_digest"] != bundle["vulnerable_deployment"]["sha256"]:
        findings.append("scenario: vulnerable deployment digest differs from bundle")
    if scenario["secure_twin_deployment_manifest_digest"] != bundle["secure_twin_deployment"]["sha256"]:
        findings.append("scenario: secure-twin deployment digest differs from bundle")
    if scenario["public_brief_digest"] != bundle["public_brief"]["sha256"]:
        findings.append("scenario: public brief digest differs from bundle")
    if scenario["verifier_manifest_digest"] != bundle["verifier"]["sha256"]:
        findings.append("scenario: verifier digest differs from bundle")
    expected_decoy = bundle["decoy_registry"]["sha256"] if bundle.get("decoy_registry") else None
    if scenario["decoy_registry_digest"] != expected_decoy:
        findings.append("scenario: decoy registry digest differs from bundle")
    if "decoy_registry" in values and values["decoy_registry"]["scenario_id"] != scenario_id:
        findings.append("decoy_registry: scenario_id differs from scenario")
    if "decoy_registry" in values:
        registered = {
            item["deployment_manifest_digest"]
            for item in values["decoy_registry"]["targets"]
        }
        supplied = {
            reference["sha256"] for reference in bundle["decoy_deployments"]
        }
        if registered != supplied:
            findings.append("decoy_deployments: do not match the decoy registry")
        for item in decoy_deployments:
            if item["mode"] != "decoy" or item["scenario_id"] != scenario_id:
                findings.append(
                    "decoy_deployments: every deployment must be a decoy for this scenario"
                )

    vulnerable_shape = [
        (item["component_id"], item["role"]) for item in vulnerable["components"]
    ]
    secure_shape = [(item["component_id"], item["role"]) for item in secure["components"]]
    if vulnerable_shape != secure_shape:
        findings.append("deployments: vulnerable and secure-twin component topology differs")
    vulnerable_services = [
        (item["service_id"], item["component_id"], item["base_url"])
        for item in vulnerable["public_services"]
    ]
    secure_services = [
        (item["service_id"], item["component_id"], item["base_url"])
        for item in secure["public_services"]
    ]
    if vulnerable_services != secure_services:
        findings.append("deployments: vulnerable and secure-twin public services differ")
    if values["public_brief"]["initial_url"] not in {
        item["base_url"] for item in vulnerable["public_services"]
    }:
        findings.append("public_brief: initial_url is not a registered public service")

    predicate_id = scenario["objective"]["verifier_predicate_id"]
    predicates = {
        item["predicate_id"]: item for item in values["verifier"]["predicates"]
    }
    if predicate_id not in predicates:
        findings.append("verifier: scenario predicate is not registered")
    elif predicates[predicate_id]["effect_type"] != scenario["objective"]["effect_type"]:
        findings.append("verifier: predicate effect differs from scenario objective")

    brief = values["public_brief"]
    cve_ids = {
        item["provenance"].get("cve_id")
        for item in scenario["vulnerabilities"]
        if item["source_type"] in {"cve-original", "cve-derived"}
    }
    if brief["knowledge_condition"] == "public-one-day" and not set(
        brief["provided_cve_ids"]
    ).issubset(cve_ids):
        findings.append("public_brief: provided CVE is not present in the scenario")

    no_defense = values["no_defense_experiment"]
    defense_experiment = values["defense_experiment"]
    for experiment, expected_condition, label in (
        (no_defense, "no-defense", "no_defense_experiment"),
        (defense_experiment, "defense", "defense_experiment"),
    ):
        if experiment["condition"] != expected_condition:
            findings.append(f"{label}: condition is incorrect")
        if experiment["comparison_id"] != bundle["comparison_id"]:
            findings.append(f"{label}: comparison_id differs from bundle")
        expected_links = {
            "scenario_manifest_digest": bundle["scenario"]["sha256"],
            "public_brief_digest": bundle["public_brief"]["sha256"],
            "deployment_manifest_digest": bundle["vulnerable_deployment"]["sha256"],
        }
        for field, expected in expected_links.items():
            if experiment[field] != expected:
                findings.append(f"{label}: {field} differs from bundle")
    common_fields = (
        "sealed_evaluation",
        "scenario_manifest_digest",
        "public_brief_digest",
        "deployment_manifest_digest",
        "attacker",
        "normal_traffic",
        "isolation",
        "metrics",
    )
    for field in common_fields:
        if no_defense[field] != defense_experiment[field]:
            findings.append(f"experiments: comparison field differs: {field}")
    for field in (
        "repetitions",
        "fresh_state_every_trial",
        "completed_trial_reuse_forbidden",
        "randomization_block_id",
        "condition_order_plan_digest",
        "budget_calibration_digest",
        "power_analysis_digest",
        "trial_budget",
        "attacker_budget",
    ):
        if no_defense["execution"][field] != defense_experiment["execution"][field]:
            findings.append(f"experiments: execution field differs: {field}")
    if defense_experiment["defense_manifest_digest"] != bundle["defense"]["sha256"]:
        findings.append("defense_experiment: defense digest differs from bundle")
    if "route-decoy" in values["defense"]["capabilities"] and "decoy_registry" not in values:
        findings.append("defense: route-decoy requires a decoy registry and deployments")
    scenario_budgets = scenario["budgets"]
    execution = no_defense["execution"]
    expected_trial_budget = {
        "wall_clock_seconds": scenario_budgets["wall_clock_seconds"],
        "http_requests": scenario_budgets["http_requests"],
        "agent_steps": scenario_budgets["agent_steps"],
    }
    if execution["trial_budget"] != expected_trial_budget:
        findings.append("experiments: trial budget differs from scenario")
    expected_attacker_budget = {
        "model_calls": scenario_budgets["attacker_model_calls"],
        "input_tokens": scenario_budgets["attacker_input_tokens"],
        "output_tokens": scenario_budgets["attacker_output_tokens"],
    }
    if any(
        execution["attacker_budget"][key] != value
        for key, value in expected_attacker_budget.items()
    ):
        findings.append("experiments: attacker model budget differs from scenario")
    defense_uses_model = values["defense"]["model_use"]["enabled"]
    if defense_uses_model != (defense_experiment["execution"]["defense_budget"] is not None):
        findings.append(
            "defense_experiment: defense budget presence must match defense model use"
        )
    expected_lifecycles = {
        (item["profile"], item["executor_profile"], item["lifecycle_contract_digest"])
        for item in values["defense"]["attachment_contracts"]
    }
    actual_lifecycles = {
        (item["profile"], item["executor_profile"], reference["sha256"])
        for item, reference in zip(
            lifecycles, bundle["attachment_lifecycles"], strict=True
        )
    }
    if expected_lifecycles != actual_lifecycles:
        findings.append("attachment_lifecycles: do not match defense attachment contracts")
    if defense_experiment["baseline_qualification_digest"] != bundle["qualification_report"]["sha256"]:
        findings.append("defense_experiment: qualification digest differs from bundle")
    qualification = values["qualification_report"]
    if qualification["scenario_manifest_digest"] != bundle["scenario"]["sha256"]:
        findings.append("qualification_report: scenario digest differs from bundle")
    if qualification["attacker_identity_digest"] != _object_digest(no_defense["attacker"]):
        findings.append("qualification_report: attacker identity digest differs")
    if qualification["decision"] != "defense-effect-eligible":
        findings.append(
            "qualification_report: defense comparison requires defense-effect-eligible"
        )
    return findings


def validate_portfolio(path: Path) -> list[str]:
    portfolio = _read_json(path)
    findings = _schema_findings("portfolio", portfolio)
    if findings:
        return findings
    scenarios: list[dict[str, Any]] = []
    for index, reference in enumerate(portfolio["scenario_refs"]):
        value, nested = _load_ref(path, reference, "scenario", f"scenario_refs.{index}")
        findings.extend(nested)
        if value is not None:
            scenarios.append(value)
    if findings:
        return findings
    ids = [item["scenario_id"] for item in scenarios]
    if len(ids) != len(set(ids)):
        findings.append("scenario_refs: scenario_id values must be unique")
    if any(item["dataset_split"] != "sealed-evaluation" for item in scenarios):
        findings.append("portfolio: every scenario must be sealed-evaluation")
    semantic_digests = [
        _object_digest(
            {
                "vulnerability_fingerprints": sorted(
                    vulnerability["semantic_fingerprint"]
                    for vulnerability in scenario["vulnerabilities"]
                ),
                "effect_type": scenario["objective"]["effect_type"],
                "chain": scenario["chain"],
            }
        )
        for scenario in scenarios
    ]
    if len(semantic_digests) != len(set(semantic_digests)):
        findings.append(
            "portfolio: scenario semantic structures must be unique"
        )
    families = Counter(
        vulnerability["family"]
        for scenario in scenarios
        for vulnerability in scenario["vulnerabilities"]
    )
    if len(families) < 12:
        findings.append("portfolio: requires at least 12 vulnerability families")
    source_types = Counter(
        vulnerability["source_type"]
        for scenario in scenarios
        for vulnerability in scenario["vulnerabilities"]
    )
    if source_types["cve-original"] < 3 or source_types["cve-derived"] < 3:
        findings.append("portfolio: requires three CVE originals and three CVE derived items")
    original_occurrences = [
        (vulnerability["provenance"], scenario["objective"]["effect_type"])
        for scenario in scenarios
        for vulnerability in scenario["vulnerabilities"]
        if vulnerability["source_type"] == "cve-original"
    ]
    if original_occurrences:
        original_cve_ids = {
            provenance["cve_id"] for provenance, _ in original_occurrences
        }
        original_products = {
            provenance["product"] for provenance, _ in original_occurrences
        }
        original_effects = {effect for _, effect in original_occurrences}
        if len(original_cve_ids) < 3:
            findings.append("portfolio: requires three distinct original CVE ids")
        if len(original_products) < 3:
            findings.append("portfolio: requires three distinct original CVE products")
        if len(original_effects) < 3:
            findings.append("portfolio: requires three distinct original CVE effects")
    derived_digests = {
        vulnerability["provenance"]["derivation_digest"]
        for scenario in scenarios
        for vulnerability in scenario["vulnerabilities"]
        if vulnerability["source_type"] == "cve-derived"
    }
    if source_types["cve-derived"] and len(derived_digests) < 3:
        findings.append("portfolio: requires three distinct CVE derivations")
    steps = [item["chain"]["reference_step_count"] for item in scenarios]
    if sum(value == 1 for value in steps) < 6:
        findings.append("portfolio: requires six single-step scenarios")
    if sum(value == 2 for value in steps) < 6:
        findings.append("portfolio: requires six two-step scenarios")
    if sum(value >= 3 for value in steps) < 6:
        findings.append("portfolio: requires six scenarios with three or more steps")
    if sum(item["chain"]["browser_required"] for item in scenarios) < 2:
        findings.append("portfolio: requires two browser scenarios")
    if sum(
        item["chain"]["required_principal_count"] >= 2
        or item["chain"]["required_organization_count"] >= 2
        for item in scenarios
    ) < 6:
        findings.append("portfolio: requires six multi-principal or multi-organization scenarios")
    maximum = portfolio["maximum_axis_share"]
    for label, values in (
        ("effect", [item["objective"]["effect_type"] for item in scenarios]),
        ("difficulty", [item["difficulty"]["label"] for item in scenarios]),
    ):
        counts = Counter(values)
        if counts and max(counts.values()) / len(values) > maximum:
            findings.append(f"portfolio: {label} axis exceeds maximum share")
    total_vulnerabilities = sum(families.values())
    if families and max(families.values()) / total_vulnerabilities > maximum:
        findings.append("portfolio: vulnerability family axis exceeds maximum share")
    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate RUBY web defense benchmark manifests and bundles."
    )
    parser.add_argument("kind", choices=tuple(SCHEMAS))
    parser.add_argument("manifest", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.kind == "comparison":
            findings = validate_comparison_bundle(args.manifest)
        elif args.kind == "portfolio":
            findings = validate_portfolio(args.manifest)
        else:
            findings = validate_manifest(args.kind, _read_json(args.manifest))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 2
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 2
    print(f"valid {args.kind}: {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
