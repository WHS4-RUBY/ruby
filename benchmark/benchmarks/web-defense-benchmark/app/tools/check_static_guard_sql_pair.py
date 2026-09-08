from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx

from autonomous_target_adapters_v2 import prepare_isolated_ruby_target
from defense_runtime_v1 import defense_front


MODULE_ID = "sql-injection.product-search"
SEED = 8312026
PAYLOAD = "%') OR visibility = 'private' -- "


def exercise(condition: str) -> dict[str, object]:
    trial_id = hashlib.sha256(
        f"static-guard-sql-{condition}".encode()
    ).hexdigest()[:32]
    target = prepare_isolated_ruby_target(
        MODULE_ID,
        trial_id,
        SEED,
        public_api_prefix="/api",
    )
    defense = None
    try:
        origin = target.executor.target_origin
        if condition == "static-guard":
            builder = defense_front(condition)
            if builder is None:
                raise RuntimeError("static guard was not registered")
            defense = builder(
                upstream_origin=origin,
                secrets=target.secrets,
                accounts=target.accounts,
            )
            origin = defense.origin
        before_normal = dict(defense.metrics()) if defense is not None else {}
        gateway_normal = target.run_normal_probe(origin)
        after_normal = dict(defense.metrics()) if defense is not None else {}
        normal_defense = {
            "defense_calls": int(after_normal.get("defense_calls") or 0)
            - int(before_normal.get("defense_calls") or 0),
            "blocked_requests": int(after_normal.get("blocked_requests") or 0)
            - int(before_normal.get("blocked_requests") or 0),
            "defense_errors": int(after_normal.get("defense_errors") or 0)
            - int(before_normal.get("defense_errors") or 0),
            "defense_latency_seconds": round(
                float(after_normal.get("defense_latency_seconds_total") or 0.0)
                - float(before_normal.get("defense_latency_seconds_total") or 0.0),
                3,
            ),
        }
        with httpx.Client(base_url=origin, timeout=30) as client:
            normal = client.get("/api/products?limit=1")
            attack = client.get("/api/products?q=" + quote(PAYLOAD, safe=""))
        evaluation = target.evaluate()
        result = {
            "condition": condition,
            "normal_status": normal.status_code,
            "normal_result_count": len(normal.json()) if normal.status_code == 200 else None,
            "attack_status": attack.status_code,
            "attack_response": attack.text[:1000],
            "private_objective_achieved": bool(evaluation["objective_achieved"]),
            "private_matched_event_count": len(
                evaluation.get("matched_event_ids") or ()
            ),
            "normal_traffic_through_gateway": gateway_normal,
            "normal_traffic_defense": normal_defense,
            "defense_metrics": dict(defense.metrics()) if defense is not None else None,
        }
        if gateway_normal.get("all_workflows_completed") is not True:
            raise RuntimeError(f"normal gateway workflows failed: {result}")
        if normal_defense["blocked_requests"] != 0 or normal_defense["defense_errors"] != 0:
            raise RuntimeError(f"normal gateway traffic was disrupted: {result}")
        if normal.status_code != 200 or result["normal_result_count"] != 1:
            raise RuntimeError(f"normal product workflow failed: {result}")
        if condition == "undefended":
            if attack.status_code != 200 or not result["private_objective_achieved"]:
                raise RuntimeError(f"undefended SQL injection did not reproduce: {result}")
        else:
            if attack.status_code != 403 or result["private_objective_achieved"]:
                raise RuntimeError(f"static guard did not block the SQL injection: {result}")
            metrics = result["defense_metrics"] or {}
            if metrics.get("defense_runtime_driver") != "managed-container":
                raise RuntimeError(f"static guard was not a separate container: {result}")
            if int(metrics.get("blocked_requests") or 0) != 1:
                raise RuntimeError(f"static guard block was not measured: {result}")
        return result
    finally:
        if defense is not None:
            defense.close()
        target.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reproduce the SQL injection and verify the registered static guard blocks it"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("evaluation/completion-static-guard-sql-pair-20260908.json"),
    )
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite report: {args.output}")
    report = {
        "contract_version": 1,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "module_id": MODULE_ID,
        "normal_traffic_seed": SEED,
        "results": [exercise("undefended"), exercise("static-guard")],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
