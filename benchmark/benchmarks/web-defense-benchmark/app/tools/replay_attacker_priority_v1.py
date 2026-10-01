from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from autonomous_trial_v2 import (
    _lane_budget_policy,
    _lane_priorities,
    _public_input_surfaces,
    _response_shape_signature,
    _route_family,
    _route_group,
    _update_lane_evidence,
)


def _snapshot(
    *,
    request_index: int,
    max_requests: int,
    surfaces: list[dict[str, object]],
    endpoints: dict[tuple[str, str], dict[str, object]],
    lanes: dict[str, dict[str, object]],
) -> dict[str, object]:
    priorities = _lane_priorities(
        surfaces,
        endpoints,
        lanes,
        used_requests=request_index,
        max_requests=max_requests,
    )
    return {
        "request_index": request_index,
        "budget_policy": _lane_budget_policy(
            priorities,
            used_requests=request_index,
            max_requests=max_requests,
        ),
        "top_priorities": priorities[:8],
    }


def replay_report(path: Path, *, max_requests: int = 100) -> dict[str, object]:
    report = json.loads(path.read_text(encoding="utf-8"))
    endpoints: dict[tuple[str, str], dict[str, object]] = {}
    lanes: dict[str, dict[str, object]] = {}
    surfaces: list[dict[str, object]] = []
    selected_groups: Counter[str] = Counter()
    snapshots: list[dict[str, object]] = []
    request_index = 0
    checkpoints = {
        max(1, max_requests - 2 * max(4, -(-max_requests // 5))),
        max(1, max_requests - max(4, -(-max_requests // 5))),
    }

    for interaction in report.get("interactions", []):
        if not isinstance(interaction, dict) or interaction.get("kind") != "http":
            continue
        request_index += 1
        action = {
            "kind": "http",
            "session": interaction.get("session", "anon"),
            "method": interaction.get("method", "GET"),
            "path": interaction.get("path", "/"),
            "headers": None,
            "body_json": None,
            "body_form": None,
            "body_multipart": None,
        }
        result = {
            "status": interaction.get("status", 0),
            "response": interaction.get("response", ""),
        }
        _update_lane_evidence(
            lanes,
            endpoints,
            action,
            result,
            request_index=request_index,
        )
        method = str(action["method"])
        route = _route_family(action["path"])
        status = int(result["status"])
        response = str(result["response"])
        state = endpoints.setdefault(
            (method, route),
            {
                "attempts": 0,
                "statuses": {},
                "response_shapes": set(),
                "sessions": set(),
            },
        )
        state["attempts"] = int(state["attempts"]) + 1
        state["statuses"][str(status)] = int(
            state["statuses"].get(str(status), 0)
        ) + 1
        state["response_shapes"].add(_response_shape_signature(response))
        state["sessions"].add(str(action["session"]))
        selected_groups[_route_group(action["path"])] += 1
        if route == "/openapi.json" and status == 200:
            discovered = _public_input_surfaces(response)
            if discovered:
                surfaces = discovered
        if request_index in checkpoints:
            snapshots.append(
                _snapshot(
                    request_index=request_index,
                    max_requests=max_requests,
                    surfaces=surfaces,
                    endpoints=endpoints,
                    lanes=lanes,
                )
            )

    if not snapshots or snapshots[-1]["request_index"] != request_index:
        snapshots.append(
            _snapshot(
                request_index=request_index,
                max_requests=max_requests,
                surfaces=surfaces,
                endpoints=endpoints,
                lanes=lanes,
            )
        )
    return {
        "source_report": str(path),
        "target_id": report.get("target_id"),
        "historical_status": report.get("status"),
        "historical_objective_achieved": report.get("objective_achieved"),
        "http_interactions": request_index,
        "historical_group_counts": dict(selected_groups.most_common()),
        "snapshots": snapshots,
        "interpretation_limit": (
            "Counterfactual ranking of recorded observations only. It does not "
            "claim that the historical outcome would change."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-requests", type=int, default=100)
    args = parser.parse_args()
    result = {
        "schema_version": 1,
        "max_requests": args.max_requests,
        "reports": [
            replay_report(path, max_requests=args.max_requests)
            for path in args.reports
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
