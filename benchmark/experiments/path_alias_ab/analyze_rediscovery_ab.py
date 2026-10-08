"""Validate and summarize the six cache-neutral Docker A/B windows."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import statistics


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, int((len(ordered) * fraction + 0.999999)) - 1)]


def describe(values):
    return {"samples": len(values), "median": statistics.median(values) if values else None,
            "p95": percentile(values, .95),
            "mean": statistics.mean(values) if values else None}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    comparison = json.loads((run / "comparison.json").read_text(encoding="utf-8"))
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    results = comparison["results"]
    expected_order = ["A", "B", "B", "A", "A", "B"]
    reasons = []
    if not comparison.get("complete") or len(results) != 6:
        reasons.append("Six completed windows are required")
    if [item["arm"] for item in results] != expected_order:
        reasons.append("Unexpected A/B order")
    windows = []
    by_arm = defaultdict(list)
    for result in results:
        path = run / f'{result["index"]:02d}-rediscovery-{result["arm"]}'
        events = [json.loads(line) for line in (path / "events.jsonl").read_text(
            encoding="utf-8").splitlines()]
        rediscoveries = [event for event in events if event.get("type") == "rediscovery"]
        cycles = [event for event in events if event.get("type") == "cycle"]
        if (result["exitCode"] or not result["complete"] or result["failures"] or
                result["protocolFailures"] or result["browserCache304"] or
                result["elapsedSeconds"] < 899 or len(rediscoveries) < 19 or
                any(not event["success"] for event in rediscoveries)):
            reasons.append(f'Window {result["index"]} failed a validity gate')
        window = {"index": result["index"], "arm": result["arm"],
                  "elapsedSeconds": result["elapsedSeconds"], "cycles": len(cycles),
                  "rediscoveries": len(rediscoveries), "cache304": result["browserCache304"],
                  "directRotations": result["rotationCountsIncludingWarmup"].get("direct", 0),
                  "rediscoveryMs": describe([x["elapsedMs"] for x in rediscoveries]),
                  "browserRequests": describe([x["browserRequests"] for x in rediscoveries]),
                  "mainJsRequests": sum(x["mainJsRequests"] for x in rediscoveries),
                  "networkBytes": describe([x["networkBytes"] for x in rediscoveries]),
                  "jsBytes": describe([x["jsBytes"] for x in rediscoveries])}
        windows.append(window)
        by_arm[result["arm"]].extend(rediscoveries)
    arms = {}
    for arm in ("A", "B"):
        rows = by_arm[arm]
        arms[arm] = {"rediscoveries": len(rows),
                     "rediscoveryMs": describe([x["elapsedMs"] for x in rows]),
                     "browserRequests": describe([x["browserRequests"] for x in rows]),
                     "mainJsRequests": sum(x["mainJsRequests"] for x in rows),
                     "networkBytes": describe([x["networkBytes"] for x in rows]),
                     "jsBytes": describe([x["jsBytes"] for x in rows])}
    report = {"valid": not reasons, "invalidReasons": reasons,
              "method": "same public-page reload/search recipe; Chromium cache disabled in both arms",
              "order": expected_order, "manifest": str(run / "manifest.json"),
              "windows": windows, "arms": arms,
              "limits": manifest["limits"]}
    (run / "analysis.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
