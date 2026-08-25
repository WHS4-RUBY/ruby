#!/usr/bin/env python3
import argparse
import json
import math
import re
from datetime import UTC, datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


def latest_run() -> Path:
    runs = [path for path in (ROOT_DIR / "results" / "runs").iterdir() if path.is_dir()]
    if not runs:
        raise RuntimeError("no APIEcho run directory found")
    return max(runs, key=lambda path: path.stat().st_mtime)


def parse_threshold(config: str) -> float:
    match = re.search(r"\n\s+threshold:\s*([0-9.]+)", config)
    if not match:
        raise RuntimeError("설정에서 DistanceDetector 임계값을 찾지 못했습니다.")
    return float(match.group(1))


def parse_dump(path: Path) -> list[dict[str, object]]:
    records = []
    text = path.read_text(encoding="utf-8")
    for block in text.split("------------------------------------------"):
        label_match = re.search(r"Label: (True|False)", block)
        vector_match = re.search(r"Vector: \[([^\]]+)\]", block, re.DOTALL)
        request_match = re.search(r"GET /[^ \".]+(?:\?[^ \".]*)?", block)
        uid_match = re.match(r"\s*([0-9a-f-]{36})", block)
        if not all((label_match, vector_match, request_match, uid_match)):
            continue
        vector = [float(item) for item in vector_match.group(1).split()]
        request = request_match.group(0)
        is_anomaly_request = "experiment=anomaly" in request
        records.append(
            {
                "unit_id": uid_match.group(1),
                "api_category": path.stem,
                "request": request,
                "request_kind": "anomaly" if is_anomaly_request else "normal",
                "ground_truth": "anomaly" if is_anomaly_request else "normal",
                "predicted_anomaly": label_match.group(1) == "True",
                "derived_anomaly_score": math.sqrt(sum(value * value for value in vector)),
                "vector": vector,
            }
        )
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", nargs="?", type=Path)
    args = parser.parse_args()
    run_dir = args.run_dir.resolve() if args.run_dir else latest_run()
    config_path = run_dir / "config.yaml"
    dump_dir = run_dir / "dump_results"
    if not config_path.exists() or not dump_dir.exists():
        raise RuntimeError(f"incomplete APIEcho run: {run_dir}")

    records = []
    for path in sorted(dump_dir.glob("*.txt")):
        records.extend(parse_dump(path))
    if not records:
        raise RuntimeError(f"no DistanceDetector records found in {dump_dir}")

    threshold = parse_threshold(config_path.read_text(encoding="utf-8"))
    anomaly_records = [record for record in records if record["request_kind"] == "anomaly"]
    normal_records = [record for record in records if record["request_kind"] == "normal"]
    detected_anomalies = [record for record in anomaly_records if record["predicted_anomaly"]]
    false_positive_normals = [record for record in normal_records if record["predicted_anomaly"]]

    summary = {
        "summarized_at_utc": datetime.now(UTC).isoformat(),
        "run_dir": str(run_dir),
        "threshold": threshold,
        "score_definition": "L2 norm of the vector, exactly as DistanceDetector computes it",
        "counts": {
            "units": len(records),
            "normal_units": len(normal_records),
            "anomaly_units": len(anomaly_records),
            "detected_anomaly_units": len(detected_anomalies),
            "false_positive_normal_units": len(false_positive_normals),
        },
        "detection_passed": bool(detected_anomalies) and not false_positive_normals,
        "records": records,
        "raw_log_locations": {
            "scap": str(ROOT_DIR / "results" / "captured"),
            "apiecho_log": str(run_dir / "apiecho.log"),
            "original_jsonl": str(run_dir / "output.jsonl"),
            "dump_results": str(dump_dir),
        },
    }
    output_path = run_dir / "detection-summary.json"
    output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    counts = summary["counts"]
    print(f"탐지 결과를 저장했습니다: {output_path}")
    print(
        "처리 결과: "
        f"전체 {counts['units']}건, "
        f"정상 {counts['normal_units']}건, "
        f"이상 {counts['anomaly_units']}건, "
        f"탐지한 이상 {counts['detected_anomaly_units']}건, "
        f"정상 오탐 {counts['false_positive_normal_units']}건"
    )
    if not summary["detection_passed"]:
        raise RuntimeError("APIEcho 이상 탐지 검증 기준을 충족하지 못했습니다.")


if __name__ == "__main__":
    main()
