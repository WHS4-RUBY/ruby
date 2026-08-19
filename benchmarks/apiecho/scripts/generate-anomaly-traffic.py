#!/usr/bin/env python3
import argparse
import json
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

BASE_URL = "http://127.0.0.1:8000"
ROOT_DIR = Path(__file__).resolve().parent.parent


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def send(path: str, kind: str, label: str, output) -> None:
    traffic_id = str(uuid4())
    started = utc_now()
    req = urllib.request.Request(
        BASE_URL + path,
        headers={"X-Request-ID": traffic_id, "Connection": "close"},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        response.read()
        record = {
            "requested_at": started,
            "completed_at": utc_now(),
            "request": f"GET {path}",
            "request_kind": kind,
            "ground_truth": label,
            "traffic_request_id": traffic_id,
            "apiecho_request_id": response.headers.get("X-APIEcho-Request-ID"),
            "status": response.status,
            "behavior": "container-local temp/passwd file IO, shell subprocess, loopback connect",
        }
    output.write(json.dumps(record, sort_keys=True) + "\n")
    output.flush()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--flush-delay", type=float, default=0.0)
    args = parser.parse_args()

    output_dir = ROOT_DIR / "results" / "traffic"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"anomaly-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.jsonl"

    with output_path.open("w", encoding="utf-8") as output:
        send("/api/users/1?experiment=anomaly", "anomaly", "anomaly", output)
        if args.flush_delay > 0:
            print(f"요청별 이벤트 확정을 위해 {args.flush_delay:.0f}초 동안 기다립니다...")
            time.sleep(args.flush_delay)
            send("/api/products/1", "normal", "normal-flush", output)

    print(f"이상 요청 1건을 생성했습니다. 요청 기록: {output_path}")


if __name__ == "__main__":
    main()
