#!/usr/bin/env python3
import argparse
import json
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

BASE_URL = "http://127.0.0.1:8000"
ENDPOINTS = ("/api/users/1", "/api/products/1")
ROOT_DIR = Path(__file__).resolve().parent.parent


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def request(path: str, expected_label: str, output) -> None:
    traffic_id = str(uuid4())
    started = utc_now()
    req = urllib.request.Request(
        BASE_URL + path,
        headers={"X-Request-ID": traffic_id, "Connection": "close"},
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        response.read()
        record = {
            "requested_at": started,
            "completed_at": utc_now(),
            "request": f"GET {path}",
            "request_kind": "normal",
            "ground_truth": expected_label,
            "traffic_request_id": traffic_id,
            "apiecho_request_id": response.headers.get("X-APIEcho-Request-ID"),
            "status": response.status,
        }
    output.write(json.dumps(record, sort_keys=True) + "\n")
    output.flush()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=25, help="API별 요청 횟수")
    parser.add_argument("--interval", type=float, default=0.05)
    parser.add_argument("--flush-delay", type=float, default=0.0)
    args = parser.parse_args()

    output_dir = ROOT_DIR / "results" / "traffic"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"normal-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.jsonl"

    with output_path.open("w", encoding="utf-8") as output:
        for _ in range(args.count):
            for endpoint in ENDPOINTS:
                request(endpoint, "normal", output)
                time.sleep(args.interval)
        if args.flush_delay > 0:
            print(f"요청별 이벤트 확정을 위해 {args.flush_delay:.0f}초 동안 기다립니다...")
            time.sleep(args.flush_delay)
            request("/api/products/1", "normal-flush", output)

    print(
        f"정상 요청 {args.count * len(ENDPOINTS)}건을 생성했습니다. "
        f"요청 기록: {output_path}"
    )


if __name__ == "__main__":
    main()
