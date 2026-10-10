"""Cookieless issuance flood and concurrent rotation against one Defense (N workers, one SQLite file).

Usage: python load_sqlite.py <label> <requests> <concurrency> [path]
"""
import asyncio
import json
import re
import statistics
import subprocess
import sys
import time

import httpx

LABEL, TOTAL, CONC = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
PATH = sys.argv[4] if len(sys.argv) > 4 else "/main.js"
STYLE = sys.argv[5] if len(sys.argv) > 5 else "nocookie"  # nocookie | cookie | rotate
BASE = "http://127.0.0.1:18090"
CONTAINER = "ruby-load-defense"


def db_stats():
    code = ("import sqlite3,os;p='/app/alias-data/path-alias.sqlite3';db=sqlite3.connect(p);"
            "c=db.execute('SELECT COUNT(*), COALESCE(SUM(confirmed=0),0) FROM path_alias_client_state').fetchone();"
            "r=db.execute('SELECT COUNT(*) FROM path_alias_alias_rows').fetchone()[0];"
            "s=sum(os.path.getsize(p+x) for x in ('','-wal','-shm') if os.path.exists(p+x));"
            "print(c[0],c[1],r,s)")
    out = subprocess.run(["docker", "exec", CONTAINER, "python", "-c", code], capture_output=True, text=True).stdout.split()
    return dict(zip(("clients", "pending", "rows", "db_bytes"), map(int, out))) if out else {}


async def main():
    latencies, statuses, errors = [], {}, 0
    queue = asyncio.Queue()
    for i in range(TOTAL):
        queue.put_nowait(i)
    async with httpx.AsyncClient(timeout=60, limits=httpx.Limits(max_connections=CONC)) as client:
        async def worker():
            nonlocal errors
            cookie = ""
            if STYLE in ("cookie", "rotate"):
                first = await client.get(BASE + "/main.js", headers={"cookie": ""})
                issued = re.search(r"ruby_alias_client=([a-z2-7]{26})", " ".join(first.headers.get_list("set-cookie")))
                cookie = "ruby_alias_client=" + issued.group(1) if issued else ""
            while True:
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                started = time.perf_counter()
                try:
                    r = await client.get(BASE + PATH, headers={"cookie": cookie})
                    statuses[r.status_code] = statuses.get(r.status_code, 0) + 1
                except httpx.HTTPError:
                    errors += 1
                latencies.append((time.perf_counter() - started) * 1000)
        before = db_stats()
        t0 = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(CONC)))
        elapsed = time.perf_counter() - t0
    latencies.sort()
    after = db_stats()
    print(json.dumps({"label": LABEL, "path": PATH, "requests": TOTAL, "concurrency": CONC, "style": STYLE,
                      "seconds": round(elapsed, 1), "rps": round(TOTAL / elapsed, 1), "statuses": statuses,
                      "transport_errors": errors,
                      "latency_ms": {"p50": round(statistics.median(latencies), 1),
                                     "p95": round(latencies[int(len(latencies) * 0.95) - 1], 1),
                                     "max": round(latencies[-1], 1)},
                      "db_before": before, "db_after": after}))


asyncio.run(main())
