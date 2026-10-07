"""기본 설정의 동작 스냅샷(레시피·가짜 셸 출력·미로 응답·HTTP 응답)이 기준선(golden_reference.json)과 같은지.

기준선은 "지금 동작이 바뀌지 않았는가"를 보는 회귀 안전망이다. 동작을 **의도적으로** 바꿨다면 아래로 기준선을 다시 만든다:

    python tests/golden_snapshot.py tests/golden_reference.json

스텁 백엔드 파일의 `last-modified` 헤더(실행할 때마다 바뀜)는 비교에서 뺀다.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REF = os.path.join(HERE, "golden_reference.json")
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


def strip(snap):
    for key, entry in snap.get("http", {}).items():
        if isinstance(entry, dict) and isinstance(entry.get("headers"), dict):
            entry["headers"].pop("last-modified", None)
            # These headers are private sidecar -> official Defense telemetry,
            # intentionally removed from the public response by Defense.
            entry["headers"].pop("x-ruby-decoy-action", None)
            entry["headers"].pop("x-ruby-decoy-strategies", None)
        if key == "GET /robots.txt" and isinstance(entry, dict):
            # The stub's existing first line varies between CRLF and LF on
            # different hosts; the resulting robots directives are identical.
            entry["body"] = entry["body"].replace("\r\n", "\n")
    return snap


out = os.path.join(tempfile.gettempdir(), "golden_now.json")
r = subprocess.run([sys.executable, os.path.join(HERE, "golden_snapshot.py"), out], capture_output=True, text=True,
                   encoding="utf-8", env={**os.environ, "PYTHONUTF8": "1"})
check("스냅샷 생성", r.returncode == 0 and os.path.exists(out), r.stderr[-300:])
if r.returncode == 0:
    ref = strip(json.load(open(REF, encoding="utf-8")))
    now = strip(json.load(open(out, encoding="utf-8")))
    check("스냅샷 키 구성이 같음", set(ref) == set(now), (sorted(ref), sorted(now)))
    for k in sorted(ref):
        if ref[k] == now.get(k):
            check(f"{k} 동일", True)
        elif isinstance(ref[k], dict):
            diff = [kk for kk in ref[k] if ref[k][kk] != now[k].get(kk)]
            check(f"{k} 동일", False, f"달라진 항목 {diff[:5]}")
        else:
            check(f"{k} 동일", False)

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
