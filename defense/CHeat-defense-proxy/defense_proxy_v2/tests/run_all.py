#!/usr/bin/env python3
"""tests/ 의 모든 테스트를 순서대로 돌려 요약한다.

    python tests/run_all.py            # 전부
    python tests/run_all.py ambig xff  # 이름에 해당 문자열이 들어간 것만

각 테스트는 독립 실행형 스크립트(PASS/FAIL 을 출력하고 실패하면 종료코드 1)이고, 프록시·스텁 백엔드를 자기 프로세스로 띄우므로
**순서대로(병렬 아님)** 돌린다 — 고정 포트를 쓴다. 필요한 것은 requirements.txt 의 패키지(fastapi·uvicorn·httpx)뿐이다.
"""
import glob
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TIMEOUT_S = 600


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):          # Windows 한글 콘솔(cp949)에서 특수문자 때문에 죽지 않게
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    wanted = sys.argv[1:]
    files = sorted(glob.glob(os.path.join(HERE, "test_*.py")))
    if wanted:
        files = [f for f in files if any(w in os.path.basename(f) for w in wanted)]
    if not files:
        print("실행할 테스트가 없다")
        return 1
    env = {**os.environ, "PYTHONUTF8": "1"}
    results = []
    for f in files:
        name = os.path.basename(f)
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, f], capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=TIMEOUT_S, env=env, cwd=HERE)
            ok, out = r.returncode == 0, r.stdout + r.stderr
        except subprocess.TimeoutExpired as e:
            ok, out = False, f"시간 초과({TIMEOUT_S}s)\n" + ((e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
        dt = time.time() - t0
        results.append((name, ok, dt))
        print(f"{'PASS' if ok else 'FAIL'}  {name}  ({dt:.0f}s)", flush=True)
        if not ok:
            lines = [ln for ln in out.splitlines() if ln.startswith("FAIL") or "Traceback" in ln or "Error" in ln]
            for ln in (lines or out.splitlines()[-10:])[:15]:
                print("      " + ln)
    bad = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(bad)}/{len(results)} 통과" + (f" — 실패: {', '.join(bad)}" if bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
