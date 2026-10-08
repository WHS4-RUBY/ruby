"""MIGRATION_TRACES 서버별 값(profile.migration) — 레시피 생성·설치 마법사·실제 프록시 동작."""
import json
import os
import subprocess
import sys
import tempfile
import time

import httpx

DEF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRATCH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, DEF_DIR)
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


print("== (A) 레시피 생성 ==")
import profiles
import transforms

prof = profiles.build_profile("apache-php", {"migration": {
    "api_prefix": "/api/internal", "bridge_version": "1.2.0", "endpoints": ["customers", "daily-export"],
    "lure_match": ["svc-sync@shop.example"], "memo_path": "/app/config/live.yml",
    "robots_disallow": ["/api/internal/"], "config_path": "/api/settings"}})
transforms.configure(prof)
rec = transforms.build_recipes()["MIGRATION_TRACES"]
paths = [r.get("path") or r.get("path_prefix") for r in rec["routes"]]
check("라우트가 api_prefix 아래", paths == ["/api/internal", "/api/internal/status", "/api/internal/"], paths)
st = json.loads(rec["routes"][0]["body"])
check("상태 JSON: 엔드포인트·버전", st["endpoints"] == ["/api/internal/customers", "/api/internal/daily-export"]
      and st["version"] == "1.2.0-rc2", st)
check("헤더 X-Backend-Bridge", rec["headers"] == {"X-Backend-Bridge": "legacy-admin-bridge/1.2.0"}, rec["headers"])
check("HTML 메모 주석의 경로", "/app/config/live.yml" in rec["html_comment"], rec["html_comment"])
check("401 키워드가 엔드포인트에서 파생(daily-export → daily, export)",
      rec["routes"][2]["match_any"] == ["customers", "daily", "export", "status"], rec["routes"][2]["match_any"])
check("로그인 미끼 문자열", rec["login_lure"]["match"] == ["svc-sync@shop.example"], rec["login_lure"]["match"])
check("robots", rec["robots_disallow"] == ["/api/internal/"], rec["robots_disallow"])
check("설정 병합 경로·값", rec["rewrite"][0]["path_re"] == "^/api/settings$"
      and rec["rewrite"][0]["json_merge"] == {"config": {"adminBridgeBase": "/api/internal"}}, rec["rewrite"])
transforms.configure(profiles.build_profile("nginx-fastapi", {"migration": {}}))
rec2 = transforms.build_recipes()["MIGRATION_TRACES"]
check("config_path 빈 값이면 병합 없음(nginx-fastapi)", rec2["rewrite"] == [], rec2["rewrite"])
check("nginx-fastapi 기본: /api/internal, 도메인 명사", json.loads(rec2["routes"][0]["body"])["endpoints"][0] == "/api/internal/customers")
try:
    profiles.build_profile("apache-php", {"migration": {"api_prefixx": "/x"}})
    check("오타 필드는 에러", False)
except ValueError:
    check("오타 필드는 에러", True)

print("== (B) 설치 마법사(비대화형) ==")
out = os.path.join(tempfile.gettempdir(), "mig_profile.json")
r = subprocess.run([sys.executable, "setup_profile.py", "--preset", "apache-php", "--yes", "--out", out,
                    "--set", "migration.api_prefix=/api/internal",
                    "--set", 'migration.lure_match=["svc-sync@shop.example"]',
                    "--set", "migration.login_path=/api/v9/identity/enter",
                    "--set", "migration.config_path="],
                   cwd=DEF_DIR, capture_output=True, text=True, encoding="utf-8", env={**os.environ, "PYTHONUTF8": "1"})
print(r.stdout.strip().splitlines()[0:4])
saved = json.load(open(out, encoding="utf-8"))
mig = saved.get("migration", {})
check("저장된 JSON 에 바꾼 필드만", set(mig) == {"api_prefix", "lure_match", "login_path", "config_path", "robots_disallow"}, mig)
check("robots 힌트가 접두어를 따라감", mig.get("robots_disallow") == ["/api/internal/", "/admin-bridge/"], mig)
check("리스트 값 파싱", mig.get("lure_match") == ["svc-sync@shop.example"], mig.get("lure_match"))

print("== (C) 실제 프록시 ==")
env = dict(os.environ)
env.update({"REAL_BACKEND": "http://127.0.0.1:4701", "DEFENSE_MODE": "transform", "ACTIVE_TECHNIQUE": "MIGRATION_TRACES",
            "TARGET_PROFILE": out, "DEFENSE_DB": os.path.join(tempfile.gettempdir(), "mp.db"), "PYTHONUTF8": "1",
            "PREFLIGHT": "0"})
if os.path.exists(env["DEFENSE_DB"]):
    os.remove(env["DEFENSE_DB"])
stub = subprocess.Popen([sys.executable, os.path.join(SCRATCH, "stub_srv.py"), "4701", "404", "none"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
proxy = subprocess.Popen([sys.executable, "-m", "uvicorn", "Defense_proxy:app", "--host", "127.0.0.1", "--port", "4702",
                          "--no-server-header", "--log-level", "warning"], cwd=DEF_DIR, env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(60):
        try:
            httpx.get("http://127.0.0.1:4702/", timeout=1); break
        except Exception:
            time.sleep(0.25)
    B = "http://127.0.0.1:4702"
    r = httpx.get(B + "/api/internal")
    check("가짜 브리지 상태 200 (/api/internal)", r.status_code == 200 and "legacy-admin-bridge" in r.text, (r.status_code, r.text[:60]))
    r = httpx.get(B + "/api/internal/users")
    check("토끼굴 401", r.status_code == 401, r.status_code)
    r = httpx.get(B + "/rest/internal")
    check("예전 접두어 /rest/internal 은 더 이상 가로채지 않음", r.status_code == 404, r.status_code)
    r = httpx.get(B + "/robots.txt")
    check("robots 에 새 접두어", "/api/internal/" in r.text and "/rest/internal/" not in r.text, r.text)
    r = httpx.post(B + "/api/v9/identity/enter", json={"email": "svc-sync@shop.example", "password": "x"})
    check("비표준 로그인 경로 + 미끼 계정 → 423", r.status_code == 423, (r.status_code, r.text[:60]))
    r = httpx.post(B + "/api/v9/identity/enter", json={"email": "someone@shop.example", "password": "x"})
    check("다른 계정은 백엔드로(423 아님)", r.status_code != 423, r.status_code)
    r = httpx.post(B + "/rest/user/login", json={"email": "svc-sync@shop.example", "password": "x"})
    check("프로필 밖 경로(/rest/user/login)는 일반 로그인 판별(login 키워드)이라 여전히 423", r.status_code == 423, r.status_code)
finally:
    proxy.terminate(); stub.terminate(); proxy.wait(timeout=10); stub.wait(timeout=10)

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
