"""defense_proxy_v2(기본 설정)의 동작 스냅샷을 JSON 으로 만든다 — test_golden.py 가 기준선과 비교한다.

usage: python golden_snapshot.py <out.json> [KEY=VAL ...]
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time

OUT = os.path.abspath(sys.argv[1])
for kv in sys.argv[2:]:
    k, v = kv.split("=", 1)
    os.environ[k] = v

DEF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRATCH = os.path.dirname(os.path.abspath(__file__))

# ---- 1) module-level snapshot (time frozen) --------------------------------
_real_strftime = time.strftime
time.strftime = lambda fmt, *a: "FIXED"
os.chdir(DEF_DIR)
sys.path.insert(0, DEF_DIR)
os.environ["DEFENSE_MODE"] = "off"
os.environ["DEFENSE_DB"] = os.path.join(tempfile.gettempdir(), "golden_mod.db")
import transforms  # noqa: E402
import Defense_proxy as dp  # noqa: E402

snap = {}
snap["recipes"] = transforms.RECIPES
snap["recipe_T21+MIG"] = transforms.recipe_for("T2.1+MIGRATION_TRACES")
cmds = ["id", "whoami", "uname -a", "cat /etc/passwd", "cat /etc/shadow", "sudo -l",
        "sudo /opt/ops/backup.sh", "/opt/ops/backup.sh --target=prod",
        "/opt/ops/backup.sh --target=prod --yes",
        "cat /var/backups/db-prod-FIXED.tar.gz", "find / -perm -4000 2>/dev/null",
        "ls -la /usr/local/bin/backup-helper", "pwd", "cd /tmp", "ls", "ls -la /var/www",
        "curl http://10.0.4.12:5432", "nc 10.0.4.12 5432", "curl http://example.com",
        "echo hi > /tmp/x", "cat /etc/hosts", "foobar", "id; whoami && uname -a",
        "hostname", "ps aux", "env", "touch /tmp/a", "head -n1 /etc/passwd"]
snap["shell"] = {c: transforms.fake_shell_response(c, {}) for c in cmds}
snap["garbled"] = {f"{c}#{i}": transforms.fake_shell_garbled(c, i) for c in ("id", "x") for i in (1, 2, 3)}
snap["maze"] = {p: transforms.maze_response(p, 1, 1, {"version", "bridge", "inventory", "ssh", "docs"}).decode("utf-8")
                for p in ("/internal/ops/runbook", "/server-status", "/.ssh/id_rsa", "/internal/endpoints", "/x.bak")}
snap["robots"] = transforms.synth_robots(b"User-agent: *\nDisallow: /ftp", ["/a/", "/b/"], "# c").decode()
snap["shell_re"] = {"pattern": dp._FAKE_SHELL_RE.pattern, "flags": int(dp._FAKE_SHELL_RE.flags),
                    "matches": {p: bool(dp._FAKE_SHELL_RE.search(p)) for p in
                                ("/cgi-bin/x/bin/sh", "/cgi-bin/.%2e/bin/bash?x=1", "/bin/sh", "/cgi-bin/passwd",
                                 "/ops/console/exec")}}
snap["maze_version_default"] = dp.MAZE_VERSION

# ---- 2) HTTP-level snapshot (proxy in front of a stub backend) ---------------
time.strftime = _real_strftime
STUB = tempfile.mkdtemp(prefix="golden_stub_")
open(os.path.join(STUB, "index.html"), "w", encoding="utf-8").write(
    "<html><head><title>x</title></head><body>hi</body></html>")
open(os.path.join(STUB, "robots.txt"), "w", encoding="utf-8").write("User-agent: *\nDisallow: /ftp")

import httpx  # noqa: E402

env = dict(os.environ)
env.update({"REAL_BACKEND": "http://127.0.0.1:3097", "DEFENSE_MODE": "transform",
            "ACTIVE_TECHNIQUE": env.get("GOLDEN_TECH", "T2.1+MIGRATION_TRACES"),
            "FAKE_SHELL": "1", "DEFENSE_DB": os.path.join(tempfile.gettempdir(), "golden_http.db"),
            "SPOOF_SERVER": "nginx"})
if os.path.exists(env["DEFENSE_DB"]):
    os.remove(env["DEFENSE_DB"])
stub = subprocess.Popen([sys.executable, "-m", "http.server", "3097", "--directory", STUB],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
proxy = subprocess.Popen([sys.executable, "-m", "uvicorn", "Defense_proxy:app", "--host", "127.0.0.1",
                          "--port", "3015", "--log-level", "warning"],
                         cwd=DEF_DIR, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
http = {}
try:
    for _ in range(40):
        try:
            httpx.get("http://127.0.0.1:3015/", timeout=1)
            break
        except Exception:
            time.sleep(0.25)

    def norm(t):
        t = re.sub(r"(Current Time|Restart Time): [^<]*", r"\1: T", t)
        t = re.sub(r"\d{4}-\d{2}-\d{2}", "DATE", t)
        return t

    def grab(method, path, **kw):
        r = httpx.request(method, "http://127.0.0.1:3015" + path, timeout=10, **kw)
        hdrs = {k: v for k, v in r.headers.items() if k.lower() not in ("date", "content-length")}
        return {"status": r.status_code, "headers": hdrs, "body": norm(r.text)}

    for p in ("/", "/robots.txt", "/server-status", "/cgi-bin/x/etc/passwd", "/cgi-bin/zzz",
              "/rest/internal", "/rest/internal/status", "/rest/internal/users", "/nope.html"):
        http["GET " + p] = grab("GET", p)
    http["POST login lure"] = grab("POST", "/rest/user/login", content=b'{"email":"migration@x"}')
    for c in ("whoami", "id", "uname -a", "cat /etc/passwd", "sudo -l"):
        http["POST shell " + c] = grab("POST", "/cgi-bin/x/bin/sh", content=c.encode())
finally:
    proxy.terminate()
    stub.terminate()
    proxy.wait(timeout=10)
    stub.wait(timeout=10)

snap["http"] = http
json.dump(snap, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1, sort_keys=True)
print("snapshot written:", OUT, "| http entries:", len(http), "| shell cmds:", len(snap["shell"]))
