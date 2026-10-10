"""defense.db 스키마가 schema_migrations 로 관리되는지 — 새 파일·레거시·현재 스키마 세 상태에서.

예전에는 try: ALTER TABLE / except OperationalError 로 컬럼을 덧붙였다. 무엇이
적용됐는지 기록이 없어서 되돌릴 수도, 다음 변경을 안전하게 얹을 수도 없었다.
"""
import importlib
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

fails = []
MODULES = ("Defense_proxy", "transforms", "profiles", "store", "proxy_core", "preflight")


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


def make_legacy(path, *, with_isolation_columns):
    extra = ", client_id TEXT DEFAULT '', defense_plan TEXT DEFAULT ''" if with_isolation_columns else ""
    columns = "ts,run,method,path,status,defense_action" + (",client_id,defense_plan"
                                                            if with_isolation_columns else "")
    values = "1,'r','GET','/x',200,'none'" + (",'c','p'" if with_isolation_columns else "")
    with sqlite3.connect(path) as conn:
        conn.executescript(
            "CREATE TABLE runs (run TEXT, mode TEXT, technique TEXT, risk_category TEXT,"
            " action TEXT, started REAL);"
            "CREATE TABLE reqs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, run TEXT,"
            f" method TEXT, path TEXT, status INTEGER, defense_action TEXT{extra});")
        conn.execute(f"INSERT INTO reqs ({columns}) VALUES ({values})")


def snapshot(path):
    with sqlite3.connect(path) as conn:
        return (
            [row[1] for row in conn.execute("PRAGMA table_info(reqs)")],
            sorted(conn.execute("SELECT component,version FROM schema_migrations")),
            conn.execute("SELECT COUNT(*) FROM reqs").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0],
        )


def boot(path):
    """init_db() 는 import 시점에 돌아간다."""
    os.environ["DEFENSE_DB"] = path
    for module in MODULES:
        sys.modules.pop(module, None)
    importlib.import_module("Defense_proxy")


os.environ.setdefault("DEFENSE_MODE", "off")
os.environ.setdefault("PREFLIGHT", "0")
work = tempfile.mkdtemp()
EXPECTED = [("cheat_sidecar", 1), ("cheat_sidecar", 2)]
ISOLATION = {"client_id", "defense_plan"}

cases = [("새 파일", None), ("격리 컬럼 없는 레거시", False), ("현재 스키마", True)]
for label, with_columns in cases:
    db = os.path.join(work, f"{len(fails)}-{label}.db".replace(" ", "_"))
    if with_columns is not None:
        make_legacy(db, with_isolation_columns=with_columns)
    boot(db)
    columns, migrations, reqs, runs = snapshot(db)
    check(f"{label}: 격리 컬럼이 확보된다", ISOLATION <= set(columns), columns)
    check(f"{label}: 적용 버전이 기록된다", migrations == EXPECTED, migrations)
    boot(db)
    columns_again, migrations_again, reqs_again, runs_again = snapshot(db)
    check(f"{label}: 재실행이 스키마를 바꾸지 않는다",
          columns_again == columns and migrations_again == migrations,
          (columns_again, migrations_again))
    check(f"{label}: 기존 요청 행이 보존된다", reqs_again == reqs, (reqs, reqs_again))
    check(f"{label}: 실행 행은 기동마다 하나 늘어난다", runs_again == runs + 1, (runs, runs_again))

print()
print("FAILED: " + ", ".join(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
