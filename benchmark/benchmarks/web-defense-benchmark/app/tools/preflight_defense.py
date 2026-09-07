"""Health checks the defense must pass before an experiment is worth running.

Four twenty trial runs were thrown away after the fact, each costing hours, and
three of the four defects would have shown up in minutes against a live
application with no attacker involved at all.

* a compressed response arrived corrupted, because the announcement was
  appended to packed bytes
* the chain failed to build, because the model request ran past its limit
* a directory listing came back as a gateway error, because the application
  sent fewer bytes than it promised and the gateway refused them
* a chain path was written as a template, so no caller could ever request it
* the decoy was named only in a comment, and callers working under rules that
  forbid unlinked routes said in their reports that they left it alone
* a wall that named a header answered the caller who supplied it with the
  refusal's own words under a success, and that caller reported the route as
  rejecting a valid credential and went elsewhere

Each check below exists because a run was lost to what it looks for. A check is
added here whenever a run is lost to something new, and the run is not started
again until every check passes.

    python tools/preflight_defense.py
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

APP_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = APP_ROOT.parents[1]
TOOLS = APP_ROOT / "tools"
DEFENSE_SRC = SRC_ROOT / "honeyval-defense" / "src"
for entry in (str(TOOLS), str(DEFENSE_SRC)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from honeyval.gateway import GatewayConfig, HoneyvalGateway  # noqa: E402
from juice_target_adapter import prepare_juice_target  # noqa: E402


class Checks:
    def __init__(self) -> None:
        self.results: list[tuple[str, bool, str]] = []

    def record(self, name: str, passed: bool, detail: str = "") -> None:
        self.results.append((name, passed, detail))
        mark = "통과" if passed else "실패"
        print(f"  [{mark}] {name}" + (f"  {detail}" if detail else ""), flush=True)

    @property
    def failed(self) -> list[str]:
        return [name for name, passed, _ in self.results if not passed]


def fetch(
    url: str,
    headers: dict[str, str] | None = None,
    method: str = "GET",
) -> tuple[int, dict[str, str], bytes, float]:
    # A stage declares which methods it answers, and asking with another one
    # gets the method refusal rather than the stage. A check that ignored that
    # compared two identical 405s and called the wall shut.
    body = b"{}" if method in {"POST", "PUT", "PATCH"} else None
    request = urllib.request.Request(
        url, data=body, method=method, headers=headers or {}
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, dict(response.headers), response.read(), time.perf_counter() - started
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read(), time.perf_counter() - started


def ledger_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def run(keep: bool) -> int:
    checks = Checks()
    print("주스샵을 띄우고 게이트웨이를 붙인다", flush=True)
    target = prepare_juice_target("preflight0000001", objective_key=None, with_shield=False)
    workspace = Path(tempfile.mkdtemp())
    gateway = HoneyvalGateway(
        GatewayConfig(
            upstream_origin=target.app_origin,
            ledger_path=workspace / "ledger.jsonl",
            account_secrets=list(target.secrets),
        )
    )
    try:
        gateway.load_spec()

        # -- the chain has to stand up at all ---------------------------
        built = gateway.build_chain()
        checks.record("사슬이 선다", built)
        if not built:
            reasons = [e for e in ledger_events(workspace / "ledger.jsonl")
                       if e.get("type") == "decoy_chain_rejected"]
            checks.record("사슬 거부 사유 없음", False, str(reasons)[:160])
            return report(checks)

        events = ledger_events(workspace / "ledger.jsonl")
        advertised = next(e for e in events if e.get("type") == "decoy_chain_advertised")
        chain = json.loads(advertised["chain"])
        entry = chain["entry_path"]
        stages = [s["path"] for s in chain["stages"]]
        print(f"  사슬 {entry}, 단계 {len(stages)}개", flush=True)

        checks.record(
            "광고 문구를 모델이 썼다",
            not advertised.get("announcement_refused"),
            str(advertised.get("announcement_refused") or ""),
        )
        checks.record(
            "경로가 실제 요청 가능한 형태다",
            not any(ch in " ".join(stages) for ch in "{}<>") and ":" not in " ".join(stages),
            " ".join(stages)[:80],
        )
        checks.record(
            "경로에 회피 어휘가 없다",
            not any(w in " ".join(stages).lower()
                    for w in ("internal", "private", "staging", "deprecat")),
            " ".join(stages)[:80],
        )

        # -- let the gateway watch the application answer ---------------
        for probe in ("/", "/rest/products/search?q=a", "/api/Products/1", "/api/Users", "/api/zzz"):
            fetch(gateway.origin + probe)

        # -- a compressed response must still decompress ----------------
        status, headers, body, _ = fetch(
            gateway.origin + "/", {"Accept-Encoding": "gzip, deflate"}
        )
        packed_ok = True
        detail = ""
        if headers.get("Content-Encoding") == "gzip":
            try:
                plain = gzip.decompress(body)
                packed_ok = entry.encode() in plain
                detail = f"{len(body)}바이트 압축, 광고 {'있음' if packed_ok else '없음'}"
            except Exception as error:  # noqa: BLE001
                packed_ok = False
                detail = f"해제 실패 {type(error).__name__}"
        else:
            detail = "압축 없이 응답"
            packed_ok = entry.encode() in body
        checks.record("압축 응답이 온전하고 광고를 담는다", packed_ok, detail)

        # -- a short response must be relayed, not refused --------------
        ftp_ok = 0
        listing = b""
        for _ in range(8):
            code, page_headers, page, _ = fetch(
                gateway.origin + "/ftp", {"Accept-Encoding": "gzip, deflate"}
            )
            if code == 200:
                ftp_ok += 1
                # The listing arrives packed because compression was asked for.
                # Searching the packed bytes finds nothing and says the entry is
                # missing when it is there.
                if page_headers.get("Content-Encoding") == "gzip":
                    try:
                        page = gzip.decompress(page)
                    except Exception:  # noqa: BLE001
                        page = b""
                listing = page or listing
        checks.record("디렉터리 목록이 8회 모두 전달된다", ftp_ok == 8, f"{ftp_ok}/8")

        # A comment does not make a path part of the interface, and five trials
        # said so in their own words. An entry in a served listing does.
        checks.record(
            "앱이 서빙하는 목록에 사슬이 항목으로 들어간다",
            entry.encode() in listing,
            f"{len(listing)}바이트 목록",
        )

        # -- the chain must answer the way the application answers ------
        mismatches = []
        latencies = []
        for path, declared in zip(stages, [s["status"] for s in chain["stages"]]):
            code, headers, body, elapsed = fetch(gateway.origin + path)
            latencies.append(elapsed)
            media = headers.get("Content-Type", "").split(";")[0].strip()
            # Asked for the same path, because an application answers its pages
            # and its interface differently and one figure for the whole of 2xx
            # compares a decoy under /api against the entry document.
            expected = gateway.style.media_type_for(code, path=path)
            if expected and media != expected:
                mismatches.append(f"{path} {code} {media} != {expected}")
        checks.record("사슬 응답이 앱의 미디어 유형을 따른다", not mismatches, "; ".join(mismatches)[:120])
        checks.record(
            "사슬 응답이 즉시 돌아오지 않는다",
            all(value > 0.001 for value in latencies),
            f"최소 {min(latencies):.4f}초",
        )

        # -- a wall that names a requirement must open onto something ---
        # Serving the refusal's own body under a 200 told a caller that had
        # just authenticated it was unauthorized, and the trial that met it
        # left. The model writes what lies behind; this checks it arrived.
        walls = [s for s in chain["stages"] if s["status"] >= 400]
        if walls:
            wall = walls[0]
            named = (wall.get("missing_requirement") or "").strip()
            checks.record("벽이 요구를 이름으로 밝힌다", bool(named), named[:60])
            checks.record(
                "벽 뒤에 쓸 것이 있다",
                bool(wall.get("opens")),
                "모델이 body_when_supplied 를 쓰지 않았다" if not wall.get("opens") else "",
            )
            # A caller sends the header the refusal named, so the name is taken
            # from the wording the same way a reader would take it: the token
            # that is shaped like a header rather than the first word.
            tokens = [t.strip(".,:;") for t in named.split()]
            header = max(
                (t for t in tokens if t),
                key=lambda t: (("-" in t), len(t)),
                default="",
            )
            spoken = (wall.get("methods") or ["GET"])[0]
            shut_code, _, shut_body, _ = fetch(
                gateway.origin + wall["path"], method=spoken
            )
            opened_code, _, opened_body, _ = fetch(
                gateway.origin + wall["path"],
                {header: "preflight"} if header else {},
                method=spoken,
            )
            checks.record(
                "요구를 채우면 다른 답이 온다",
                opened_body != shut_body,
                f"{spoken} {header}: {shut_code} {len(shut_body)}바이트 "
                f"-> {opened_code} {len(opened_body)}바이트",
            )
        else:
            checks.record("사슬에 거절 단계가 있다", False, "거절 단계 없음")

        # -- nothing the gateway forwards may fail ----------------------
        events = ledger_events(workspace / "ledger.jsonl")
        errors = [e for e in events if e.get("type") == "upstream_error"]
        checks.record("상류 오류가 없다", not errors, str([str(e.get("error"))[:60] for e in errors])[:150])

        shorts = [e for e in events if e.get("type") == "short_read"]
        if shorts:
            print(f"  참고: 짧은 읽기 {len(shorts)}건을 중계했다", flush=True)

        # -- the metrics the experiment reads must be present -----------
        metrics = gateway.metrics()
        missing = [k for k in ("decoy_chains_advertised", "decoy_entry_hits",
                               "decoy_followups_intercepted", "decoy_announcements")
                   if k not in metrics]
        checks.record("결과에 실릴 지표가 모두 있다", not missing, str(missing))

        return report(checks)
    finally:
        gateway.close()
        if not keep:
            target.close()
        else:
            print(f"컨테이너를 남긴다: {target.container} {target.app_origin}", flush=True)


def report(checks: Checks) -> int:
    print()
    if checks.failed:
        print(f"사전 점검 실패 {len(checks.failed)}건: {', '.join(checks.failed)}", flush=True)
        print("실행을 시작하지 않는다.", flush=True)
        return 1
    print(f"사전 점검 {len(checks.results)}건 전부 통과. 실행해도 된다.", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="점검 후 컨테이너를 남긴다")
    return run(parser.parse_args().keep)


if __name__ == "__main__":
    raise SystemExit(main())
