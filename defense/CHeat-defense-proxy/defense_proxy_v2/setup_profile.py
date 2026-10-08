#!/usr/bin/env python3
"""프로필 설정 도구 — 배포 전에 관리자가 "내 서버" 정보를 입력해 target_profile.json 을 만든다.
(질문에 답하면 설정 파일이 만들어지는 대화형 도구이고, 프록시를 설치하거나 실행하지는 않는다.)

    python setup_profile.py                         # 대화형 (백엔드를 물어보고 지문으로 프리셋을 추천)
    python setup_profile.py --backend http://127.0.0.1:8080 --preset nginx-fastapi --yes
    python setup_profile.py --preset apache-php --set web.server_banner="Apache/2.4.58 (Ubuntu)" \\
                            --set shell.hostname=web-01 --out target_profile.json --yes

결과 JSON 은 프리셋과 **다른 필드만** 담는다(+ "preset" 키). 쓰는 법:

    TARGET_PROFILE=./target_profile.json uvicorn Defense_proxy:app ...

끝나면 preflight 정합성 검사를 한 번 돌려 모순이 있으면 알려준다. 더 세밀한 필드(passwd 줄, SUID 목록,
미끼 경로, 내부 DB 정보 등)는 profiles.py 의 PRESETS 를 보고 JSON 에 직접 추가하면 된다.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys

import preflight
import profiles

# 대화형으로 물어볼 핵심 필드 (경로, 설명)
_PROMPTS = [
    ("web.server_banner", "Server 배너"),
    ("web.x_powered_by", "X-Powered-By (없으면 빈칸)"),
    ("shell.user", "서비스 실행 사용자"),
    ("shell.uid", "그 사용자 uid"),
    ("shell.gid", "그 사용자 gid"),
    ("shell.hostname", "호스트명"),
    ("shell.webroot", "웹 루트(pwd)"),
    ("shell.db_host", "내부 DB 호스트/IP"),
]

# MIGRATION_TRACES(가짜 마이그레이션 브리지)를 쓸 때만 묻는 서버별 값 — 대상 앱의 API 관례·계정·경로에 맞춘다.
# 리스트 값(lure_match, endpoints)은 JSON 으로 입력한다(예: ["svc-sync@shop.example"]).
_MIGRATION_PROMPTS = [
    ("migration.api_prefix", "가짜 브리지를 둘 API 접두어(실제 앱에 없는 경로, 예: /api/internal)"),
    ("migration.login_path", "로그인 API 경로(예: /api/auth/login)"),
    ("migration.lure_match", "로그인 미끼 계정/문자열 목록(JSON, 예: [\"svc-migration@회사도메인\"])"),
    ("migration.memo_path", "HTML 주석에 쓸 설정 파일 경로(셸 웹루트와 어울리게, 예: /app/config/current.yml)"),
    ("migration.config_path", "adminBridgeBase 를 병합할 실제 JSON 엔드포인트(없으면 빈칸=병합 안 함)"),
]


def _get(d: dict, path: str):
    for k in path.split("."):
        d = d[k]
    return d


def _set(d: dict, path: str, value) -> None:
    keys = path.split(".")
    for k in keys[:-1]:
        d = d[k]
    if keys[-1] not in d:
        raise SystemExit(f"알 수 없는 필드: {path!r}")
    d[keys[-1]] = value


def _parse(raw: str, like):
    """입력 문자열을 기존 값의 타입에 맞춘다 (uid 는 int)."""
    if isinstance(like, bool):
        return raw.lower() in ("1", "true", "yes", "y")
    if isinstance(like, int):
        return int(raw)
    if isinstance(like, (list, dict)):
        return json.loads(raw)
    return raw


def _diff(base, new):
    """new 중 base 와 다른 필드만 중첩 dict 로."""
    out = {}
    for k, v in new.items():
        if k in ("name", "description"):
            continue
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            sub = _diff(base[k], v)
            if sub:
                out[k] = sub
        elif v != base.get(k):
            out[k] = v
    return out


def _guess_preset(backend: str | None) -> tuple[str | None, str]:
    if not backend:
        return None, ""
    probe = preflight.probe_backend(backend, profiles.get_preset(profiles.DEFAULT_PRESET))
    if not probe.get("ok"):
        return None, f"(백엔드 {backend} 에 연결 못 함 — 지문 추천 생략)"
    tags = probe["tags"]
    best = max(profiles.PRESETS, key=lambda n: len(tags & set(profiles.PRESETS[n]["family"])))
    note = f"백엔드 단서: {probe.get('raw_clues') or '없음'}"
    return (best if tags & set(profiles.PRESETS[best]["family"]) else None), note


def _ask(prompt: str, default, interactive: bool):
    if not interactive:
        return default
    try:
        raw = input(f"  {prompt} [{default}]: ").strip()
    except EOFError:
        return default
    return raw if raw != "" else default


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--preset", help=f"프리셋 ({', '.join(profiles.PRESETS)})")
    ap.add_argument("--backend", help="실제 백엔드 URL — 지문으로 프리셋 추천 + 정합성 검사에 사용")
    ap.add_argument("--set", action="append", default=[], metavar="a.b=value", help="필드 덮어쓰기(반복 가능)")
    ap.add_argument("--out", default="target_profile.json")
    ap.add_argument("--yes", action="store_true", help="질문 없이 (프리셋 기본값 + --set 만 반영)")
    args = ap.parse_args()
    interactive = not args.yes and sys.stdin.isatty()

    guess, note = _guess_preset(args.backend)
    if note:
        print(note)
    preset = args.preset or guess or profiles.DEFAULT_PRESET
    if interactive and not args.preset:
        print("프리셋:")
        for n, p in profiles.PRESETS.items():
            print(f"  - {n}: {p['description']}")
        preset = _ask("사용할 프리셋", preset, True)
    base = profiles.get_preset(preset)
    prof = copy.deepcopy(base)

    def _prompt_fields(prompts) -> None:
        for path, label in prompts:
            cur = _get(prof, path)
            raw = _ask(label, "" if cur is None else cur, True)
            if str(raw) != str("" if cur is None else cur):
                _set(prof, path, _parse(str(raw), cur) if cur is not None else (raw or None))

    if interactive:
        print("내 서버 정보 (엔터 = 프리셋 기본값 유지):")
        _prompt_fields(_PROMPTS)
        if _ask("MIGRATION_TRACES(가짜 마이그레이션 브리지)도 쓰나요? 서버별 값을 입력합니다 (y/N)",
                "N", True).lower() in ("y", "yes"):
            print("MIGRATION_TRACES 서버별 값 (엔터 = 프리셋 기본값 유지):")
            _prompt_fields(_MIGRATION_PROMPTS)
    for kv in args.set:
        k, v = kv.split("=", 1)
        _set(prof, k, _parse(v, _get(prof, k)))

    # API 접두어를 바꿨는데 robots 힌트가 예전 접두어 그대로면 같이 맞춰준다 (브리지 경로와 robots 광고가 어긋나는 것 방지)
    old_p, new_p = base["migration"]["api_prefix"], prof["migration"]["api_prefix"]
    if new_p != old_p:
        rd = prof["migration"]["robots_disallow"]
        fixed = [new_p.rstrip("/") + "/" if x == old_p.rstrip("/") + "/" else x for x in rd]
        if fixed != rd:
            prof["migration"]["robots_disallow"] = fixed
            print(f"  (migration.robots_disallow 의 {old_p.rstrip('/') + '/'!r} 를 {new_p.rstrip('/') + '/'!r} 로 같이 바꿨다)")

    # 호스트명이 바뀌었는데 커널 문자열이 그대로면 같이 맞춰준다 (uname -a 와 hostname 모순 방지)
    old_h, new_h = base["shell"]["hostname"], prof["shell"]["hostname"]
    if new_h != old_h and prof["shell"]["kernel"] == base["shell"]["kernel"]:
        prof["shell"]["kernel"] = base["shell"]["kernel"].replace(old_h, new_h)
        print(f"  (kernel 문자열의 호스트명을 {new_h!r} 로 같이 바꿨다)")
    # 사용자가 바뀌었는데 passwd 에 없으면 한 줄 추가 (whoami 와 cat /etc/passwd 모순 방지)
    sh = prof["shell"]
    if not any(ln.split(":")[0] == sh["user"] for ln in sh["passwd"]):
        sh["passwd"].append(f"{sh['user']}:x:{sh['uid']}:{sh['gid']}::/home/{sh['user']}:/bin/bash")
        print(f"  (passwd 에 {sh['user']!r} 줄을 추가했다)")

    overrides = {"preset": preset, **_diff(base, prof)}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(overrides, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"\n저장: {args.out}  (덮어쓴 필드 {len(overrides) - 1}개 그룹)")
    print(f"  실행: TARGET_PROFILE={args.out} uvicorn Defense_proxy:app ...")

    final = profiles.build_profile(preset, {k: v for k, v in overrides.items() if k != "preset"})
    findings = preflight.check_profile(final)
    if args.backend:
        findings += preflight.check_backend(final, preflight.probe_backend(args.backend, final))
    print("\n정합성 검사:")
    warns = preflight.report(findings) if findings else 0
    if not findings:
        print("  문제 없음")
    return 1 if warns else 0


if __name__ == "__main__":
    raise SystemExit(main())
