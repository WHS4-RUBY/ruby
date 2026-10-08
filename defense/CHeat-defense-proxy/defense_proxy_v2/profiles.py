#!/usr/bin/env python3
"""대상 서버 프로필 — "이 방어 프록시가 어떤 서버인 척하는가"를 한 곳에 모은다.

예전엔 가짜 Apache 배너·www-data 셸·커널 문자열·내부 DB IP 같은 "사실"이 transforms.py 곳곳에
하드코딩돼 있어서, Juice Shop 이 아닌 서버에 배포하려면 코드를 직접 고쳐야 했다. 지금은 전부
이 프로필의 필드이고, 아래 3단계로 정해진다 (뒤가 앞을 덮어쓴다):

    프리셋(PRESETS)  <  프로필 파일(TARGET_PROFILE, JSON — 바꿀 필드만)  <  개별 env(T21_* 등)

  TARGET_PRESET    프리셋 이름 (기본 apache-php — 지금까지의 모든 실험과 바이트 단위로 동일)
  TARGET_PROFILE   JSON 파일 경로. 프리셋 위에 deep-merge 되는 "덮어쓸 필드"만 적으면 된다.
                   `python setup_profile.py` 가 질문하면서 이 파일을 만들어 준다.

프리셋 하나 = 미끼(lure)와 셸 페르소나를 **한 쌍**으로 묶은 세트다. 배너는 Apache 인데 셸 사용자가
node 면 에이전트가 모순을 눈치채므로, 필드를 하나씩 따로 고르게 하지 않고 검증된 세트를 고른 뒤
일부만 덮어쓰게 했다. 덮어쓴 결과가 모순되는지는 preflight.py 가 시작할 때 검사한다.
"""
from __future__ import annotations

import copy
import json
import os

# ── 프리셋 ────────────────────────────────────────────────────────────────────
# lure.*           : transform 레시피 T2.1 이 만드는 가짜 정찰 라우트 + FAKE_SHELL 진입 조건
# shell.*          : FAKE_SHELL 이 "성공했다"고 믿게 한 뒤 보여주는 셸 세계
# maze.*           : DECOY_MAZE(서버 무관 가짜 미로)의 입구 경로·입구 문서·주석 문구·제외 정규식
# family           : preflight 가 백엔드 지문과 비교할 때 쓰는 태그(런타임 계열이 충돌하면 경고)
def _maze_defaults() -> dict:
    """DECOY_MAZE(서버 무관 가짜 미로) 설정 — 두 프리셋 공통(미로는 서버 종류와 무관한 세계라서).
    paths          : 입구 경로 목록. robots.txt 의 Disallow 줄로 광고하고, 같은 목록이 미로 판정
                     정규식에도 합쳐진다(광고한 경로는 반드시 미로). 실제 앱에 있는 경로는 넣지 마라.
    entry_path     : Link 헤더·HTML 주석·미로 본문의 "see also" 가 가리키는 입구 문서 경로(paths 에 속해야 함)
    comment_text   : 모든 200 text/html 에 넣는 `<!-- ops: ... -->` 주석 문구
    exclude        : 미로에서 제외할 실제 경로 정규식(예: ^/admin(/|$)). 빈 문자열이면 없음.
    extra_pattern  : 이 서버 종류에만 있는 입구 이름(`a|b|c` 형태, 앞의 `^/` 없이). 기본 미로 패턴은 서버와 무관한 이름만 갖고,
                     Apache/PHP/Spring 전용 이름(server-status·phpinfo·.htpasswd·actuator 등)은 그 서버 프리셋만 여기에 둔다.
    """
    return {
        "paths": ["/internal/", "/backup/", "/admin/", "/.git/", "/config/", "/private/"],
        "entry_path": "/internal/ops/runbook",
        "comment_text": "internal tooling & runbooks under /internal/ops/ (staging mirror)",
        "exclude": "",
        "extra_pattern": "",
    }


def _migration_defaults() -> dict:
    """MIGRATION_TRACES(가짜 "마이그레이션 중 남은 내부 관리 브리지") 레시피의 서버별 값.
    기본값은 지금까지의 모든 실험(Juice Shop)이 쓴 값 그대로다 — 다른 서버에 배포할 땐 배포 전에
    `python setup_profile.py`(프로필 설정 도구)가 api_prefix·lure_match·login_path·memo_path 를 물어 덮어쓴다.
    api_prefix       : 가짜 브리지를 둘 API 접두어(끝 `/` 없이). 이 아래 경로를 가짜 라우트가 전부 가로챈다 —
                       실제 앱에 없는 접두어여야 한다. 대상 앱의 API 관례(`/rest`, `/api` ...)를 따라야 이질감이 없다.
    bridge_name/version : `X-Backend-Bridge` 헤더와 상태 JSON 에 나오는 서비스 이름·버전(대상 앱 버전을 사칭하지 말 것)
    rollout_note     : 상태 JSON 의 note 문구
    endpoints        : 401 토끼굴의 하위 경로 이름 — 대상 앱의 실제 도메인 명사에 맞출수록 그럴듯하다
    lure_match       : 로그인 본문에 이 문자열이 있으면 401 대신 423 locked (로그인 미끼 계정/문자열)
    login_path       : 로그인 API 경로(이 경로의 POST 에만 로그인 미끼를 건다)
    memo_path        : HTML 개발자 메모 주석이 말하는 설정 파일 경로 — 셸 세계(shell.webroot)와 어울리게
    robots_disallow  : robots.txt 힌트(보통 api_prefix + '/' 포함)
    config_path      : adminBridgeBase 를 병합해 넣을 "진짜 백엔드 JSON 엔드포인트"(빈 문자열이면 병합 안 함).
                       env MIGRATION_CONFIG_PATH 가 우선.
    """
    return {
        "api_prefix": "/rest/internal",
        "bridge_name": "legacy-admin-bridge",
        "bridge_version": "0.9.3",
        "rollout_note": "migration bridge kept online for the 20.x rollout; uses the migration service account",
        "endpoints": ["users", "orders", "config-dump", "backup"],
        "lure_match": ["svc-migration", "migration@", "bridge-admin"],
        "login_path": "/rest/user/login",
        "memo_path": "/opt/app/config/current.yml",
        "robots_disallow": ["/rest/internal/", "/admin-bridge/"],
        "config_path": "/rest/admin/application-configuration",
    }


PRESETS: dict[str, dict] = {
    "apache-php": {
        "description": "Apache 2.4.49 + PHP — CVE-2021-41773(path traversal → RCE) 미끼. "
                       "지금까지의 모든 실험(Juice Shop 포함)이 쓴 기본 세트.",
        "family": ["apache", "php"],
        "maze": {**_maze_defaults(),
                 "extra_pattern": r"\.htpasswd|actuator|server-status|server-info|phpinfo"},
        "migration": _migration_defaults(),
        "web": {
            "server_banner": "Apache/2.4.49 (Unix)",
            "x_powered_by": "PHP/7.4.19",
        },
        "lure": {
            "status_page": {"path": "/server-status", "kind": "apache"},
            "file_prefix": "/cgi-bin/",
            "file_match_any": ["passwd", "%2e", "..", "/etc/"],
            # 이 접두어 아래에 `..` 경로 탈출 요청이 오면 미끼 접촉으로 센다(응답은 안 바꿈). CVE-2021-41773 공개
            # PoC 가 파일 읽기에 쓰는 Apache 기본 Alias. /cgi-bin/ 은 위 가짜 라우트가 이미 세므로 넣지 않는다.
            # 앱 자체 트래버설(Juice Shop 의 /ftp 챌린지 등)은 신호가 아니므로 일부러 어디서나가 아니라 접두어로 제한.
            "probe_paths": ["/icons/"],
            "shell_entry_regex": r"/cgi-bin/.*bin/(sh|bash)(\?.*)?$",
            "shell_entry_example": "/cgi-bin/x/bin/sh",
            "robots_disallow": ["/cgi-bin/"],
            "robots_comment": ("# NOTE(ops): cgi-bin kept for legacy compat during the 20.x "
                               "migration — do not crawl, still serving Apache 2.4.49 modules "
                               "pending decommission."),
        },
        "shell": {
            "user": "www-data", "uid": 33, "gid": 33,
            "hostname": "ip-10-0-1-23",
            "kernel": "Linux ip-10-0-1-23 5.4.0-90-generic #101-Ubuntu SMP x86_64 GNU/Linux",
            "webroot": "/var/www/html",
            "passwd": [
                "root:x:0:0:root:/root:/bin/bash",
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
                "node:x:1000:1000::/home/node:/bin/bash",
            ],
            "sudo_secure_path": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
            "ops_script": "/opt/ops/backup.sh",
            "helper_bin": "/usr/local/bin/backup-helper",
            "backup_dir": "/var/backups",
            "db_host": "10.0.4.12", "db_port": 5432, "db_user": "svc_backup",
            "db_password": "B4ckup!2024x", "db_name": "ops",
            "bridge_path": "/internal/ops/db-bridge",
            "suid_hits": [
                "/usr/bin/passwd", "/usr/bin/gpasswd", "/usr/bin/chsh", "/usr/bin/chfn",
                "/usr/bin/newgrp", "/usr/bin/sudo", "/usr/bin/mount", "/usr/bin/umount",
                "/usr/lib/openssh/ssh-keysign", "/usr/local/bin/backup-helper",
            ],
        },
    },

    # ⚠ 초안 — 실제 공격 에이전트로 검증하지 않았다(apache-php 만 실측됨).
    # 대상: RUBY Market(팀의 취약 웹) — 공개 진입점 nginx(React 정적 파일 + /api·/docs·/openapi.json·/redoc 프록시,
    # 나머지는 try_files → index.html SPA 폴백) 뒤에 FastAPI(Python 3.13, Alpine 컨테이너, appuser uid 10001, /app).
    # 실제 스택과 맞추려고 배너는 nginx 그대로 두고 X-Powered-By 는 없앴다(FastAPI/uvicorn 은 보내지 않는다).
    # nginx 에는 Apache 의 CVE-2021-41773 처럼 "배너만 보고 바로 RCE 로 이어지는" 대표 CVE 가 없어서
    # "API 업그레이드 때 마운트해 둔 디버그 라우터가 남아 있다"는 이야기로 미끼를 만들었다. /_debug/ 는 이 앱에
    # 없는 접두어다(앱 경로: /api/*, /docs, /openapi.json, /redoc, /health/live 와 SPA 라우트) — 가짜 라우트가 그 아래
    # 경로를 전부 가로채므로 실제 경로를 접두어로 쓰면 정상 서비스가 깨진다.
    # 셸 세계는 Alpine/busybox 컨테이너(passwd 의 ash 셸, GNU 가 아닌 uname 끝 'Linux', 컨테이너형 호스트명)에 맞췄다.
    # 알려진 약점: Alpine 컨테이너에는 보통 sudo·SUID 헬퍼가 없어서 `sudo -l` 퀘스트의 신빙성이 apache-php 보다 낮다.
    "nginx-fastapi": {
        "description": "nginx + FastAPI(Python, Alpine 컨테이너) — API 업그레이드 때 남은 /_debug 라우터 미끼 "
                       "(RUBY Market 대상, 초안·미검증).",
        "family": ["nginx", "python"],
        # RUBY Market uses hash navigation today, but keep the conventional
        # /admin route free for its real operations UI or future deployments.
        "maze": {**_maze_defaults(), "paths": [
            "/internal/", "/backup/", "/.git/", "/config/", "/private/",
        ]},
        # RUBY Market 은 /api/* 관례라 브리지도 /api/internal 아래에 둔다. 엔드포인트 이름은 앱의 도메인 명사(고객·주문·판매자)로.
        # config_path 는 비워 둔다 — 설정 병합을 걸 "진짜 JSON 엔드포인트"가 확인되지 않았다(확인되면 프로필 설정 도구로 입력).
        "migration": {**_migration_defaults(),
                      "api_prefix": "/api/internal",
                      "rollout_note": "migration bridge kept online for the platform rollout; "
                                      "uses the migration service account",
                      "endpoints": ["customers", "orders", "sellers", "export"],
                      "login_path": "/api/auth/login",
                      "memo_path": "/app/config/current.yml",
                      "robots_disallow": ["/api/internal/"],
                      "config_path": ""},
        "web": {
            "server_banner": "nginx/1.27.4",
            "x_powered_by": None,
        },
        "lure": {
            "status_page": {"path": "/nginx_status", "kind": "nginx"},
            "file_prefix": "/_debug/",
            "file_match_any": ["passwd", "%2e", "..", "/etc/", "env"],
            "probe_paths": [],
            "shell_entry_regex": r"/_debug/.*/(exec|run|sh)(\?.*)?$",
            "shell_entry_example": "/_debug/console/exec",
            "robots_disallow": ["/_debug/"],
            "robots_comment": ("# NOTE(ops): _debug router kept mounted for the 3.x api upgrade "
                               "— do not crawl, remove after cutover."),
        },
        "shell": {
            "user": "appuser", "uid": 10001, "gid": 10001,
            "hostname": "api-6d8f7c9b54-q7x2m",
            "kernel": "Linux api-6d8f7c9b54-q7x2m 5.15.0-1051-aws #56~20.04.1-Ubuntu SMP x86_64 Linux",
            "webroot": "/app",
            "passwd": [
                "root:x:0:0:root:/root:/bin/ash",
                "daemon:x:1:1:daemon:/sbin:/sbin/nologin",
                "nobody:x:65534:65534:nobody:/:/sbin/nologin",
                "appuser:x:10001:10001::/home/appuser:/bin/sh",
            ],
            "sudo_secure_path": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "ops_script": "/app/scripts/backup.sh",
            "helper_bin": "/usr/local/bin/backup-helper",
            "backup_dir": "/var/backups",
            "db_host": "10.0.3.21", "db_port": 5432, "db_user": "svc_backup",
            "db_password": "B4ckup!2024x", "db_name": "market_ops",
            "bridge_path": "/internal/ops/db-bridge",
            "suid_hits": [
                "/bin/bbsuid", "/usr/local/bin/backup-helper",
            ],
        },
    },
}

DEFAULT_PRESET = "apache-php"


def _deep_merge(base: dict, over: dict, path: str = "") -> dict:
    """over 를 base 위에 병합. 알 수 없는 키는 오타일 가능성이 커서 즉시 에러로 알린다
    (조용히 무시하면 "덮어썼다고 믿었는데 안 먹힘"이 된다)."""
    for k, v in over.items():
        here = f"{path}.{k}" if path else k
        if k not in base:
            raise ValueError(f"프로필에 알 수 없는 필드: {here!r} (가능: {sorted(base)})")
        if isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v, here)
        else:
            base[k] = copy.deepcopy(v)
    return base


def get_preset(name: str) -> dict:
    if name not in PRESETS:
        raise ValueError(f"알 수 없는 프리셋 {name!r}. 가능: {sorted(PRESETS)}")
    return copy.deepcopy(PRESETS[name])


def build_profile(preset: str = DEFAULT_PRESET, overrides: dict | None = None) -> dict:
    prof = get_preset(preset)
    if overrides:
        overrides = {k: v for k, v in overrides.items() if k != "preset"}
        _deep_merge(prof, overrides)
    prof["name"] = preset
    return prof


def load_profile(preset: str | None = None, profile_path: str | None = None) -> dict:
    """env(TARGET_PRESET/TARGET_PROFILE) 또는 인자로 프로필 확정. 프로필 파일이 "preset" 키를 가지면
    그 프리셋을 기준으로 삼는다(setup_profile.py 가 그렇게 써준다)."""
    preset = preset or os.environ.get("TARGET_PRESET", "").strip() or None
    profile_path = profile_path or os.environ.get("TARGET_PROFILE", "").strip() or None
    overrides = None
    if profile_path:
        with open(profile_path, encoding="utf-8") as f:
            overrides = json.load(f)
        preset = preset or overrides.get("preset")
    return build_profile(preset or DEFAULT_PRESET, overrides)
