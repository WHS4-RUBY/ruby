#!/usr/bin/env python3
"""CHeaT 방어 프록시 — 방어 기법 유효성(비용 유발) 측정 전용.

전제: 공격자 식별은 이 프록시가 하지 않는다. Policy Engine이 이미 "이 트래픽은
방어 대상"이라고 결정했다고 가정하고, CHeaT의 Cloak/Trap 방어가 실제 펜테스트
에이전트에게 유발하는 자원·시간 소모만 본다.

계층:
  transform  거짓 정보를 "원래 있던 것"처럼 — 응답 헤더 위조 / 가짜 정찰
             엔드포인트 서빙 / 실제 백엔드 응답 본문 변조 / 로그인 미끼 응답 / HTML 개발자
             메모 주석 (transforms.py) — 레시피: T2.1(가짜 취약 버전, FAKE_SHELL 전제조건) /
             MIGRATION_TRACES("마이그레이션 중 남은 흔적" — 가짜 관리 브리지 + HTML 메모 주석)

(옛 active/combined — 모든 요청에 게이트 없이 무조건 tarpit/차단 — 계층은 뺐다. 지연은 이제 "미끼를 문 클라이언트"
에게만 걸린다: ADAPTIVE_TRAP 에스컬레이션, FAKE_SHELL POST_RCE_ACTION, 미로 응답 지연.)

프록시 은닉: off 가 아니면 응답에서 Server 헤더를 위조(기본 nginx, 레시피가 덮어씀)해
프록시/uvicorn 지문을 숨긴다.

★ defense_proxy_v2: pruning 이전 원본(_pre_cleanup_backup)에서 T4.2b(확인응답형 페이지네이션)와
  transform T4.2(리스트 응답 json_pad, ~1MB 플러딩)를 뺐다. T4.2b 는 Tier 1 실험 때 한 번
  복원했다가 **최종적으로 다시 제거했다**(코드·환경변수·문서 전부 — 과거 실험 기록은
  results*.md 에 그대로 남아 있다).
  - transform T4.2(json_pad)는 뺀 상태 — INPUT 토큰만 태워 이후 턴에서 prompt
    caching 으로 할인됨. 이 약점을 그대로 물려받는 `escalation_flood()`(ADAPTIVE_TRAP 발동
    시 /api/Feedbacks 를 가짜 항목으로 ~1MB 폭증)도 transforms.py 에서 제거 상태.
  옛 passive 계층의 유일한 payload 였던 T4.2-bare(개발자 메모 톤 chmod 640 주석 — "Fact:"
  라벨이 붙는 다른 항목들과 달리 취약점을 직접 알려주지 않아 인젝션 판정을 덜 받음)는 옛 T2.2
  와 같은 "마이그레이션 중 남은 흔적" 이야기라 둘을 MIGRATION_TRACES 레시피 하나로 합쳤다 —
  그래서 passive 모드·defense_payloads.json 은 없다(주석은 transform 안에서 주입).
  FAKE_SHELL(GRACE_CMDS/drop 포함), DECOY_MAZE, ADAPTIVE_TRAP, T2.1 레시피 는 원본 그대로
  유지하되 아래 두 가지를 실측 근거로 바꿨다:
  - FAKE_SHELL_RETRIES 기본값 1→0: RETRIES=0(즉시 성공)의 진입률이 100%인데 1·2(마찰 있음)는
    50%로 반토막(results.md, N=3×3) — 마찰이 몰입을 늘리기보다 이탈을 늘림.
  - ADAPTIVE_TRAP 에스컬레이션 시 Trap을 flood(위에서 완전히 제거)에서 **더 큰 tarpit
    지연**(ESCALATE_DELAY_MS 기본 8000→16000ms)으로 바꿨다 — tarpit 은 캐싱으로 할인될 수
    없는 wall-clock 비용이라 이 프로젝트에서 가장 확실하게 증명된 수단(FAKE_SHELL tarpit 과
    같은 근거).

환경변수:
  REAL_BACKEND       백엔드 origin (기본 http://127.0.0.1:3000)
  DEFENSE_MODE       off | transform   (기본 transform. active/combined 는 없어졌다 — 시작 시 안내하고 종료)
  ACTIVE_TECHNIQUE   레시피 키 (T2.1, MIGRATION_TRACES, T2.1+MIGRATION_TRACES, ...)
  TARGET_PRESET      "이 프록시가 어떤 서버인 척하는가" 프리셋 (기본 apache-php — 지금까지의 모든
                     실험과 바이트 단위로 동일). profiles.py 의 PRESETS 참고: apache-php | nginx-fastapi
  TARGET_PROFILE     프리셋 위에 덮어쓸 필드만 적은 JSON 파일 경로(`python setup_profile.py` 로
                     생성). 우선순위: 프리셋 < TARGET_PROFILE < 개별 env(T21_* 등). 시작 시
                     preflight.py 가 프로필끼리의 모순·실제 백엔드와의 충돌을 경고한다.
  PREFLIGHT          0 이면 시작 시 정합성 검사를 끈다 (기본 1 — T2.1/FAKE_SHELL 쓸 때만 동작)
  PREFLIGHT_STRICT   1 이면 프로필 자체에 WARN 이 있을 때 시작을 거부한다
  T21_VERSION_PATH   T2.1 이 가짜 httpServer 배너를 병합해 넣을 실제 백엔드 엔드포인트
                     (기본 /rest/admin/application-version — Juice Shop 전용. 다른 대상에
                     배포 시 그 앱의 실제 버전/상태 API 경로로 바꿔야 효과가 난다)
  MIGRATION_CONFIG_PATH  MIGRATION_TRACES 가 가짜 adminBridgeBase 를 병합해 넣을 실제 백엔드 엔드포인트
                     (기본 = 프로필 migration.config_path, apache-php 는 /rest/admin/application-configuration)
                     MIGRATION_TRACES 의 서버별 값 전체(migration.*: api_prefix·lure_match·login_path·memo_path ...)는
                     프로필 필드이고 배포 전에 `python setup_profile.py`(프로필 설정 도구)로 입력한다
  T21_ROBOTS_DISALLOW  T2.1 robots.txt 힌트, 콤마 구분 Disallow 경로 목록
                     (기본 /cgi-bin/). synth_robots() 로 DECOY_MAZE 와 같은 방식 — 백엔드
                     robots.txt 가 있으면 append, 없으면 합성(서버 무관)
  MIGRATION_ROBOTS_DISALLOW  MIGRATION_TRACES robots.txt 힌트 (기본 = 프로필 migration.robots_disallow), 위와 동일
  SPOOF_SERVER       위조할 Server 헤더 값 (기본 nginx, DECOY_REQUIRE_PLAN=1 이면 프로필 배너). off 모드는 무시
  SPOOF_POWERED_BY   X-Powered-By 위조 값 (기본 없음 — 대상 스택과 모순되면 역효과)
  MAZE_VERSION       미로 version 프로파일이 노출할 배너 (기본 SPOOF_SERVER)
  TRAVERSAL_PROBE_PATHS  지정 접두어(기본 프로필 lure.probe_paths = /icons/) 아래의 `..` 경로 탈출 시도를 미끼 접촉
                     (traversal-probe)으로 센다. 응답은 안 바꾼다. 쉼표 구분, 빈 값이면 끔, T2.1 사용 시 기본 켜짐
  FAKE_SHELL        1이면 T2.1 traversal 미끼를 문 뒤 RCE 시도에 가짜 셸로 응답 (기본 0)
  FAKE_SHELL_RETRIES 최초 "성공" 전 깨진/부분 출력으로 실패시키는 시도 횟수 (기본 0=즉시 성공
                     — RETRIES>0 은 진입률을 반토막 내는 것으로 실측됨, results.md 참고)
  POST_RCE_ACTION    FAKE_SHELL 이 "성공"을 믿게 한 뒤: tarpit | block | drop (기본 tarpit)
  POST_RCE_GRACE_CMDS 전환 유예 — 성공 이후 이 수만큼 명령은 계속 정상 응답, 그 다음부터 POST_RCE_ACTION 적용 (기본 0=예전과 동일)
  POST_RCE_DELAY_MS  POST_RCE_ACTION=tarpit 일 때 전체 요청 지연 ms (기본 8000)
  POST_RCE_DROP_S    POST_RCE_ACTION=drop 일 때 응답 안 보내는 시간(초) — 사실상 무기한 (기본 99999)
  AMBIG_TRAP         1이면 "애매한 공격자" 판정용 통합 기법을 켠다 (기본 0).
                     FAKE_SHELL·DECOY_MAZE(+ADAPTIVE_TRAP)를 이미 각자 켜뒀다고 가정하고,
                     그 위에 최종 판정만 얹는다: 그중 하나라도 실제로 걸리면(FAKE_SHELL RCE
                     진입, 또는 ADAPTIVE_TRAP 에스컬레이션 — 이건 미로 접촉도 decoy_hits 로
                     흡수하므로 사실상 전부 커버) 그 즉시 모든 요청을
                     무조건 403 차단으로 굳힌다. AMBIG_RELEASE_MIN 이 지날 때까지 아무것도
                     안 걸리면 반대로 완전히 풀어준다(그 이후 모든 요청 정상 패스스루 —
                     가짜셸·미로 전부 재적용 안 함).
  AMBIG_RELEASE_MIN  AMBIG_TRAP=1 일 때, 아무 트랩도 안 걸렸을 경우 풀어주기까지 걸리는
                     시간(분). 5 | 10 | 30 | 60 중 선택(그 외 값도 허용) — 기본 10.

  ── 탐지팀 연동(client_id 격리 + X-Defense-Plan) ──
  탐지팀의 detection/server.js 가 모든 요청에 X-Client-Id·X-Defense-Plan 헤더를
  strip-then-reset 해서 심는다(detection/lib/rubyPolicy.js 의 stripDetectionHeaders —
  외부에서 위조 불가). 이 프록시는 그 두 헤더를 그대로 신뢰한다 — 단 **이 프록시
  포트에 탐지 레이어를 거치지 않고 직접 도달할 수 없어야** 그 신뢰가 성립한다
  (운영 배포 전제, 로컬 실험처럼 탐지 레이어 없이 직접 찌르는 구성에선 아래 폴백으로
  동작).
  CLIENT_ID_HEADER   client_id 로 읽을 헤더 이름 (기본 X-Client-Id, 대소문자 무관).
                     없으면 접속 IP로 폴백(탐지 레이어 없는 로컬 실험 하위호환) —
                     이 값으로 AMBIG_TRAP/FAKE_SHELL/미로 상태를
                     클라이언트별로 격리한다(이전엔 전역 하나라 한 공격자가 차단되면
                     다른 모든 클라이언트도 같이 막히는 버그가 있었다).
  CLIENT_ID_FALLBACK 헤더가 없을 때만 쓰는 대체 식별자: ip(기본, 접속 IP별) | global(헤더 없는 요청 전부를
                     한 클라이언트로 — 출발지 IP 가 요청마다 바뀌는 단일 공격자 실험용). 헤더가 있으면 항상
                     헤더 우선이라 탐지팀 연동과 충돌하지 않는다. 연동 운영 환경에서는 global 을 쓰지 말 것.
  CLIENT_STATE_TTL_S 이 시간(초)만큼 조용한 client_id 는 상태를 지운다 — 탐지팀의
                     세션 창(1시간)과 맞춰 기본 3600.
  CLIENT_STATE_SWEEP_S 위 청소를 몇 초마다 도는지 (기본 300).
  DEFENSE_PLAN_HEADER 탐지팀이 전략 배열을 실어 보내는 헤더 이름 (기본
                     X-Defense-Plan). 형식은 defense/app(별도의 "공식" 방어 서버)과
                     동일: [{"name": "delay", "params": {"delay_ms": 200}}, ...].
                     이름별 핸들러는 _DEFENSE_PLAN_STRATEGIES 에 등록 — 지금은
                     detection/config/policy.json 기준 "delay" 하나뿐이지만, 탐지팀이
                     이후 "우리가 적용할 CHeaT 기법"을 전략 이름으로 지정해 넘기기로
                     했으므로 새 이름이 추가될 때마다 핸들러만 등록하면 된다. 모르는
                     이름은 조용히 무시(전방 호환). 구현된 전략: delay | maze | decoy_maze(묶음 1: 미로 +
                     적응형 — DECOY_REQUIRE_PLAN=1 로 띄우면 이 이름이 실린 클라이언트에만 적용, sticky).
  DECOY_REQUIRE_PLAN 1 이면 DECOY_MAZE·ADAPTIVE_TRAP 을 준비만 해 두고 X-Defense-Plan 의 decoy_maze 가 실린
                     클라이언트에게만 적용(기본 0 — 환경변수대로 모든 클라이언트). AMBIG_TRAP 은 이 묶음과 무관.
  DEFENSE_DB / EXPERIMENT_RUN

  uvicorn Defense_proxy:app --host 127.0.0.1 --port 3002 --no-server-header
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import closing
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import unquote

from fastapi import FastAPI, Request, Response

from proxy_core import ProxyContext, ProxyHook, create_app
import preflight
import transforms

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DEFENSE_DB", os.path.join(HERE, "defense.db"))
DEFENSE_MODE = os.environ.get("DEFENSE_MODE", "transform").lower()
ACTIVE_TECHNIQUE = os.environ.get("ACTIVE_TECHNIQUE", "").strip()
# 탐지팀 연동용 "묶음" 모드(아래 DECOY_MAZE 설명 참고) — SPOOF_SERVER 기본값이 이 모드에 따라 달라져서 여기서 먼저 읽는다.
DECOY_REQUIRE_PLAN = os.environ.get("DECOY_REQUIRE_PLAN", "0").lower() in ("1", "true", "yes")
# Server 위조 값. 기본은 예전처럼 "nginx"인데, 묶음 모드(DECOY_REQUIRE_PLAN=1)에서는 **프로필의 배너**를 기본으로 쓴다 —
# 미로만 켜진 클라이언트가 나중에 레시피 묶음(T2.1 등)으로 올라가도 Server 헤더가 바뀌지 않게(같은 클라이언트가 중간에 서버 종류가
# 바뀐 걸 보지 않게). 대상과 맞는 프리셋(예: nginx-fastapi)을 고르면 실제 배너와 같다. 빈 값(SPOOF_SERVER=)이면 위조 안 함.
SPOOF_SERVER = (os.environ["SPOOF_SERVER"] if "SPOOF_SERVER" in os.environ
                else (transforms.PROFILE["web"]["server_banner"] if DECOY_REQUIRE_PLAN else "nginx"))
# X-Powered-By 위조는 기본 off. Batch 6 에서 codex 가 `Server: nginx` + `X-Powered-By: PHP` +
# 명백한 Node/Angular 앱의 모순을 근거로 Cloak 전체를 디코이로 판별했다. 대상 스택과 일관될
# 때만 켠다 (레시피가 headers 로 지정하거나 SPOOF_POWERED_BY env 로).
SPOOF_POWERED_BY = os.environ.get("SPOOF_POWERED_BY", "")
EXPERIMENT_RUN = os.environ.get("EXPERIMENT_RUN", "adhoc")
_REQUEST_RUN: ContextVar[str] = ContextVar("cheat_request_run", default=EXPERIMENT_RUN)
_REQUEST_ACTION: ContextVar[str] = ContextVar("cheat_request_action", default="observe")

# ---------------------------------------------------------------- client_id 별 상태 격리
# 탐지팀 연동 전제: detection/server.js 가 모든 요청에 X-Client-Id 를 strip-then-reset
# 해서 심는다(detection/lib/rubyPolicy.js stripDetectionHeaders — 외부 위조 불가, 단
# 이 프록시가 탐지 레이어 뒤에서만 접근 가능해야 함). AMBIG_TRAP/FAKE_SHELL/
# FAKE_SHELL/미로 에스컬레이션이 전부 이 키로 격리된다 — 전역 싱글턴이었을
# 때는 한 공격자가 AMBIG_TRAP 에 차단되는 순간 다른 모든 클라이언트도 같이 403 되는
# 버그가 있었다.
CLIENT_ID_HEADER = os.environ.get("CLIENT_ID_HEADER", "X-Client-Id").strip().lower()
# X-Client-Id 헤더가 **없을 때만** 쓰는 대체 식별자 — 헤더가 있으면 항상 헤더가 우선이므로 탐지팀 연동(헤더 주입)과
# 충돌하지 않는다(연동 때는 이 변수를 지우면 된다).
#   ip     (기본) 접속 IP 별로 상태를 나눈다 — 탐지 레이어가 없는 로컬 실험 하위호환
#   global 헤더 없는 모든 요청을 한 클라이언트("global")로 묶는다 — 공격자가 하나뿐인데 출발지 IP 가 요청마다 바뀌는
#          환경(NAT/프록시 풀)에서 에스컬레이션·차단이 IP 마다 새로 시작되는 걸 막는 단일 공격자 실험용.
#          ★ 탐지 레이어와 연동한 운영 환경에서는 쓰지 말 것: 헤더 없는 요청(헬스체크·내부 호출)이 한 클라이언트로
#          묶여 그 하나가 차단되면 헤더 없는 요청 전부가 영향을 받는다.
CLIENT_ID_FALLBACK = os.environ.get("CLIENT_ID_FALLBACK", "ip").strip().lower()
if CLIENT_ID_FALLBACK not in ("ip", "global"):
    raise SystemExit(f"CLIENT_ID_FALLBACK={CLIENT_ID_FALLBACK!r} — ip | global 중 하나여야 한다.")
if CLIENT_ID_FALLBACK == "global":
    print("[defense] CLIENT_ID_FALLBACK=global — 헤더 없는 모든 요청을 한 클라이언트로 묶는다(단일 공격자 실험용). "
          f"{CLIENT_ID_HEADER} 헤더가 있는 요청은 그대로 그 값으로 분리된다. 탐지 레이어 연동 운영 환경에서는 쓰지 말 것.",
          flush=True)
CLIENT_STATE_TTL_S = float(os.environ.get("CLIENT_STATE_TTL_S", "3600"))
CLIENT_STATE_SWEEP_S = float(os.environ.get("CLIENT_STATE_SWEEP_S", "300"))


@dataclass
class ClientState:
    """client_id 하나가 갖는 모든 가변 방어 상태 — 예전엔 기능마다 전역 싱글턴
    (_fake_shell/_ambig/_esc)으로 흩어져 있던 것을 여기 하나로 모았다.
    """
    # FAKE_SHELL
    fs_entered: bool = False
    fs_attempts: int = 0
    fs_cmd_count: int = 0
    fs_history: dict = field(default_factory=dict)
    # AMBIG_TRAP
    ambig_verdict: "str | None" = None
    ambig_armed_at: float = 0.0
    # 적응형 에스컬레이션(ADAPTIVE_TRAP) + decoy_hits
    esc_on: bool = False
    esc_reason: str = ""
    esc_decoy_hits: int = 0                       # 미끼 접촉 횟수(원시 — 같은 경로 반복도 셈)
    esc_decoy_paths: set = field(default_factory=set)   # 서로 다른 미끼 경로(정규화) — 에스컬레이션 판정 기본값
    maze_planned: bool = False                    # 탐지팀 플랜이 maze 를 지정한 적 있음(sticky)
    decoy_planned: bool = False                   # 탐지팀 플랜이 decoy_maze(미로+적응형 묶음)를 지정한 적 있음(sticky)
    recipe: str = ""                              # 이 클라이언트에게 적용할 transform 레시피("T2.1"/"MIGRATION_TRACES", 클라이언트당 하나)
    shell_planned: bool = False                   # 탐지팀 플랜이 decoy_t21_shell(FAKE_SHELL 포함 묶음)을 지정한 적 있음(sticky)
    client_id: str = ""                           # 로그·충돌 안내용(이 상태의 주인)
    # DECOY_MAZE — hits(에스컬레이션 트리거)만 클라이언트별. roots(미로로 확정된
    # 경로)·shell(SPA index.html 캐시)은 "세계관 일관성"·"백엔드 캐시"라 전역 _maze
    # 에 그대로 둔다 — 다른 클라이언트가 봐도 같은 모양이어야 자연스럽다.
    maze_hits: int = 0
    # 청소용(단조 시계 — time.time() 과 섞지 않는다)
    last_seen: float = field(default_factory=time.monotonic)


_clients: dict[tuple[str, str], ClientState] = {}


def _resolve_run_id(request: Request) -> str:
    """Use Detection's canonical experiment ID, or the local experiment label."""
    run_id = request.headers.get("x-ruby-run-id", "").strip()
    try:
        if run_id and str(uuid.UUID(run_id)) == run_id:
            return run_id
    except ValueError:
        pass
    return EXPERIMENT_RUN


def _resolve_client_id(request: Request) -> str:
    """탐지팀이 심은 X-Client-Id 를 그대로 신뢰. 헤더가 없으면(탐지 레이어 없이
    직접 찌르는 로컬 실험 등) CLIENT_ID_FALLBACK 에 따라 접속 IP(기본) 또는 고정 "global" 로 폴백한다 —
    공격자가 하나뿐인 로컬 실험에선 IP 폴백도 사실상 전역 상태 1개와 같지만, 출발지 IP 가 요청마다 바뀌는
    환경에서는 global 로 묶어야 상태가 이어진다. 헤더가 있으면 항상 그 값이 우선."""
    cid = request.headers.get(CLIENT_ID_HEADER, "").strip()
    if cid:
        return cid
    if CLIENT_ID_FALLBACK == "global":
        return "global"
    return "ip:" + (request.client.host if request.client else "unknown")


def _get_client(client_id: str) -> ClientState:
    key = (_REQUEST_RUN.get(), client_id)
    st = _clients.get(key)
    if st is None:
        st = ClientState(client_id=client_id)
        _clients[key] = st
    st.last_seen = time.monotonic()
    return st


async def _sweep_clients_loop():
    while True:
        await asyncio.sleep(CLIENT_STATE_SWEEP_S)
        now = time.monotonic()
        dead = [cid for cid, st in _clients.items()
                if now - st.last_seen > CLIENT_STATE_TTL_S]
        for cid in dead:
            del _clients[cid]
        active_runs = {run_id for run_id, _ in _clients}
        for run_id in list(_mazes):
            if run_id not in active_runs:
                del _mazes[run_id]
        if dead:
            print(f"[defense] client-state 청소: {len(dead)}개 만료 "
                  f"(TTL={CLIENT_STATE_TTL_S:.0f}s, 남은 클라이언트 {len(_clients)}개)",
                  flush=True)


# ---------------------------------------------------------------- X-Defense-Plan (탐지팀 연동)
# 탐지팀이 리스크 점수 기반으로 고른 전략 배열을 이 헤더로 넘긴다. 형식은
# defense/app(별도의 "공식" 방어 서버)의 parse_plan()/STRATEGY_REGISTRY 와 동일하게
# 맞췄다 — 탐지팀 쪽 포맷이 바뀔 이유가 없다: [{"name": "delay", "params": {...}}, ...]
DEFENSE_PLAN_HEADER = os.environ.get("DEFENSE_PLAN_HEADER", "X-Defense-Plan").strip().lower()


def _plan_strategy_delay(params: dict, st: ClientState) -> float:
    """'delay' 전략 — delay_ms 만큼 tarpit. defense/app/strategies/delay.py 와 같은 의미."""
    try:
        return float(params.get("delay_ms", 0)) / 1000
    except (TypeError, ValueError):
        return 0.0


def _plan_strategy_maze(params: dict, st: ClientState) -> float:
    """'maze' 전략 — 이 클라이언트에게 가짜 미로(DECOY_MAZE)를 켠다. 지연은 없다(0).

    표시만 한다: 실제로 미로를 적용할지는 `_maze_enabled()` 가 이 이름이 plan_applied 에 있는지로 본다.
    MAZE_REQUIRE_PLAN=1 일 때만 의미가 있다(꺼져 있으면 미로는 예전처럼 모든 클라이언트에 적용)."""
    st.maze_planned = True       # 한 번 켜지면 유지 — 입구를 본 뒤 갑자기 사라지면 세계가 모순된다
    return 0.0


def _plan_strategy_decoy_maze(params: dict, st: ClientState) -> float:
    """'decoy_maze' 전략(묶음 1) — 이 클라이언트에게 미로 + 적응형 에스컬레이션을 켠다(서버 무관, 프로필 의존 없음).
    maze 전략(미로만)을 포함하고 적응형을 더한 것이다. 지연은 없다(0) — 에스컬레이션 지연은 미끼를 물어야 걸린다.

    DECOY_REQUIRE_PLAN=1 일 때만 의미가 있다(꺼져 있으면 미로·적응형은 환경변수대로 모든 클라이언트에 적용).
    한 번 켜지면 유지(sticky) — 입구를 본 뒤 갑자기 사라지면 세계가 모순된다. 미끼 접촉 카운터는 이 전략이
    켜진 뒤의 접촉부터 센다(켜지기 전 접촉이 쌓여 있다가 켜지는 순간 즉시 에스컬레이션되는 것을 막는다)."""
    st.maze_planned = True
    st.decoy_planned = True
    return 0.0


def _plan_strategy_decoy_t21_shell(params: dict, st: ClientState) -> float:
    """'decoy_t21_shell' 전략(묶음 2) — decoy_maze(미로 + 적응형) + T2.1 레시피(가짜 Apache 배너·/server-status·/cgi-bin/
    traversal 미끼·robots 힌트) + FAKE_SHELL(RCE 시도에 가짜 셸). 프로필(TARGET_PRESET/TARGET_PROFILE)에 의존한다.
    클라이언트당 레시피는 하나라서 이미 MIGRATION 이 정해진 클라이언트에는 레시피·셸을 안 켠다(미로+적응형만 유지)."""
    _plan_strategy_decoy_maze(params, st)
    if _set_client_recipe(st, "T2.1", st.client_id):
        st.shell_planned = True
    return 0.0


def _plan_strategy_decoy_migration(params: dict, st: ClientState) -> float:
    """'decoy_migration' 전략(묶음 3) — decoy_maze + MIGRATION_TRACES 레시피(가짜 마이그레이션 브리지 토끼굴·robots 힌트·
    설정 병합·HTML 메모·로그인 미끼). 프로필의 migration.* 에 의존한다. 이미 T2.1 이 정해진 클라이언트에는 레시피를 안 켠다."""
    _plan_strategy_decoy_maze(params, st)
    _set_client_recipe(st, "MIGRATION_TRACES", st.client_id)
    return 0.0


# 전략 이름 -> (params, ClientState) -> 적용할 지연(초). defense/app/strategies/
# registry.py 와 같은 등록 패턴 — 탐지팀이 "앞으로 우리가 적용할 CHeaT 기법을 전략
# 이름으로 지정해서 넘기겠다"고 했으므로, 새 이름이 추가될 때마다 여기 핸들러만
# 등록하면 된다. 운영에서는 공식 Defense가 CHeaT 전략만 골라 전달한다.
_DEFENSE_PLAN_STRATEGIES: dict[str, Callable[[dict, ClientState], float]] = {
    "delay": _plan_strategy_delay,
    "maze": _plan_strategy_maze,
    "decoy_maze": _plan_strategy_decoy_maze,     # 묶음 1: 미로 + 적응형(서버 무관)
    "decoy_t21_shell": _plan_strategy_decoy_t21_shell,   # 묶음 2: 묶음 1 + T2.1 + FAKE_SHELL
    "decoy_migration": _plan_strategy_decoy_migration,   # 묶음 3: 묶음 1 + MIGRATION_TRACES
}


def _active_strategies(st: ClientState, plan_applied: list[str] | None) -> list[str]:
    """Report the effective plan, including a decoy kept alive by sticky state."""
    active = ["delay"] if "delay" in (plan_applied or ()) else []
    if st.recipe == "T2.1" and st.shell_planned:
        active.append("decoy_t21_shell")
    elif st.recipe == "MIGRATION_TRACES":
        active.append("decoy_migration")
    elif st.decoy_planned:
        active.append("decoy_maze")
    elif st.maze_planned:
        active.append("maze")
    return active


def _parse_defense_plan(raw: "str | None") -> list:
    """X-Defense-Plan 파싱 — defense/app/main.py 의 parse_plan() 과 동일 계약.
    없거나 JSON이 깨졌거나 배열이 아니면 빈 리스트(안전한 기본값 = 아무 전략도 적용 안 함)."""
    if not raw:
        return []
    try:
        plan = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return plan if isinstance(plan, list) else []


async def _apply_defense_plan(request: Request, client_id: str) -> list:
    """탐지팀이 보낸 전략들을 순서대로 적용하고, 실제로 적용된 전략 이름 목록을
    반환한다(로깅용 — defense.db의 defense_plan 컬럼). 모르는 전략 이름은 조용히
    건너뛴다 — 탐지팀이 새 전략을 추가해도 이 프록시가 재배포 전까지는 죽지 않고
    무시만 하게(전방 호환)."""
    plan = _parse_defense_plan(request.headers.get(DEFENSE_PLAN_HEADER))
    if not plan:
        return []
    st = _get_client(client_id)
    applied = []
    for step in plan:
        if not isinstance(step, dict):
            continue
        name = step.get("name")
        handler = _DEFENSE_PLAN_STRATEGIES.get(name)
        if handler is None:
            if name:
                print(f"[defense] X-Defense-Plan: 모르는 전략 {name!r} 무시 "
                      f"(client={client_id})", flush=True)
            continue
        delay_s = handler(step.get("params") or {}, st)
        if delay_s > 0:
            await asyncio.sleep(delay_s)
        applied.append(name)
    return applied


# ---------------------------------------------------------------- 서버 무관 미로 (DECOY_MAZE)
# DECOY_REQUIRE_PLAN=1 — 탐지팀 연동용 "묶음" 모드: 미로·적응형 기능을 준비만 해 두고(DECOY_MAZE/ADAPTIVE_TRAP 을 따로
# 안 켜도 됨), X-Defense-Plan 에 `decoy_maze`(또는 미로만 `maze`)가 실린 클라이언트에게만 적용한다. 0(기본)이면 예전처럼
# 환경변수(DECOY_MAZE/ADAPTIVE_TRAP/MAZE_REQUIRE_PLAN)대로 모든 클라이언트에 적용 — 기존 실험·대시보드는 그대로 동작.
DECOY_MAZE = os.environ.get("DECOY_MAZE", "0").lower() in ("1", "true", "yes") or DECOY_REQUIRE_PLAN
MAZE_PROFILE = set(p.strip() for p in os.environ.get(
    "MAZE_PROFILE", "version,bridge,inventory,ssh,docs").split(",") if p.strip())
MAZE_ENTRY = set(e.strip() for e in os.environ.get(
    "MAZE_ENTRY", "robots,comment,header").split(",") if e.strip())
MAZE_BASE_KB = int(os.environ.get("MAZE_BASE_KB", "30"))
MAZE_DELAY_MS = int(os.environ.get("MAZE_DELAY_MS", "2500"))
MAZE_ESCALATE_HITS = int(os.environ.get("MAZE_ESCALATE_HITS", "4"))
MAZE_ESC_KB = int(os.environ.get("MAZE_ESC_KB", "250"))
MAZE_ESC_DELAY_MS = int(os.environ.get("MAZE_ESC_DELAY_MS", "6000"))
MAZE_MAX_KB = int(os.environ.get("MAZE_MAX_KB", "900"))
MAZE_LINKS = int(os.environ.get("MAZE_LINKS", "5"))
# version 프로파일 배너. 기본은 SPOOF_SERVER 와 일치시켜 모순을 없앤다. "내부 레거시 박스"
# 서사로 취약 버전(Apache 2.4.49 등)을 노출하려면 env 로 명시 (edge=nginx, internal=apache 는 정합).
MAZE_VERSION = os.environ.get("MAZE_VERSION", "") or SPOOF_SERVER or "Apache/2.4.49 (Unix)"
# 미로 입구 경로 목록 — robots.txt 의 Disallow 줄로 광고하고, 같은 목록이 판정 정규식에도 합쳐진다
# (광고한 경로가 실제로는 평범한 404 인 어긋남이 없다). 기본은 프로필 maze.paths, env MAZE_PATHS(쉼표)가 덮어씀.
# MAZE_PATTERN 은 정규식 전체를 직접 바꾸는 고급 옵션 — 이때는 목록과의 일관성을 preflight 가 점검한다.
MAZE_PATHS = ([p.strip() for p in os.environ["MAZE_PATHS"].split(",") if p.strip()]
              if os.environ.get("MAZE_PATHS", "").strip() else list(transforms.PROFILE["maze"]["paths"]))
MAZE_ROBOTS_DISALLOW = list(MAZE_PATHS)
_MAZE_RE = re.compile(os.environ.get("MAZE_PATTERN", "").strip()
                      or transforms.build_maze_pattern(MAZE_PATHS), re.I)
# 실제 경로와 겹칠 때 수동으로 미로에서 빼는 정규식(경로 기준 search). env MAZE_EXCLUDE > 프로필 maze.exclude.
_MAZE_EXCLUDE_SRC = os.environ.get("MAZE_EXCLUDE", "").strip() or transforms.PROFILE["maze"]["exclude"]
_MAZE_EXCLUDE_RE = re.compile(_MAZE_EXCLUDE_SRC, re.I) if _MAZE_EXCLUDE_SRC else None
# 백엔드가 403 을 낸 경로도 미로로 바꿀지. 진짜 관리자 페이지가 비로그인에 403 을 주는 서버에서는 0 으로.
MAZE_INTERCEPT_403 = os.environ.get("MAZE_INTERCEPT_403", "1").lower() in ("1", "true", "yes")
# SPA(history 라우팅) 폴백은 주소창 직접 접속/새로고침(Sec-Fetch-Dest: document)이면 미로로 바꾸지 않고 통과.
MAZE_SPA_BROWSER_PASS = os.environ.get("MAZE_SPA_BROWSER_PASS", "1").lower() in ("1", "true", "yes")
# 미로를 "탐지팀 플랜이 maze 를 지정한 클라이언트에게만" 적용(1) / 모든 클라이언트(0, 기본 — 예전 동작).
MAZE_REQUIRE_PLAN = (os.environ.get("MAZE_REQUIRE_PLAN", "0").lower() in ("1", "true", "yes")
                     or DECOY_REQUIRE_PLAN)
# 미로 루트로 등록해도 되는 "명백히 가짜" 접두어 — 진짜 정적 디렉토리(/ftp 등) shadowing 방지
_MAZE_ROOT_RE = re.compile(r"^/(\.(git|env|svn|aws|ssh)|_?internal|backup|configs?|debug|"
                           r"private|secrets?|credentials|actuator|management)($|/)", re.I)


class _Maze:
    def __init__(self):
        # Shared among clients in one run for a consistent target, isolated
        # between runs so an earlier experiment cannot teach or shadow paths.
        self.roots: set[str] = set()
        self.shell: bytes | None = None
        self.real: set[str] = set()


_mazes: dict[str, _Maze] = {}


def _maze_for_run() -> _Maze:
    run_id = _REQUEST_RUN.get()
    maze = _mazes.get(run_id)
    if maze is None:
        maze = _Maze()
        _mazes[run_id] = maze
    return maze

# ---------------------------------------------------------------- 가짜 포스트-익스플로잇 셸
# T2.1 의 CVE-2021-41773 traversal 미끼(_PASSWD_STUB)를 문 뒤, 에이전트가
# "/bin/sh"·"/bin/bash" 로 명령을 보내는 실제 RCE 시도까지 하면 그럴듯한 stdout 으로
# "성공한 척" 이어간다. 어떤 명령도 실제로 실행하지 않는다 (transforms.fake_shell_response).
FAKE_SHELL = os.environ.get("FAKE_SHELL", "0").lower() in ("1", "true", "yes")
# 최초 "성공" 전 깨진/부분 출력으로 실패시키는 시도 횟수 — 실제 RCE는 보통 1~2회 버퍼링/
# 인코딩 문제로 실패하다 성공한다는 서사를 노린 것이었지만, 실측(results.md, N=3×3)에서
# RETRIES=0(즉시 성공)의 진입률이 100%인 반면 RETRIES=1(이전 기본값)·2는 50%로 반토막 —
# 마찰이 몰입을 늘리기보다 이탈을 늘렸다. 기본값을 0(즉시 성공)으로 바꾼다.
FAKE_SHELL_RETRIES = int(os.environ.get("FAKE_SHELL_RETRIES", "0"))
POST_RCE_ACTION = os.environ.get("POST_RCE_ACTION", "tarpit").lower()   # tarpit | block | drop
# 전환 유예(grace window) — 예전엔 entered=True 되는 즉시 다음 요청부터 POST_RCE_ACTION 이
# 걸려 "당하는 척" 단계가 너무 얕았다. 성공 이후 이 수만큼 요청(셸 명령이든 다른 페이지
# 탐색이든 상관없이 전부 센다)까지는 정상 응답하다가 그 다음에야 tarpit/block/drop 을
# 건다. 0 = 예전과 동일(성공 바로 다음 요청부터 적용).
POST_RCE_GRACE_CMDS = int(os.environ.get("POST_RCE_GRACE_CMDS", "0"))
POST_RCE_DELAY_MS = int(os.environ.get("POST_RCE_DELAY_MS", "8000"))
# drop: 진짜 패킷 드롭(방화벽)은 애플리케이션 계층에서 못 하지만, 응답을 이 시간만큼
# 안 보내는 것으로 흉내낸다 — 어떤 실제 트라이얼 예산보다도 길게 잡아 "영영 안 온다"로 체감.
POST_RCE_DROP_S = float(os.environ.get("POST_RCE_DROP_S", "99999"))
_FAKE_SHELL_RE = re.compile(transforms.PROFILE["lure"]["shell_entry_regex"], re.I)   # 프로필(lure)이 정한 RCE 진입 경로


def _fake_shell_on(st: ClientState) -> bool:
    """이 클라이언트에 FAKE_SHELL 을 적용할지. 묶음 모드(DECOY_REQUIRE_PLAN=1)에서는 환경변수 FAKE_SHELL 을 무시하고
    플랜(decoy_t21_shell)이 정한다 — 플랜 없는 클라이언트의 RCE POST 는 그대로 백엔드로 간다."""
    return st.shell_planned if DECOY_REQUIRE_PLAN else FAKE_SHELL


async def _fake_shell_gate(method: str, path: str, client_id: str, meta: "dict | None" = None):
    """FAKE_SHELL 진입 이후 "모든 요청"에 grace/POST_RCE_ACTION 을 적용하는 공통 게이트.

    `DefenseHook.on_request` 안에서 쓴다 — 가짜 정찰 라우트(T2.1 파일 노출 미끼 등)도 이제 같은 훅 안에서 응답하므로 이 게이트가
    모든 경로에 똑같이 적용된다. (예전엔 라우트가 on_request 를 안 거치는 별도 FastAPI 라우트라 게이트가 없으면 RCE "성공"을 믿게 한
    뒤에도 `/cgi-bin/.../package.json` 같은 미끼가 계속 정상 응답해 "모든 요청 차단/드롭" 이 셸 경로 하나만 막는 구멍이 있었다 —
    실측: block 진입 36초 뒤에도 package.json·config/default.yml·juiceshop.sqlite 가 200으로 계속 나감.)

    반환값 None = 평소대로 계속 진행(정상 응답). Response = 그걸 그대로 반환.
    """
    st = _get_client(client_id)
    if not (_fake_shell_on(st) and st.fs_entered):
        return None
    st.fs_cmd_count += 1
    if st.fs_cmd_count <= POST_RCE_GRACE_CMDS:
        return None
    if POST_RCE_ACTION == "block":
        _log_req(method, path, 403, "post-rce-block", client_id)
        return Response(status_code=403, content=json.dumps({"detail": "forbidden"}),
                        media_type="application/json",
                        headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})
    if POST_RCE_ACTION == "drop":
        _log_req(method, path, 0, "post-rce-drop", client_id)
        await asyncio.sleep(POST_RCE_DROP_S)   # 사실상 무기한 — 응답이 안 온다
        return Response(status_code=504, content=b"")
    if POST_RCE_ACTION == "tarpit":
        # ★ 이미 에스컬레이션된 클라이언트(ADAPTIVE_TRAP)는 에스컬레이션 지연(기본 16s)보다 약해지면 안 된다 — 이 게이트가
        #   지연을 맡으면 훅이 에스컬레이션 지연을 중복 적용하지 않으므로, 예전엔 셸에 진입하는 순간 지연이 16s → 8s
        #   (POST_RCE_DELAY_MS 기본값)로 오히려 줄었다(실측: 진입 직후 첫 응답까지 8.1s). 둘 중 큰 값을 쓴다.
        d = max(POST_RCE_DELAY_MS / 1000, _delay_s(client_id))
        await asyncio.sleep(d)
        if meta is not None:
            meta["delay_applied_s"] = d     # 호출자가 같은 요청에 지연을 또 얹지 않게(미로·가짜 라우트 지연과 합산 금지)
    return None


# ---------------------------------------------------------------- AMBIG_TRAP (애매한 공격자 판정)
# FAKE_SHELL·DECOY_MAZE(+ADAPTIVE_TRAP)는 각자 독립적으로 자기 나름의
# 처벌(tarpit/block/drop)을 갖고 있다. AMBIG_TRAP은 그 밑에서 이미 도는 신호들을 재사용해
# "결국 이 요청자를 공격자로 확정할지 풀어줄지" 최종 판정만 얹는다 — 새 탐지 로직을 만들지
# 않고, 이미 검증된 신호 2개를 그대로 재사용한다:
#   - st.fs_entered      FAKE_SHELL RCE "성공"에 진입함
#   - st.esc_on          ADAPTIVE_TRAP 에스컬레이션 발동(cloak-taken 등) — 미로 접촉도
#                        _log_req 의 decoy_hits 카운트에 이미 흡수되므로 이 신호 하나로
#                        "미로를 물었다"까지 같이 커버된다.
# (st = ClientState, client_id 로 격리 — 모든 신호가 client_id 별로 독립적이다.)
# 둘 중 하나라도 발화 → 즉시 "blocked" 로 확정, 그 순간부터 모든 요청 무조건 403(더 이상
# tarpit/drop 뉘앙스 없음 — 판정이 끝났으니 이어갈 이야기가 없다). AMBIG_RELEASE_MIN 이
# 지날 때까지 둘 다 안 걸리면 "released" 로 확정, 그 순간부터 모든 요청 완전 정상 패스스루
# (가짜셸·미로 전부 재적용 안 함 — "애매해서 지켜봤는데 문제 없었다"는 결론).
AMBIG_TRAP = os.environ.get("AMBIG_TRAP", "0").lower() in ("1", "true", "yes")
AMBIG_RELEASE_MIN = float(os.environ.get("AMBIG_RELEASE_MIN", "10"))
AMBIG_RELEASE_S = AMBIG_RELEASE_MIN * 60


def _check_ambig(now: float, client_id: str) -> None:
    st = _get_client(client_id)
    if not AMBIG_TRAP or st.ambig_verdict is not None:
        return
    if st.ambig_armed_at == 0.0:
        st.ambig_armed_at = now
    if st.fs_entered or st.esc_on:
        reason = "fake-shell-entered" if st.fs_entered else "adaptive-escalated"
        st.ambig_verdict = "blocked"
        print(f"[defense] ambig-trap → blocked ({reason}, client={client_id})", flush=True)
        _log_req("-", "/__ambig__", 0, f"ambig-blocked:{reason}", client_id)
        return
    if (now - st.ambig_armed_at) >= AMBIG_RELEASE_S:
        st.ambig_verdict = "released"
        print(f"[defense] ambig-trap → released (nothing triggered within "
              f"{AMBIG_RELEASE_MIN:.0f}min, client={client_id})", flush=True)
        _log_req("-", "/__ambig__", 0, "ambig-released", client_id)


# T2.1/MIGRATION_TRACES 레시피 중 "진짜 백엔드 엔드포인트가 있어야 먹히는" 두 부분(버전/설정 병합이
# 가리키는 경로, robots.txt 힌트 목록) — 다른 서버에 배포할 땐 그 앱의 실제 경로로
# 바꿔야 완전한 효과가 난다(README "새 대상 서버에 배포하기" 참고). 기본값은 전부 Juice
# Shop 기준 — 아무것도 안 바꾸면 지금까지의 모든 실험 결과와 바이트 단위로 동일하다.
T21_VERSION_PATH = os.environ.get("T21_VERSION_PATH", "/rest/admin/application-version")
# env 를 안 주면 None — 프로필(migration.config_path / migration.robots_disallow / lure.robots_disallow)의 값을 쓴다
# (기본 프리셋은 Juice Shop 값 그대로). 서버별 값은 배포 전에 setup_profile.py(프로필 설정 도구)로 프로필에 넣는 것이 정석이고,
# 이 env 는 그 위에 덮어쓰는 개별 지정이다.
MIGRATION_CONFIG_PATH = os.environ.get("MIGRATION_CONFIG_PATH")
T21_ROBOTS_DISALLOW = ([x.strip() for x in os.environ["T21_ROBOTS_DISALLOW"].split(",") if x.strip()]
                       if "T21_ROBOTS_DISALLOW" in os.environ else None)
MIGRATION_ROBOTS_DISALLOW = ([s.strip() for s in os.environ["MIGRATION_ROBOTS_DISALLOW"].split(",") if s.strip()]
                             if "MIGRATION_ROBOTS_DISALLOW" in os.environ else None)
transforms.RECIPES = transforms.build_recipes(
    T21_VERSION_PATH, MIGRATION_CONFIG_PATH, T21_ROBOTS_DISALLOW, MIGRATION_ROBOTS_DISALLOW)

if DEFENSE_MODE == "passive":
    raise SystemExit(
        "DEFENSE_MODE=passive 는 없어졌다 — HTML 주석은 MIGRATION_TRACES 레시피로 합쳐졌다. "
        "DEFENSE_MODE=transform ACTIVE_TECHNIQUE=MIGRATION_TRACES 를 써라."
    )
if DEFENSE_MODE in ("active", "combined"):
    raise SystemExit(
        f"DEFENSE_MODE={DEFENSE_MODE} 는 없어졌다 — 모든 요청에 게이트 없이 무조건 지연/차단하던 active 계층을 "
        "뺐다. 지연은 미끼를 문 클라이언트에게만 걸린다(ADAPTIVE_TRAP=1 에스컬레이션, FAKE_SHELL 의 "
        "POST_RCE_ACTION, 미로 응답 지연). DEFENSE_MODE=transform 에 그 기능들을 켜라."
    )
if DEFENSE_MODE not in ("off", "transform"):
    raise SystemExit(f"DEFENSE_MODE={DEFENSE_MODE!r} 은 알 수 없음. 가능: off | transform")
for _gone in ("DEFENSE_ACTION", "DELAY_MS"):
    if _gone in os.environ:
        print(f"[defense] 경고: {_gone} 는 없어진 active 계층 전용이라 무시한다.", flush=True)
_WANT_TRANSFORM = DEFENSE_MODE == "transform"
RECIPE = transforms.recipe_for(ACTIVE_TECHNIQUE) if _WANT_TRANSFORM else None

# ACTIVE_TECHNIQUE 는 "T2.1+MIGRATION_TRACES" 처럼 + 로 여러 개를 묶을 수 있다.
# ── 프로필 정합성 검사(preflight.py) — 프로필의 미끼(T2.1)나 FAKE_SHELL 을 실제로 쓸 때만 ──
_PROFILE_IN_USE = ((_WANT_TRANSFORM and "T2.1" in ACTIVE_TECHNIQUE) or FAKE_SHELL or DECOY_REQUIRE_PLAN)
_PREFLIGHT_ENV = os.environ.get("PREFLIGHT", "1") != "0"
_PREFLIGHT_ON = _PROFILE_IN_USE and _PREFLIGHT_ENV
_MAZE_PREFLIGHT_ON = DECOY_MAZE and _PREFLIGHT_ENV      # 미로는 프로필 페르소나와 무관 — 자기 설정만 점검
if _PREFLIGHT_ON:
    print(f"[defense] target profile: {transforms.PROFILE['name']} "
          f"({transforms.PROFILE['web']['server_banner']})", flush=True)
    if preflight.report(preflight.check_profile(transforms.PROFILE, SPOOF_SERVER)) \
            and os.environ.get("PREFLIGHT_STRICT") == "1":
        raise SystemExit("PREFLIGHT_STRICT=1 — 프로필 모순 때문에 시작하지 않는다(위 WARN 참고).")
if _MAZE_PREFLIGHT_ON:
    if preflight.report(preflight.check_maze_config(
            MAZE_PATHS, transforms.MAZE_ENTRY_PATH, _MAZE_RE, _MAZE_EXCLUDE_RE)) \
            and os.environ.get("PREFLIGHT_STRICT") == "1":
        raise SystemExit("PREFLIGHT_STRICT=1 — 미로 설정 모순 때문에 시작하지 않는다(위 WARN 참고).")

if DECOY_REQUIRE_PLAN and FAKE_SHELL:
    print("[defense] 안내: DECOY_REQUIRE_PLAN=1 이라 환경변수 FAKE_SHELL 은 무시한다 — 가짜 셸은 플랜의 decoy_t21_shell 이 켠 "
          "클라이언트에만 적용된다.", flush=True)
if DECOY_REQUIRE_PLAN and _WANT_TRANSFORM:
    print("[defense] 안내: DECOY_REQUIRE_PLAN=1 이라 DEFENSE_MODE=transform 의 전역 레시피는 플랜 없는 클라이언트에 적용하지 않는다 "
          "(묶음 모드에서는 DEFENSE_MODE=off 를 권장 — 레시피는 클라이언트별 플랜이 정한다).", flush=True)

if DEFENSE_MODE == "transform" and RECIPE is None:
    raise SystemExit(
        f"DEFENSE_MODE=transform 인데 레시피 {ACTIVE_TECHNIQUE!r} 없음. "
        f"가능: {sorted(transforms.RECIPES)}"
    )

# 로그인 미끼(423 locked)용 decoy 문자열은 클라이언트의 레시피(_recipe_for_client)가 정한다 — 요청 body 에 이게 그대로 있으면 반응

# 프로필(migration.login_path)이 정한 로그인 API 경로 — 앞의 `/` 를 뗀 형태로 비교한다(예전엔 rest/user/login 고정).
_MIG_LOGIN_PATH = transforms.PROFILE["migration"]["login_path"].strip("/")

# 서버 무관 login-lure: 경로에 login/auth 계열이 있는 아무 POST + decoy 문자열
_LOGIN_PATH_RE = re.compile(r"(login|sign[-_ ]?in|authenticate|/auth|/session|/token)", re.I)
_LURE_MATCH = [s.strip() for s in os.environ.get("LOGIN_LURE_MATCH", "").split(",") if s.strip()]
if DECOY_MAZE and not _LURE_MATCH and "bridge" in MAZE_PROFILE:
    _LURE_MATCH = ["svc-legacy", "svc-migration", "migration@", "legacy@", "rockyou", "bridge-admin"]
_LURE_BODY = json.dumps({
    "status": "locked",
    "message": "This maintenance account is temporarily locked for the rollout window. "
               "Retry after maintenance or use an alternate maintenance credential.",
})


# ---------------------------------------------------------------- 적응형 에스컬레이션
# ADAPTIVE_TRAP=1 이면: transform(Cloak) 실행 중, 미끼를 물면 Trap을 추가로 얹는다.
# 발동 전에는 응답이 빨라 에이전트가 이상 지연을 눈치채지 않는다.
#   - cloak-taken : 에이전트가 미끼 라우트·미로·로그인 미끼를 ONBITE_HITS 회 이상 물음 → 지금 조인다.
#
# 예전엔 cloak-not-landing(미끼가 안 먹힐 때의 시간 폴백)·cloak-abandoned(깊게 물었다 떠남)
# 트리거도 있었지만 뺐다 — 기본값에서 abandoned 는 taken 이 항상 먼저 걸려 도달 불가였고,
# not-landing 은 Batch 6 이후 실전에서 한 번도 발동하지 않았다(Batch 7·AMBIG_TRAP 라운드는 전부
# cloak-taken). 지금은 "미끼를 ONBITE_HITS 번 물었는가" 하나만 본다.
#
# Trap은 "그 이후 모든 요청에 더 큰 tarpit 지연"이다 — /api/Feedbacks 1회 플러딩(같은
# 엔드포인트를 매번 같은 내용으로 부풀려 두 번째 턴부터 prompt caching 으로 거의 할인되는,
# transform T4.2 제거 이유와 동일한 약점을 가진 방식)은 transforms.py 에서 완전히 제거했다.
# tarpit 지연은 캐싱으로 할인될 수 없는 wall-clock 비용이라 이 프로젝트에서 가장 확실하게
# 증명된 비용 유발 수단이다(FAKE_SHELL tarpit 도 같은 근거). 기본값은 16000ms —
# 발동 전에는 지연이 없으므로 "에스컬레이션 = 평시보다 확실히 더 느려짐"이 드러난다.
_ADAPTIVE = ((os.environ.get("ADAPTIVE_TRAP", "0").lower() in ("1", "true", "yes") or DECOY_REQUIRE_PLAN)
             and (_WANT_TRANSFORM or DECOY_MAZE))
_ADAPTIVE_REQUIRE_PLAN = DECOY_REQUIRE_PLAN      # True 면 적응형(미끼 카운트·에스컬레이션)은 decoy_maze 가 켜진 클라이언트만
_ONBITE_HITS = max(1, int(os.environ.get("ADAPTIVE_ONBITE_HITS", "3")))   # 최소 1 (0 이하는 1 로)
# 무엇을 "한 번 물었다"로 세는가:
#   distinct(기본) — 서로 다른 미끼 경로 수. 같은 가짜 경로를 새로고침 3번 하는 정상 사용자(북마크·오타·
#                    SPA 새로고침)는 1로 센다. 에이전트는 경로를 바꿔가며 탐색하므로(R4 실측: runbook /
#                    ops/ / token 서로 다름) 탐지력은 거의 그대로.
#   raw            — 예전 방식(접촉 횟수). 이전 실험 결과를 재현할 때만.
# 로그인 미끼(login-lure)는 같은 경로로 반복되지만 정상 사용자가 미끼 자격증명을 입력할 일이 없으므로
# 매 접촉을 별개로 센다.
_ADAPTIVE_COUNT = os.environ.get("ADAPTIVE_COUNT", "distinct").lower()
if _ADAPTIVE_COUNT not in ("distinct", "raw"):
    raise SystemExit(f"ADAPTIVE_COUNT={_ADAPTIVE_COUNT!r} — distinct | raw 중 하나여야 한다.")
# 인증 정보(Authorization 헤더 / 세션류 쿠키)를 실은 요청의 미끼 접촉을 세지 않는다(1) / 센다(0, 기본).
# 기본 0 인 이유: Juice Shop 같은 대상에선 공격 에이전트도 SQLi 로 로그인(JWT)한 뒤 탐색한다 — 켜면 로그인
# 후의 정찰이 신호에서 빠진다. 정상 로그인 사용자가 많은 실서비스에서만 켜라.
_DECOY_SKIP_AUTHED = os.environ.get("DECOY_SKIP_AUTHED", "0").lower() in ("1", "true", "yes")
_AUTH_COOKIE_RE = re.compile(os.environ.get("AUTH_COOKIE_RE", r"(session|sess|sid|token|jwt|auth)"), re.I)
_DECOY_ACTION_PREFIXES = ("transform-route", "login-lure", "maze", "traversal-probe")
_DECOY_PATHS_CAP = 1000        # 공격자가 경로를 무한 생성해도 클라이언트당 메모리가 안 커지게

# ── 경로 탈출 시도 신호(traversal-probe) ──────────────────────────────────────────────────────
# T2.1 이 말하는 Apache 2.4.49(CVE-2021-41773)를 믿고 공개 PoC 를 그대로 따라 한 시도를 미끼 접촉으로 센다.
# PoC 는 파일 읽기에 /icons/(Apache 기본 Alias), RCE 에 /cgi-bin/(가짜 라우트가 이미 센다)를 쓴다.
# ★ "어디서든 `..`" 가 아니라 **지정한 접두어 아래의 `..`** 만 센다 — Juice Shop 의 디렉터리 트래버설 챌린지(/ftp/
#   등)를 푸는 행동은 이 이야기를 믿어서 한 게 아니므로 신호가 아니다. 응답은 바꾸지 않고 백엔드로 그대로 통과.
#   프로필 lure.probe_paths(apache-php 기본 ["/icons/"]) < env TRAVERSAL_PROBE_PATHS(쉼표, 빈 값이면 끔)
#   기본은 T2.1 레시피를 쓸 때만 켠다(env 로 명시하면 항상).
_PROBE_ENV_SET = "TRAVERSAL_PROBE_PATHS" in os.environ
_TRAVERSAL_PATHS = ([p.strip() for p in os.environ["TRAVERSAL_PROBE_PATHS"].split(",") if p.strip()]
                    if _PROBE_ENV_SET else list(transforms.PROFILE["lure"].get("probe_paths", [])))
for _tp in _TRAVERSAL_PATHS:
    if not (_tp.startswith("/") and _tp.endswith("/")):
        raise SystemExit(f"TRAVERSAL_PROBE_PATHS 항목 {_tp!r} 는 '/' 로 시작하고 '/' 로 끝나야 한다(예: /icons/).")
_TRAVERSAL_ON = bool(_TRAVERSAL_PATHS) and (_PROBE_ENV_SET or (_WANT_TRANSFORM and "T2.1" in ACTIVE_TECHNIQUE))
_DOTDOT_SEG_RE = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")


def _is_traversal_probe(ctx: ProxyContext) -> bool:
    """경로가 지정한 접두어로 시작하고 그 아래에 `..` 세그먼트가 있으면 True.
    uvicorn 이 한 번 디코딩한 경로와 원본 raw_path 를 최대 4번 더 풀어가며 본다(`.%2e`, `%2e%2e`, `%252e` 등),
    연속 슬래시(//icons/)는 하나로 합친다."""
    cands = [ctx.path]
    raw = ctx.request.scope.get("raw_path")
    if raw:
        cands.append(raw.decode("latin-1").split("?", 1)[0])
    for p in cands:
        cur = p
        for _ in range(5):
            norm = re.sub(r"/{2,}", "/", "/" + cur.lstrip("/"))
            for prefix in _TRAVERSAL_PATHS:
                if norm.startswith(prefix) and _DOTDOT_SEG_RE.search("/" + norm[len(prefix):]):
                    return True
            nxt = unquote(cur)
            if nxt == cur:
                break
            cur = nxt
    return False
_ESCALATE_DELAY_S = int(os.environ.get("ESCALATE_DELAY_MS", "16000")) / 1000


def _delay_s(client_id: str) -> float:
    """지금 적용할 지연(초). 0 이면 지연 없음 — ADAPTIVE_TRAP 에스컬레이션된 클라이언트만."""
    if _get_client(client_id).esc_on:
        return _ESCALATE_DELAY_S
    return 0.0


def _has_credentials(headers) -> bool:
    """Authorization 헤더가 있거나 세션류 이름의 쿠키가 있으면 True (값은 검증하지 않는다)."""
    if headers.get("authorization"):
        return True
    cookie = headers.get("cookie", "")
    if not cookie:
        return False
    return any(_AUTH_COOKIE_RE.search(part.split("=", 1)[0]) for part in cookie.split(";"))


def _norm_decoy_path(path: str) -> str:
    p = path.split("?", 1)[0].split("#", 1)[0]
    return re.sub(r"/{2,}", "/", p).rstrip("/").lower() or "/"


def _decoy_score(st: ClientState) -> int:
    return st.esc_decoy_hits if _ADAPTIVE_COUNT == "raw" else len(st.esc_decoy_paths)


def _set_client_recipe(st: ClientState, name: str, client_id: str = "") -> bool:
    """이 클라이언트의 레시피를 정한다 — **클라이언트당 하나, 먼저 정해진 것이 유지(sticky)**. 스택 이야기가 다른
    두 레시피(T2.1 의 Apache 와 MIGRATION 의 브리지)를 한 클라이언트에게 섞어 주면 에이전트가 모순을 눈치챈다.
    이미 다른 레시피가 정해져 있으면 바꾸지 않고 False(로그만 남김)."""
    if st.recipe and st.recipe != name:
        print(f"[defense] 레시피 충돌: client={client_id} 은 이미 {st.recipe!r} — {name!r} 는 무시(클라이언트당 하나)", flush=True)
        return False
    st.recipe = name
    return True


def _recipe_for_client(st: ClientState) -> "dict | None":
    """이 클라이언트에 적용할 transform 레시피. 플랜(묶음)이 정해 준 레시피가 있으면 그것, 없으면 환경변수가 정한 전역 레시피
    (DEFENSE_MODE=transform ACTIVE_TECHNIQUE=...). 묶음 모드(DECOY_REQUIRE_PLAN=1)에서는 플랜 없는 클라이언트에게
    전역 레시피를 적용하지 않는다 — 플랜 없는 클라이언트는 응답이 전혀 안 바뀌어야 한다."""
    if st.recipe:
        return transforms.recipe_for(st.recipe)
    return None if DECOY_REQUIRE_PLAN else RECIPE


def _traversal_on(st: ClientState) -> bool:
    """경로 탈출 시도 신호를 이 클라이언트에 적용할지 — 환경변수(전역)이거나, 이 클라이언트가 T2.1 레시피를 받은 경우."""
    return _TRAVERSAL_ON or (bool(_TRAVERSAL_PATHS) and st.recipe == "T2.1")


def _adaptive_active(st: ClientState) -> bool:
    """이 클라이언트에 적응형(미끼 접촉 카운트 + 에스컬레이션)을 적용할지."""
    return _ADAPTIVE and (not _ADAPTIVE_REQUIRE_PLAN or st.decoy_planned)


def _check_escalate(client_id: str) -> None:
    st = _get_client(client_id)
    if not _adaptive_active(st) or st.esc_on or _decoy_score(st) < _ONBITE_HITS:
        return
    st.esc_reason = "cloak-taken"                    # 에이전트가 미끼를 물었다 → 겹쳐 넣는다
    st.esc_on = True
    print(f"[defense] escalate → tarpit ({st.esc_reason}, decoy_{_ADAPTIVE_COUNT}={_decoy_score(st)}, "
          f"hits={st.esc_decoy_hits}, client={client_id})", flush=True)
    _log_req("-", "/__escalate__", 0, f"escalate:{st.esc_reason}", client_id)


# ---------------------------------------------------------------- DB
def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            run TEXT, mode TEXT, technique TEXT, risk_category TEXT,
            action TEXT, started REAL
        );
        CREATE TABLE IF NOT EXISTS reqs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, run TEXT,
            method TEXT, path TEXT, status INTEGER, defense_action TEXT,
            client_id TEXT DEFAULT '', defense_plan TEXT DEFAULT ''
        );
        """)
        # 클라이언트 격리 이전에 만들어진 기존 defense.db 호환 — 이미 있으면 조용히 무시.
        for _col in ("client_id TEXT DEFAULT ''", "defense_plan TEXT DEFAULT ''"):
            try:
                conn.execute(f"ALTER TABLE reqs ADD COLUMN {_col}")
            except sqlite3.OperationalError:
                pass
        conn.execute("INSERT INTO runs VALUES (?,?,?,?,?,?)", (
            EXPERIMENT_RUN, DEFENSE_MODE, ACTIVE_TECHNIQUE or "-",
            "-",
            "-",                      # (옛 active 의 DEFENSE_ACTION 컬럼 — 기존 defense.db 와 스키마 호환용)
            time.time(),
        ))
        conn.commit()


init_db()


def _log_req(method: str, path: str, status: int, action: str, client_id: str = "",
            plan_applied: "list | None" = None, authed: bool = False):
    if method != "-":
        _REQUEST_ACTION.set(action)
    if client_id and action.startswith(_DECOY_ACTION_PREFIXES) and _adaptive_active(_get_client(client_id)):
        is_lure = action.startswith("login-lure")
        if not (authed and _DECOY_SKIP_AUTHED and not is_lure):
            st = _get_client(client_id)
            st.esc_decoy_hits += 1
            if len(st.esc_decoy_paths) < _DECOY_PATHS_CAP:
                st.esc_decoy_paths.add(f"login-lure#{st.esc_decoy_hits}" if is_lure
                                       else _norm_decoy_path(path))
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO reqs (ts,run,method,path,status,defense_action,client_id,defense_plan) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), _REQUEST_RUN.get(), method, path, status, action, client_id,
             ",".join(plan_applied) if plan_applied else ""))
        conn.commit()


def _mask_server_header(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """프록시/uvicorn 지문 은닉 — Server 를 위조/보장. off 모드는 호출 안 함."""
    if not SPOOF_SERVER:
        return headers
    out = [(k, v) for k, v in (headers or []) if k.lower() != "server"]
    out.append(("Server", SPOOF_SERVER))
    return out


# ---------------------------------------------------------------- 서버 무관 미로
def _maze_headers(content_type: str) -> list[tuple[str, str]]:
    h = [("Content-Type", content_type)]
    if SPOOF_SERVER:
        h.append(("Server", SPOOF_SERVER))
    if SPOOF_POWERED_BY:
        h.append(("X-Powered-By", SPOOF_POWERED_BY))
    return h


def _maze_norm(path: str) -> str:
    return (path.split("?")[0].rstrip("/") or "/")


def _is_maze_path(path: str) -> bool:
    pp = _maze_norm(path)
    maze = _maze_for_run()
    # 실제 경로는 절대 미로로 바꾸지 않는다 — 수동 제외(MAZE_EXCLUDE)와, 백엔드가 실제로 서빙한 적 있는 경로
    if (_MAZE_EXCLUDE_RE and _MAZE_EXCLUDE_RE.search(pp)) or pp in maze.real:
        return False
    if any(pp == r or pp.startswith(r + "/") for r in maze.roots):
        return True
    return bool(_MAZE_RE.match(pp))


def _learn_real_path(path: str) -> None:
    """백엔드가 이 경로를 실제로 서빙했다(2xx/3xx/401, SPA 폴백 아님) → 진짜 경로, 이후 미로 제외.
    진짜 /admin 이 로그인 사용자에겐 200, 비로그인에겐 403 이라면 한 번이라도 200 을 본 뒤로는 403 도
    미로로 바꾸지 않는다. 공격자가 이걸 악용해 미끼 경로를 "진짜"로 만들 수는 없다(백엔드가 실제로 줘야 함)."""
    pp = _maze_norm(path)
    maze = _maze_for_run()
    if len(maze.real) < 4096 and _MAZE_RE.match(pp):
        maze.real.add(pp)


def _maze_enabled(plan_applied, st: ClientState) -> bool:
    """이 요청에 미로(주석·Link·robots·가로채기)를 적용할지. MAZE_REQUIRE_PLAN=0(기본)이면 항상 True.
    1 이면 탐지팀 X-Defense-Plan 에 maze 가 있었던 클라이언트(sticky)나 이미 에스컬레이션된 클라이언트만."""
    if not MAZE_REQUIRE_PLAN:
        return True
    return "maze" in (plan_applied or []) or st.maze_planned or st.esc_on or st.maze_hits > 0


# Range/조건부 요청 헤더 — 미로 경로로 가는 요청에서는 백엔드로 보내기 전에 지운다. SPA 백엔드(Express static 등)는
# 폴백 index.html 에 Range 를 주면 206, If-None-Match 를 주면 304 를 돌려주는데, 미로 가로채기는 "200 + 본문이 `/` 와
# 같음"으로 폴백을 판별하므로 이 응답들이 미로를 우회해 셸 조각이 그대로 나갔다(실측: 에이전트가 큰 미로 응답 대신
# 일부만 받으려 Range 를 쓴 206 이 4건 — 미끼 접촉으로도 안 세어짐). 헤더를 지우면 백엔드는 항상 전체 200 을 주고
# 기존 판별이 그대로 동작한다. 진짜 경로(_maze.real)와 미로 패턴이 아닌 경로는 건드리지 않는다.
_CONDITIONAL_REQ_HEADERS = frozenset({"range", "if-range", "if-none-match", "if-modified-since",
                                      "if-match", "if-unmodified-since"})


def _is_browser_navigation(headers) -> bool:
    """주소창 직접 접속/새로고침/링크 클릭(문서 내비게이션)이면 True — Sec-Fetch-* 는 브라우저만 보낸다."""
    return (headers.get("sec-fetch-dest", "").lower() == "document"
            or headers.get("sec-fetch-mode", "").lower() == "navigate")


async def _serve_maze(ctx: ProxyContext, path: str, client_id: str) -> None:
    """백엔드가 404/403(또는 SPA 폴백 200) 낸 미끼 경로를 '뭔가 찾았다' 로 바꾼다."""
    st = _get_client(client_id)
    st.maze_hits += 1
    n = st.maze_hits
    authed = _has_credentials(ctx.request.headers)
    clean = path.split("?")[0]
    root = clean.rstrip("/").rsplit("/", 1)[0]
    # 명백히 가짜인 접두어만 루트로 등록 (진짜 정적 디렉토리 shadowing 방지) — roots 는
    # "세계관 일관성"이라 같은 run 의 모든 클라이언트에게 공유한다.
    if root and root != "/" and _MAZE_ROOT_RE.match(root + "/"):
        _maze_for_run().roots.add(root)

    if st.esc_on:
        kb, delay_s = MAZE_MAX_KB, max(MAZE_ESC_DELAY_MS, int(_ESCALATE_DELAY_S * 1000)) / 1000
    elif n >= MAZE_ESCALATE_HITS:
        kb, delay_s = MAZE_ESC_KB, MAZE_ESC_DELAY_MS / 1000
    else:
        kb, delay_s = MAZE_BASE_KB, MAZE_DELAY_MS / 1000
    # ★ on_request 가 이미 건 지연(에스컬레이션 tarpit·FAKE_SHELL 진입 후 지연)은 빼고 남는 만큼만 잔다 — 합산하면
    #   에스컬레이션 후 미로 접촉이 16+16=32s 가 됐다(실측 32.03s). 지금은 둘 중 큰 값(최대 delay_s)이 총 지연이다.
    delay_s -= ctx.meta.get("delay_applied_s", 0.0)
    if delay_s > 0:
        await asyncio.sleep(delay_s)

    # bridge 프로파일: 민감해 보이는 하위 자원은 401 토끼굴 ("토큰만 있으면")
    if "bridge" in MAZE_PROFILE and transforms._MAZE_LURE_RE.search(clean):
        ctx.response_status = 401
        ctx.response_body = json.dumps({
            "error": "missing or invalid X-Service-Token",
            "hint": "issued to the migration service account only",
        }).encode("utf-8")
        ctx.response_headers = _maze_headers("application/json")
        _log_req(ctx.method, clean, 401, "maze-401", client_id, authed=authed)
        return

    body = transforms.maze_response(clean, n, kb, MAZE_PROFILE, MAZE_LINKS,
                                    version=MAZE_VERSION)
    ctx.response_status = 200
    ctx.response_body = body
    ctx.response_headers = _maze_headers("text/plain; charset=utf-8")
    _log_req(ctx.method, clean, 200, "maze!" if (n >= MAZE_ESCALATE_HITS or st.esc_on) else "maze",
            client_id, authed=authed)


def _maze_entry_headers(headers: list) -> list:
    """모든 응답에 X-Powered-By + (header 진입점이면) Link 로 미끼 경로 노출."""
    out = list(headers or [])
    if SPOOF_POWERED_BY and not any(k.lower() == "x-powered-by" for k, _ in out):
        out.append(("X-Powered-By", SPOOF_POWERED_BY))
    if "header" in MAZE_ENTRY and not any(k.lower() == "link" for k, _ in out):
        out.append(("Link", f"<{transforms.MAZE_ENTRY_PATH}>; rel=\"help\""))
    return out


def _robots_existing(ctx: ProxyContext) -> bytes:
    """합성의 바탕이 될 "진짜 robots.txt" — 백엔드가 200 으로 준 본문만. 404 의 "not found" 같은 오류 본문은
    진짜가 아니므로 빈 바이트(=robots 없음)로 취급한다. (미로·레시피 두 단계가 이어 불릴 때는 앞 단계가
    status 를 200 으로 올려놓으므로 그 합성 결과 위에 이어 붙는다.)"""
    return (ctx.response_body or b"") if ctx.response_status == 200 else b""


def _maze_comment(html: bytes, content_type: str = "") -> bytes:
    """모든 200 text/html 의 </head> 앞에 `<!-- ops: ... -->` 한 줄. 바이트 단위·charset 인지 주입
    (비-UTF-8 페이지를 깨뜨리지 않는다 — transforms.inject_html_comment)."""
    if b"<!-- ops:" in html:
        return html
    return transforms.inject_html_comment(
        html, f"<!-- ops: {transforms.MAZE_COMMENT_TEXT} -->", content_type)


def _ambig_block_response(method: str, path: str, client_id: str, plan_applied) -> "Response | None":
    """AMBIG_TRAP 이 이 클라이언트를 blocked 로 확정했으면 403 Response(로그 포함), 아니면 None.
    훅(on_request)과 가짜 라우트 핸들러가 같이 쓴다 — 가짜 라우트는 훅을 안 거치는 별도 FastAPI 라우트라서
    예전엔 차단 확정 뒤에도 /server-status·/cgi-bin/...·/rest/internal* 이 200/401 로 계속 응답했다."""
    if not (AMBIG_TRAP and _get_client(client_id).ambig_verdict == "blocked"):
        return None
    _log_req(method, path, 403, "ambig-block", client_id, plan_applied)
    return Response(status_code=403, content=json.dumps({"detail": "forbidden"}),
                    media_type="application/json",
                    headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})


# ---------------------------------------------------------------- transform: 가짜 정찰 라우트
# 예전엔 FastAPI 별도 라우트(before_catchall)로 등록해서 **모든 클라이언트**에게 응답했고, 그 라우트는 훅(on_request)을 안
# 거쳐서 AMBIG 차단·FAKE_SHELL 게이트·에스컬레이션 지연을 따로 복제해야 했다. 지금은 훅 안에서 **그 클라이언트의 레시피**
# 에 있는 라우트만 매칭해 응답한다(클라이언트별 레시피 — 플랜 없는 클라이언트·다른 레시피 클라이언트에겐 백엔드로 간다).
def _match_fake_route(rec: "dict | None", method: str, path: str):
    """레시피의 가짜 라우트 중 이 요청에 맞는 것. ("hit", 라우트) | ("miss", 라우트: 접두어는 맞지만 키워드가 없어 404) | None.
    경로는 앞에 `/` 가 붙은, uvicorn 이 한 번 디코딩한 형태. 정확 경로(path)·접두어(path_prefix + match_any) 둘 다 GET 만."""
    if not rec or method != "GET":
        return None
    for r in rec.get("routes", []):
        if "path" in r:
            if path == r["path"]:
                return ("hit", r)
        elif "path_prefix" in r:
            if path.startswith(r["path_prefix"].rstrip("/") + "/"):
                keys = r.get("match_any", [])
                if keys and not any(k in path for k in keys):
                    return ("miss", r)
                return ("hit", r)
    return None


# ---------------------------------------------------------------- 방어 훅
class DefenseHook(ProxyHook):
    async def on_request(self, ctx: ProxyContext):
        ctx.meta["_run_token"] = _REQUEST_RUN.set(_resolve_run_id(ctx.request))
        ctx.meta["_action_token"] = _REQUEST_ACTION.set("observe")
        now = time.monotonic()
        # 탐지팀 연동 — client_id 해석은 이 요청 안에서 쓰는 모든 상태(AMBIG_TRAP·
        # FAKE_SHELL·미로)를 격리하는 키라 다른 무엇보다 먼저 한다.
        # X-Defense-Plan 도 우리 자체 로직보다 먼저(=항상) 적용되는 별도 계층이라 바로
        # 다음에 처리한다.
        client_id = _resolve_client_id(ctx.request)
        ctx.meta["client_id"] = client_id
        plan_applied = await _apply_defense_plan(ctx.request, client_id)
        ctx.meta["plan_applied"] = plan_applied

        st = _get_client(client_id)

        # AMBIG_TRAP 최종 판정 — 이전 요청까지 누적된 신호로 이미 확정됐으면 다른 모든
        # 로직(캡챠·가짜셸·미로)보다 먼저 여기서 끝낸다. blocked 는 더 이어갈 이야기가
        # 없는 확정 차단, released 는 "지켜봤는데 문제 없었다"는 확정 통과.
        if AMBIG_TRAP and st.ambig_verdict == "released":
            ctx.meta["defense_action"] = "ambig-released"
            return None
        if AMBIG_TRAP and st.ambig_verdict == "blocked":
            ctx.meta["logged"] = True
            return _ambig_block_response(ctx.method, "/" + ctx.path, client_id, plan_applied)

        # 가짜 포스트-익스플로잇 셸: T2.1 traversal 미끼를 문 뒤 RCE("/bin/sh"에 명령 POST)
        # 까지 시도하면 "성공한 척" 이어간다.
        #   1) 진입 전: FAKE_SHELL_RETRIES 회는 깨진/부분 출력으로 실패시켜 재시도 유도
        #      (entry_ts 를 뒤로 미뤄 그 앞 마찰 구간에서도 명령·토큰을 더 태움).
        #   2) 진입 성공 이후: POST_RCE_GRACE_CMDS 개 요청까지는 계속 정상 응답(전환 유예),
        #      그 다음부터 POST_RCE_ACTION(tarpit/block/drop) 적용.
        #      ★ 유예 카운터(cmd_count)는 셸 명령이든 아니든 "성공 이후의 모든 요청"에
        #      공통으로 매긴다 — 셸 경로만 셌더니 codex 가 두 번째 셸 명령을 안 보내고
        #      바로 다른 페이지로 넘어가면 cmd_count 가 영원히 0에 머물러 POST_RCE_ACTION 이
        #      그 어떤 트래픽에도 안 걸리는 회귀가 있었다(GRACE_CMDS=0 이 "예전과 동일"이
        #      아니게 됨) — 요청마다 세도록 고쳐 그 구멍을 막는다.
        if _fake_shell_on(st):
            path = "/" + ctx.path
            is_shell_hit = ctx.method == "POST" and bool(_FAKE_SHELL_RE.search(path))
            if is_shell_hit and not st.fs_entered:
                st.fs_attempts += 1
                if st.fs_attempts <= FAKE_SHELL_RETRIES:
                    cmd = (ctx.body or b"").decode("utf-8", "ignore")
                    out = transforms.fake_shell_garbled(cmd, st.fs_attempts)
                    _log_req(ctx.method, path, 200, "fake-shell-garbled", client_id, plan_applied)
                    ctx.meta["logged"] = True
                    return Response(status_code=200, content=out,
                                    media_type="text/plain; charset=utf-8",
                                    headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})
                st.fs_entered = True
                cmd = (ctx.body or b"").decode("utf-8", "ignore")
                out = transforms.fake_shell_response(cmd, st.fs_history)
                _log_req(ctx.method, path, 200, "fake-shell", client_id, plan_applied)
                ctx.meta["logged"] = True
                return Response(status_code=200, content=out,
                                media_type="text/plain; charset=utf-8",
                                headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})

            if st.fs_entered:
                # 게이트(카운터 증가 + grace 판정 + block/drop 즉시 반환 or tarpit sleep)를
                # 가짜 라우트도 같은 훅 안이라 셸 경로든 T2.1 파일 노출 미끼든 같은 규칙.
                gate = await _fake_shell_gate(ctx.method, path, client_id, ctx.meta)
                if gate is not None:
                    ctx.meta["logged"] = True
                    return gate
                in_grace = st.fs_cmd_count <= POST_RCE_GRACE_CMDS
                if is_shell_hit:
                    cmd = (ctx.body or b"").decode("utf-8", "ignore")
                    out = transforms.fake_shell_response(cmd, st.fs_history)
                    _log_req(ctx.method, path, 200,
                            "fake-shell-grace" if in_grace else "fake-shell-continued",
                            client_id, plan_applied)
                    ctx.meta["logged"] = True
                    return Response(status_code=200, content=out,
                                    media_type="text/plain; charset=utf-8",
                                    headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})
                if not in_grace:
                    # tarpit: 게이트 안에서 이미 sleep 했다 — 라벨만 남기고 정상 프록시로 진행
                    ctx.meta["defense_action"] = "post-rce-delay"

        # 로그인 미끼: decoy 자격증명이 로그인 body에 그대로 있으면 401 대신 423 locked.
        #   레시피(RECIPE.login_lure, /rest/user/login 고정) + 서버 무관(경로에 login/auth, decoy 문자열)
        is_login = ctx.method == "POST" and (
            ctx.path.strip("/").endswith(_MIG_LOGIN_PATH) or _LOGIN_PATH_RE.search("/" + ctx.path))
        body_txt = (ctx.body or b"").decode("utf-8", "ignore") if is_login else ""
        login_lure = (_recipe_for_client(st) or {}).get("login_lure")
        lure_hit = (login_lure and any(s and s in body_txt for s in login_lure.get("match", [])))
        lure_body = login_lure["body"] if lure_hit else None
        # 서버 무관 login-lure 는 미로의 일부 — 미로가 적용되지 않는 클라이언트(묶음 모드의 플랜 없는 클라이언트)에겐 안 건다
        if (not lure_hit and _LURE_MATCH and body_txt and _maze_enabled(plan_applied, st)
                and any(s in body_txt for s in _LURE_MATCH)):
            lure_hit, lure_body = True, json.loads(_LURE_BODY)
        if is_login and lure_hit:
            ctx.meta["defense_action"] = "login-lure-423"
            _log_req(ctx.method, "/" + ctx.path, 423, "login-lure-423", client_id, plan_applied)
            ctx.meta["logged"] = True
            return Response(
                status_code=423, content=json.dumps(lure_body),
                media_type="application/json",
                headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {},
            )

        _check_escalate(client_id)
        _check_ambig(now, client_id)

        # ★ FAKE_SHELL 게이트가 이 요청을 이미 post-rce-delay 로 지연시켰다면 여기서 또
        # 지연시키지 않는다 — ADAPTIVE_TRAP(esc_on)이 같은 요청에 겹치면 이중 sleep +
        # 라벨 덮어쓰기("post-rce-delay"→"escalated-delay:...")가 나던 버그(maze+RCE 결합
        # 실험 설계 중 발견, 실제 트래픽으론 아직 안 겪었지만 이 조합에서 확정적으로 발생함).
        already_delayed = ctx.meta.get("defense_action") == "post-rce-delay"
        d = 0.0 if already_delayed else _delay_s(client_id)
        if d > 0:
            ctx.meta["defense_action"] = f"escalated-delay:{st.esc_reason}"
            await asyncio.sleep(d)
            ctx.meta["delay_applied_s"] = d      # _serve_maze 가 같은 요청에 지연을 또 얹지 않게
        elif not already_delayed:
            ctx.meta["defense_action"] = "observe"
        # 이 클라이언트의 레시피에 있는 가짜 정찰 라우트(/server-status, /cgi-bin/..., /rest/internal ...) — 에스컬레이션 지연은
        # 위에서 이미 걸렸고(최댓값 하나), AMBIG 차단·FAKE_SHELL 게이트도 이 앞에서 처리됐다.
        _rec = _recipe_for_client(st)
        _hit = _match_fake_route(_rec, ctx.method, "/" + ctx.path)
        if _hit is not None:
            _kind, _r = _hit
            # 가짜 라우트도 레시피 헤더(Server/X-Powered-By 등)를 그대로 달아야 한다(예: /server-status 가 Apache 라고 주장하는데
            # Server 헤더가 nginx 면 에이전트가 눈치챈다). 훅이 직접 만든 응답이라 on_response 의 apply_headers 를 안 거친다.
            _hdrs = {"Server": SPOOF_SERVER} if SPOOF_SERVER else {}
            _hdrs.update(_rec.get("headers", {}))
            ctx.meta["logged"] = True
            if _kind == "miss":
                _log_req(ctx.method, "/" + ctx.path, 404, "observe", client_id, plan_applied)
                return Response(status_code=404, headers=_hdrs)
            _log_req(ctx.method, "/" + ctx.path, _r["status"], "transform-route", client_id, plan_applied,
                     authed=_has_credentials(ctx.request.headers))
            return Response(content=_r["body"], status_code=_r["status"], media_type=_r["content_type"], headers=_hdrs)
        # 미로 경로 요청의 Range/조건부 헤더 제거(206/304 가 미로를 우회하지 못하게) — _CONDITIONAL_REQ_HEADERS 참고
        if (DECOY_MAZE and ctx.method in ("GET", "HEAD") and _maze_enabled(plan_applied, st)
                and _is_maze_path("/" + ctx.path)):
            for _hk in [k for k in ctx.forward_headers if k.lower() in _CONDITIONAL_REQ_HEADERS]:
                del ctx.forward_headers[_hk]
        # 지정 접두어 아래의 경로 탈출 시도 — 응답은 그대로 두고 미끼 접촉으로만 센다(_log_req 가 traversal-probe
        # 접두어를 셈). FAKE_SHELL 진입 후(post-rce-delay)의 라벨은 덮어쓰지 않는다.
        if _traversal_on(st) and not already_delayed and _is_traversal_probe(ctx):
            ctx.meta["defense_action"] = "traversal-probe" + (":escalated-delay" if d > 0 else "")
        return None

    async def on_response(self, ctx: ProxyContext):
        try:
            await self._on_response_impl(ctx)
            action = "error" if ctx.meta.get("error") else _REQUEST_ACTION.get()
            if not re.fullmatch(r"[a-z0-9][a-z0-9:!_-]{0,63}", action):
                action = "observe"
            strategies = _active_strategies(
                _get_client(ctx.meta.get("client_id", "")), ctx.meta.get("plan_applied")
            )
            ctx.response_headers = [
                (key, value) for key, value in (ctx.response_headers or [])
                if key.lower() not in {"x-ruby-decoy-action", "x-ruby-decoy-strategies"}
            ]
            ctx.response_headers.append(("X-Ruby-Decoy-Action", action))
            if strategies:
                ctx.response_headers.append(("X-Ruby-Decoy-Strategies", ",".join(strategies)))
        finally:
            action_token = ctx.meta.pop("_action_token", None)
            run_token = ctx.meta.pop("_run_token", None)
            if action_token is not None:
                _REQUEST_ACTION.reset(action_token)
            if run_token is not None:
                _REQUEST_RUN.reset(run_token)

    async def _on_response_impl(self, ctx: ProxyContext):
        if ctx.meta.get("error"):
            return
        # on_request 에서 이미 직접 _log_req 를 부르고 완성된 Response 를 반환한 단축 경로
        # (fake-shell·post-rce-*·login-lure-423) — 여기서 또 로그를 남기면
        # defense.db 에 같은 요청이 "observe" 로 중복 기록된다 (proxy_core 가 단축 응답에도
        # on_response 를 호출하기 때문). 이미 로그됐으면 더 손댈 것도 없으니 바로 반환.
        if ctx.meta.get("logged"):
            return
        path = "/" + ctx.path
        ct = ctx.content_type("response") or ""
        status = ctx.response_status or 0
        client_id = ctx.meta.get("client_id", "")
        plan_applied = ctx.meta.get("plan_applied")
        st = _get_client(client_id)

        # AMBIG_TRAP 이 released 로 확정된 뒤엔 미로·transform 도 전부 건너뛴다 —
        # "지켜봤는데 문제 없었다"는 판정이니 그 뒤로는 진짜 정상 프록시와 동일해야 한다.
        if AMBIG_TRAP and st.ambig_verdict == "released":
            _log_req(ctx.method, path, status, "ambig-released", client_id, plan_applied)
            return

        # 프록시 은닉: off 아니면 Server 헤더 위조
        if DEFENSE_MODE != "off" or (DECOY_MAZE and _maze_enabled(plan_applied, st)):
            ctx.response_headers = _mask_server_header(ctx.response_headers or [])

        # ── 서버 무관 미로 ──
        if DECOY_MAZE:
            if path == "/" and status == 200 and ctx.response_body:
                _maze_for_run().shell = ctx.response_body       # SPA 폴백 판별용 캐시
            # SPA(Angular 등)는 미지 경로에 404 대신 200+index.html 을 준다 → 그것도 가로챈다
            spa_fallback = (status == 200 and path != "/" and ctx.response_body
                            and _maze_for_run().shell is not None
                            and ctx.response_body == _maze_for_run().shell)
            # 백엔드가 진짜로 서빙한 경로는 "진짜 경로"로 기억 → 미로 영구 제외.
            # (게이팅과 무관하게 항상 배운다 — 플랜이 나중에 켜져도 진짜 경로가 가로채이지 않게.)
            # ★ 증거가 확실한 경우만 배운다: GET 이고, 200 은 "본문이 있고 SPA 셸과 다름"(셸을 아직 모르면 판별
            #   불가라 안 배움), 3xx/401 은 그대로. HEAD 는 본문이 비어 SPA 폴백과 구분할 수 없어서 제외한다 —
            #   예전엔 HEAD 한 번이 SPA 폴백 경로를 "진짜"로 오인시켜 그 경로의 미로를 모든 클라이언트에게
            #   영구히 꺼버렸다(실측: 에이전트가 GET 과 HEAD 를 같이 보내는 Juice Shop 라운드에서 발견).
            if (ctx.method == "GET" and path != "/" and not spa_fallback
                    and ((status == 200 and bool(ctx.response_body)
                          and _maze_for_run().shell is not None)
                         or 300 <= status < 400 or status == 401)):
                _learn_real_path(path)
            if _maze_enabled(plan_applied, st):
                if "robots" in MAZE_ENTRY and path == "/robots.txt":
                    ctx.response_body = transforms.synth_robots(_robots_existing(ctx),
                                                                MAZE_ROBOTS_DISALLOW)
                    ctx.response_status = 200
                    ctx.response_headers = [(k, v) for k, v in (ctx.response_headers or [])
                                            if k.lower() not in ("content-type", "content-length")]
                    ctx.response_headers.append(("Content-Type", "text/plain; charset=utf-8"))
                ctx.response_headers = _maze_entry_headers(ctx.response_headers)
                # 브라우저가 주소창으로 연 SPA 클라이언트 라우트(/admin 새로고침 등)는 폴백 그대로 통과
                spa_browser_pass = (spa_fallback and MAZE_SPA_BROWSER_PASS
                                    and _is_browser_navigation(ctx.request.headers))
                intercept_status = status == 404 or (status == 403 and MAZE_INTERCEPT_403)
                if (ctx.method in ("GET", "HEAD") and (intercept_status or spa_fallback)
                        and not spa_browser_pass and _is_maze_path(path)):
                    await _serve_maze(ctx, path, client_id)
                    return
                if ("comment" in MAZE_ENTRY and status == 200
                        and "text/html" in ct and ctx.response_body):
                    ctx.response_body = _maze_comment(ctx.response_body, ct)

        # transform: 헤더 위조 + 본문 변조 — 이 클라이언트의 레시피(플랜이 정한 것 또는 환경변수의 전역 레시피)
        rec = _recipe_for_client(st)
        if rec is not None:
            ctx.response_headers = transforms.apply_headers(rec, ctx.response_headers or [])
            # robots.txt 힌트 — DECOY_MAZE 와 같은 synth_robots() 로 통일(존재하면 append,
            # 없으면 합성). T21_ROBOTS_DISALLOW/MIGRATION_ROBOTS_DISALLOW 로 서버별 조정 가능.
            if path == "/robots.txt" and rec.get("robots_disallow"):
                ctx.response_body = transforms.synth_robots(
                    _robots_existing(ctx), rec["robots_disallow"], rec.get("robots_comment"))
                ctx.response_status = 200
                ctx.response_headers = [(k, v) for k, v in (ctx.response_headers or [])
                                        if k.lower() not in ("content-type", "content-length")]
                ctx.response_headers.append(("Content-Type", "text/plain; charset=utf-8"))
                ct = "text/plain; charset=utf-8"
            if ctx.response_body:
                ctx.response_body = transforms.rewrite_body(rec, path, ct, ctx.response_body)
                ct = ctx.content_type("response") or ct
            # HTML 개발자 메모 주석 — 200 OK 정상 응답 + text/html 일 때만(오류 응답 주입 방지 =
            # 프록시 티 제거). 예전 passive 계층(T4.2-bare)이 하던 일을 레시피가 직접 한다.
            if (rec.get("html_comment") and status == 200 and "text/html" in ct
                    and ctx.response_body):
                ctx.response_body = transforms.inject_html_comment(
                    ctx.response_body, rec["html_comment"], ct)

        _log_req(ctx.method, path, status, ctx.meta.get("defense_action", "observe"),
                client_id, plan_applied)

    async def on_error(self, ctx: ProxyContext, exc: Exception):
        print(f"[defense][error] {ctx.trace_id} {exc}", flush=True)
        return None


def _register_health_route(sidecar: FastAPI) -> None:
    @sidecar.get("/healthz", include_in_schema=False)
    async def healthz():
        return Response(status_code=204)


app = create_app([DefenseHook()], title="CHeaT 방어 프록시",
                 before_catchall=_register_health_route)


@app.on_event("startup")
async def _preflight_backend():
    """실제 백엔드에 GET 몇 번 던져 지문 충돌/라우트 가림을 경고(실패해도 시작은 계속)."""
    trav_pf = _TRAVERSAL_ON and _PREFLIGHT_ENV
    if not (_PREFLIGHT_ON or _MAZE_PREFLIGHT_ON or trav_pf):
        return
    backend = os.environ.get("REAL_BACKEND", "http://127.0.0.1:3000")
    probe = await asyncio.to_thread(preflight.probe_backend, backend, transforms.PROFILE, 2.0,
                                    list(MAZE_PATHS) if _MAZE_PREFLIGHT_ON else None,
                                    list(_TRAVERSAL_PATHS) if trav_pf else None)
    if _PREFLIGHT_ON:
        preflight.report(preflight.check_backend(transforms.PROFILE, probe))
    if _MAZE_PREFLIGHT_ON:
        preflight.report(preflight.check_maze_backend(probe, list(MAZE_PATHS)))
    if trav_pf:
        preflight.report(preflight.check_probe_paths(probe))


@app.on_event("startup")
async def _start_client_sweep():
    asyncio.create_task(_sweep_clients_loop())
