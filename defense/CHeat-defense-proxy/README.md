# CHeaT Defense Proxy

LLM 펜테스트 에이전트(`codex` 등)를 상대로 **CHeaT**(*Cloak · Honey · Trap*, USENIX Security '25)의
방어 아이디어를 리버스 프록시로 주입해, 에이전트가 소모하는 **시간·토큰·요청·명령 수**가 무방어
대비 얼마나 늘어나는지 측정하는 실험 도구

## 전제

- **공격자 식별은 하지 않는다.** Policy Engine이 이미 "이 트래픽은 방어 대상"으로 판정했다고 가정.
- **Honey(허니토큰 탐지)는 범위 밖.** Cloak(오도)과 Trap(지연·자원 소모)만 다룬다.
- 침해 차단은 애플리케이션의 몫. 프록시의 목표는 **공격자 비용 유발**이지 차단이 아니다.

## 디렉터리 구조

```
CHeat-defense-proxy/
├── defense_proxy_v1/   원본 — Batch 1~9 전체 실험, 모든 기법 포함(T4.2b·passive 전체·
│                       T1.2/T2.2/T4.1/T4.2/T4.3/T6.3 레시피 등). 실험 하니스(experiments/)와
│                       결과 기록(results.md)이 여기 있다. "이 프로젝트가 실제로 뭘 해봤는지"
│                       전체 이력을 보려면 여기.
└── defense_proxy_v2/   정리판 — 실측으로 효과가 확인된 것만 남기고 나머지를 뺀 버전
                        (T2.1/T2.2 Cloak, FAKE_SHELL, DECOY_MAZE+ADAPTIVE_TRAP, active/combined,
                        passive는 T4.2-bare 하나만). 여기에만 있는 것: 로그인 가능한 실시간
                        GUI 대시보드(dashboard.py) — 방어 모드를 웹에서 골라 프록시를 직접
                        켜고 끄고, 요청 로그·타임라인을 실시간으로 본다. 실제로 써보거나
                        새 실험을 돌리려면 여기.
```

**어느 쪽을 봐야 하나:**

| 하고 싶은 것 | 여기로 |
|---|---|
| 지금까지 어떤 기법을 실험했고 뭐가 효과 있었는지 읽기 | [`defense_proxy_v1/results.md`](defense_proxy_v1/results.md) |
| 방어 프록시를 직접 켜보고 GUI로 관찰하기 | [`defense_proxy_v2/README.md`](defense_proxy_v2/README.md) — 깃 클론부터 대시보드 실행까지 단계별 안내 |
| 기존 실험(Batch 9 등)을 재현하거나 새 배치를 돌리기 | [`defense_proxy_v1/experiments/run_batch9.sh`](defense_proxy_v1/experiments/run_batch9.sh) |
| 제거된 기법이 왜 빠졌는지(효과 없음 실측 근거) 확인 | [`defense_proxy_v2/README.md`](defense_proxy_v2/README.md)의 "`defense_proxy_v1`(원본) 대비 무엇이 빠졌나" 표 |

두 디렉터리는 서로 독립적으로 실행 가능하다(각자 `Defense_proxy.py`/`transforms.py`/
`proxy_core.py`/`defense_payloads.json`/`requirements.txt` 를 따로 가짐) — 한쪽을 고쳐도
다른 쪽엔 영향 없다.

## 핵심 결과 요약

1. **서버 무관 미로(`DECOY_MAZE`)가 노력 대비 최고.** 무방어 대비 total 토큰 4.5×·셸 명령 5×·
   wall-clock 1.7× (Batch 7, N=2). 무조건 tarpit 없이도.
3. **무조건 tarpit(`active`)은 프롬프트·미끼와 무관하게 항상 통한다.** 
4. **방어는 "차단"이 아니다.** 어떤 구성도 쉬운 챌린지 획득(solved)은 못 막는다 — 공격자의
   시간·토큰만 2~5배 태운다.
5. **T4.2b(확인응답형 페이지네이션)·transform T4.2·passive 대부분은 효과가 검증되지 않거나
   역효과였다** — 그래서 `defense_proxy_v2`에서 빠졌다. 자세한 근거는 `results.md`와
   `defense_proxy_v2/README.md`.

## 요구사항 (양쪽 공통)

| 도구 | 용도 |
|---|---|
| Python 3.10+ | 프록시·대시보드 실행 (`requirements.txt`: fastapi · uvicorn · httpx) |
| Docker | 대상 앱 컨테이너 (`bkimminich/juice-shop`) |
| `codex` CLI | 공격 에이전트 (`codex exec --json`) — `defense_proxy_v2`를 대시보드로만 써보는 거라면 없어도 됨 |

각 서브디렉터리 안에서 각자 venv를 만들어 쓴다 — 자세한 설치·실행 순서는 각 README 참고.
