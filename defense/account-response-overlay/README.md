# Agent 계정 방어: 중위험 오버레이 + 고위험 격리 (V1/V2)

탐지팀이 Agent로 확정한 요청만 받는 리버스 프록시다. 정상 사용자는 탐지팀 게이트웨이에서 원본 사이트로 직접 간다. **중위험** 요청에는 기존 Response Overlay를 적용한다. **고위험** 요청은 원본으로 전혀 전달하지 않고, 같은 프록시 안의 별도 격리 핸들러와 기존 V1/V2 decoy만 사용한다. 두 모드는 `/ftp`와 `/ops/*`를 처리하는 하나의 내장 decoy를 공유한다.

```text
정상 사용자 ──────────────────────────────→ 원본 사이트
중위험 Agent ─→ 탐지팀 게이트웨이 ─→ Response Overlay ─→ 원본 사이트
                                            └→ 화면/헤더 미끼 ─→ V1/V2 decoy
고위험 Agent ─→ 탐지팀 게이트웨이 ─→ 격리 핸들러 ────────→ 같은 V1/V2 decoy
                                            └→ 로컬 401/404·미끼 페이지
```

아래 표는 **기존 중위험 모드**의 동작이다.

| Agent의 행동·원본 상태 | 화면/헤더 단서 | 진입점 |
|---|---|---|
| 로그인 화면·로그인 실패, 계정 경로 401/403 | 복구 링크·카드, `X-Recovery-API` | `/ops/recovery/accounts` |
| 정찰 경로 403/404, 설정한 SPA 정찰 경로의 200 HTML | Legacy Storage 카드, `X-Legacy-Storage` | `/ftp` |
| 비일반 API/서비스 경로 2xx | Service Manifest 카드, `X-Internal-API` | `/ops/service/manifest` |
| Agent의 `robots.txt` 요청 | 기존 내용 뒤에 decoy `Disallow` 경로 추가 | `/ftp`, `/ops/...` |
| 일반 화면·정적 자산 | 상황별 헤더 없음 | 원본 응답 |

상황별 헤더는 우선순위에 따라 한 종류만 붙는다. 헤더보다 **클릭 가능한 DOM 링크와 카드**가 주 진입점이다. Agent에게 반환하는 HTML에만 작은 스크립트를 삽입하여 로그인 화면의 상시 복구 링크, 로그인 실패 후 카드, 정찰·API 상황 카드와 메뉴의 `Legacy Services`를 만든다. JSON·JavaScript·이미지 본문은 그대로 둔다. 직접 연 JSON이나 HTML이 없는 응답은 화면 카드를 표시할 수 없으므로 헤더만 남는다. 변경된 응답은 `no-store, private`로 보내고 원본 캐시 검증자를 제거한다.

고위험 판정은 탐지팀이 `sign_headers(..., risk='high')`로 **위험 등급까지 서명**해 같은 프록시에 보낸다. 이 요청은 원본 URL이나 원본 HTTP 클라이언트를 만들기 전에 [고위험 핸들러](defense/high_risk.py)로 분기한다. `/ftp`, `/ops/*`, 기존 미끼 CSS는 그대로 내장 decoy에 전달한다. `/login`과 설정한 로그인 경로는 계정 복구 페이지/401로, `/admin`은 Legacy Storage로, `/api/*`와 다른 원본 경로는 로컬 JSON/HTML 401·404 또는 서비스 manifest로 응답한다. 따라서 고위험 모드의 일반 화면은 실제 사이트와 동일하지 않다. 고위험의 `/`와 `/ops/service`는 `Internal Operations Console` 카드 대시보드를 보여 준다. Account Registry는 `/ops/recovery/accounts`, Legacy Storage는 `/ftp`, Backup Management는 `/ops/archive`, Service Manifest는 `/ops/service/manifest`로 이어진다. 공개 감사 로그 경로는 기존에 없어서 Audit Logs만 같은 `/ops/service` 네임스페이스의 고위험 전용 합성 페이지 `/ops/service/audit`로 연결하며 실제 방어 감사 DB는 공개하지 않는다. 고위험 actor는 영속 보관되어 나중에 중위험 서명이 와도 다시 원본으로 나가지 않는다. 탐지팀 게이트웨이도 해당 actor를 계속 이 프록시로 보내야 한다.

## 사이트별 설정

[config/site-juice-shop.toml](config/site-juice-shop.toml)에 로그인 경로, DOM 선택자, 계정·정찰·API 분류, 일반 화면 API 제외 목록, 원본 인증 쿠키명, `robots.txt` 미끼 경로, decoy 표시명·계정을 모았다. [config/site-generic-example.toml](config/site-generic-example.toml)은 다른 사이트용 예시다. 다른 사이트에서는 overlay TOML의 `origin_url`과 `site_profile`을 바꾸고, 프로필의 경로·선택자를 실제 사이트에 맞춘다. 오버레이 코드나 decoy 서비스 수를 바꿀 필요는 없다. V1/V2는 여전히 **계정 복구 기록을 따라가는 시나리오**이므로, 다른 공격 목표까지 자동으로 재현하는 범용 웹 복제기는 아니다.

V1은 증거 체인 끝에서 `/ops/service/session/login`으로 **가짜** 관리자 로그인을 제공한다. V2는 성공 없이 후속 참조를 계속 연결한다. 두 버전 모두 Agent의 설정된 로그인 `POST`를 실제 원본으로 전달하지 않는다. 중위험 Agent는 미끼를 따르지 않으면 다른 원본 경로의 응답을 계속 볼 수 있다. 고위험 Agent는 어떤 경로도 원본으로 전달되지 않는다.

Agent별 미끼 노출 경로와 decoy 진입·단계는 `state/lure-events.sqlite3`에 별도로 기록한다. actor는 HMAC으로 가명화하며 요청 본문, 토큰, 원본 쿠키, 전체 decoy URL은 저장하지 않는다. 계측 장애는 프록시 응답을 바꾸지 않는다.

## 실행과 검증

Python 3.11 이상과 실행 중인 원본 서버가 필요하다. 탐지팀 게이트웨이는 Agent의 method, raw path+query, body에 서명한다. 무서명 요청은 오버레이에서 403으로 거절한다.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
mkdir -p state
.venv/bin/python -m defense.cli init
.venv/bin/python -m defense.cli init-security --database state/security.sqlite3
# 탐지팀과 공유하는 32바이트 이상 detector.key를 state/detector.key에 배치
OVERLAY_CONFIG=config/overlay-v2.toml OVERLAY_ORIGIN_URL=http://127.0.0.1:3000 \
  .venv/bin/python -m uvicorn defense.overlay:app_factory --factory --host 127.0.0.1 --port 8080 --workers 1 --no-proxy-headers
```

V1은 `OVERLAY_CONFIG=config/overlay-v1.toml`을 사용한다. 상태와 키는 `state/`에 두며 배포 ZIP에는 포함하지 않는다. 테스트는 `.venv/bin/python -m pytest -q`와 `node --test tests/test_lure_ui.cjs`다. 실제 Juice Shop 로컬 실험은 [LIVE_LAB.md](LIVE_LAB.md), 탐지팀 연결 계약은 [INTEGRATION.md](INTEGRATION.md), 이번 검증 결과는 [VALIDATION.md](VALIDATION.md)에 있다.
