# Token gate Docker 실험 중간 기록

작성: 2026-09-29, 후속 테스트 완료: 2026-09-30 (Asia/Seoul). **로컬 Docker 범위의 결과이며 원격 배포 평가는 아니다.**

## 사용자 요청과 범위

- v2.1 구현과 4절 테스트 완료 후, 사용자 요청으로 Detection 쿠키 병합도 수정했다.
- 사용자는 원격 서버 확인보다 **로컬 Docker 웹·공격자 테스트를 먼저 진행**하라고 했다.
- 최신 요청: 작업이 끊겨도 이어갈 수 있도록 중간 Markdown 기록을 남길 것.
- 현재 브랜치: `feature/defense-token-gate`. 변경은 아직 커밋·푸시하지 않았다.
- 기존 다른 실습 컨테이너(`student_03_bof_shellcode`)와 orphan 컨테이너는 삭제하지 않는다.

## 완료된 구현·검증

- Defense 토큰 게이트, main.py 연결, 스모크 스크립트, 로컬 Compose 환경변수 구현.
- Defense 테스트: 31개 통과(판정표 20개 subTest 포함), import 검사 통과.
- Detection `proxyCore.js`: `onProxyRes`에서 로컬 응답 쿠키를 보관하고 라이브러리 헤더 복사 후 백엔드 쿠키와 병합.
- 실제 HTTP 프록시 회귀 테스트 8개 통과. Detection 전체 122개 중 121개 통과, 실패 0개, CRS 바이너리 테스트 1개 SKIP.
- requirements와 package-lock 등 의존성 명세는 변경하지 않았다.

## Docker 환경

- Docker Desktop은 실행 중. 샌드박스 안에서는 엔진 접근이 거부되어 Docker 명령은 승인된 권한으로 실행한다.
- `docker compose -f docker-compose.local.yml up --build -d --wait --wait-timeout 180` 실행 완료.
- Detection → Defense → Juice Shop 세 컨테이너 모두 healthy 확인.
- 호스트 URL: `http://localhost:8081`; Docker 네트워크: `ruby-local_ai-defense-net`.
- 현재 모드: **off**. 고정 실험 키 `local-docker-token-gate-test`, epoch 10초, grace 1.
- 대상 이미지 ID: `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e` (로컬 `bkimminich/juice-shop:latest`).
- Playwright 공식 이미지 `mcr.microsoft.com/playwright:v1.63.0-noble` 기반 `ruby-token-gate-browser:local` 빌드 완료.
- 연결된 GUI 브라우저가 없어 Chromium 브라우저 실험은 Docker 안의 headless Playwright로 수행한다.

## 산출물 위치

모든 실행 스크립트·원시 결과는 저장소 루트의 `.tmp/token-gate-docker-20260929/`에 있다(ignored, 커밋하지 않음).

- `baseline.json`: off 모드 OPTIONS 상태와 Allow/CORS 헤더 저장 완료.
- `fixed_attacker.py`: 로컬 프록시만 대상으로 하는 8개 고정 공격·쿠키 적응 시나리오.
- `attacker-off.json`: 실제 off 모드 결과 저장 완료.
- `Dockerfile.browser`, `browser_test.cjs`: Chromium의 첫 화면·검색·상품 상세·새로고침·뒤로/앞으로 확인.
- `browser-off.json`, `browser-off.png`: 브라우저 테스트 완료 시 생성 예정.
- `llm_prompt.txt`, `llm-off/`: LLM 공격자 시도 기록. **유효 결과 없음**(아래 참조).

## 지금까지 확인한 실제 결과

### off 기준 고정 공격

`fixed_attacker.py`를 `ruby-local-defense` 이미지의 별도 공격자 컨테이너에서 실행했다. 8개 요청 모두 기대 상태 200과 일치했다.

| 시나리오 | 결과 |
|---|---|
| 쿠키 없는 상품 API 직통 | 200 |
| 쿠키 없는 SQL 주입 로그인 | 200, 인증 토큰 발급, JWT의 admin 역할 확인 |
| HTML Accept로 선언한 POST SQL 주입 | 200, admin 역할 확인 |
| HTML Accept로 선언한 GET API | 200 |
| GET API 응답 쿠키 획득 후 SQL 주입 | 200, admin 역할 확인 |
| HTML 페이지 접근 | 200 |
| 페이지 쿠키로 상품 API | 200 |
| 페이지 쿠키로 SQL 주입 | 200, admin 역할 확인 |

JWT 역할은 로컬 앱이 반환한 토큰의 claim을 읽은 확인이며, 후속 관리자 기능 실행까지 검증한 것은 아니다. 쿠키·Bearer 토큰 값은 결과 JSON에 기록하지 않았다.

### LLM 공격자 시도

기존 이미지 `ruby-sim-pentestgpt-agent:e8b1bb7-codexfix1`의 Codex CLI 0.153.4를 사용했다. 호스트 인증 파일 하나만 read-only로 연결했고, 결과 폴더만 writable로 연결했다. 모델은 별도 지정 없이 기본 `gpt-6-astra`가 선택됐다. 공격 범위는 로컬 `http://detection:8080`뿐이며 최대 20 HTTP 요청으로 제한했다.

**Codex 서비스가 요청을 사이버보안 위험으로 거절했다.** `This content was flagged for possible cybersecurity risk` 오류가 나왔으며, 실제 LLM 공격 성공률·적응 비용으로 평가할 결과가 없다. 모델·프롬프트를 바꿔 거절을 우회하지 않는다. 해당 테스트 컨테이너 중지 명령을 실행했다(다른 컨테이너는 대상으로 삼지 않음).

## 2026-09-29 당시 진행 중이던 명령과 계획

아래는 재개 시점의 작업 목록이다. 완료 결과는 문서 끝의 후속 실행 결과를 참조한다.

- off 브라우저 테스트가 실행 중이다. tool exec session `55515`의 출력을 확인한다.
- LLM 실행 session `65293`이 완전히 종료됐는지 확인한다. 실패 결과만 기록하고 재시도하지 않는다.
- 브라우저 off 결과를 확인해 UI selector 문제와 앱 문제를 구분한다. 필요한 경우 **테스트 harness만** 보완한다.
- off 측정 종료 후 observe, enforce를 순서대로 설정하고 각각 고정 공격·브라우저 테스트를 실행한다. 모드 변경 시에는 기존 기준 실험이 끝났는지 먼저 확인한다.
- enforce에서는 기존 스모크 스크립트에 `--stale --epoch-s 10 --grace 1 --baseline .tmp/token-gate-docker-20260929/baseline.json`을 전달한다.
- 새 페이지 응답의 `__ruby_tg`, `dcid`, `dlsid` 보존을 실제 파이프라인에서 확인한다.
- 로그에서 `would_block`, `block`, `refresh`, `page_declared_json`과 stale 상태를 확인한다.
- 브라우저 정상 흐름은 초기 epoch 10초가 아닌 60초로 분리해 실행하는 것이 좋다. 현재 off 브라우저는 만료가 없으므로 10초 설정의 영향이 없다.
- 마지막에는 테스트 서버 상태·모드를 기록하고, 사용자에게 정상 흐름/고정 공격/LLM 미실행의 범위를 구분해 보고한다.

## 재개할 때 주의

- 이 기록의 현재 모드·진행 상태는 뒤에 갱신될 수 있으므로 최신 내용을 확인한다.
- 고정 공격 성공/차단을 전체 공격자 성공률로 일반화하지 않는다.
- 캐시·절전·Socket.IO·서비스워커 복원은 별도 한계 시나리오이며 아직 실행하지 않았다.
- 원격 프록시에는 아직 배포하지 않았다.

## 2026-09-30 후속 실행 결과

- off 모드 Chromium 테스트는 로그인 버튼 선택자의 불일치를 확인해 테스트 harness만 수정한 뒤 다시 실행했다. 첫 화면·검색·상품 상세·새로고침·뒤로/앞으로 **5/5 통과**, HTTP 403 및 페이지 오류 0건.
- observe, enforce에서도 같은 Chromium 5/5 단계가 각각 통과했다(epoch 60초). 두 모드에서 브라우저 쿠키에 `__ruby_tg`, `dcid`, `dlsid`가 함께 존재했고, 수집한 응답에서 HTTP 403 및 페이지 오류가 없었다.
- 고정 요청 8개: off 8/8 기대값 일치, observe 8/8 기대값 일치(모두 200), enforce 8/8 기대값 일치(직통 API·직통 SQL 주입 로그인·HTML 선언 POST SQL 주입은 403; 나머지 5개는 200). HTML 선언 GET API가 페이지로 분류되어 토큰을 발급하므로, 그 쿠키를 이용한 SQL 주입은 enforce에서도 200과 admin JWT claim을 얻었다. 페이지 방문 후의 SQL 주입도 200이었다. 이는 우회 가능성을 보여 주는 고정 시나리오 결과다.
- enforce 스모크 테스트 1~7 통과: 쿠키 없는 API·위조 토큰·만료 토큰 차단, 페이지 쿠키 발급, 유효 쿠키 API 통과, OPTIONS off 기준값 보존, HTML 선언 GET API 통과. epoch 10초, grace 1로 실행했다.
- 별도 grace 재현에서 이전 epoch 쿠키로 API 200을 받고 새 `__ruby_tg` 쿠키를 확인했다. observe 로그에 `refresh, grace` 1건이 기록됐다.
- observe 10초 로그: `would_block, missing` 3건, `refresh, grace` 1건, `page_declared_json` 1건. enforce 10초 로그: `block, missing` 4건, `block, invalid` 1건, `block, stale` 1건, `page_declared_json` 2건. 로그는 `.tmp/token-gate-docker-20260929/`에 보관했다.
- LLM 공격자 테스트는 앞서 기록한 서비스 거절로 유효 결과가 없으며 재시도하지 않았다. 캐시·절전·Socket.IO·서비스워커 복원과 원격 프록시 배포는 이번 범위에 포함되지 않았다.
- 종료 시 Defense 모드를 **off**로 복구했다. Detection, Defense, Juice Shop 세 컨테이너 모두 healthy이며 `http://localhost:8081`에서 계속 실행 중이다. 다른 실습·orphan 컨테이너는 건드리지 않았다.
- 변경 사항은 커밋하거나 푸시하지 않았다. 테스트 harness와 원시 JSON·PNG·로그는 ignored `.tmp/token-gate-docker-20260929/`에 남아 있다.
