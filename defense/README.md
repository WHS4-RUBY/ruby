# RUBY Defense

RUBY의 방어 계층을 개발하는 영역입니다. Detection Proxy의 Policy Engine이 X-Defense-Plan 헤더로 넘긴 전략에 따라 요청에 차단, 변환, 지연, 기만 등의 방어 기법을 적용합니다.

## 담당 범위

- Defense Proxy
- 방어 전략 적용기
- 요청 차단·변환·지연·기만 기법
- 기법별 설정과 실행 결과 기록
- 방어 로그와 계층 간 인터페이스 정의
- 방어 기법의 단위·통합 테스트

공격 탐지와 위험도·정책에 따른 전략 선택은 모두 [`detection/`](../detection/)에서 관리합니다 (구간별 전략은 `detection/config/policy.json`).

## Target 연결

운영 Compose에서는 Detection과 Defense가 같은 `TARGET_CHOICES`를 읽습니다. 관리 화면에서 선택한 대상 ID와 실행 ID가 공유 선택 파일에 저장되고, Defense가 그 ID의 내부 주소로 요청을 전달합니다. 현재 운영 대상은 `juice-shop=http://juice-shop-target:3000`과 `ruby-shop=http://ruby-web-target:8080`입니다. `TARGET_DEFAULT_ID`는 이 목록에 있는 ID로 지정해야 합니다. 실험 공격은 공개 포트 80으로 보내야 Detection과 Defense를 통과합니다. 벤치마크 선택 화면의 포트 3020으로 직접 보낸 요청은 이 파이프라인과 두 대시보드에 기록되지 않습니다.

운영 Compose는 두 대상에 각각 비공개 CHeaT sidecar(`cheat-juice:3012`, `cheat-ruby:3012`)를 연결합니다. 해당 ID의 HTTP 요청은 `Detection → Defense → 대상별 sidecar → Target`으로 흐릅니다. 다른 ID에 sidecar 설정이 없으면 Defense가 Target에 직접 전달합니다. WebSocket은 sidecar를 거치지 않고 선택된 Target으로 직접 연결됩니다.

| 환경변수 | 기본값 | 설명 |
| --- | --- | --- |
| `TARGET_CHOICES` | 없음 | 관리 화면에서 선택할 `id=내부 URL` 목록. Detection과 Defense에 같은 값을 전달합니다. |
| `TARGET_DEFAULT_ID` | `legacy` | 선택 파일에 유효한 이전 선택이 없을 때 사용할 대상 ID. |
| `TARGET_SELECTION_FILE` | 없음 | Detection이 기록한 선택 ID·실행 ID를 Defense가 읽을 공유 파일. Compose가 이 파일을 공유합니다. |
| `DECOY_UPSTREAM_CHOICES` | 없음 | 대상 ID별 비공개 CHeaT sidecar URL. 해당 ID의 HTTP 요청만 sidecar로 보냅니다. |
| `TARGET_PORT` | `9000` | 이름 붙은 대상이 없는 독립 실행/legacy 구성의 Target 포트. Compose 기본값은 `3000`입니다. |
| `TARGET_HOST` | `localhost` | 독립 실행/legacy 구성의 Target 호스트. Compose는 `host.docker.internal`을 지정합니다. |

Compose의 단일 Target(legacy) 구성은 루트 `.env`의 `TARGET_PORT`를 사용합니다. 이때 Target은 Defense 컨테이너에서 접근 가능한 주소(`0.0.0.0` 또는 Docker 브리지 주소)에 바인딩해야 합니다. `/readyz`는 현재 선택된 Target의 TCP 연결만 확인하며 sidecar 상태는 검사하지 않습니다.

## 대시보드

운영 서버의 관리 리스너는 `127.0.0.1:8088`에만 바인딩됩니다. 관리자 컴퓨터에서 `ssh -N -L 127.0.0.1:8088:127.0.0.1:8088 USER@SERVER`로 터널을 연 뒤 `http://127.0.0.1:8088/__defense/dashboard`에 접속합니다. 로컬 Compose에서는 `http://127.0.0.1:18088/__defense/dashboard`를 사용합니다. 공개 포트 80(로컬 Compose의 8081)의 관리 경로는 404를 반환합니다.

대시보드는 공용 Defense 프로세스가 실제로 처리한 요청만 표시합니다.

- 전체·방어 적용·차단·오류 요청 수
- 방어 지연을 포함한 평균 처리 시간
- 최근 1시간 요청 흐름과 전략별 적용 횟수
- 최근 요청의 클라이언트 ID, 경로, 적용 전략과 처리 결과

`DEFENSE_DASHBOARD_PASSWORD`를 지정하면 관리 API가 로그인 세션으로 보호됩니다. 배포용 Compose는 이 값이 없으면 시작하지 않으며 GitHub Actions에서는 같은 이름의 Repository Secret을 전달합니다. 기본 설정은 HTTPS와 Secure 쿠키를 요구합니다. 현재 서버의 SSH 터널을 통한 HTTP 관리 접속에는 `ALLOW_INSECURE_DASHBOARD_HTTP=true`, `DEFENSE_DASHBOARD_REQUIRE_HTTPS=false`, `DEFENSE_DASHBOARD_COOKIE_SECURE=false`를 함께 지정합니다. 이 경우에도 대시보드는 공개 포트 80에 노출되지 않습니다.

로그인은 클라이언트별 실패 횟수를 제한하고, 세션은 만료 시간과 최대 개수에 따라 정리합니다. 이벤트는 요청 본문이나 인증 정보를 저장하지 않으며, 메모리에 최근 `DEFENSE_EVENT_LIMIT`건만 보관합니다. 단일 Uvicorn 프로세스의 운영 지표이므로 여러 worker로 확장할 때는 외부 저장소로 교체해야 합니다.

## 구현 구조

- `app/main.py`: `X-Defense-Plan` 실행과 Target 전달
- `app/decoy_routing.py`: 대상별 sidecar 주소와 기만 전략 헤더 분리
- `app/dashboard.py`: 관리 API와 대시보드 라우터
- `app/dashboard_auth.py`: 로그인 제한과 세션 수명 관리
- `app/strategies/`: 방어 전략 구현과 Registry
- `app/monitoring.py`: 상한이 있는 요청 이벤트와 집계
- `app/public/dashboard.html`: Detection 대시보드와 같은 형태의 운영 화면

공식 Defense 전략은 `DefenseStrategy`를 구현해 Registry에 등록합니다. CHeaT 기만 전략은 비공개 sidecar에서 실행하고, Defense가 sidecar의 실제 적용 전략과 동작을 대시보드에 집계합니다.

## 전략 계약과 요청 추적

Detection이 보낸 `X-Ruby-Request-Id`를 두 대시보드의 요청 ID로 사용합니다. Defense 이벤트는 이전 완료 요청 기반 Automation·Attack·Risk 점수, 정책 출처, 대상 ID·실행 ID, 실제 실행 전략과 sidecar 동작, 백엔드 HTTP 상태 및 `forwarded`·`blocked`·`error` 결과를 기록합니다. Defense는 sidecar에 `X-Defense-Plan`의 기만 전략만 전달하고, 지연과 속도 제한은 자체 실행해 중복 적용하지 않습니다. Sidecar는 내부 식별·계획 헤더를 Target으로 전달하지 않습니다. 응답의 `X-Ruby-Decoy-Action`·`X-Ruby-Decoy-Strategies`는 Defense가 기록한 뒤 클라이언트 응답에서 제거합니다. `X-Defense-Signal: rate_limited`는 Defense가 429를 반환한 경우에만 Detection으로 되돌립니다. Target이 보낸 같은 이름의 신호 헤더는 제거합니다.

전략의 `apply(request, params, state)`는 요청 단계에서 실행합니다. `DefenseResult`는 즉시 반환할 응답, Target에 보낼 헤더, 백엔드 응답 변형 함수, 다음 클라이언트 상태를 담을 수 있습니다. 공식 Defense의 상태는 전략 이름, 선택된 실행 ID(없으면 대상 ID), `X-Client-Id`별로 분리하고, 기본 10분 미사용 시 만료되며 최대 10,000개를 유지합니다. `DEFENSE_STATE_TTL_SECONDS`와 `DEFENSE_STATE_LIMIT`로 조절합니다. 동일 클라이언트의 동시 상태 변경은 순서대로 처리합니다. Sidecar의 기만 상태도 실행 ID와 클라이언트별로 분리됩니다. 해제 뒤에도 새 요청은 Detection에서 다시 점수화되고, 위험 정책이 재선택되면 전략에 재진입합니다. 공식 Defense에는 영구적인 `blocked/released` 판정이나 다중 프로세스 공유 상태가 없습니다.

응답 변형 전략이 있으면 백엔드 본문을 받아 변형한 뒤 전송합니다. 본문은 기본 4 MiB까지 허용하며 `DEFENSE_TRANSFORM_BODY_LIMIT`로 조절합니다. 한도를 넘으면 502와 오류 이벤트를 반환합니다. 변형 전략이 없는 공식 Defense 응답은 스트리밍하지만, 현재 CHeaT sidecar는 HTTP 요청·응답 본문을 버퍼링하므로 sidecar를 거치는 경로는 종단 간 스트리밍이 아닙니다. 스트림이 중간에 끊기면 이미 보낸 HTTP 상태를 502로 바꿀 수 없으므로 연결이 중단되고 Defense 이벤트는 `outcome=error`로 남습니다. 이벤트의 `status`는 이미 전송한 백엔드 상태일 수 있으므로 결과와 함께 읽어야 합니다.

WebSocket은 업그레이드 요청 시 공식 Defense 전략을 한 번 적용하고 선택된 Target에 직접 연결한 뒤 텍스트·바이너리 프레임을 그대로 중계합니다. Sidecar 기만과 프레임별 탐지·응답 변형은 적용하지 않습니다. `/__defense` 관리 경로는 WebSocket 엔드포인트가 없으므로 업그레이드를 거부합니다.

`X-Client-Id`와 `X-Ruby-*`는 내부 Detection 프록시가 재생성하는 헤더입니다. Defense에 직접 접속할 수 있으면 헤더를 위조할 수 있으므로 배포에서는 Defense 포트를 외부에 공개하지 말고 Detection과 같은 비공개 네트워크에서만 접근시키세요. 이벤트와 전략 상태는 단일 프로세스 메모리에만 보관되고 재시작 시 사라집니다.

## 참여 방법

`main`에 직접 push하지 않고 작업 브랜치에서 변경한 뒤 Pull Request를 제출합니다. 자세한 규칙은 [루트 CONTRIBUTING.md](../CONTRIBUTING.md)를 확인하세요.

## 보안 주의사항

API 키, 토큰, 실제 서버 주소, 원본 공격 로그와 개인정보를 커밋하지 않습니다. 필요한 환경변수는 값이 제거된 `.env.example`로만 공유합니다.
