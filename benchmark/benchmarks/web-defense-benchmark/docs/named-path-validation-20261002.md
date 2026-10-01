# 공개 이름 경로 로컬 검증 — 2026-10-02

이 문서는 `fix/minseo-fetch`의 경로 게이트웨이와 대상 전환 오버레이를 **로컬 임시 Docker 프로젝트**에서 확인한 기록이다. 운영 서버의 설정·컨테이너는 변경하지 않았다. 기존 로컬 프로젝트의 중지된 컨테이너도 그대로 두고, 별도 프로젝트와 임시 포트 `127.0.0.1:18081`을 사용했다. 이 검사는 공격 방어 효과 평가가 아니다.

| 상태 | 공개 진입점 검사 | 결과 |
| --- | --- | --- |
| 기본 Juice Shop | `/` → `/juice-shop/`; `/juice-shop/` 화면; `/juice-shop/styles.css`; `/rest/products/search?q=` | 이동 주소가 외부 포트를 유지하고, 화면·정적 파일·읽기 전용 API가 각각 200 |
| 기본 Juice Shop | `/ruby-market/`; `/__detection/api/sessions`; `/__defense/api/snapshot` | 비활성 화면 404, 미인증 관리 API 각각 401 |
| 기본 Juice Shop | `/juice-shop/socket.io/?EIO=4&transport=websocket` 업그레이드 | HTTP 101; 이후 WebSocket 프레임 왕복은 시험하지 않음 |
| Market 전환 | `/` → `/ruby-market/`; `/ruby-market/`; `/assets/index-…js`; `/api/products` | 화면·정적 파일·상품 4건을 포함한 읽기 전용 API가 200 |
| Market 전환 | `/juice-shop/`; 관리 API | 비활성 화면 404, 미인증 관리 API 401 |
| Juice Shop 복귀 | `/` → `/juice-shop/`; `/juice-shop/`; `/rest/products/search?q=` | 302/200/200, `/ruby-market/`은 404 |
| 제3 이름 경로 규칙 | 게이트웨이에서 `my-shop`을 선택해 `/my-shop/`, `/juice-shop/`, 루트 API 확인 | 200/404/200. 이 검사는 이름 경로 규칙만 확인했고 제3자 웹사이트를 연결하지 않음 |
| 관리 WebSocket 경계 | 두 대시보드 경로에 미인증 Upgrade | 각각 HTTP 403 |

Market 전환에는 실제 로컬 RUBY Market 웹·API·데이터 서비스 스택을 사용했다. Defense의 `BENCHMARK_TARGET_URL=http://ruby-web-target:8080`, Detection의 `TARGET_PROFILE_FILE=/app/config/target.json`, 게이트웨이의 `RUBY_PUBLIC_NAME=ruby-market`을 컨테이너 설정에서 함께 확인했다. Market 화면 응답에는 Detection이 삽입한 미끼 링크와 telemetry 스크립트가 포함되어 공개 경로가 파이프라인을 통과했다. `/api/products` 응답에는 `X-Ruby-Request-Id`와 `x-defense-applied: none` 헤더가 있었다. 이는 **정상 읽기 요청**의 전달 증거이며 고위험 요청 방어 효과를 뜻하지 않는다.

전환 직후 이전 번들 Juice Shop 컨테이너가 프로필 전환만으로 정지하지 않는 Compose 동작을 발견했다. Market·제3 사이트 전환 문서에 `stop benchmark-target` 절차를 추가하고 로컬에서 정지 상태를 확인했다. 처음부터 해당 오버레이로 실행하면 번들 대상은 시작하지 않는다. 기본 Compose와 세 대상 오버레이의 구문 검사, 대상 선택 계약 검사도 통과했다.

범위 밖에 남은 항목은 실제 운영 서버의 이름 경로 배포, RUBY Market의 브라우저 로그인·전체 화면 탐색, WebSocket 프레임별 검사, 새 제3 사이트의 쿠키·리다이렉트·CORS/CSRF 검증, TLS 프록시 배치와 부하·정상 사용자 지연 측정이다. Market 화면이 다른 호스트 포트에서 열린다는 사실은 이번 공개 파이프라인 검사의 대체 근거가 아니다.
