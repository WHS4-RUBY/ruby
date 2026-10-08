# 탐지팀 연결 계약

탐지팀 게이트웨이는 안정적인 actor ID와 점수로 Agent 판정을 영속화한다. `examples/detector_integration.py`의 `plan_overlay_request`는 정상 요청을 **원본**, 중위험 Agent를 **기존 Response Overlay**로 보내는 예시다. `plan_high_risk_request`는 고위험 Agent를 같은 프록시의 **격리 핸들러**로 보내는 서명 예시다. 이 예시는 라우팅 결정과 서명 헤더만 만들며 실제 HTTP 전달은 탐지팀 게이트웨이가 구현한다. 오버레이는 정상 사용자의 공개 진입점이 아니며, 무서명 요청을 원본으로 통과시키지 않는다.

게이트웨이는 Agent 요청의 **동일한 method, raw path+query, body**에 `sign_headers`로 서명한다. 클라이언트가 보낸 `X-Defense-*`는 제거하고 탐지팀이 만든 헤더만 보낸다. 오버레이의 `DetectorVerifier`는 서명, 30초 시간 창, nonce 재사용을 확인한다. 탐지 DB와 detector.key는 재시작 후에도 유지한다. 탐지 대상 판정은 클라이언트의 임의 헤더가 아니라 탐지팀의 결정이어야 한다.

고위험에는 `sign_headers(secret, actor, method, raw_target, body, risk="high")`를 사용한다. `X-Defense-Risk: high`는 HMAC에 포함되므로 헤더만 바꾸거나 추가해 격리 모드를 선택할 수 없다. 첫 고위험 요청의 actor는 기존 보안 DB에 가명화된 영구 격리 표시로 저장된다. 이후 같은 actor가 중위험 형식의 유효한 서명으로 들어와도 고위험 핸들러가 처리한다. 탐지팀은 고위험 actor를 정상 원본으로 직접 돌려보내지 않고 계속 이 프록시에 보내야 한다.

중위험 Agent의 `/ftp`, `/ftp/...`, `/ops/...` 요청은 내장 V1/V2 decoy로 간다. `site_profile`에 지정한 로그인 경로의 `POST`는 원본을 호출하지 않고 로컬 401 복구 단서를 반환한다. 그 외 요청은 설정의 **고정된** `origin_url`로 전달한다. 원본 응답을 받은 뒤 `select_deception_headers(path, method, status_code, content_type, profile)`를 호출한다. 계정 401/403 → 숨겨진 경로 403/404 또는 설정한 SPA 정찰 경로의 200 HTML → 비인증 API 2xx 순서로 하나를 고르며, 해당하지 않으면 `{}`를 반환한다. Agent에게 반환할 HTML에는 상황별 화면 미끼용 스크립트를 추가한다. 로그인 화면의 복구 링크, 로그인 실패 후 폼 카드, 응답 헤더에 따라 바뀌는 정찰·API 카드, 사이드 메뉴의 `Legacy Services`가 모두 이 스크립트에서 나온다. 일반 JavaScript·JSON·이미지 본문은 수정하지 않는다. 원본 장애는 502로 끝나며 decoy나 다른 원본으로 fallback하지 않는다.

원본으로 전달할 때 탐지 서명과 오버레이 전용 쿠키를 제거하고, Agent의 Authorization 및 프로필에 지정한 원본 인증 쿠키도 제거한다. 기타 일반 쿠키는 원본 기능을 위해 유지한다. decoy로 보낼 때는 `isolation_headers`로 원본 인증 정보를 제거한다. V1이 복구 기록 끝에서 안내하는 `/ops/service/session/login` 및 `/ops/service/session/whoami`는 decoy 내부의 기존 로그인·조회 로직으로 연결한다. 중위험에서 설정된 실제 로그인 경로는 원본으로 가지 않으며, 그 밖의 원본 경로는 기존대로 원본에 전달된다. 중위험 Agent가 여전히 원본의 비인증 경로에 접근할 수 있다는 점은 실험 설계에 명시해야 한다.

고위험 핸들러는 원본 URL을 사용하지 않는다. `/ftp`와 `/ops/*`는 같은 decoy 인스턴스로, `/login`과 설정된 로그인 경로는 복구 페이지/401로, `/admin`은 기존 Legacy Storage 페이지로, `/api/*`와 나머지 경로는 로컬 JSON/HTML 401·404 또는 manifest로 응답한다. 고위험 `/`와 `/ops/service`는 전용 Internal Operations Console을 반환한다. `/ops/service/audit`은 고위험 전용 합성 이벤트 목록이며 실제 방어 감사 기록을 읽지 않는다. 기존 중위험 `/ops/service`와 기타 decoy 경로는 그대로 유지된다. 고위험 요청의 직접 원본 전달 경로는 없다.

Docker 배포 예시는 `deploy/compose.yaml`이다. 오버레이 컨테이너는 탐지팀 전용 네트워크와 원본 전용 네트워크에 연결되고 호스트 공개 포트는 없다. `deploy/.env.example`의 원본 주소·네트워크·V1/V2 설정을 실제 배포에 맞게 채운다. `init-security` 프로필을 처음 한 번 실행하고 detector.key를 상태 볼륨에 공급한다. `overlay-server-v1.toml`과 `overlay-server-v2.toml`은 TLS 게이트웨이 뒤에서 사용할 Secure 가짜 인증 쿠키 설정이다.

현재 HTTP `:80` 운영 Compose에서는 대상별 사설 오버레이에 `OVERLAY_CONFIG=/app/config/overlay-production-juice-v2.toml` 또는 `/app/config/overlay-production-ruby-v2.toml`을 지정한다. `OVERLAY_ORIGIN_URL`은 각각 `http://juice-shop-target:3000`과 `http://ruby-web-target:8080`으로 고정한다. `OVERLAY_DETECTOR_KEY`는 Defense 서명기와 같은 64자리 hex 문자열을 **문자열 바이트 그대로** 제공한다. `overlay_bootstrap`이 각 영속 볼륨의 `detector.key`, `session.key`, `security.sqlite3`를 최초 생성하고 재시작 때 일치와 무결성을 검증한다. 기존 키와 다른 값을 주거나 DB만 없어진 상태에서는 격리 기록을 초기화하지 않고 시작에 실패한다. 가짜 세션 키만 분실하면 해당 가짜 세션을 무효화하고 재생성한다. 이미 detector key와 DB를 따로 준비한 기존 배포는 환경변수 없이도 시작할 수 있다. 비공개 `:8080`의 TCP 연결로 컨테이너 상태를 확인한다. HTTP 요청은 모두 서명 검증을 받아 무서명 `/healthz`도 403이다.

RUBY의 실제 로그인 경로는 `/api/auth/login`이다. 프런트엔드는 토큰을 로컬 저장소에 보관하고 Bearer 헤더를 사용하며, 서버는 `ruby_session` 쿠키도 인증에 사용한다. `site-ruby-shop.toml`은 RUBY의 로그인 폼·메뉴 DOM과 쿠키 이름을 정의한다. 분류된 중위험 Agent의 로그인 POST는 원본에 닿지 않고 401 미끼가 되며, 그 외 원본 요청에서도 Bearer와 `ruby_session`·`ruby_remember`를 제거한다. 따라서 원본의 보호 API는 401을 줄 수 있다. V2 미끼는 원본 RUBY 토큰을 발급하지 않는다. 이를 정상 사용자의 로그인 보존 요구와 함께 검증해야 한다.

통합 검증에서는 정상 사용자가 오버레이를 거치지 않는지, 고위험 요청이 어떤 경로에서도 origin 로그에 남지 않는지, Agent의 비 HTML 원본 응답 본문이 같은지, 401/403·403/404·2xx에서 서로 다른 헤더와 화면 카드가 선택되는지, `/ftp`와 `/ops/...` 및 Agent 로그인 시도가 원본 로그에 남지 않는지 확인한다.

다른 사이트에서는 overlay TOML의 `origin_url`과 `site_profile`을 변경한다. 프로필은 로그인 경로와 DOM 선택자, 미끼 선택 분류·제외 목록, decoy 표시명·계정을 담는다. Agent의 `robots.txt`는 기존 원본 내용을 보존하면서 로컬 decoy 경로를 덧붙이고, 원본 404이면 Agent에게만 새 텍스트 파일을 제공한다. 별도 `state/lure-events.sqlite3`는 가명화한 actor·미끼 종류·decoy 단계만 최대 5만 행 기록한다. 원본 인증 정보나 전체 URL은 저장하지 않는다.
