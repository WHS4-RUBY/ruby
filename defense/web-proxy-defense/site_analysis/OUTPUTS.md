# 분석기 출력과 방어 모듈의 사용

이 문서는 두 가지를 정리한다.
- 분석기가 무엇을 내놓는지
- 그 출력으로 팀의 각 방어 모듈이 무엇을 할 수 있는지

모듈 쪽 근거는 팀 `main` 251ef4f8(환경 리팩터링 PR #48의 병합 커밋)의 코드이며 `경로:행`으로 적었다. 실제 배포 상태는 확인하지 않았다.

## 1. 분석기가 내놓는 것

### 1.1 파일

| 파일 | 공개 여부 | 내용 |
| --- | --- | --- |
| `<저장소>/.tmp/site-analysis/<이름>.json` | 공개용 기록. 원본 값을 가린 기록이라는 뜻이며 `.tmp/`는 `.gitignore` 대상이라 커밋되지 않는다 | 아래 1.2의 기록 |
| `%LOCALAPPDATA%/ruby-site-analysis/<이름>-<해시>/state.json` | 비공개 | 관찰 원자료(화면 텍스트, HTML 소스, 응답 본문, 요청과 응답 목록), 진행 상태, 가림 전 답 |
| 같은 폴더 `ledger.json` | 비공개 | 비용 장부, 호출 기록(제공자 오류 원문 포함), 반복 실패 계수 |
| 같은 폴더 `run-<회차>-<묶음>.json` | 비공개 | 가림 전 축 답 원본. 뒷단계가 실패해도 다시 분석하지 않게 보관 |
| `%LOCALAPPDATA%/ruby-site-analysis/sessions/<이름>.json` | 비공개 | 운영자 도구가 일반 계정으로 한 번 로그인해 얻은 쿠키 |

### 1.2 공개 기록의 주요 칸

| 칸 | 뜻 |
| --- | --- |
| `target` | 원본 URL의 SHA-256만 남는다. URL 원문은 없다 |
| `runs[]` | 회차별 기록. 앞 회차들은 익명(`anonymous`), 뒤 회차들은 운영자가 준비한 일반 계정(`session`) |
| `runs[].axes` | 축 53개의 답(1.3) |
| `runs[].facts` | 브라우저 계측 사실: 화면과 요청 목록(주소는 가림을 거침), 상태 코드, 헤더 이름과 값(민감 헤더 값 제외), 쿠키 이름과 속성(값 제외), 폼의 method, action, 칸 이름(값 제외), 외부 호스트, WebSocket 주소, 응답 본문의 크기와 수집 상태(본문 자체 제외) |
| `runs[].model_decisions`, `decision_events` | 둘러보기에서 모델이 고른 행동. 인자와 URL 원문은 가림을 통과한 것만 남는다 |
| `runs[].finished_at` | 그 회차의 분석과 가림이 모두 끝났을 때만 채워진다 |
| `merged_by_authority` | 같은 권한의 회차끼리 축마다 합친 결과(1.4). 익명과 일반 계정은 서로 확인으로 세지 않는다 |
| `response_times[]` | 응답 시간 측정값. 경로는 해시로만 남는다 |
| `consumer_guidance` | 받는 쪽 안내. 메움은 `both-runs` 사실만 근거로 쓴다 |
| `removal_handoff` | 분석에 쓴 자격 환경변수 이름과 복사 계정 제거 표시. 자격 값은 항상 `null` |
| `limitations` | 고정 관찰 한계: POST 미전송, 서비스워커 차단, WebSocket 송신 내용 미수집, 가림 정확성 미검증 |
| `model_calls[]` | 호출별 목적, 모델, 토큰, 비용, 경과 시간. 프롬프트, 답 원문, 제공자 오류 원문은 없다 |
| `metrics`, `stop_reason`, `resume_pending` | 비용, 단계별 사용액, 회차별 "못 봄" 축 수, 중단 사유, 남은 단계 |

### 1.3 축 53개(질문 6묶음)

| 묶음 | 축 수 | 무엇을 답하나 | 받는 쪽 |
| --- | --- | --- | --- |
| appearance | 6 | 화면 종류, 경로 모양 묶음, 반복 메뉴, 이동 깊이, 기기별 판, 여러 단계 흐름 | 검증 |
| content | 16 | 항목 종류와 구성, 개수, 순서와 쪽 나눔, 관계, 분류와 상태, 수치 범위, 시간 분포, 분량, 문체, 표기, 빈 자리, 자료에 따라 바뀌는 부분 | 메움(일부 운영, 검증) |
| access | 9 | 입구와 매개변수 이름, 쓰기 표면, 칸 제약, 로그인과 복구 표면, 자격 방식, 권한별로 보이는 것, API 응답 모양, CAPTCHA 같은 관문 | 메움, 운영 |
| identity | 5 | 원본 고유 값(운영자 이름, 로고, 연락처, 사람 이름, 소스 속 분석 ID나 키)이 어느 자리에 어떤 모양으로 있는지. 값 대신 자리표시 | 제거 |
| runtime | 9 | 헤더와 쿠키의 뜻, CDN과 프록시 신호, 생성기와 판, 정적 자원 경로, 응답 형식, 실시간 채널, 외부 호스트, CSP와 CORS, 오류 화면, 주소 습관 | 검증 |
| generic | 8 | 고정 질문이 다루지 않는 구조, 판 이력, 내려받기, 개인화, 실시간 내용, 재방문 차이, 동의 배너 | 운영, 검증 |

### 1.4 답의 모양과 표시

- **회차 축 답:** `{status, description, evidence[], confidence, final?}`. 모델이 덧붙인 다른 키도 그대로 둔다.
  - `status`는 다음 넷 중 하나다.
    - 관찰됨: 직접 확인함
    - 없음: 부재 근거가 충분함
    - 사례 부족: 판단할 사례가 모자람
    - 못 봄: 열지 못했거나 읽지 못함
  - `description`의 이름, 제목, 연락처 자리는 `{person-name}` 같은 자리표시로 쓴다.
  - `evidence`는 관찰 참조(`sample-N` 등)다.
  - `final:false`는 더 읽으면 바뀔 수 있는 잠정 답이라는 표시다.
- **합친 축:** 두 회차 원답과 모델이 합친 답을 함께 둔다.
  - 합친 답의 `findings`는 사실마다 다음 셋 중 하나의 표시를 붙인다.
    - `both-runs`: 두 회차가 모두 뒷받침함. 메움은 이것만 근거로 쓴다
    - `single-run`: 한 회차만 뒷받침함
    - `contradictory`: 두 회차가 엇갈림
  - `agreement=true`는 축 전체의 승인이 아니다.
- **출력에 절대 없는 것:**
  - URL 원문(해시와 가린 모양만 남음)
  - 응답 본문, 화면 텍스트, HTML 소스
  - 요청 본문
  - 쿠키 값, 인증 헤더 값
  - 폼 입력 값
  - 자격 값
  - 프롬프트와 모델 답 원문
  - 사람 이름, 연락처, 원문 인용

### 1.5 지금 쓸 수 있는 결과(2026-10-11)

- `wordpress-analysis-7`: 전 단계 완료. 수정 전 코드로 돈 예비 결과다.
- `wordpress-analysis-8`, `gitea-analysis-3`, `redmine-analysis-3`: 4회차 축 답과 축 답 가림까지 있다. 사실 칸 가림과 합치기는 미뤘다. 그래서 `both-runs` 표시는 아직 없다.

## 2. 방어 모듈이 출력으로 할 수 있는 것

표의 "방법" 칸은 넷 중 하나다.
- **바로:** 공개 기록에 그 정보가 있다
- **비공개 내보내기 필요:** 실제 경로처럼 비공개 체크포인트에만 있다
- **사람 검토:** 출력은 근거 자료이고 값을 정하는 것은 운영자다
- **불가:** 출력으로 정할 수 없다

공통 제약이 하나 있다. 공개 기록은 경로를 해시나 가린 모양으로만 남긴다. 실제 경로가 필요한 설정은 비공개 체크포인트에서 경로를 꺼내는 도구가 있어야 하는데, 이 도구는 아직 없다.

### 2.1 격리 미끼 웹 방어(`defense/web-proxy-defense`, 이 분석기의 1차 소비자)

| 하는 일 | 분석기 출처 |
| --- | --- |
| 복사본에서 원본 고유 값을 지울 위치를 찾음 | identity 묶음 축, `removal_handoff` |
| 지운 자리를 원본과 같은 모양의 가짜 자료로 채움 | content, access 묶음의 `both-runs` 사실 |
| 복사본이 원본과 같은 골격과 기술적 겉모습을 갖췄는지 검증 | appearance, runtime 묶음 축, `facts`의 상태 코드, 헤더, 쿠키 이름 |
| 운영 중 관찰 한계(관문, 개인화, 실시간 내용)를 고려 | access의 관문 축, generic 묶음 축 |

미끼웹 생성 코드(`decoy_build`)는 이 PR에 포함하지 않는다. 읽는 쪽은 `final` 표시와 정해진 키 밖의 내용을 보존해 받는다.

### 2.2 계정 응답 오버레이(`defense/account-response-overlay`)

사이트 프로필 TOML(`defense/site_profile.py:12-32`)과 오버레이 설정을 읽는다. 251ef4f8에서 사이트 프로필에 `decoy_namespaces` 키가 생겼고, 미끼 경로 값은 공용 카탈로그 `shared/decoy-catalog.json`의 사본(`config/decoy-catalog.json`)에서 읽는다(`defense/decoy_paths.py:24-45`).

| 입력 | 분석기 출처 | 방법 |
| --- | --- | --- |
| `api_prefixes`, `ordinary_api_prefixes` (`site_profile.py:21-22`) | `facts.requests[]` 중 화면이 스스로 부른 fetch/xhr 요청, 축 machine_interfaces, entry_points | 가림을 통과한 주소는 바로, 경로 구간이 자리표시로 바뀐 주소는 비공개 내보내기 필요 |
| `ordinary_api_exact` (`site_profile.py:23`, 정확 일치 목록) | 같은 요청 목록 | 가림을 통과한 주소만 바로. 예시 기록의 일반 계정 4회차는 요청 주소 117건이 모두 가려져 비공개 내보내기가 필요했다 |
| `account_terms` (`site_profile.py:18`) | 축 authentication_surfaces, permission_levels, path_groups의 경로 사례 | 사람 검토. 분석기는 낱말이 아니라 경로 사례를 준다 |
| `recon_segments` (`site_profile.py:19`) | 값은 공격자 정찰 낱말이라 분석 대상이 아니다. 정상 경로와 겹치는지 점검할 자료만 준다 | 불가(충돌 점검 자료는 비공개 내보내기 필요) |
| `login_paths`, `recon_html_paths` (`site_profile.py:14, 20`) | 축 authentication_surfaces, credential_methods, path_groups, error_screens | 사람 검토 |
| `login_form_selector` (`site_profile.py:15`) | 둘러보기의 폼 확인 결정 | 사람 검토 |
| `recovery_anchor_selector`, `menu_selector` (`site_profile.py:16-17`) | 축 authentication_surfaces, navigation과 비공개 HTML 소스 | 비공개 내보내기 필요 |
| `origin_auth_cookies` (`site_profile.py:24`) | 일반 계정 회차의 쿠키 이름과 속성 | 비공개 내보내기 필요 |
| `max_response_bytes` (`overlay.py:48`) | 응답 크기 헤더 | 사람 검토. 예시 응답 대부분이 gzip이라 기록된 Content-Length는 압축 크기, 즉 하한이다. 오버레이는 비압축으로 받아 센다(`overlay.py:133, 293-296`) |
| `timeout_seconds` (`overlay.py:49`) | `response_times[]` | 바로(참고 수치) |
| `site_adapter` (`config.py:49`, 값은 `juice_shop` 또는 `generic`, 같은 파일 `75-76`) | 축 product_identity, generator | 바로 |
| `decoy_namespaces` (`site_profile.py:32`, 로드 검증 `51-58`) | 축 path_groups, same_host_apps, 공개 route 해시 | 사람 검토. 미끼가 차지할 경로는 운영자가 정한다. 생략하면 카탈로그 값을 쓴다. 실제 경로와 겹치는지는 다음 행과 같은 방법으로 대조한다 |
| 미끼 네임스페이스와 실제 경로의 충돌 점검 (판별 `decoy_paths.py:67-74`, 값 `config/decoy-catalog.json`) | 축 path_groups, same_host_apps, 공개 route 해시 | 정확 경로는 운영자가 아는 주소의 해시로 대조 가능. 접두사 충돌까지 보려면 비공개 내보내기 필요. 요청의 미끼 판별(`overlay.py:263`)과 Detection의 `decoy_path_hit` 신호(`detection/lib/decoyPaths.js:57-69`)는 프로필의 `decoy_namespaces`가 아니라 카탈로그 값을 쓴다 |
| `decoy_brand`, `decoy_admin_email`, `decoy_service`, `robots_disallow`, `origin_url` | 분석기는 사람, 조직, 메일 값을 만들지 않고 URL 원문을 남기지 않는다 | 불가 |

### 2.3 CHeaT 방어 프록시 v2(`defense/CHeat-defense-proxy/defense_proxy_v2`)

`TARGET_PRESET`, `TARGET_PROFILE`(JSON), `MAZE_*` 환경변수를 읽는다(`profiles.py:236-246`, `Defense_proxy.py:395-426`). 251ef4f8에서 미로 진입 경로(`maze.entry_path`)는 공용 카탈로그 `shared/decoy-catalog.json`에도 선언되며, Detection은 그 경로 접근을 `decoy_path_hit` 신호로 센다. 프리셋 값과 카탈로그 값의 일치는 `defense/tests/test_decoy_catalog_contract.py:97-102`가 확인한다.

| 입력 | 분석기 출처 | 방법 |
| --- | --- | --- |
| `web.server_banner`, `web.x_powered_by` (`profiles.py:90-91`) | `facts.responses[].headers`의 Server, X-Powered-By, 축 front_layer, product_identity | 바로 |
| `MAZE_EXCLUDE`, `maze.paths`, `maze.entry_path` (`profiles.py:31-46`) | 실제 경로 목록, 축 path_groups, authentication_surfaces | 비공개 내보내기 필요. 미로 경로가 실제 경로와 겹치지 않게 하는 데 쓴다 |
| `migration.api_prefix`, `migration.login_path`, `T21_VERSION_PATH`, `lure.status_page.path` | 축 machine_interfaces, authentication_surfaces와 실제 경로 | 비공개 내보내기 필요 |
| `migration.endpoints` (`profiles.py:59`) | 합친 결과의 item_sets, relations_ownership, categories_states | 사람 검토. 항목 종류를 경로 이름으로 옮기는 것은 사람이 한다. 이 값은 현재 정책이 고르지 않는 이전 흔적 전략에서만 쓰인다 |
| `AUTH_COOKIE_RE` (`Defense_proxy.py:672`) | 일반 계정 회차의 쿠키 이름 | 비공개 내보내기 필요 |
| `TARGET_PRESET`, `family`, `MAZE_SPA_BROWSER_PASS`, `MAZE_INTERCEPT_403` | 축 product_identity, front_layer, navigation, error_screens | 사람 검토 |
| 지연 값 `MAZE_DELAY_MS` 등 (`Defense_proxy.py:399-405`) | `response_times[]` | 바로(원본 응답 시간 대비 참고 수치) |
| `REAL_BACKEND`, shell 위장 값, robots 내용 | 출력에 없음 | 불가 |

### 2.4 경로 별칭 v4(`defense/app/path_alias.py`)

경로 파일(`PATH_ALIAS_ROUTES_FILE`, `path_alias.py:314-370`)과 보호 접두사(`PATH_ALIAS_PREFIXES`, `path_alias.py:98-111`)를 읽는다. SQLite는 모듈이 스스로 만드는 클라이언트별 별칭 상태이며 입력이 아니다(`path_alias.py:535-564`).

| 입력 | 분석기 출처 | 방법 |
| --- | --- | --- |
| `routes[]`의 고정 경로와 템플릿, 메서드 (`path_alias.py:158-202, 314-322`) | `facts.requests[]`의 주소 모양과 메서드, 축 path_groups | 사람 검토. 팀 문서도 경로 파일은 운영자가 검토한다고 정함 |
| `query_routes[]`, `action_routes[]` (`path_alias.py:232-280`) | 축 entry_points(매개변수 이름), `facts.form_attempts[]` | 사람 검토 |
| `PATH_ALIAS_PREFIXES` | fetch/xhr 요청 주소의 앞부분, 축 machine_interfaces | 사람 검토 |
| 경로 수집기 입력 `*.runtime.json`, HAR, JS/HTML 파일 (`defense/scripts/discover_path_alias_routes.py:158-236`) | 비공개 체크포인트의 요청 목록과 응답 본문 | 비공개 내보내기 필요 |
| 제출이나 클릭으로만 나가는 POST/PUT/DELETE API, 관리자 전용 API, 운영 수치 | 분석기는 GET과 HEAD만 보내고 관리 영역을 열지 않는다 | 불가 |

### 2.5 탐지와 정책(`detection/`), 지연과 속도 제한 전략(`defense/app/strategies/`)

- 탐지 규칙과 정책 선택(`detection/lib/policyEngine.js`, `detection/config/policy.json`)에는 웹별 입력 통로가 없다. 251ef4f8의 `defense/README.md:155`도 Detection의 비즈니스 로직 탐지 모듈이 Juice Shop에 묶여 있고 `policy.json`에 이를 바꿀 설정 항목이 없다고 적는다.
  - 웹별 지식은 탐지 코드 안에 상수로 들어 있다. 예: 로그인 경로와 칸 이름(`detection/lib/loginBruteForce.js:31, 40-55`), 역할 전용 경로(`roleGatedAccess.js:38-90`), API 경로 접두사(`featureExtractor.js:212`)와 자원 경로 이름(같은 파일 `33-34`).
  - 그래서 분석기 출력은 이 값들을 다른 웹에 맞출 때 사람이 참고할 사실표로만 쓸 수 있다.
  - 참고 근거가 되는 축: authentication_surfaces, credential_methods, permission_levels, write_surfaces, field_constraints, numeric_ranges, machine_interfaces, path_groups.
- 지연(`strategies/delay.py:14-27`)과 속도 제한(`strategies/rate_limit.py:14-32`)의 수치는 원본 측정 없이 정해져 있다.
  - 분석기의 `response_times[]`와 화면당 하위 요청 수를 비교 근거로 쓸 수 있다.
  - 이 값은 자동 브라우저 하나의 측정이라 정상 사용자 기준선은 아니다.
- 출력으로 정할 수 없는 것:
  - 공격 판정 값(점수 가중치, 정책 임계값)
  - 정상 사용자의 요청 간격 기준선
  - JSON API 쓰기 본문의 칸
  - 토큰과 JWT 구성
  - 관리자 권한 경로

이것들은 탐지와 정책 담당의 판단이며, 방어 쪽이 다시 구현하지 않는다.

## 3. 아직 없는 연결

- **비공개 경로 내보내기:** 실제 경로, 쿠키 이름, HTML 선택자가 필요한 설정이 있다(오버레이, CHeaT, 경로 별칭). 이런 설정을 채우려면 비공개 체크포인트에서 이 값들을 운영자에게만 꺼내 주는 도구가 필요하다.
- **설정 초안 생성기:** 분석 결과를 위 표에 따라 오버레이 TOML, CHeaT `TARGET_PROFILE`, 경로 파일 초안으로 옮기는 도구가 없다. 초안은 운영자 검토를 거쳐야 한다.
- 각 모듈이 이 출력을 실제로 받아 쓰는 것은 그 모듈 담당의 결정이다. 이 문서는 모듈 코드를 바꾸자는 제안이 아니라, 이미 읽는 입력에 무엇을 줄 수 있는지 정리한 것이다.
