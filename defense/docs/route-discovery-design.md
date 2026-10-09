# 설치형 경로 별칭: 경로 발견과 저장 단위

## 저장 단위

별칭 키는 **앱 × 사용자(Defense 쿠키) × API 경로 × 세대**다. 현재 `path_alias_clients`는 `(app_id, client_id)`의 세대를, `path_alias_client_rows`는 각 경로의 실제 별칭과 만료 시각을 저장한다. 같은 사용자의 다른 API는 서로 다른 별칭이고, 다른 사용자의 같은 API도 별개다. 화면마다 같은 API의 별칭을 다시 발급하지 않는다. 브라우저의 여러 탭이 한 사용자의 쿠키와 별칭을 공유할 수 있어야 하기 때문이다.

v4(2026-10-09)부터 테이블은 `path_alias_client_state`(세대·미확인 여부)와 `path_alias_alias_rows`(별칭·만료·폐기 사유)이며, 응답에 실제로 나온 경로만 발급한다. 기본 저장소는 SQLite이고 PostgreSQL은 다중 호스트용 선택 사항이다([설치·운영 가이드](path-alias-operations.md)).

SQLite의 [WAL 모드](https://www.sqlite.org/wal.html)는 같은 호스트의 여러 프로세스에서 읽기와 쓰기를 병행하는 데 맞다. 쓰기 트랜잭션은 한 번에 하나이므로 발급·교체는 짧게 끝내고, 사용자 수와 쓰기량이 커지면 측정 후 중앙 DB로 옮긴다. WAL 파일을 네트워크 파일 시스템에 두고 여러 서버가 공유하는 구성은 SQLite 문서의 지원 범위를 벗어난다. 현재의 `UNIQUE(app_id, client_id, route_path, generation)`은 사용자별 경로 별칭 중복을 막고, `alias_route` 기본 키는 역방향 조회에 사용된다. 복합 키와 인덱스는 [SQLite 스키마 문서](https://www.sqlite.org/lang_createtable.html)를 기준으로 한다.

## 설치 과정의 경로 발견

1. 별칭 적용 전 앱에서 공개 HTML·JS를 자동 수집한다. `python -m defense.scripts.discover_path_alias_routes --fetch http://shop.example --asset-dir local-assets --output route-report.json`을 사용한다. 같은 출처의 script와 동적 JS chunk만 최대 64개, 총 32 MiB까지 가져온다. 기존 경로 설정과 비교하려면 `--routes existing-routes.json`을 더한다. 정상 사용 중 브라우저 HAR도 있으면 `BROWSER.har --origin http://shop.example`을 함께 지정한다. `--origin`은 HAR에서 다른 사이트 요청을 제외한다. HAR에는 계정 정보가 있을 수 있으므로 원본은 로컬에만 두고, 보고서에는 경로·관찰된 HTTP 메서드·출처 파일명·경로를 담은 쿼리 키만 넣는다.
2. 운영자가 경로 후보와 쿼리 라우팅 근거를 검토해 실제 API 경로, 메서드, 라우팅 키를 확정한다. AI 모델 호출과 설정 초안 생성은 제공하지 않는다.
3. 운영자가 제안과 정상 사용자 흐름을 확인한 뒤 `PATH_ALIAS_ROUTES_FILE`로 승격한다. 후보 수집이나 AI 출력만으로 `enforce` 설정을 바꾸지 않는다. 누락된 경로는 실제 사용에 404를 낼 수 있다.

2026-10-06 로컬 Juice Shop의 `frontend/dist/frontend` 전체 JS·HTML을 수집기로 확인했다. **52개 경로 후보 중 51개는 현재 경로 설정에 직접 매칭되고, `/rest/image-captcha/` 한 개는 런타임에 ID를 붙이는 `/rest/image-captcha/{id}`의 접두사**였다. 번들만으로는 경로 값을 담는 쿼리 키가 발견되지 않았다. 이 결과는 해당 빌드의 정적 자산에 한정되며, 로그인 후 네트워크 요청과 다른 앱의 쿼리 라우팅은 별도로 봐야 한다.

## URL 파싱 경계

### 실행 중 API 수집

정적 자산에 없는 API를 확인하려면 Playwright가 설치된 로컬 테스트 환경에서 다음처럼 실제 사용자 흐름을 실행한다. 별칭 적용 전 앱의 origin을 사용한다.

```sh
node defense/scripts/capture_api_requests.cjs --origin http://localhost:3000 --steps defense/config/juice-shop-discovery-flow.json --output capture.runtime.json
python -m defense.scripts.discover_path_alias_routes capture.runtime.json --routes defense/config/juice-shop-routes.json --origin http://localhost:3000 --output route-report.json
```

흐름 JSON은 `goto`, `click`, `fill`, `press`, `waitFor`, `wait`, `reload`, `back`, `forward` 단계 배열이다. `click`·`fill`·`press`·`waitFor`에는 Playwright 선택자 `selector`를 쓴다. `goto`는 같은 출처의 `path`만 허용한다. `fill`은 비밀번호 등을 파일에 적지 않도록 `valueEnv`로 환경변수 이름을 받는다. 로그인 세션이 이미 준비돼 있으면 `--storage-state state.json`을 추가한다. 수집기는 같은 출처의 보호 경로 요청, 보호 접두사 밖의 같은 출처 fetch/XHR, 그리고 그 경로를 쿼리 값에 담은 dispatcher 요청을 기록한다. 각 항목은 method·pathname·query key·응답 상태다. `--route-keys route,action`으로 운영자가 지정한 키의 값만 경로형(`path`)·기능형(`action`)·불명(`opaque`)으로 분류해 기록한다. 본문에 지정 키가 있으면 키 이름만 `body_selector_keys`로 남긴다. 보고서의 `routing_dispatchers`는 dispatcher별 권장 설정(`query_routes`/`action_routes`/수동 검토)을, `unsupported_routing`은 본문 라우팅·불명 값을, `same_origin_api_outside_prefixes`는 접두사 밖 API를 보여 준다. 쿠키, 헤더, 요청 본문, 일반 쿼리 값은 저장하지 않는다. 경로에 개인 식별자가 포함될 수 있으므로 결과 파일은 검토 후 공유한다.
다른 웹의 API 접두사가 `/graphql`, `/v1/`이라면 두 명령에 모두 `--prefixes /graphql,/v1/`을 지정한다. 브라우저 흐름이 실패하거나 페이지 오류가 발생하면 보고서의 `incomplete_runtime_captures`에 파일명이 들어가므로 해당 수집을 완전한 경로 목록으로 취급하지 않는다.

이 방식은 **흐름에서 실제 방문한 화면과 수행한 동작**의 API를 추가로 찾는다. 로그인하지 않은 화면, 역할별 화면, 실행하지 않은 기능, 서버 간 요청은 자동으로 완전 탐색하지 않는다. 경로 템플릿과 메서드 제안은 후보 보고서를 검토한 뒤 확정하고, 보고서만으로 `PATH_ALIAS_ROUTES_FILE`을 자동 변경하지 않는다.
2026-10-07 로컬 Juice Shop의 샘플 흐름 6단계를 실행해 API 요청 16건, 고유 경로 6개를 수집했다. 6개 모두 기존 경로 설정에 포함됐고, 흐름 실패와 페이지 오류는 없었다. 이 수치는 샘플 흐름의 관찰 범위이며 앱 전체 API 수를 뜻하지 않는다.

## URL 파싱 경계

요청의 pathname과 query는 분리해 다룬다. 라우팅에 쓰지 않는 쿼리 필드는 인코딩, 중복 키, 빈 값까지 원본 바이트로 보존한다. `/#/login` 같은 fragment는 HTTP 요청에 전송되지 않는 브라우저 내부 경로다.

### 쿼리 기반 API 라우팅

`/gateway?route=/api/items`처럼 쿼리 값이 API 경로를 선택하는 앱은 경로 설정 파일에 `query_routes`를 추가한다. [설정 예시](../config/query-routing-example.json):

```json
{
  "routes": [{"path": "/api/items", "methods": ["GET"]}],
  "query_routes": [{"path": "/gateway", "parameter": "route"}]
}
```

응답 HTML·JS·JSON의 상대 dispatcher URL과 같은 출처의 Location 헤더에서 `route` 값을 해당 사용자의 별칭으로 치환한다. `%2Fapi%2Fitems`처럼 인코딩된 값과 HTML의 `&amp;` 구분도 지원한다. 요청 `/gateway?route=/__ruby_alias_…`는 `/gateway?route=/api/items`로 복원해 후속 전략과 대상 웹에 전달한다. 외부 주소로 프록시 대상을 변경하지 않는다.

라우팅 값에는 기존 별칭의 사용자 귀속·만료·메서드·동적 경로 검사를 동일하게 적용한다. enforce에서 원본 보호 경로, 다른 사용자/만료 별칭, 보호 대상이 섞인 중복 라우팅 키, 잘못된 보호 경로 값은 전달 전에 404로 거부하고 사유별 교체 규칙을 적용한다. 보호 경로가 아닌 값(`route=/home`, `route=home`)은 v4부터 그대로 통과한다. 라우팅 키가 없는 요청과 지정하지 않은 키는 기존 경로 정책을 따른다. `/`도 dispatcher로 설정할 수 있다. 라우팅 설정을 변경하면 config hash가 바뀌어 기존 별칭이 무효화된다.

쿼리가 이동 주소인지 API 선택자인지는 URL만으로 확정할 수 없어 진입 경로와 파라미터 이름을 앱별로 지정한다. 설정된 값은 `/`로 시작하는 경로이며 자체 쿼리·fragment나 외부 URL은 허용하지 않는다. 액션 이름 기반 라우팅(`/api.php?action=login`)은 `action_routes`로 지원한다(가이드 3절). JavaScript에서 URLSearchParams로 값을 따로 조립하는 코드와 본문 속 라우팅 선택자는 치환할 수 없다. 본문 선택자가 보호 대상이면 enforce에서 거부하고 `body_routing_unsupported`로 기록한다.

테스트용 `/gateway`를 사용한 통합 검사로 인코딩된 값의 응답 치환·요청 복원, HTML 구분자, 후속 전략에 복원된 쿼리 전달, 원본/외국 사용자/오래된 별칭·중복 키 차단, 메서드 제한과 동적 경로를 확인했다. 실제 앱의 쿼리 라우팅 흐름을 검사한 결과로 해석하지 않는다.
