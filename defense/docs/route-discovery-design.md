# 설치형 경로 별칭: 경로 발견과 저장 단위

## 저장 단위

별칭 키는 **앱 × 사용자(Defense 쿠키) × API 경로 × 세대**다. 현재 `path_alias_clients`는 `(app_id, client_id)`의 세대를, `path_alias_client_rows`는 각 경로의 실제 별칭과 만료 시각을 저장한다. 같은 사용자의 다른 API는 서로 다른 별칭이고, 다른 사용자의 같은 API도 별개다. 화면마다 같은 API의 별칭을 다시 발급하지 않는다. 브라우저의 여러 탭이 한 사용자의 쿠키와 별칭을 공유할 수 있어야 하기 때문이다.

SQLite의 [WAL 모드](https://www.sqlite.org/wal.html)는 같은 호스트의 여러 프로세스에서 읽기와 쓰기를 병행하는 데 맞다. 쓰기 트랜잭션은 한 번에 하나이므로 발급·교체는 짧게 끝내고, 사용자 수와 쓰기량이 커지면 측정 후 중앙 DB로 옮긴다. WAL 파일을 네트워크 파일 시스템에 두고 여러 서버가 공유하는 구성은 SQLite 문서의 지원 범위를 벗어난다. 현재의 `UNIQUE(app_id, client_id, route_path, generation)`은 사용자별 경로 별칭 중복을 막고, `alias_route` 기본 키는 역방향 조회에 사용된다. 복합 키와 인덱스는 [SQLite 스키마 문서](https://www.sqlite.org/lang_createtable.html)를 기준으로 한다.

## 설치 과정의 경로 발견

1. 별칭 적용 전 앱에서 공개 HTML·JS를 자동 수집한다. `python -m defense.scripts.discover_path_alias_routes --fetch http://shop.example --asset-dir local-assets --output route-report.json`을 사용한다. 같은 출처의 script와 동적 JS chunk만 최대 64개, 총 32 MiB까지 가져온다. 기존 경로 설정과 비교하려면 `--routes existing-routes.json`을 더한다. 정상 사용 중 브라우저 HAR도 있으면 `BROWSER.har --origin http://shop.example`을 함께 지정한다. `--origin`은 HAR에서 다른 사이트 요청을 제외한다. HAR에는 계정 정보가 있을 수 있으므로 원본은 로컬에만 두고, 보고서에는 경로·관찰된 HTTP 메서드·출처 파일명·경로를 담은 쿼리 키만 넣는다.
2. AI는 이 **후보 보고서**를 입력으로 받아 정적 경로와 `{id}`·`{tail*}` 템플릿, 메서드를 제안한다. 실제 요청에서 관찰되지 않은 메서드나 쿼리 라우팅 의미는 추측으로 확정하지 않는다. 모델 제공자는 아직 정하지 않았으므로 수집기와 모델 호출을 분리한다.
3. 운영자가 제안과 정상 사용자 흐름을 확인한 뒤 `PATH_ALIAS_ROUTES_FILE`로 승격한다. 후보 수집이나 AI 출력만으로 `enforce` 설정을 바꾸지 않는다. 누락된 경로는 실제 사용에 404를 낼 수 있다.

2026-10-06 로컬 Juice Shop의 `frontend/dist/frontend` 전체 JS·HTML을 수집기로 확인했다. **52개 경로 후보 중 51개는 현재 경로 설정에 직접 매칭되고, `/rest/image-captcha/` 한 개는 런타임에 ID를 붙이는 `/rest/image-captcha/{id}`의 접두사**였다. 번들만으로는 경로 값을 담는 쿼리 키가 발견되지 않았다. 이 결과는 해당 빌드의 정적 자산에 한정되며, 로그인 후 네트워크 요청과 다른 앱의 쿼리 라우팅은 별도로 봐야 한다.

## URL 파싱 경계

요청의 pathname과 query는 분리해 다룬다. 프록시는 쿼리를 파싱 후 재조립하지 않고 원본 바이트를 업스트림에 전달한다. 따라서 `?next=%2Fapi%2F...`, 중복 키, 빈 값의 표기가 바뀌지 않는다. `?next=/rest/...`가 단순 이동 대상인지, 실제 API 라우팅 선택자인지는 앱마다 다르다. **쿼리에 경로 문자열이 나타났다는 이유만으로 직접 경로 공격으로 분류하거나 별칭을 발급하지 않는다.** 해당 앱의 실제 요청 예시와 정상 사용자 검증이 확보되면 그 키와 엔드포인트를 명시적으로 설정하는 방식으로 확장한다. `/#/login` 같은 fragment는 HTTP 요청에 전송되지 않는 브라우저 내부 경로다.
