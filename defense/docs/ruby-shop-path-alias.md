# RUBY Shop 경로 별칭 시험 절차

이 문서는 기존 경로 별칭 v3를 RUBY Shop에 적용한 변경분만 설명한다. 팀의 Juice Shop 설정, 탐지 및 정책 결정은 바꾸지 않는다. 현재 확인한 것은 격리된 로컬 시험이며 팀 서버 배포나 운영 통합 완료를 뜻하지 않는다.

## 변경한 것

| 기존 Juice Shop 시험 | RUBY Shop 시험 |
|---|---|
| `config/juice-shop-routes.json` | `config/ruby-shop-routes.json`의 63개 경로 및 템플릿 |
| `/rest/`, `/api/` 보호 | `/api/` 보호 |
| Juice Shop 원본 주소 | 별도로 실행한 RUBY Shop 원본 주소 |
| 기본 클라이언트 앱 ID | `PATH_ALIAS_APP_ID=ruby-shop` |
| 관리 경로가 같은 프록시에서 열릴 수 있음 | 공격자 공개 진입점에서 `DEFENSE_PUBLIC_TARGET_ONLY=true`로 `/__defense` 차단 및 프록시 자체 문서 라우트 해제 |

RUBY Shop의 `/api/products`, `/api/search` 등을 별칭으로 바꾼다. 올바른 클라이언트 쿠키와 별칭을 받은 요청만 원래 경로로 복원해 전달한다. 원래 `/api/` 경로 직접 요청, 다른 클라이언트의 별칭, 교체 전 별칭은 404가 된다. 이 동작은 경로 발견을 어렵게 할 뿐 SQL 삽입 자체를 막지 않는다.

## 격리된 환경에서 설정

RUBY Shop과 방어 프록시를 로컬 또는 전용 시험 네트워크에서 실행한다. `BENCHMARK_TARGET_URL`에는 공격자가 직접 접근할 수 없는 RUBY Shop 내부 주소를 넣는다. 아래 값은 예시이며 공용 팀 서버에 그대로 적용하지 않는다.

```text
BENCHMARK_TARGET_URL=http://ruby-shop:80
PATH_ALIAS_MODE=enforce
PATH_ALIAS_ROUTES_FILE=/app/config/ruby-shop-routes.json
PATH_ALIAS_PREFIXES=/api/
PATH_ALIAS_APP_ID=ruby-shop
PATH_ALIAS_DB_PATH=/app/data/path-alias.sqlite3
DEFENSE_PUBLIC_TARGET_ONLY=true
TOKEN_GATE_MODE=off
```

컨테이너 경로는 실제 마운트 위치에 맞춰 조정한다. `PATH_ALIAS_DB_PATH`는 재시작 후에도 유지되는 시험 전용 볼륨을 사용한다. `TOKEN_GATE_MODE=off`는 별칭만 비교하려는 시험 조건이며 팀 정책을 대체하지 않는다. 관리 화면이 필요하면 공격자 진입점과 분리하고 기존 대시보드 인증을 유지한다. `DEFENSE_PUBLIC_TARGET_ONLY=true`에서는 프록시의 `/__defense`와 자체 `/docs`, `/redoc`, `/openapi.json` 라우트가 제공되지 않는다. 다만 같은 이름의 **원본 RUBY Shop** `/openapi.json`은 프록시를 통해 전달될 수 있다.

독립적으로 실행한 RUBY Shop 주소를 지정한 뒤 저장소 루트에서 읽기 전용 스모크 검사를 실행한다.

```powershell
$env:RUBY_SHOP_SMOKE_TARGET = "http://127.0.0.1:18080"
python -m defense.scripts.ruby_shop_alias_smoke
```

스크립트는 원본에 GET만 보내고 별칭 DB는 임시 디렉터리에 만든다. 정상 화면과 JS, 상품 목록·상세·검색 별칭 200, 원래 경로·다른 클라이언트 별칭·교체 전 별칭 404, 관리 API 404를 확인한다. 63개 경로 전체 기능 검사는 아니다. 대상 주소를 생략하면 실행하지 않는다.

단위 검사:

```powershell
python -m unittest defense.tests.test_path_alias defense.tests.test_ruby_shop_public_entrypoint -q
```

## 이번 시험 결과와 남은 한계

[RUBY Shop SQL 삽입 A/B 기록](../../benchmark/experiments/path_alias_ab/ruby-shop-sqli-opus5-20261001.md)에 공격자 실행 조건과 수치를 분리해 기록했다. 두 조건 모두 공격에 성공했다. 별칭 조건에서 더 오래 걸리고 요청 및 토큰이 늘었지만 각 1회여서 효과로 일반화할 수 없다. 공격자는 별칭을 알아차렸고 원본 OpenAPI 응답을 통해 별칭 경로를 확인했다.

팀 통합 전에는 다음을 확인해야 한다.

- 공격자 공개 진입점과 관리 진입점이 실제 배포망에서도 분리되는가
- 원본 OpenAPI와 기타 응답에서 별칭이 얼마나 쉽게 노출되는가
- 정상 브라우저 사용, 로그인 및 63개 경로 중 필요한 기능이 별칭 교체 후에도 작동하는가
- 탐지·정책 계층이 별칭 프록시를 거친 요청의 경로와 클라이언트 ID를 어떻게 기록하는가

원본 웹으로 우회 접근할 수 있다면 별칭 방어는 성립하지 않는다. 이 설정만으로 서버 격리를 보장하지 않는다.
