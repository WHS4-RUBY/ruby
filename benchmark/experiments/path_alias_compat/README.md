# 경로 별칭 v4 호환성·부하 검증 도구

[설치·운영 가이드 7절](../../../defense/docs/path-alias-operations.md#7-검증-결과)의 결과를 다시 만드는 스크립트다. 모두 로컬 일회용 컨테이너를 대상으로 하며 공격 대상은 로컬 Juice Shop뿐이다.

## 준비

```sh
docker run -d --name ruby-verify-juice -p 3000:3000 bkimminich/juice-shop   # 20.2.0에서 검증
```

저장소 루트에 `verify.env`(커밋하지 않음)를 만든다. 값은 로컬 전용 임의 문자열이다.

```
PATH_ALIAS_MODE=enforce
PATH_ALIAS_ROUTES_FILE=/app/config/juice-shop-routes.json
PATH_ALIAS_PREFIXES=/rest/,/api/,/b2b/
TARGET_CHOICES=legacy=http://host.docker.internal:3000,alternate=http://host.docker.internal:3000
TARGET_DEFAULT_ID=legacy
CSRF_ALLOWED_ORIGINS=http://localhost:8081,http://127.0.0.1:8081,http://host.docker.internal:8081
CRS_MODE=enforce
TOKEN_GATE_MODE=off
DETECTION_DASHBOARD_PASSWORD=<로컬 임의값>
DEFENSE_DASHBOARD_PASSWORD=<로컬 임의값>
PAYLOAD_FINGERPRINT_KEY=<로컬 임의값>
DCID_HMAC_SECRET=<로컬 임의값>
ACCOUNT_ID_HASH_KEY=<로컬 임의값>
OVERLAY_DETECTOR_KEY=<64자리 hex>
```

```sh
docker compose -p ruby-verify --env-file verify.env -f docker-compose.local.yml up -d --build --wait
```

Windows Git Bash에서는 `MSYS_NO_PATHCONV=1`을 먼저 export한다(경로 형태 인자·환경변수가 바뀌는 것을 막는다).

## 스크립트

| 파일 | 내용 |
|---|---|
| `http_matrix.py <label>` | 쿠키 반환/미반환 클라이언트의 별칭·원본·변형·공격 요청 17개 검사. 별칭 위치 확인을 위해 Defense SQLite를 읽는다(검증 전용) |
| `run_modes.sh` + `mode_matrix.py` | off/audit/observe/enforce와 준비되지 않은 경로 파일(`defense/config/juice-unready.tmp.json`, `juice-shop-routes.json`에서 `enforce_ready=false`로 만든 임시 복사본)을 쿠키 반환 여부와 교차 |
| `browser_flows.cjs <label> [base] [--wait-expiry 초]` | Playwright 정상 사용자 흐름. `ruby-token-gate-browser` 이미지 등 `/runner/node_modules/playwright`가 있는 컨테이너에서 실행: `docker run --rm -v $PWD/benchmark/experiments/path_alias_compat:/verify <image> node /verify/browser_flows.cjs enforce` |
| `cookieless_attack.py` | 쿠키 미반환 공격·같은 NAT·지문 변경·DCID 변조/재발급 단계별 Defense 이벤트(정책 출처·위험도·전략). `VERIFY_DASHBOARD_PASSWORD` 필요 |
| `restart_load.sh KEY=VALUE…` + `load_sqlite.py <label> <요청> <동시> [경로] [nocookie|cookie|rotate]` | 4 worker Defense + 한 SQLite 파일 부하. `ruby-verify-defense` 이미지와 Juice Shop을 쓴다 |
| `dispatcher_app.py`, `dispatcher-routes.json` | 경로형·기능형 dispatcher 에코 대상(가이드 7.1의 dispatcher 행) |

흐름 순서에 주의한다. 쿠키를 돌려주는 클라이언트가 원본 경로를 한 번 호출하면 정책대로 그 클라이언트의 별칭이 모두 교체되므로, 별칭 검사는 원본 호출 전에 둔다.
