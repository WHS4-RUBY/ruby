# 리팩토링 최종 보고서 (Phase 2~5)

Phase 0/1 의 조사 결과는 [`refactor-inventory.md`](refactor-inventory.md)에 있다.
이 문서는 거기서 확인한 문제를 어떻게 고쳤는지, 무엇이 바뀌었고 무엇을 안 했는지,
되돌리는 방법을 적는다.

기준: `a89ecab`(Phase 1 보고서) → `9945d1d`. 커밋 19개, 100개 파일, +5539 −839.

---

## 1. 요구사항별 결과

| 요구사항 | 결과 |
| --- | --- |
| 1. 미끼 경로 단일 출처 | `shared/decoy-catalog.json` 하나. Detection·오버레이가 같은 값을 읽고 CHeaT 는 계약 테스트로 일치를 강제. 미끼 적중을 공격 신호 `decoy_path_hit` 으로 채점 |
| 2. 사이트 일반화 | 미끼 네임스페이스를 사이트 프로파일이 선언(`decoy_namespaces`). 코드에서 `/ftp`·`/ops` 리터럴과 `juice`/`ruby` 분기 제거. **Defense 까지만** — 아래 "하지 않은 것" 참조 |
| 3. 중복 제거 | 인벤토리가 꼽은 중복 8건 전부. TOML 16→11(−78줄), Compose 공통 env 148줄, Detection 라우트 이중 선언 |
| 4. DB 통일 | 공용 접근 계층 1개(언어당) + `schema_migrations` 전면 도입. Detection 4→1, 오버레이 3→2. fail-closed 저장소 2개는 의도적으로 분리 유지. `target-selection.json` 은 소유자를 Detection 으로 확정하고 양쪽 검증 경계값을 통일 |

## 2. 구조로 바뀐 것

### 공유 원본과 사본

`shared/` 가 편집 원본이고 각 서비스 트리에 사본을 커밋한다. 네 이미지의 빌드
컨텍스트가 모두 하위 디렉터리라 Docker 가 `COPY ../` 를 금지하기 때문이다.
`scripts/sync-shared.sh` 가 복사·검사하고 `defense/tests/test_shared_sources.py` 가
CI 에서 동일성을 강제한다.

| 원본 | 사본 수 | 내용 |
| --- | --- | --- |
| `shared/decoy-catalog.json` | 2 | 미끼 네임스페이스·진입 경로·단서 헤더·미끼 쿠키·신원 |
| `shared/event-schema.json` | 1 | 정본 이벤트 필드명과 저장소별 별칭 |
| `shared/py/store.py` | 3 | SQLite 연결·트랜잭션·마이그레이션 |
| `shared/target-selection.json` | 0 (선언만) | 대상 선택 파일의 소유자와 검증 경계값. 계약 테스트가 양쪽 구현과의 일치를 강제 |

### 저장소

| 컨테이너 | 전 | 후 |
| --- | --- | --- |
| detection | 4 (SQLite 3 + JSON 1) | **1** `detection.sqlite3` |
| overlay-* | 3 | **2** `telemetry.sqlite3` + `security.sqlite3` |
| defense | 2 | 2 (유지, 아래 이유) |
| cheat-* | 1 | 1 |

`schema_migrations(component, version, applied_at)` 는 복합 키라 한 파일이 여러
컴포넌트를 독립 버전으로 담는다. 저장소 전체에서 유일했던
`try ALTER TABLE / except OperationalError` 를 대체했고, `path_alias` 에 방치돼 있던
v3 테이블 2개도 마이그레이션에서 DROP 한다.

### 대상 선택 파일의 소유자와 경계값

Detection 이 유일한 writer 이고 Defense 는 같은 named volume 을 `:ro` 로 읽는다.
HTTP API 로 바꾸지 않았다 — Defense→Detection 런타임 의존이 새로 생기고 대시보드
인증 경로를 거쳐야 한다.

같은 파일을 양쪽이 서로 다른 규칙으로 검증하고 있었다. Detection 은 항상 canonical
UUID 와 `toISOString()` 만 쓰고 Defense 의 **헤더** 경로는 이미 canonical UUID 를
강제했으므로, 느슨한 쪽을 좁혀 맞췄다.

| 항목 | Detection (전) | Defense (전) | 통일 후 |
| --- | --- | --- | --- |
| target ID | 32자 | 64자 | **32자** |
| `runId` | `[a-zA-Z0-9:-]{1,100}` | 길이 1–128 | **canonical UUID** (헤더 경로와 동일) |
| `changedAt` | `Date.parse` | 길이 1–64 | **파싱 가능한 ISO** |
| 크기 상한 | 없음 | 8192 바이트 | **양쪽 8192 바이트** |

### 중복 제거 내역

| 중복 | 정본 |
| --- | --- |
| 미끼 경로 판별 5곳 | `decoy_paths.is_overlay_decoy` / `detection/lib/decoyPaths.js` |
| 세션 별칭 표 2곳 | `decoy_paths.session_aliases` (쿼리 보존 차이는 호출처에 유지) |
| 경로 상수 5곳 | 카탈로그 |
| `/swagger`·`/openapi` 판정 2곳 | `decoy_paths.prefixed` |
| robots.txt 생성기 3곳 | `decoy_paths.robots_body` |
| 진입/단계 경로 집합 | `decoy_paths.is_entry` |
| `HOP_HEADERS` 2곳 | `decoy_paths` |
| 단서 헤더 리터럴 3종 | `decoy_paths.clue_headers` |
| TOML no-op 테이블 77줄 | 삭제 (dataclass 기본값과 동일) |
| Compose 공통 env 148줄 | `docker-compose.common.yml` + `extends` |
| Detection 라우트 이중 선언 | 템플릿 하나에서 정규식 생성 |

## 3. 삭제·이동한 파일

삭제 6개:

```text
defense/account-response-overlay/config/default.toml            (decoy-v2.toml 과 byte-identical)
defense/account-response-overlay/config/decoy-server-v1.toml    (secure_cookie 한 값 차이)
defense/account-response-overlay/config/decoy-server-v2.toml    (같음)
defense/account-response-overlay/config/overlay-server-v1.toml  (decoy_config 한 줄 차이, 실행 참조 0건)
defense/account-response-overlay/config/overlay-server-v2.toml  (같음)
defense/account-response-overlay/defense/sites/juice_shop/__init__.py
```

이동(`git mv`, 이력 보존): `defense/sites/juice_shop/` → `defense/sites/account_decoy/`
6개 파일.

**CHeaT v1 은 삭제하지 않았다.** 실행 참조는 0건이지만 Markdown 참조가 16건(5개 파일)
남아 있고, "참조가 남아 있으면 삭제하지 않는다"는 규칙을 따랐다. 지우려면
`results.md` 만 남기고 6파일(168KB)을 삭제하고 16개 링크를 정리하면 된다 — 그중 2개는
이미 깨진 링크다.

## 4. 환경변수 변경과 마이그레이션

### 이름이 바뀐 것

| 전 | 후 | 비고 |
| --- | --- | --- |
| `XSS_DB_PATH`, `XSS_CONFIRMED_DB_PATH`, `XSS_REFLECTED_DB_PATH`, `SCHEMA_LEARNING_FILE` | `DETECTION_STORE_DB` | 구 변수가 설정돼 있으면 Detection 이 경고를 띄운다 |
| 오버레이 TOML `audit_path` 전용 | `DEFENSE_TELEMETRY_DB` (TOML 도 계속 유효) | 미끼 링 경로가 더 이상 `security_db` 형제로 파생되지 않는다 |
| — | `OVERLAY_SECURE_COOKIE` | 삭제한 `*-server-*` 변종 4개를 대체 |
| — | `DEFAULT_SITE_PROFILE` | `default_site_profile()` 의 Juice Shop 하드코딩 대체 |

이름이 그대로인 것: `PATH_ALIAS_DB_PATH`, `DEFENSE_OVERLAY_STATE_DB`,
`DEFENSE_SECURITY_DB`, `DEFENSE_DB` — 가리키는 파일이 바뀌지 않았다.

제거: `deploy.yml` 의 `PATH_ALIAS_DB_PASSWORD` 배선. `path_alias.py` 가
`PATH_ALIAS_DB_URL` 을 거부하므로 쓰이지 않는 죽은 배선이었다.

### 마이그레이션

둘 다 멱등이고, 구 파일이 없으면 아무것도 하지 않는다. 옮긴 구 파일은
`<이름>.migrated` 로 바꿔 둔다.

```bash
# Detection: xss-candidates.db / xss-confirmed.db / xss-reflected.db / schema-learning.json
docker compose exec detection node scripts/migrate-stores.js
docker compose exec detection node scripts/migrate-stores.js --dry-run   # 미리 보기

# 오버레이: events.sqlite3 / lure-events.sqlite3
docker compose exec overlay-juice python -m defense.cli \
    --config /app/config/decoy-production-juice-v2.toml migrate-telemetry
```

CHeaT 와 `path_alias` 는 별도 명령이 없다 — 기동 시 기존 볼륨의 스키마를 버전으로
환산해 기록만 남기고(DDL 미실행) 이어서 쓴다.

## 5. 관측 가능한 동작 변경 (전부 별도 커밋)

| 커밋 | 변경 | 영향 |
| --- | --- | --- |
| `5081af0` | 미끼 단계 분류에 세그먼트 경계 요구 | `/ops/recoveryXYZ`·`/ftpx` 가 패밀리로 오분류되던 것이 `decoy` 로. `/ops/recovery/accounts/` 가 단계→진입으로 |
| `5081af0` | 내부 미끼 robots 출처 | 하드코딩 `/ftp` → 프로파일. 오버레이 배포에서는 이 분기에 도달하지 않아 관측되지 않는다 |
| `64e6af0` | `decoy_path_hit` 신호 추가 | 미끼 경로 적중이 공격 점수에 `8/35×0.17 ≈ 0.039` 기여. 상한과 가중치는 불변이라 임계값 자체는 안 바뀌고 같은 요청이 더 빨리 구간에 닿는다 |
| `e4e2757` | `generic` 사이트의 `/api/Challenges` | Juice 챌린지 JSON → 404. 내부 미끼 앱이 미끼 경로만 받으므로 배포에서는 도달하지 않는다 |
| `7282c67` | 텔레메트리 DB 파일명 | `events.sqlite3`+`lure-events.sqlite3` → `telemetry.sqlite3` |
| (D3) | 대상 선택 파일 검증 강화 | UUID 아닌 `runId`·파싱 안 되는 `changedAt`·8192 바이트 초과를 거부한다. Detection 이 쓰는 값은 전부 통과하므로 실제 데이터에는 영향이 없고, 손으로 만든 파일이나 32자 초과 target ID 는 거부된다 |

동작 보존 커밋에서는 동일성을 기계적으로 증명했다:

- 판별 함수: 구 구현과 30개 경로 × 3함수 + 별칭·robots·헤더 전부 동일
- TOML 정리: 21개 설정의 로딩 결과(중첩 dataclass 전개) 완전 동일
- Compose 추출: `docker compose config` 렌더 양쪽 **byte-identical**
- Detection 라우트: 구 정규식과 2규칙 × 11 URL 전부 동일
- CHeaT 마이그레이션: 새 파일·레거시·현재 스키마 세 상태에서 컬럼 확보·행 보존·재실행 안전

## 6. 하지 않은 것과 이유

| 항목 | 이유 |
| --- | --- |
| `routes.sqlite3`·`security.sqlite3` 를 합치기 | fail-closed 저장소다. `main.py` 는 `OverlayRouteError` 를, `core.py` 는 감사 쓰기 실패를 503 으로 돌려준다. 요청마다 쓰는 저장소와 파일을 공유하면 그쪽 쓰기 락이 정상 요청을 503 으로 만든다. 접근 계층만 통일했다 |
| Detection 7개 모듈의 사이트 일반화 | `businessLogicSignatures`·`roleGated`·`priceIntegrity`·`priceTampering`·`loginBruteForce`·`passwordResetAbuse`·`identityMismatch` 는 여전히 Juice Shop 라우트·JWT 클레임·쿠키명에 묶여 있다. CI 가 Juice Shop 을 전혀 쓰지 않아(정적 index.html 하나) 테스트로 보호되지 않는 상태에서 손대는 위험이 컸다. 모듈별 현황은 인벤토리 1-D 에 있다 |
| `sites/account_decoy/` 파일 단위 분할 | `cycle.py`·`facade.py` 에 Juice 전용 `/api/Challenges` 가 있어 가르려면 decoy 엔진 수술이 된다. 디렉터리 이름만 내용에 맞추고 종속 지점을 `site_adapter` 로 게이트했다 |
| 이벤트 필드명 강제 통일 | Detection 의 `targetRunId` 는 `experimentRunId` 와 구별해야 하고, CHeaT·오버레이의 snake_case 컬럼은 경계 밖에서 읽는 곳이 없다. 정본 이름과 별칭을 선언하고 테스트로 고정했다 |
| CHeaT v1 삭제 | Markdown 참조 16건 |
| 미끼 경로 시드화 | `/ops/recovery/accounts` 같은 경로 자체가 배포 간 고정 지문이다. 카탈로그가 생겨 이제 구조적으로 가능해졌지만 범위 외다 |

## 7. 남은 위험

1. **공용 사본 방식** — `shared/` 원본과 사본이 어긋나면 서비스가 서로 다른 미끼
   경로를 본다. `scripts/sync-shared.sh --check` 와 `test_shared_sources.py` 가 CI 에서
   막지만, 사본을 손으로 고치면 그 커밋에서 바로 실패한다(의도된 동작).
2. **`decoy_path_hit` 의 오탐** — `/ftp` 는 Juice Shop 에 실제로 있는 경로다. 정찰
   목적이 아닌 접근까지 공격 신호가 될 수 있다. 끄려면 `policy.json` 에
   `detection.deception.points.attack.decoy_path_hit = 0`.
3. **Detection 비즈니스 로직의 사이트 종속** — 새 사이트를 붙이면 Defense 의
   미끼·오버레이는 동작하지만 Detection 의 7개 모듈은 조용히 무력화된다.
   `defense/README.md` 의 사이트 추가 절에 명시했다.
4. **CHeaT 테스트 3건이 불안정** — 전부 리팩토링과 무관하며 CHeaT 디렉터리는
   Phase 3 시작 시점과 byte-identical 이다(`git diff` 로 확인).
   - `test_dashboard_and_preset.py` — 컨테이너 기본 uid(10001)에서만 실패.
     `--user 0` 으로는 전부 통과. `dashboard.py` 가 운영 이미지 COPY allowlist 에서
     제외돼 있어 생기는 환경 차이다.
   - `test_xff.py` — 보호 단정 5개는 통과하고 회귀 확인용 "대조군" 1개만 실패한다.
     이 환경에서는 `X-Forwarded-For` 위조 우회가 재현되지 않아 "취약점이 있어야
     한다"는 단정이 실패한다.
   - `test_delay_not_summed.py` — **순서 의존 flaky**. 단독 실행이나 이름 필터로는
     통과하고 전체 20개 순서에서만 실패한다(여러 번 재현). 그래서 CHeaT 는
     17~18/20 사이를 왕복한다.
   세 건 모두 GitHub Actions 에서는 결과가 다를 수 있으므로 CI 결과로 교차 확인이 필요하다.
5. **매니페스트 갱신 마찰** — 오버레이 패키지의 파일을 바꾸면
   `scripts/gen_manifest.sh` 를 돌려 `MANIFEST.sha256` 을 같은 커밋에 넣어야 한다.
   잊으면 CI 가 막고 고치는 명령을 출력한다.
6. **대시보드 설명문의 배점 표기** — `dashboard.html` 의 기존 설명문은 점수를 산문에
   박아 두었다. `policy.json` 으로 배점을 덮어쓰면 그 문장이 실제와 어긋난다.

## 8. 되돌리는 방법

커밋이 기능 단위로 나뉘어 있어 개별 revert 가 가능하다. 동작 변경 커밋만 되돌리고
싶으면:

```bash
git revert 5081af0   # 미끼 단계 분류·robots 출처 교정
git revert 64e6af0   # decoy_path_hit 신호
git revert e4e2757   # sites 패키지 이름 + /api/Challenges 게이트
```

`decoy_path_hit` 은 revert 없이 `policy.json` 으로도 끌 수 있다(위 7-2).

Phase 단위로 되돌리려면 역순으로 revert 한다. Phase 3 의 저장소 통합을 되돌릴 때는
**데이터 이전이 자동으로 되돌아가지 않는다** — 통합 DB 에 쌓인 행은 구 파일로 돌아가지
않으므로, 되돌린 뒤에는 `<이름>.migrated` 파일을 원래 이름으로 되돌리고 통합 DB 를
치우는 수동 작업이 필요하다. 가장 안전한 되돌리기는 리팩토링 이전 이미지 태그로
재배포하면서 구 볼륨을 그대로 쓰는 것이다(`deploy.yml` 이 SHA 태그로 배포하므로
`a89ecab` 이전 태그를 쓰면 된다).

## 9. 검증 현황

| 스위트 | Phase 1 기준선 | 현재 |
| --- | --- | --- |
| Detection `npm test` | 237 | **265** |
| Detection CRS 바이너리 | 12 | **12** |
| Defense `unittest` | 185 | **250** |
| CHeaT `run_all.py` | 16~17/19 (아래 참조) | **17~18/20** (아래 참조) |
| Overlay `pytest` | 64 | **81** |
| Overlay lure UI | 6 | **6** |
| Defense Node 2종 | 12 + 6 | **12 + 6** |
| `MANIFEST.sha256` | 54/61, **7 FAILED** | **72/72, 0 FAILED** + CI 검증 |

측정은 Docker 전용이다. 로컬 호스트에는 의존성이 없고 `defense`(fastapi 0.115 /
httpx 0.27.2)와 오버레이(fastapi 0.141.1 / httpx 0.28.1)의 핀이 충돌해 단일 venv 로는
네 스위트를 동시에 돌릴 수 없다. 명령은 인벤토리의 "측정 방식" 절에 있다.

CI 에 추가된 검사: 미끼 카탈로그 계약 테스트, 공용 사본 drift, 이벤트 스키마 계약,
대상 선택 경계값 계약, Compose 환경변수 중복, 릴리스 매니페스트 검증.
