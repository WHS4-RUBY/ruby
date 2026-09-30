# 경로 별칭 구현 기획 v1 (별칭 기법 2b단계)

> 작성: 심형섭 · 2026-09-30
> 상태: Defense 구현, 단위·통합 테스트, 로컬 Docker 검증(브라우저 오탐·고정 공격·회전) 완료. **에이전트 공격 실험은 미실행.**
> 이전 단계: [토큰 게이트 기획 v2.1](token-gate-plan.md) (1단계, 현재 관찰 전용)

---

## 1. 배경과 목표

### 1.1 처음 아이디어

LLM 공격 에이전트가 기억해 둔 주소로 바로 접근하지 못하도록, 주소(별칭)를 주기마다 바꿔서 공급한다.

### 1.2 토큰 게이트만으로 부족했던 이유

- 토큰은 "누가 보냈나"만 본다. 외워 둔 주소는 그대로 통한다.
- enforce 실험에서 `Accept: text/html`만 붙여 쿠키를 받으면 SQL 주입까지 성공했다 ([진행 기록](token-gate-docker-progress.md) 2026-09-30 후속 결과).
- codex는 페이지를 보지 않고 **알려진 API 14개를 한 번에 직접 호출**했다 (토큰 게이트 기획 1.3).

경로 별칭은 **외워 둔 주소 자체를 무효화**한다. 정상 브라우저는 Defense가 바꿔 쓴 화면 코드만 받기 때문에 원래 주소를 보낼 이유가 없다. 그래서 원래 주소로 온 요청은 "화면을 거치지 않고 경로를 알고 있었다"는 강한 신호가 된다.

### 1.3 이 기법이 증명하는 것과 증명하지 못하는 것

- 막는 것: 사전 지식·공개 문서·이전 세션에서 **외워 둔 경로로 바로 호출**하는 행동
- 막지 못하는 것: 페이지와 JS를 읽고 **현재 별칭을 알아내는** 에이전트. 이 경우 기법의 효과는 차단이 아니라 **재탐색 강요**(주기마다 다시 읽어야 함)와 탐지 신호다.
- 브라우저를 조종하는 에이전트(Playwright 등)는 정상 사용자와 구분하지 못한다.

---

## 2. 동작 설계

### 2.1 확정한 결정 (2026-09-30)

| 항목 | 결정 | 이유 |
|---|---|---|
| 별칭 단위 | **접두사 단위** (`/rest/` → `/pxxxxxxxxxx/`) | 경로마다 바꾸면 치환 누락과 앱 파손 위험이 커진다 |
| 적용 범위 | **모든 클라이언트 공통** | 클라이언트별 별칭은 다음 단계 |
| enforce 응답 | **404** `{"error":"not_found"}` | 미끼 응답은 다음 단계 |
| 주기 | **10분, 유예 1주기** | 짧으면 캐시·오래 켜 둔 탭이 깨진다 |

### 2.2 별칭

- 보호 접두사: 기본 `/rest/`, `/api/` (`PATH_ALIAS_PREFIXES`)
- 별칭 = `"/p" + base32(HMAC-SHA256(SECRET, "alias|<epoch>|<prefix>"))[:10] + "/"`, 소문자
- `epoch = floor(now / EPOCH_S)`. 서버에 상태를 저장하지 않는다.
- 접두사마다 다른 별칭이므로 별칭만 보고 원래 접두사를 알 수 없다.

### 2.3 요청 판정

| 요청 경로 | 분류 | observe | enforce |
|---|---|---|---|
| 현재·유예 주기 별칭 | `alias` | 원래 경로로 변환해 전달 | 같음 |
| 유예보다 오래된 별칭 (최근 12주기까지) | `stale` | 변환해 전달 + `would_block` 기록 | **404**, 백엔드 미전달 |
| 원래 경로 (`/rest/...`, `/api/...`) | `direct` | 그대로 전달 + `would_block` 기록 | **404**, 백엔드 미전달 |
| 그 밖 | `other` | 그대로 전달 | 같음 |

**원래 경로 판별은 Express 라우팅과 같게 정규화한다.** 로컬 Juice Shop에서 `/REST/`, `/Rest/Products/Search`, `//rest/`가 모두 같은 API로 응답하는 것을 확인했다. 그래서 대소문자, 연속 슬래시, `.`·`..` 세그먼트를 정규화한 뒤 비교한다.

### 2.4 응답 바꿔 쓰기

- 대상: `text/html`, JavaScript, JSON(`+json` 포함), 압축 없음, `HEAD`·204·304 제외
- 방법: 본문에서 보호 접두사를 현재 별칭으로 치환한다 (대소문자 무시, 원래 경로 판별과 일관되게).
  - 호스트나 다른 세그먼트에 붙은 접두사(`example.com/api/`, `/foo/rest/`)는 다른 URL이므로 바꾸지 않는다.
  - 상대 경로 `./rest/`와 템플릿 `` `${host}/rest/` ``는 바꾼다. Juice Shop의 `hostServer`는 `"."`이다.
- `Location` 헤더: 같은 호스트이거나 상대 경로일 때 바꾼다.
- 바꾼 응답은 `ETag`·`Last-Modified`를 지우고 `Cache-Control: no-store`로 설정한다. 바꾼 곳이 없으면 원래 헤더를 유지한다.
- 별칭이 켜져 있으면 백엔드로 보내는 `If-None-Match`·`If-Modified-Since`를 제거한다. 그래야 기법을 켜기 전에 캐시한 JS가 304로 재사용되지 않는다.
- 본문이 `PATH_ALIAS_MAX_REWRITE_BYTES`(기본 8 MiB)를 넘으면 바꾸지 않고 그대로 전달하며 `rewrite_skipped: "too_large"`를 기록한다.
- 나머지 응답은 기존 스트리밍 전달을 그대로 쓴다.

### 2.5 로그

`ruby.defense.path_alias` logger, 요청당 JSON 한 줄. `other`이면서 바꾼 곳이 없는 요청은 기록하지 않는다.

```json
{"event":"path_alias","ts":1790000000.0,"mode":"enforce","client_id":"abc","method":"GET","path":"/rest/products/search","real_path":"/rest/products/search","kind":"direct","alias_state":null,"decision":"block","upstream_status":null,"rewrites":0,"rewrite_skipped":null,"ua_family":"curl"}
```

- `decision`: `pass` / `translate` / `would_block` / `block`
- 쿼리 문자열, 요청 본문, 쿠키는 기록하지 않는다.
- 대시보드 이벤트 경로는 변환한 원래 경로로 기록한다 (주기마다 경로가 쪼개지지 않게). 적용 전략 이름은 `path_alias`.

### 2.6 설정

| 변수 | 기본값 | 유효 범위 |
|---|---|---|
| `PATH_ALIAS_MODE` | `off` | `off` / `observe` / `enforce`. 그 밖의 값이면 시작 실패 |
| `PATH_ALIAS_SECRET` | 빈 값 | 비면 무작위 생성 + 경고. **실험할 때는 고정값 필수** |
| `PATH_ALIAS_EPOCH_S` | `600` | 1 이상 |
| `PATH_ALIAS_GRACE_EPOCHS` | `1` | 0~10 |
| `PATH_ALIAS_PREFIXES` | `/rest/,/api/` | `/이름/` 형식, 쉼표 구분 |
| `PATH_ALIAS_MAX_REWRITE_BYTES` | `8388608` | 1 이상 |

`off`는 `PATH_ALIAS_MODE`만 읽고 나머지는 읽지도 검증하지도 않는다. 동작은 기존과 완전히 같다.

---

## 3. 코드

- `defense/app/path_alias.py` (새 파일): 설정, 별칭 계산, 판정, 본문·`Location` 치환, 로그
- `defense/app/main.py`: `catch_all` 앞에서 판정·변환·차단, 뒤에서 `alias_proxy_response`로 응답 치환. 팀원의 `streaming_proxy_response`는 본문 iterator를 선택 인자로 받도록만 바꿨다.
- `defense/tests/test_path_alias.py` (새 파일): 29개
- `docker-compose.local.yml`, `.env.example`: defense 환경변수 추가 (기본 `off`)

---

## 4. 검증 결과 (2026-09-30, 로컬 Docker)

조건: Detection → Defense → Juice Shop 20.2.0. **CRS는 `observe`로 고정**해서 CRS 차단이 결과에 섞이지 않게 했다. 비밀키는 고정값.

**단위·통합 테스트**: `python -m unittest discover -s defense/tests -p 'test_*.py'` 기준 새 테스트 29개 통과. 기존 defense 테스트도 통과. 단, `test_monitoring`의 기존 실패 1개는 이번 변경과 무관하며 원본 `main`에서도 실패한다.

**응답 치환**: `main.js`의 `/rest/` 42곳, `/api/` 15곳 중 53곳이 바뀌었다. 남은 4곳은 Detection의 `deceptionEngine.js`가 Defense 다음 단계에서 주석으로 넣는 미끼 경로다(`/rest/internal/...`). 주석이라 브라우저는 호출하지 않고, 에이전트가 따라가면 `direct`로 잡힌다.

**정상 브라우저 (Chromium headless, `scripts/browser_inspection_regression.cjs` 5단계)**

| 모드 | 5단계 | 페이지 오류 | 4xx/5xx | 브라우저의 원래 경로 접근 |
|---|---|---|---|---|
| observe | 5/5 | 0 | 0 | **0건** (별칭 변환 31건) |
| enforce | 5/5 | 0 | 0 | — |

**외워 둔 주소 직접 호출 (enforce)**: `/rest/products/search`, `/api/Products`, `/rest/user/whoami`, `/api/Challenges`, `/rest/admin/application-version`, `/REST/...`, `//rest/...`, `/./api/...` 8건 모두 404. 페이지 JS에서 읽은 현재 별칭으로는 200.

**회전**: 주기 10초·유예 1로 띄워, 발급 직후 200이던 별칭이 32초 뒤 404가 되고 새 별칭은 200인 것을 확인했다 (4.1 참고).

### 4.1 회전 확인 원시 결과

```text
PATH_ALIAS_MODE=enforce PATH_ALIAS_EPOCH_S=10 PATH_ALIAS_GRACE_EPOCHS=1 CRS_MODE=observe
t=0   old alias /pynmm4x3loj/ -> 200
t=32s old alias /pynmm4x3loj/ -> 404   (log: kind=stale alias_state=stale decision=block)
t=32s new alias /pmteepwot37/ -> 200
```

---

## 5. 실험 설계 (다음에 할 일)

**이번에는 별칭 설정만 바꾼다.** CRS·토큰 게이트·delay·rate limit 설정은 모든 조건에서 같게 고정한다. CRS는 `observe`로 둔다.

| 조건 | `PATH_ALIAS_MODE` |
|---|---|
| 기준 | `off` |
| 관찰 | `observe` |
| 적용 | `enforce` |

**공격자**
1. 고정 스크립트: 외워 둔 경로 목록을 바로 호출 (결정적 기준선)
2. LLM 에이전트: 같은 프롬프트, 같은 요청 상한. 이전 Codex 실행은 서비스가 요청을 거절해서 결과가 없었다 (진행 기록). **실험 전에 공격자 확보가 선결 과제다.**

**지표**
- `direct` 요청 수와 비율 (외워 둔 경로에 얼마나 의존하는가)
- 첫 번째 성공한 API 호출까지 걸린 요청 수와 시간
- 404를 받은 뒤 적응하는가, 어떻게 적응하는가 (JS 읽기 / 포기 / 무차별 시도)
- 풀린 챌린지 수, 토큰 사용량
- 정상 브라우저 오탐: 0건이 기준

**한계 시나리오 (관찰·기록 대상)**
- 20분 넘게 열어 둔 탭: 화면 코드에 박힌 별칭이 만료되면 enforce에서 API가 404가 된다. 새로고침하면 복구되는지 기록한다.
- 서비스워커 캐시 복원 (Juice Shop 사용 여부 미확인)
- socket.io는 보호 접두사가 아니므로 영향 없음

---

## 6. 알려진 한계

- **JS를 읽는 에이전트는 현재 별칭을 알아낸다** (1.3).
- **오래 열어 둔 탭**: 별칭 수명은 로드 후 최소 `EPOCH_S × GRACE`, 최대 `EPOCH_S × (GRACE+1)`. 기본값에서 10~20분.
- **동적으로 조합한 경로**(`"re" + "st/"` 등)나 JSON의 `\/rest\/` 이스케이프는 치환하지 못한다. 이런 앱은 브라우저 오탐 검사에서 드러난다.
- **절대 URL**(`http://host:port/rest/`)은 호스트가 붙어 있어 치환하지 않는다. Juice Shop은 해당 없음.
- **Detection은 별칭 경로를 본다.** Detection의 경로 기반 점수·스키마 학습이 주기마다 쪼개질 수 있다. 영향을 기록하고 필요하면 탐지팀과 협의한다.
- 별칭이 모두에게 같으므로 에이전트끼리 공유할 수 있다.
- 압축 응답, 8 MiB 초과 본문은 치환하지 않는다.
- WebSocket은 대상이 아니다.

## 7. 다음 단계 (이번 범위 아님)

- 클라이언트별 별칭 (`dcid`에 묶기) → 공유 방지
- enforce에서 404 대신 미끼 응답 (CHeat의 DECOY_MAZE와 결합)
- `direct`·`stale` 신호를 Detection으로 전달 (3단계, 탐지팀과 PR로 협의)
- 경로 단위 별칭
