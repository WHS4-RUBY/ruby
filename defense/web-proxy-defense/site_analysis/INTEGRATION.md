# site_analysis를 현재 프로젝트에 붙이는 방법

이 문서는 원본 웹 분석기(`site_analysis`)가 현재 RUBY 구성의 어디에 놓이는지와 연결 방법을 정리한다. 팀 코드의 근거는 팀 `main` 251ef4f8(`251ef4f81272141c03ad634f5decf70997fe8ebc`, 환경 리팩터링 PR #48의 병합 커밋)의 `경로:행`이고, 분석기 파일(`console.py`, `model.py` 등)의 행 번호는 이 PR이 추가하는 파일 기준이다. 실제 서버 배포 상태는 미확인이다. 환경 리팩터링 병합의 내용과 지금의 연결 방법은 6절에 있다.

## 1. 현재 요청 경로

요청 흐름, 헤더 계약, 대상 선택 파일의 정본 설명은 루트 `INTEGRATION.md`의 "요청 흐름"(9-22행), "헤더 계약"(24-80행), "대상 선택 파일"(82-92행) 절이다. 아래 그림과 표는 분석기의 위치(2절)를 판단하는 데 쓴 코드 근거다.

```text
클라이언트 -> 공개 :80 -> Detection :8081       탐지, 정책 선택, X-Defense-Plan 작성
                -> Defense :8080                 경로 별칭(1단계), 공식 전략, 전달 경로 선택
                     -> 대상별 CHeaT sidecar :3012 -> 보호 대상
                     -> 대상별 계정 오버레이 :8080 -> 보호 대상(고위험 격리는 전달하지 않음)
                     -> 보호 대상(sidecar가 없는 대상 ID)
관리자 -> SSH 터널 -> 127.0.0.1:8088 -> Detection 관리 리스너 :8080(대상 선택, 두 대시보드)
```

| 구간 | 코드 근거 |
| --- | --- |
| 공개 포트와 관리 포트 | `docker-compose.yml:8-10`. 리스너별 경로 제한은 `detection/server.js:176`과 `detection/lib/listenerBoundary.js:16-30`, 관리 리스너 기동은 `detection/server.js:1623-1625` |
| 공통 환경변수 | Detection과 Defense의 공통 환경변수는 `docker-compose.common.yml`의 `detection-base`(11-57행)와 `defense-base`(59-91행)에 있고, `docker-compose.yml`이 `extends`로 가져온다(같은 파일 `11-13, 48-50`) |
| 대상 목록과 선택 | Detection과 Defense가 같은 `TARGET_CHOICES`를 읽는다(`docker-compose.common.yml:14, 63`). 대상 ID는 기동할 때 형식 검사를 받는다(`detection/lib/targetSelection.js:12, 30`, `defense/app/target_selection.py:22, 108-110`). Detection의 선택 저장소는 `detection/server.js:163-171`, 관리 API는 `detection/lib/targetSelectionRoutes.js:8, 13`. 선택 파일은 `detection-data` 볼륨으로 공유하고 Defense는 읽기만 한다(`docker-compose.common.yml:16, 65`, `docker-compose.yml:28, 66`) |
| 정책 선택 | `detection/server.js:1403-1423`이 이전 완료 요청의 점수로 규칙을 고르고 대상 ID와 실행 ID 헤더를 붙인다. 규칙 선택은 `detection/lib/policyEngine.js:110-117`, `X-Defense-Plan` 작성은 같은 파일 `123-133`. 규칙 값은 `detection/config/policy.json` |
| Detection에서 Defense로 | `TARGET_URL=http://defense:8080`(`docker-compose.common.yml:13`), `detection/server.js:90, 1600-1601` |
| Defense 입구 | `defense/app/main.py:920-924`. 대상 ID는 허용 목록 안에서만 해석한다(`main.py:927`, `defense/app/target_selection.py:164-175`). 계획 읽기는 `main.py:939` |
| 경로 별칭 1단계 | `main.py:942-962`. 기본 모드는 `off`(`docker-compose.common.yml:66`, 운영 Compose는 이 값을 덮어쓰지 않는다), 경로 파일은 같은 파일 `70` |
| 오버레이와 공식 전략 | 오버레이 경로 결정은 `main.py:1038`(`_overlay_route`는 `283`), 공식 전략 실행은 `main.py:1050` |
| sidecar 또는 대상 | 대상 ID별 주소표는 `docker-compose.yml:53-54`와 `main.py:43-48`. 오버레이가 아니면 sidecar 주소를 쓴다(`main.py:1081`). 전달 주소는 `1113`, 전송은 `1134` |
| 보호 대상 | sidecar의 `REAL_BACKEND`(`docker-compose.yml:87, 108`), 오버레이의 `OVERLAY_ORIGIN_URL`(같은 파일 `137, 163`). 보호 대상 컨테이너는 이 Compose 파일에 정의되어 있지 않다 |

## 2. 분석기의 위치

- 분석기는 1절의 요청 경로 밖에 있다. 대상을 보호하기 전에 한 번 실행하는 준비 단계다.
- 실시간 트래픽을 받지 않고, 공격이 진행되는 동안 실행되지 않으며, 서비스 포트를 열지 않는다. 로컬 콘솔도 `127.0.0.1`의 빈 포트에만 바인딩한다(`console.py:1656, 1661`).
- 결과는 파일로 넘긴다. 공개 기록은 `<저장소>/.tmp/site-analysis/<이름>.json`이고, 관찰 원자료와 진행 상태는 저장소 밖 비공개 체크포인트에 있다(`OUTPUTS.md` 1.1).
- 현재 소비자는 격리 미끼 웹 방어(`defense/web-proxy-defense`)의 미끼웹 생성 단계 하나다. 그 코드(`decoy_build`)는 이 PR에 없다.
- 계정 오버레이, CHeaT, 경로 별칭은 출력을 사람이 검토한 설정 입력 자료로 쓸 수 있다. 모듈별 칸과 방법은 `OUTPUTS.md` 2절에 있다. 탐지와 정책에는 웹별 입력 통로가 없어 참고 사실표로만 쓸 수 있다(`OUTPUTS.md` 2.5).
- 분석 대상에는 공개 포트 80을 거치지 않고 접속한다. 80을 거치면 분석기 요청도 Detection 기록과 정책 적용을 받으며, 자동 브라우저가 미끼 응답을 받으면 원본 대신 방어 출력을 분석하게 된다. 251ef4f8에서는 원본의 실제 경로가 공용 미끼 카탈로그에서 Detection 신호 대상으로 지정된 경로(계정 오버레이 네임스페이스, CHeaT 미로 진입 경로)와 겹치면 그 요청이 `decoy_path_hit` 공격 신호로도 기록된다(`detection/lib/deceptionEngine.js:244-250`, `detection/lib/decoyPaths.js:16-24, 57-69`). 이 항목은 1절 경로와 코드에서 나온 판단이며 시험한 결과는 아니다. 대상 내부 주소에 닿지 않으면 그 대상만 전달하는 중계를 `SITE_ANALYSIS_PROXY`로 지정한다.
- `OUTPUTS.md` 1.5의 사용 가능한 결과는 로컬 복사본 웹 세 개(WordPress, Gitea, Redmine)다. `TARGET_CHOICES`의 두 대상(`juice-shop`, `ruby-shop`)의 분석 기록은 아직 없다.

## 3. 이 PR이 바꾸는 것과 바꾸지 않는 것

추가하는 것은 `defense/web-proxy-defense/site_analysis/` 하나다. 다음은 바꾸지 않는다.

- `docker-compose.yml`, `docker-compose.local.yml`, `docker-compose.common.yml`, 루트 `.env`와 `.env.example`
- `shared/`, `scripts/`, 루트 `INTEGRATION.md`
- `detection/`, `defense/app/`, `defense/config/`, `defense/tests/`, `defense/CHeat-defense-proxy/`, `defense/account-response-overlay/`
- `.github/workflows/`

빌드와 CI에도 들어가지 않는다. 다음은 251ef4f8에서 다시 확인한 근거다.

- Defense 이미지는 `app`과 `config`만 복사한다(`defense/Dockerfile:5-6`). `defense/.dockerignore`가 없어 `docker build ./defense`의 빌드 문맥에는 이 폴더가 포함되지만 이미지에는 들어가지 않는다. 배포 워크플로도 같은 문맥 `./defense`로 Defense 이미지를 만든다(`.github/workflows/deploy.yml:29-30`).
- CI의 defense 단위 시험은 `defense/tests`만 탐색한다(`.github/workflows/ci.yml:67`). 병합으로 추가된 defense 시험 6개(`test_compose_env.py`, `test_decoy_catalog_contract.py`, `test_event_schema.py`, `test_shared_sources.py`, `test_store.py`, `test_target_selection_contract.py`)는 정해진 파일만 읽는다. 251ef4f8 전체에서 `web-proxy-defense`나 `site_analysis`를 가리키는 코드, 설정, 문서는 없다.
- 공유 원본의 사본 목록(`scripts/sync-shared.sh:16-23`)에도 이 폴더는 없다.

분석기의 환경 가정은 다음이 전부다.

| 가정 | 내용과 근거 |
| --- | --- |
| Python과 브라우저 | Python 3.13 이상(`console.py:457`, `run-console.cmd:8-9`), Playwright와 Chromium. Defense 이미지(`python:3.12-slim`, `defense/Dockerfile:1`)와 CI(3.12, `.github/workflows/ci.yml:57`)의 Python 판과 다르다 |
| 제공자 CLI | 로그인된 `codex`(기본) 또는 `claude` CLI를 PATH에서 찾는다(`model.py:295-299`). API 키를 직접 받지 않는다 |
| 단가 파일 | `--rates`가 없으면 분석이 시작 전에 멈춘다(`model.py:55`). `rates.example.json`을 복사해 채운다 |
| 공개 기록 위치 | `<저장소>/.tmp/` 아래(`record.py:15`, `console.py:38`). `.tmp/`는 `.gitignore:48` 대상이다 |
| 비공개 상태 위치 | `LOCALAPPDATA/ruby-site-analysis/`(`resume.py:85-90`). 값이 없으면 macOS는 `~/Library/Application Support`, 그 밖은 `~/.local/state`를 쓴다. 저장소 안 경로는 거부한다(`resume.py:94-96`). 세션 파일 준비는 `LOCALAPPDATA`가 반드시 있어야 한다(`session_prepare.py:16-18`) |
| 패키지 깊이 | `record.py:14`의 `ROOT = PACKAGE.parents[2]`가 저장소 루트를 가리킨다. 폴더를 다른 깊이로 옮기면 `ROOT`와 `.tmp` 위치가 바뀐다. 명령은 `defense/web-proxy-defense`에서 `python -m site_analysis.<명령>`으로 실행한다(`console.py:37`) |
| 중계(선택) | `SITE_ANALYSIS_PROXY`가 있으면 브라우저 요청과 HTTP 대체 관찰 요청을 그 중계로 보낸다(`observer.py:863, 931`). 콘솔은 http, https, socks5 주소만 받는다(`console.py:338`) |

Docker는 필요하지 않다.

## 4. 연결 제안

세 단계 모두 선택 사항이다. (b)와 (c)는 환경 담당과 정한다. 환경 리팩터링(PR #48)은 `main`에 병합됐고, 병합된 구조에서 확인한 제약과 연결 방법은 6.3절과 6.4절에 있다.

**(a) 지금: 로컬 실행**

- 콘솔(`python -B -m site_analysis.console`) 또는 CLI(`python -B -m site_analysis.analyze ...`)로 실행한다. 준비물과 명령은 `README.md`의 "준비"와 "실행" 절에 있다.
- 대상은 원본 URL이거나, 중계 뒤에 둔 미끼 복사본이다.
- 환경 파일을 바꾸지 않는다. 결과는 실행한 PC의 `.tmp/`와 `LOCALAPPDATA`에만 남는다.

**(b) 다음: 일회성 도구 단계**

- 대상을 `TARGET_CHOICES`에 등록한 뒤 한 번 실행하는 도구 서비스나 설정 스크립트 단계로 둔다.
- 마운트할 것: 제공자 CLI 로그인 폴더(호스트에서 읽기 전용), 단가 파일(읽기 전용), 출력 폴더(`<저장소>/.tmp/site-analysis`), 비공개 상태 폴더(`LOCALAPPDATA`를 저장소 밖 절대 경로로 지정).
- 포트를 열지 않는다. Detection, Defense, sidecar, 오버레이의 설정과 `depends_on`에 넣지 않으므로 요청 경로는 그대로다. `docker compose up`의 기본 기동 대상에서도 뺀다(예: `profiles: ["tools"]` 또는 별도 Compose 파일). 공통 파일 `docker-compose.common.yml`에는 둘 수 없다(6.3절).
- Python 3.13과 Chromium이 필요해 Defense 이미지를 그대로 쓸 수 없고 별도 이미지가 필요하다.
- 제공자 로그인 파일은 이미지에 넣지 않고 마운트만 한다. 저장소는 공개 상태이며 `.gitignore`는 `auth.json`과 `.codex/`를 제외한다(`.gitignore:15-16`).
- 이 폴더의 보고서에 컨테이너 안 실행 기록은 없다.

**(c) 나중: 검토된 설정 초안 단계**

- 분석 출력을 모듈 설정 초안으로 옮긴다. 대상은 계정 오버레이의 사이트 프로필 TOML(`defense/account-response-overlay/config/`, 키 목록은 `defense/README.md:140-149`), CHeaT `TARGET_PROFILE`(현재 Compose는 `TARGET_PRESET`만 지정, `docker-compose.yml:88, 109`), 경로 별칭 경로 파일(`defense/config/*-routes.json`)이다.
- 초안은 운영자가 검토하고 승인한 뒤에만 적용한다. 자동 적용은 하지 않는다.
- 실제 경로, 쿠키 이름, 선택자가 필요한 칸은 비공개 내보내기 도구가 먼저 있어야 한다. 초안 생성기와 내보내기 도구는 아직 없다(`OUTPUTS.md` 3절).
- 각 모듈이 초안을 받아 쓸지는 그 모듈 담당이 정한다.

## 5. 환경 담당에게 확인할 것

1. 병합된 구조에서 배포 전에 한 번 도는 단계(대상 등록 뒤 분석)를 어디에 두는가. 설정 스크립트, 별도 Compose 파일, CI 수동 작업 중 어느 쪽인가.
2. 루트 Compose에 기본 기동되지 않는 도구 프로필(`profiles: ["tools"]`)을 두어도 되는가. 251ef4f8의 루트 Compose 세 파일에는 `profiles` 항목이 없다. 저장소 안의 선례는 오버레이 배포 Compose의 `init-security` 서비스다(`defense/account-response-overlay/deploy/compose.yaml:16-23`).
3. 대상별 파일(분석 기록, 사이트 프로필과 오버레이 TOML, CHeaT 프로필, 경로 파일)을 어디에 모으는가. 지금은 분석 기록이 실행한 PC의 `.tmp/`, 사이트 프로필과 오버레이 TOML이 `defense/account-response-overlay/config/`, 경로 파일이 `defense/config/`, CHeaT 설정이 Compose 환경변수에 있다.
4. 분석 기록 이름을 `TARGET_CHOICES`의 대상 ID에 맞추는가(예: `.tmp/site-analysis/juice-shop.json`). 대상 ID 형식은 정해졌다(6.3절). 같은 대상의 판이 바뀌면 기록을 어떻게 구분하는가.
5. 분석기가 공개 포트 80을 거치지 않고 대상 내부 주소에 닿는 네트워크를 병합된 구조에서도 쓸 수 있는가.

## 6. 환경 리팩터링(PR #48) 병합 뒤의 상태

이 절은 팀 `main` 251ef4f8의 파일과 GitHub의 PR, CI 기록을 읽은 결과다. 이 구성을 기동하거나 팀 시험을 실행하지 않았다.

### 6.1 병합 기록

| 항목 | 내용 |
| --- | --- |
| PR | 팀 저장소 `WHS4-RUBY/ruby`의 PR #48. 환경 담당의 리팩터링이며 브랜치는 `refactor/inventory-phase1`이다 |
| 병합 | 2026-10-11 05:41 KST(2026-10-10T20:41:14Z)에 squash 병합됐다. 병합 커밋은 `251ef4f81272141c03ad634f5decf70997fe8ebc`이고 부모는 이전 `main` e8e0ab8e다 |
| 변경 규모 | 파일 112개, 추가 6,914줄, 삭제 863줄 |
| CI와 배포 | 병합 커밋의 push CI 실행(`38084715165`)은 다섯 작업(`detection-check`, `python-check (defense)`, `decoy-check`, `overlay-check`, `integration-check`)이 모두 성공했다. 뒤이은 Deploy 실행(`38085133309`)은 이미지 네 개의 빌드와 push가 성공하고 `deploy` 작업이 실패했다. 실패 원인은 읽지 않았고 실제 서버 배포 상태는 미확인이다 |

### 6.2 이 PR과 겹치는 파일

- 변경 파일 112개 중 `defense/web-proxy-defense/` 아래 파일은 없다. 이 PR과 공유하는 파일이 없고, 이 PR의 기준 커밋은 251ef4f8이다.
- `defense/Dockerfile`과 `.gitignore`는 바뀌지 않았고 `defense/.dockerignore`도 추가되지 않았다. `ci.yml:67`의 defense 단위 시험 명령도 같다. 3절의 "빌드와 CI에 들어가지 않는다"는 판단은 251ef4f8에서도 같다.
- 루트 `INTEGRATION.md`, `README.md`, `defense/README.md`, `docs/refactor-summary.md`, `docs/refactor-inventory.md`, Compose 파일 세 개, `.env.example`에는 이 분석기나 `defense/web-proxy-defense`가 나오지 않는다.

### 6.3 분석기와 관련된 변경

| 변경 | 251ef4f8의 내용 | 분석기에 주는 의미 |
| --- | --- | --- |
| 루트 `INTEGRATION.md`(신규) | Detection, Defense, CHeaT sidecar, 계정 오버레이 사이의 요청 흐름(9-22행), 헤더 계약(24-80행), 대상 선택 파일(82-92행), 이벤트 필드명(94-112행), 공유 설정(114-130행), 신뢰 경계(132-143행)를 적는다 | 분석기는 이 흐름 밖에 있어 헤더 계약의 당사자가 아니다. 이 문서 1절의 요청 경로와 대상 선택 설명은 루트 문서가 정본이다 |
| `shared/target-selection.json`(신규, 사본 없이 선언만) | 대상 선택 파일의 소유자를 Detection으로 정하고(4행) writer와 reader를 적는다(15-21행). 경계값은 대상 ID 형식 `^[a-z][a-z0-9-]{0,31}$`, `runId` 정규 UUID, `changedAt` ISO 시각, 8192바이트 상한이다(22-27행). `defense/tests/test_target_selection_contract.py:39-74`가 두 구현과의 일치를 강제한다 | 대상 ID의 정본 형식이다. 대상 ID 목록은 이 파일에 없고 `TARGET_CHOICES` 환경변수에 있다(`docker-compose.common.yml:14, 63`, 예시는 `.env.example:14, 18`). 이 형식이 아닌 ID가 있으면 Detection과 Defense가 기동하지 않는다(`detection/lib/targetSelection.js:30`, `defense/app/target_selection.py:108-110`). 콘솔의 기록 이름 규칙(`console.py:48`의 `NAME`)은 이 형식의 ID를 받는다. 다만 Windows에서는 `con`, `nul`, `com1` 같은 예약 이름을 거부하므로(`console.py:303-304`), 이런 ID는 형식에 맞아도 기록 이름으로 쓸 수 없다 |
| `shared/event-schema.json`(신규) | 미끼 적중, 차단, 전략 적용 이벤트의 정본 필드 9개(10-20행)와 저장소별 별칭(21행부터)을 선언한다. 사본은 `detection/config/event-schema.json`이고 `defense/tests/test_event_schema.py`가 선언과 구현의 일치를 강제한다 | 분석기는 요청 이벤트를 기록하지 않아 직접 관계가 없다 |
| `docker-compose.common.yml`(신규) | 두 Compose가 함께 쓰는 Detection, Defense 환경변수를 `detection-base`(11-57행), `defense-base`(59-91행)로 모으고 `docker-compose.yml`과 `docker-compose.local.yml`이 `extends`로 가져온다. 이 파일에는 `image`와 `build`가 없다(5행). `defense/tests/test_compose_env.py:54-57`이 공통 파일에 `image:`, `build:`가 없는지, 같은 파일 `67-74`가 두 Compose의 detection, defense 서비스에 같은 값이 중복되지 않는지 검사한다 | 이미지가 필요한 분석기 도구 서비스는 공통 파일에 둘 수 없다. 루트 Compose 세 파일에는 `profiles` 항목이 없다 |
| 통합 저장소 | 컨테이너마다 자기 SQLite 파일을 쓰고 `schema_migrations(component, version, applied_at)`로 스키마를 관리한다(`defense/README.md:157-176`). 공용 접근 계층의 원본은 `shared/py/store.py`이고 Defense, 오버레이, CHeaT에 사본을 둔다(`scripts/sync-shared.sh:19-21`). Detection은 `detection.sqlite3`를 쓴다(`docker-compose.common.yml:22`) | 분석기 코드는 SQLite를 쓰지 않는다. 상태는 `LOCALAPPDATA` 아래 체크포인트와 `.tmp/` 아래 JSON 기록이라 통합 대상이 아니다. 도구 서비스로 두어도 저장소 볼륨을 마운트할 필요가 없다 |
| 공용 미끼 카탈로그와 사이트 프로필의 `decoy_namespaces` | 미끼 네임스페이스, 진입 경로, 단서 헤더는 `shared/decoy-catalog.json`에 두고 Detection과 오버레이에 사본을 둔다(`scripts/sync-shared.sh:17-18`). 사이트 프로필에 `decoy_namespaces` 키가 생겼다(`defense/account-response-overlay/defense/site_profile.py:32`). 생략하면 카탈로그 값을 쓰고, 로드할 때 `robots_disallow`는 선언한 네임스페이스 안이어야 하며 `login_paths`는 네임스페이스와 겹칠 수 없다(같은 파일 `51-58`). 새 사이트는 `site-generic-example.toml`을 복사한 사이트 프로필 하나로 붙인다(`defense/README.md:138-151`). 같은 README는 이 절차의 범위가 Defense까지이고 Detection의 비즈니스 로직 탐지 7개 모듈은 Juice Shop에 묶여 있다고 적는다(`defense/README.md:155`) | `OUTPUTS.md` 2.2의 사이트 프로필 키 표와 행 번호를 251ef4f8 기준으로 다시 맞췄다. 요청 경로의 미끼 판별(`defense/account-response-overlay/defense/overlay.py:263`)과 Detection의 `decoy_path_hit` 신호(`detection/lib/decoyPaths.js:57-69`)는 카탈로그 값을 쓴다. 원본의 실제 경로가 그 네임스페이스와 겹치는지는 분석기의 path_groups 축으로 점검할 수 있다(`OUTPUTS.md` 2.2) |

### 6.4 지금의 연결 방법

1. 이 PR은 251ef4f8 위에 있다. 겹치는 경로가 없어 병합으로 바뀐 팀 파일은 이 PR에 들어가지 않는다.
2. 분석 기록 이름은 `TARGET_CHOICES`의 대상 ID로 정한다(예: `.tmp/site-analysis/juice-shop.json`, `.tmp/site-analysis/ruby-shop.json`). 새 대상의 ID는 `shared/target-selection.json`의 `idPattern`(23행)을 따른다. Detection과 Defense는 이 형식이 아닌 ID로 기동하지 않으므로, Windows 예약 이름을 뺀 운영 대상 ID는 그대로 기록 이름으로 쓸 수 있다. 같은 대상의 판을 구분하는 방법은 5절 4번 질문으로 남는다.
3. 도구 서비스를 둔다면 위치는 환경 담당이 정한다. 251ef4f8에서 확인한 제약은 공통 파일 `docker-compose.common.yml`에 `image`와 `build`를 둘 수 없다는 것이다(`defense/tests/test_compose_env.py:54-57`). 4절 (b)의 조건(포트를 열지 않음, 요청 경로 서비스의 `depends_on`에 넣지 않음, 기본 기동에서 뺌)은 그대로 둔다.
4. 제공자 CLI 로그인 파일은 호스트에서 읽기 전용으로 마운트만 하고 이미지에 넣지 않는다. 저장소는 공개 상태이고 `.gitignore:15-16`이 `auth.json`과 `.codex/`를 제외한다.
5. 요청 흐름, 헤더 계약, 대상 선택 파일, 공유 설정은 루트 `INTEGRATION.md`를 따른다. 이 문서는 분석기의 위치와 환경 가정(2절, 3절), 연결 제안(4절)만 정본으로 둔다. 1절의 표는 그 판단에 쓴 251ef4f8 기준 코드 근거다.
6. 5절의 질문은 251ef4f8에서도 열려 있다. 대상 ID 형식은 정해졌지만(5절 4번의 일부), 분석 단계의 위치, 도구 프로필 허용, 대상별 파일 위치, 대상 내부 주소에 닿는 네트워크는 6.2절의 문서에서 찾지 못했다.
