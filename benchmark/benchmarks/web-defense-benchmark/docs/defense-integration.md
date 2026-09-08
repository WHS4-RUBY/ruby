# 방어 모듈 연결 안내

RUBY 벤치마크는 방어 구현을 import하지 않고 등록 파일과 inline HTTP 계약으로 연결합니다. 현재 실행 계층이 지원하는 프로필은 `inline-http`입니다. 기능 매니페스트에 다른 프로필을 선언할 수는 있지만 대응 실행기가 생기기 전까지는 선택할 수 없습니다.

## 1. 요청 경로

```text
공격자 또는 정상 사용자
        |
RUBY 공통 게이트웨이와 계측기
        |---- /v2/decision ----> 방어 어댑터
        |<--- 방어 행동 --------|
        |
취약 웹 또는 원본 취약 제품
```

`proxy-only`도 같은 RUBY 게이트웨이를 사용합니다. 이 조건에서는 방어 판단 호출만 생략하므로 공통 프록시 비용을 방어 효과와 분리할 수 있습니다.

방어 어댑터는 [`../contracts/defense-adapter.openapi.yaml`](../contracts/defense-adapter.openapi.yaml)의 다음 API를 구현해야 합니다.

| API | 호출 시점 |
| --- | --- |
| `GET /v2/health` | 시작 후 방어 ID, 버전과 매니페스트 digest 확인 |
| `POST /v2/reset` | 매 시험 직전 상태 초기화 |
| `POST /v2/decision` | 각 요청과 응답 단계 판정 |
| `GET /v2/metrics` | 실행 중 시간 보정과 종료 결과 수집 |

결정 행동은 `pass`, `block`, `delay`, `rewrite-request`, `replace-response`, `route-decoy`, `terminate-session`입니다. 연결 계층은 단계에 맞지 않는 행동, 등록되지 않은 미끼, 다른 origin으로의 요청 변경과 잘못된 Base64 본문을 거부합니다.

## 2. 현재 등록 조건 확인

### Windows PowerShell

```powershell
.\scripts\defense.ps1 list
.\scripts\defense.ps1 validate
```

### Linux 또는 macOS

```bash
./scripts/defense.sh list
./scripts/defense.sh validate
```

기본 등록부는 `app/configs/stage3a-defense-runtime-registry-v2.json`입니다. 다른 등록부를 시험하려면 PowerShell에서는 `-Registry`, Bash에서는 `RUBY_DEFENSE_REGISTRY`를 사용합니다. 등록부는 저장소 안에 있어야 하며 절대 경로, 상위 디렉터리 이탈과 예약 조건 이름 `undefended`, `proxy-only`는 거부됩니다.

## 3. 연결 방식

| 드라이버 | 용도 | 제한 |
| --- | --- | --- |
| `managed-container` | digest 고정 이미지 또는 로컬 소스가 고정된 개발 빌드 | CPU, 메모리, PID, 읽기 전용 파일 시스템과 네트워크 정책 필수 |
| `external-http` | 이미 실행 중인 어댑터의 로컬 개발과 호환성 검사 | `127.0.0.1` 또는 `localhost` 주소만 허용 |

격리 정책이 `isolated`인 관리형 방어는 인터넷 경로가 없는 내부 Docker 네트워크에만 연결됩니다. Docker Desktop은 내부망 컨테이너의 포트를 호스트에 직접 게시하지 않으므로 RUBY가 고정 목적의 제어 relay를 별도 컨테이너로 실행합니다. relay는 loopback 요청을 `defense-adapter`의 제어 포트로만 전달하며 대상, 평가기와 데이터베이스 주소를 받지 않습니다.

외부 모델 호출이 필요한 방어는 `internet-egress`를 명시하고 그 조건을 결과에 기록해야 합니다. 호스트 환경변수는 등록부의 `secret_env_names`에 적힌 이름만 컨테이너에 전달되며 값은 JSON 설정과 결과에 저장하지 않습니다.

## 4. 등록 파일

등록부는 [`../contracts/defense-runtime-registry.schema.json`](../contracts/defense-runtime-registry.schema.json)을 따릅니다.

| 필드 | 설명 |
| --- | --- |
| `condition_id` | `conditions` 객체의 키이며 캠페인 조건 이름 |
| `driver` | `managed-container` 또는 `external-http` |
| `path_scope` | 경로 기준을 벤치마크 또는 저장소 루트로 선택 |
| `manifest_path` | 방어 기능, 출처, 상태와 모델 사용을 기록한 매니페스트 |
| `lifecycle_path` | timeout, reset과 실패 결과를 기록한 계약 |
| `image`, `control_port` | 관리형 컨테이너 이미지와 제어 포트 |
| `endpoint` 또는 `endpoint_env` | loopback 외부 어댑터 주소 또는 그 주소가 든 환경변수 이름 |
| `resource_limits` | CPU, 메모리, PID와 tmpfs 상한 |
| `network_policy` | `isolated` 또는 `internet-egress` |
| `secret_env_names` | 방어 컨테이너에 전달해도 되는 환경변수 이름 |

공식 비교에 쓰는 사전 빌드 이미지는 `name@sha256:...` 형태로 고정해야 합니다. `build`를 쓰는 개발 조건은 `context`, `dockerfile`과 `source_files`를 모두 선언하며, 계산한 소스 digest가 기능 매니페스트와 다르면 시작하지 않습니다.

외부 방어는 `external-http` 드라이버와 `endpoint_env`를 등록하고 해당 환경변수에 loopback origin을 넣어 선택합니다. 미등록 방어 소스나 비밀 값은 기본 조건의 목록, 검증과 실행에 필요하지 않습니다.

## 5. 연결 smoke test

공통 게이트웨이, 어댑터 identity, reset, 정상 전달과 정리를 한 번에 검사합니다.

```powershell
.\scripts\defense.ps1 smoke -Condition proxy-only
.\scripts\defense.ps1 smoke -Condition static-guard `
  -RequestPath "/api/products?q=%27)%20or%20visibility%20=%20%27private%27%20--%20" `
  -ExpectedStatus 403
```

```bash
./scripts/defense.sh smoke --condition proxy-only
./scripts/defense.sh smoke --condition static-guard \
  --request-path "/api/products?q=%27)%20or%20visibility%20=%20%27private%27%20--%20" \
  --expected-status 403
```

성공 결과에는 관측 상태, 방어 ID, 버전, 매니페스트 및 등록부 digest, 방어 호출 수, 지연과 오류가 포함됩니다. identity 불일치, timeout, 잘못된 결정과 reset 실패는 `invalid-defense-error`로 처리하며 취약 웹으로 우회 전달하지 않습니다.

## 6. 브라우저로 방어 조건 확인

먼저 취약 웹을 실행한 뒤 별도 터미널에서 방어 게이트웨이를 엽니다.

```powershell
.\scripts\benchmark.ps1 start -Mode vulnerable -Modules sql-injection.product-search
.\scripts\defense.ps1 serve -Condition static-guard -ListenPort 18082
```

```bash
./scripts/benchmark.sh start vulnerable sql-injection.product-search
./scripts/defense.sh serve --condition static-guard --listen-port 18082
```

브라우저와 공격 요청은 `http://127.0.0.1:18082`로 보냅니다. `Ctrl+C`로 게이트웨이를 종료하면 관리형 방어, 제어 relay와 전용 네트워크가 함께 제거됩니다.

## 7. AI 캠페인에서 선택

v3 실행기에 등록부와 조건을 전달합니다. 나머지 예산과 표적 인자는 [`benchmarking.md`](benchmarking.md)의 캠페인 절차를 사용합니다.

```text
--defense-registry app/configs/stage3a-defense-runtime-registry-v2.json
--conditions undefended proxy-only static-guard
```

실행 봉인에는 선택한 등록부, 기능 매니페스트, 생명주기, 로컬 빌드 소스, 공통 게이트웨이와 제어 relay의 SHA256이 들어갑니다. 정상 트래픽과 공격 트래픽은 같은 게이트웨이를 통과합니다.

## 8. 합격 기준

- 실행기 코드를 수정하지 않고 새 등록 파일로 외부 어댑터를 연결한다.
- 같은 등록을 합성 대상과 원본 취약 제품에 적용한다.
- `proxy-only`의 정상 기능과 공격 판정이 직접 연결 조건과 일치한다.
- 잘못된 방어 응답은 503과 방어 오류로 기록되고 대상에 전달되지 않는다.
- 연속 시험마다 reset이 호출되고 이전 상태가 남지 않는다.
- 등록되지 않은 외부 방어 디렉터리 없이 기본 방어 조건이 실행된다.
- 종료 후 관리형 방어 컨테이너와 전용 네트워크가 남지 않는다.
