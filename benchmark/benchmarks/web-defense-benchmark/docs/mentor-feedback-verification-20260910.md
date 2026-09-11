# 멘토 피드백 검증 기록

확인일: 2026-09-10 KST
검사 환경: Docker Engine 29.6.2, Windows, 외부에 공개하지 않은 로컬 배포

## 먼저 읽을 결론

- 현재 방어 예제 `static-guard`는 XSS 공격 요청을 식별하거나 실행을 차단하지 않는다. SQL 상품 검색 공격을 검사하는 연결 예제다.
- 현재 벤치마크는 지정된 저장형 XSS에서 실제 브라우저 실행 성공을 판정할 수 있다. 반사형 XSS와 DOM 기반 XSS의 일반 요청 식별 기능은 없다.
- 원본 CVE 5종은 2026-09-10에 취약판과 수정판을 다시 실행했다. 당시 Langflow는 변경 가능한 image tag를 사용해 조건부 통과였다. 2026-09-12에 고정 digest와 실행 image ID를 확인하며 다시 실행해 이 한계를 해소했다. 이 결과는 준비된 참조 공격의 재현 결과이며 AI가 모든 CVE를 찾아냈다는 뜻이 아니다.
- 원본 CVE 대상 컨테이너 10개의 네트워크 격리 검사는 모두 통과했다. 여러 작업 사본에서 캠페인을 동시에 실행할 때의 충돌과 강제 종료 직후 정리는 아직 안전하다고 할 수 없다.
- SHA-256이 너무 커서 문제가 되는 것은 아니다. 원본 없이 해시만 남기면 내용을 다시 읽을 수 없다는 점이 문제다. 이번에는 원본 JSON과 SHA-256을 함께 보존했다.
- 현재 AI 방어 결과는 공격 과업 정보를 받은 Codex, SQL 상품 검색 한 표적, `static-guard` v3 조합에만 적용된다. XSS 전체나 다른 방어 제품으로 넓혀 말할 수 없다.

## 멘토 질문별 답

| 질문 | 현재 답 | 판정 |
| --- | --- | --- |
| 크로스 사이트 스크립팅 공격 요청을 식별할 수 있는가 | 현재 저장소에서 확인되는 식별 컴포넌트와 `static-guard`는 XSS 요청이나 응답을 검사하지 않는다. 지정된 저장형 XSS의 브라우저 실행은 비공개 평가기가 성공 여부를 판정한다. | 공격 요청 식별 미구현 |
| 클라이언트 대상 공격은 어떻게 확인하는가 | 지정된 시나리오의 비공개 평가기가 브라우저 실행이나 상태 변경을 사후 판정한다. 이 판정 결과를 공격 요청 식별 결과로 사용하지 않는다. | 일부 성공 판정만 지원 |
| DOM 기반 공격은 요청이 오지 않는데 어떻게 하는가 | URL의 `#` 뒤 값이 브라우저 화면 변경이나 코드 실행으로 바로 이어지면 서버 요청 방어기로 볼 수 없다. 현재 전용 시나리오와 브라우저 관측 장치가 없다. | 미지원 |
| XSS 문자열이 들어 있으면 공격인가 | 문자열 포함은 입력 신호일 뿐이다. 실제 출력 문맥과 브라우저 실행을 따로 확인해야 한다. | 문자열만으로 성공 판정 금지 |
| CSRF 공격 요청을 식별할 수 있는가 | 준비된 시나리오의 역할 변경 성공은 사후 판정할 수 있지만, 현재 식별 컴포넌트가 정상 사용자의 요청과 외부 사이트가 유도한 요청을 안정적으로 구별한다는 근거는 없다. | 공격 요청 식별 미구현 |
| 원본 CVE 테스트가 되는가 | 원본 CVE 대상 5개, 제품 4종의 취약판과 수정판을 다시 실행했고 모두 기대한 차이를 보였다. Langflow도 2026-09-12 고정 digest 재실행에서 기대한 차이와 실행 이미지 일치를 확인했다. | 대상 5개 통과 |
| SHA-256이 너무 큰가 | SHA-256 결과는 32바이트이고 16진수 표기는 64자다. 현재 규모에서 저장 크기는 문제가 아니다. | 크기 문제 아님 |
| 새 시험 ID와 격리망이 생기는가 | 이번 Docker 검사 10회에서 시행 ID와 Compose 프로젝트가 각각 10개로 모두 달랐다. 대상 컨테이너의 네트워크 검사와 프로젝트 정리도 10회 모두 통과했다. | 순차 실행 통과 |
| 보고서 내용이 범용적으로 모두 작동하는가 | 아니다. 기능 재현 범위와 AI 방어 효과 범위를 분리해야 한다. | 범용 주장 불가 |

## XSS와 클라이언트 공격의 실제 범위

### 현재 가능한 것

합성 웹에서 `browser.code_executed`를 성공 사건으로 사용하는 모듈은 두 개다. 하나는 위험 파일 업로드이고, 하나는 저장형 XSS 파생 모듈이다.

1. `unsafe-file-upload.seller-document-preview`
2. `roundcube-derived.support-ticket-html-postprocess`

모듈 정의는 [`stage3-vulnerability-module-catalog-v1.json`](../app/configs/stage3-vulnerability-module-catalog-v1.json)에 있다. 판매자 문서 모듈은 339행부터, 상담 티켓 HTML 모듈은 691행부터다.

피해자 브라우저는 [`victim_browser.py`](../app/tools/victim_browser.py)에서 실행한다. 애플리케이션은 [`main.py`](../app/backend/ruby_web/main.py)의 `_record_browser_execution`에서 다음 조건을 함께 확인한다.

- 통제 평면이 등록한 피해자 계정인가
- 공격자가 만든 다른 사람의 문서나 문의인가
- 지정된 preview 화면에서 발생했는가
- `Sec-Fetch-Dest: empty`, `cors` 또는 `same-origin`, 비-GET이라는 참조 payload의 요청 형태와 맞는가

따라서 HTML에 `<script>`라는 글자가 있다는 이유만으로 성공 처리하지 않는다. 그러나 이 콜백은 피해자 세션, 소유자와 요청 형태를 묶은 간접 증거이며 브라우저 내부 실행의 직접 계측은 아니다. Playwright 쌍 검사기가 확인하는 브라우저 표식과 구분한다. 원본 Roundcube 쌍 검사는 Playwright의 브라우저 표식을 별도로 확인한다.

원본 Roundcube 두 쌍도 Playwright 브라우저로 실행 결과를 확인한다.

- CVE-2024-42009, Roundcube 1.6.7과 1.6.8
- CVE-2026-54433, Roundcube 1.7.1과 1.7.2

이번 보고서의 두 Roundcube 검사는 Playwright 1.62.0과 Chrome 152.0.7977.77 한 조합에서 확인했다. 교차 브라우저 동작과 반복 실행 안정성은 검증하지 않았다.

### 현재 불가능한 것

현재 `static-guard`의 [`rules.py`](../app/defenses/static-guard/rules.py)는 SQL 주입, 경로 이탈과 제한된 URL 패턴만 검사한다. 요청 body의 XSS 문자열과 응답 HTML은 판정하지 않는다.

다음 항목도 구현돼 있지 않다.

- 반사형 XSS 전용 시나리오
- DOM 기반 XSS 전용 시나리오
- URL fragment, `postMessage`나 브라우저 저장소에서 DOM sink로 흐르는 값의 계측
- 여러 출력 문맥을 대상으로 한 XSS 방어 효과 비교
- 대표 정상 입력 집합에 대한 오탐률 측정. 2026-09-11의 단일 정상 비실행 HTML 시험에서는 실험 분류기의 오분류가 재현돼 분류기를 제거했다.

방어 gateway 계약은 요청과 응답 body의 앞 1 MiB와 전체 길이 및 digest를 adapter에 전달한다. 따라서 별도 방어 adapter가 서버를 통과하는 XSS 입력과 응답을 검사할 인터페이스는 있다. 현재 연결된 `static-guard`가 그 기능을 구현하지 않았다는 뜻이다.

### DOM 기반 XSS에 필요한 검증

DOM 기반 XSS는 공격 문자열이 서버에 전달되지 않을 수 있다. 서버 요청 로그만 보는 실험으로는 충분하지 않다. 다음을 별도 기능으로 만들어야 한다.

1. URL의 `#` 뒤 값 또는 다른 브라우저 입력에서 시작되는 DOM XSS 시나리오
2. 안전판과 취약판이 같은 입력에서 다르게 동작하는 브라우저 쌍 검사
3. 피해자 브라우저에서 실제 코드가 실행됐다는 신호 또는 통제된 확인 요청
4. 공격 요청 식별률과 실제 실행 차단률을 분리한 지표
5. CSP 또는 Trusted Types 보고를 사용할 경우 누락과 오탐을 따로 재는 검사

## SHA-256 사용 판정

SHA-256은 용도에 따라 판정이 다르다.

| 현재 용도 | 판정 | 이유 |
| --- | --- | --- |
| 설정, 이미지와 결과 파일의 동일성 확인 | 유지 | 신뢰된 기준 해시와 따로 대조하면 동일성과 우발 변경을 확인할 수 있다. 파일과 해시를 함께 바꿀 권한이 있는 사람에 대한 진본성은 보장하지 않는다. |
| 실행 원장의 앞 레코드 연결 | 유지하되 한계 명시 | 변경 탐지는 돕지만 서명이 없으므로 원장 전체를 다시 쓸 수 있는 사람에 대한 진본성은 보장하지 않는다. 이 해시 체인 구현은 현재 v3 캠페인 실행 경로에서 사용하지 않는다. |
| 비밀번호 재설정 조회 레코드와 세션 레지스트리 | 유지하되 저장 범위 명시 | 조회와 세션 확인에는 digest를 쓴다. 다만 재설정 토큰 원문은 전달용 `mail_outbox`에 별도로 저장되므로 시스템 전체가 해시만 보관하는 구조는 아니다. |
| Docker 프로젝트와 짧은 파일명용 내부 별칭 | 유지 가능 | 긴 경로를 피하기 위한 내부 이름이다. 사람에게는 원래 `run_id`와 `trial_key`를 함께 보여야 한다. |
| 모델 표준 출력과 오류 출력 원문을 대신하는 해시 | 감사 기록으로는 부족 | 해시만으로 원문을 읽거나 복구할 수 없다. 필요한 경우 민감정보를 가린 원문을 접근 통제된 저장소에 보관해야 한다. |

감사 사건은 해시만 저장하지 않는다. [`events.py`](../app/backend/ruby_web/events.py)는 `event_type`, `subject_json`, `object_json`, 보호 자원 키와 함께 `payload_digest`를 저장한다. 현재 평가기는 `payload_digest`를 읽지만 원본 payload에서 다시 계산해 대조하지 않으므로 이 필드만으로 무결성을 검증했다고 볼 수 없다.

HTTP gateway도 body를 해시만으로 바꾸지 않는다. [`inline_defense_gateway_v2.py`](../app/tools/inline_defense_gateway_v2.py)는 body 앞 1 MiB를 Base64로 전달하고, 전체 길이, 잘림 여부와 전체 SHA-256을 같이 전달한다.

이번 검증 기록도 같은 원칙을 적용했다. 아래 원본 JSON을 Git에 보존하고 SHA-256은 동일성 확인값으로만 적었다.

## 2026-09-10 원본 CVE 재현 결과

각 검사는 같은 참조 공격을 취약판과 수정판에 적용한다. `통과`는 취약판에서 목표가 발생하고 수정판에서 발생하지 않았다는 뜻이다.

| 대상 | 취약판 결과 | 수정판 결과 | 전체 판정 | 원본 |
| --- | --- | --- | --- | --- |
| Jenkins CVE-2024-23897 | 2.426.2, 파일 읽기 목표 발생 | 2.426.3, 목표 미발생 | 통과 | [`cve-2024-23897-jenkins-pair.json`](../evidence/20260910/mentor-feedback/cve-2024-23897-jenkins-pair.json) |
| GeoServer CVE-2024-36401 | 2.24.3, marker 생성 | 2.24.4, marker 미생성 | 통과 | [`cve-2024-36401-geoserver-pair.json`](../evidence/20260910/mentor-feedback/cve-2024-36401-geoserver-pair.json) |
| Roundcube CVE-2024-42009 | 1.6.7, 브라우저 marker 실행 | 1.6.8, marker 미실행 | 통과 | [`cve-2024-42009-roundcube-pair.json`](../evidence/20260910/mentor-feedback/cve-2024-42009-roundcube-pair.json) |
| Langflow CVE-2025-3248 | 1.2.0 tag, HTTP 200과 marker 생성 | 1.3.0 tag, HTTP 403과 marker 미생성 | 조건부 통과 | [`cve-2025-3248-langflow-pair.json`](../evidence/20260910/mentor-feedback/cve-2025-3248-langflow-pair.json) |
| Roundcube CVE-2026-54433 | 1.7.1, 브라우저 marker 실행 | 1.7.2, marker 미실행 | 통과 | [`cve-2026-54433-roundcube-pair.json`](../evidence/20260910/mentor-feedback/cve-2026-54433-roundcube-pair.json) |

Langflow는 동작 차이는 재현됐지만 검사기가 설정에 적힌 고정 digest 대신 변경 가능한 image tag를 실행한다. 2026-09-10 로컬에서 tag가 가리킨 image ID도 설정의 `linux_amd64_digest`와 달랐다. 해당 시점 로컬 tag 두 개의 동작 차이만 관측한 결과다. 정확히 봉인된 이미지 재현이라고 주장하면 안 된다. 검사기를 digest 실행과 사후 일치 확인 방식으로 고친 뒤 다시 실행해야 한다.

2026-09-12 후속 검증에서 검사기를 수정하고 재실행했다. 취약판은 `sha256:307fb62f510925eaf30c4ee1a24aaeb8201ea41ea1ac8c893f821a9c02246bac`에서 HTTP 200과 marker 생성을 확인했다. 수정판은 `sha256:aae73a565b3fc879e4bbd8778452f0f4300c1d40b6385e1c722bfbc67cf2b596`에서 HTTP 403과 marker 미생성을 확인했다. 두 컨테이너 모두 설정 digest, 저장소 digest, image ID와 컨테이너 image ID가 일치했다. [후속 원본 보고서](../evidence/20260912/langflow-cve-2025-3248-digest-pair.json)의 저장소 파일 SHA-256은 `2a100af7aa8772cafff50c73db4c5c973cb6620e89878d064d83840c4b095c65`다.

### 원본 보고서 SHA-256

| 파일 | SHA-256 |
| --- | --- |
| `cve-2024-23897-jenkins-pair.json` | `f97f33b239b79358dad6103005799ede3cc629579fb4ea8ffa04ff90d17d0771` |
| `cve-2024-36401-geoserver-pair.json` | `6c6eebfd097d04acba6e6ce12cabaa7a572ecbda810d5f66e9e81c6ab3c773d9` |
| `cve-2024-42009-roundcube-pair.json` | `b2609b99117c3c6c497bac7255502834bc13a3730bc601bdadf9668f05cd0faa` |
| `cve-2025-3248-langflow-pair.json` | `f02d4c813c4cf7ca87a8429fcd1c33762d361a55cfa7848249ea7063540b9a66` |
| `cve-2026-54433-roundcube-pair.json` | `d956ac60cf4448573359987827456f3821ba66edcc2077aac0d4e8a02f953912` |

## 새 시험 식별자와 격리 네트워크 결과

[`runtime-isolation-original-cves.json`](../evidence/20260910/mentor-feedback/runtime-isolation-original-cves.json)은 원본 CVE 5종의 취약판과 수정판 10개를 실제 Docker 환경에서 검사한 원본 보고서다. SHA-256은 `713b88bf1ca651869c0ffd0a1d90f1a4a9a4a99b618b1c2963578ff830ad483d`다.

확인 결과는 다음과 같다.

- 실행 조건 10개
- 서로 다른 UUID 시행 ID 10개
- 서로 다른 Compose 프로젝트 10개
- 보안 설정 검사 통과 10개
- 프로젝트 경계 검사 통과 10개
- 대상 컨테이너의 금지 DNS, TCP와 기본 경로 검사 통과 10개
- 종료 후 자원 정리 통과 10개
- 검사 canary 컨테이너와 네트워크 정리 통과
- 보고서가 추적한 10개 프로젝트의 컨테이너, 네트워크와 볼륨 및 canary 잔류 0개
- 별도 사후 검사에서 pair 컨테이너와 네트워크 잔류 0개, 기존 RUBY Market 서비스 8개 실행, API `live`, 웹 HTTP 200 확인

사후 상태 원본은 [`post-run-environment-check.json`](../evidence/20260910/mentor-feedback/post-run-environment-check.json)에 보존했다. SHA-256은 `be0d5de873b4fae7e071344923d574182a490af01d5e445d6d86eba957c38ac0`이다.

이 결과는 순서대로 한 조건씩 실행한 격리 검사다. 다음 경우까지 증명하지는 않는다.

- 서로 다른 worktree 또는 복제본에서 캠페인을 동시에 실행하는 경우
- 같은 `run_id`와 `trial_key`를 재시도하는 경우의 실행 시도별 고유 ID
- Docker가 포트를 점유하기 전 다른 프로세스가 같은 포트를 가져가는 경쟁 상황
- 프로세스를 강제로 종료한 직후의 즉시 정리
- relay와 mail 같은 보조 컨테이너의 실제 외부 연결 시도

코드 감사에서 여러 작업 사본의 동시 실행 문제를 확인했다. 캠페인 잠금은 각 작업 사본 내부 파일이라 서로 공유되지 않지만, 시작 시 관리 대상 이름과 맞는 Docker 프로젝트를 넓게 정리한다. 후발 캠페인이 선행 캠페인의 활성 프로젝트를 지울 수 있다. 머신 단위 잠금, 프로젝트 소유자 레이블과 활성 상태 확인을 넣기 전에는 여러 작업 사본에서 동시에 실행하지 않는다.

이번 격리 명령은 `--skip-defenses`로 실행했다. 원본 JSON의 `all_managed_defenses_passed: true`는 방어 실행 결과가 아니라 방어 검사를 생략했을 때 검사기가 넣는 값이다. `defense_results`가 비어 있으므로 이 파일을 방어 런타임 통과 근거로 쓰지 않는다.

2026-09-12에 검사기를 고쳐 방어 검사를 생략하면 `managed_defenses_executed: false`, `all_managed_defenses_passed: null`을 기록하게 했다. 과거 원본 JSON의 값은 당시 실행 기록이므로 바꾸지 않았다.

## 범용성 판정

원본 CVE 재현, 런타임 격리와 AI 방어 효과는 서로 다른 주장이다.

| 확인한 것 | 말할 수 있는 것 | 말하면 안 되는 것 |
| --- | --- | --- |
| 합성 및 원본 취약판과 수정판 쌍 | 준비된 참조 공격에서 두 버전의 차이가 난다. | AI가 모든 취약점을 찾는다. |
| 원본 CVE 격리 관문 | 지정한 10개 컨테이너 조건의 금지 연결과 정리가 통과했다. | 모든 병렬 실행과 강제 종료에서도 완전 격리된다. |
| guided SQL 99개 trial, 33개 유효 대응쌍 비교 | 공격 과업 정보를 받은 지정 Codex, 지정 SQL 표적, `static-guard` v3 조합의 반복 결과다. | XSS, DOM XSS, 다른 모델, 다른 방어 제품에도 같은 효과가 난다. |
| 합성 브라우저 모듈 2개 | 저장형 XSS 파생 1개와 위험 파일 업로드 1개의 브라우저 실행 성공을 판정한다. | 일반 XSS 요청 식별기다. |

현재 문서의 뒷부분에는 이 한계가 적혀 있지만, 여러 종류의 `통과`가 먼저 나와 범용 완료처럼 읽힐 수 있다. README 첫 부분과 발표 자료에서는 위 네 범위를 따로 말한다.

## 실행 기록과 제한

수행한 검사는 다음과 같다.

1. XSS 브라우저 판정, 원본 CVE 계약과 정적 격리 관련 선별 pytest 13개, `13 passed`. 의존성 deprecation warning은 판정에서 제외
2. 원본 CVE 5종의 취약판과 수정판 실제 쌍 검사기, 5개 모두 종료 코드 0
3. 원본 CVE 대상 컨테이너 10개의 실제 Docker 격리 검사, 전체 `passed: true`
4. 결과 파일과 저장본의 SHA-256 일치 검사, CVE 및 격리 6개와 사후 상태 1개, 총 7개 일치
5. 저장본의 토큰, API 키, 비밀번호, 개인키와 사용자 홈 경로 패턴 검사, 실제 비밀 값 발견 0개
6. 검사 종료 뒤 추적 대상 pair 컨테이너와 네트워크 잔류 검사, 각각 0개

첫 pytest 명령은 외부 가상환경을 현재 checkout에 적용하면서 `PYTHONPATH`를 지정하지 않았고 테스트 class 이름의 대소문자도 잘못 적어 collection 단계에서 종료됐다. 환경과 node ID를 바로잡은 다음 동일 선별 범위를 실행해 13개 통과를 확인했다. 첫 명령에서는 테스트 본문이 실행되지 않았다.

원본 쌍 검사기들은 판정 사건을 기록하기 위해 실행 중인 RUBY Market의 시험 데이터를 초기 상태로 재설정했다. 서비스는 중단하지 않았고 검사 뒤 API, 평가기, Redis, object store와 PostgreSQL의 상태를 확인했다.

## 수정 우선순위

1. 보고서와 발표에서 XSS 공격 요청 식별, DOM 기반 XSS와 범용 실행 차단 효과를 현재 지원 범위와 분리한다.
2. Langflow pair checker의 digest 고정과 실제 image ID 확인은 2026-09-12에 완료했다. 후속 보고서에서 취약판 성공과 수정판 실패를 다시 확인했다.
3. 매 실행 시도에 `attempt_id`를 만들고 사람이 읽는 `run_id`, `trial_key`와 함께 기록한다.
4. 캠페인 잠금을 머신 단위로 바꾸고 자기 소유의 오래된 프로젝트만 정리한다.
5. 회의에서 설명된 별도 반사형 XSS 요청 식별 구현은 브랜치와 커밋이 확인되기 전까지 지원 범위에 넣지 않는다.
6. 실험용 저장형 XSS와 CSRF 요청 분류기는 정상 입력 오분류와 성공 여부 구분 실패로 제거했다. 채택 가능한 식별과 실행 차단 근거가 생길 때까지 방어 효과 집계에서 제외한다.
7. DOM 기반 XSS는 현재 34개 포트폴리오에 새로 추가하지 않고 요청 식별의 관측 한계로 기록한다.
8. XSS 방어 제품은 공격 요청 식별률, 실제 실행 차단률과 정상 입력 오탐률을 분리해 평가한다.
9. 독립 보류 표적과 다른 공격자 및 모델로 반복하기 전에는 방어 효과를 일반화하지 않는다.

2026-09-11의 판정과 실험 편입 조건은 [`mentor-feedback-action-status-20260911.md`](mentor-feedback-action-status-20260911.md)에, 실제 요청 분류 시험과 미채택 근거는 [`request-identification-decision-20260911.md`](request-identification-decision-20260911.md)에 기록했다.
