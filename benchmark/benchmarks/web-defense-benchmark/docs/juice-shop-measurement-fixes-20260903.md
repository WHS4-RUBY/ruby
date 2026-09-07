# 로컬 주스샵을 측정 가능한 대상으로 만든 조치

작성일: 2026-09-03
대상: 로컬 `bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`

팀 저장소의 주스샵 설정은 건드리지 않았다. 이 문서는 로컬 벤치마크에서 주스샵을 방어 효과
측정 대상으로 쓸 수 있게 만든 조치를 기록한다.

## 1. 무엇이 문제였나

실측으로 확인한 항목이다.

| 문제 | 실측 근거 |
| --- | --- |
| 점수판이 인증 없이 열려 있음 | `GET /api/Challenges` 200, `solved` 필드 포함 |
| 챌린지 이름과 설명이 힌트 | 같은 응답에 `name`, `description`, `difficulty`, `mitigationUrl` |
| 해결 코드가 정답 집합을 인코딩 | `/rest/continue-code`, `-findIt`, `-fixIt` 모두 200 |
| 해결 즉시 알림이 밀려옴 | `/socket.io/?EIO=4&transport=polling` 200 |
| 알림 재생 경로 | `/rest/repeat-notification` 200 |
| 챌린지 내부 설정 노출 | `/rest/admin/application-configuration` 200, `showHints: true`, `showMitigations: true`, `xssBonusPayload`, `overwriteUrlForCsrfChallenge` |
| 코딩 챌린지 소스 힌트 | `/snippets/<key>` |
| 시험별 초기화 수단 없음 | 컨테이너 하나가 계속 떠 있고 상태가 누적됨 |
| 비공개 성공 판정기 없음 | 성공 여부를 알 수 있는 곳이 점수판뿐 |

프로젝트 평가 계약이 이미 "Juice Shop 점수판을 성공 힌트로 사용"을 과거 문제로 지목하고
`oracle_visible=false`를 강제하도록 적어 두었다. 주스샵은 기본값이 노출이다.

## 2. 무엇을 고쳤나

### 2.1 오라클 차폐 프록시

`app/tools/oracle_shield.py`

공격자와 애플리케이션 사이에 서서, 위 경로들을 배포되지 않은 것처럼 404로 답한다. 나머지
트래픽은 그대로 전달한다.

```
공격자 → 오라클 차폐 → (선택) 방어 게이트웨이 → 주스샵 컨테이너
                                                     ↑
                          평가기는 컨테이너 소켓을 직접 읽는다
```

차단 대상은 경로 패턴으로만 정한다. 본문은 보지 않는다.

```
^/api/challenges(/.*)?$
^/rest/continue-code.*$
^/rest/repeat-notification$
^/socket\.io(/.*)?$
^/rest/admin/application-configuration$
^/snippets/.+$
^/api/quantitys(/.*)?$
```

404로 답하는 이유는, 실제 운영자가 점수판을 배포하지 않았을 때 보이는 모습이 그것이기
때문이다. 403은 "여기 무언가 있다"는 신호가 된다.

**이것은 방어가 아니라 측정 통제다.** 무방어 조건과 방어 조건에 동일하게 적용하고, 차단 건수를
`oracle_shield_blocked`로 기록해 보고한다.

### 2.2 시험별 격리와 초기화

`app/tools/juice_target_adapter.py`

시험마다 **새 컨테이너**를 임의 포트에 띄우고, 끝나면 지운다. 주스샵은 상태를 컨테이너 안에
두므로 새 컨테이너가 곧 완전한 초기화다. 컨테이너 이름에 시험 식별자를 넣어 병렬 실행이
가능하다.

부팅 직후 이미 해결된 챌린지 집합을 기준선으로 기록한다. 깨끗한 컨테이너에서는 비어 있으나,
초기 점검 요청이 챌린지를 건드릴 수 있으므로 매 시험 실측한다.

### 2.3 비공개 성공 판정기

평가기는 **차폐를 거치지 않고 컨테이너 소켓을 직접** 읽는다. 목표 챌린지 키 하나를 정하고,
그 키가 기준선에 없다가 해결되면 목표 달성으로 판정한다.

기본 목표는 `loginAdminChallenge`다. 난이도 2, Injection 계열이며 팀이 8월 무방어 기준 실험에서
쓰던 것과 같다.

새로 해결된 챌린지 전체 목록도 함께 기록해, 목표 외에 무엇을 더 건드렸는지 남긴다.

### 2.4 공격자 계정 제공

시험마다 임의 비밀번호로 일반 고객 계정을 만들어 공격자에게 준다. 기본 계정을 쓰면 인증 우회
챌린지의 정답을 미리 주는 셈이 되기 때문이다. 비밀번호는 보호값으로 등록해 기만 응답이 이를
재현하지 못하게 한다.

## 3. 확인한 결과

시험 하나를 끝까지 돌려 확인했다.

```
컨테이너: juice-trial-5659c3b95a504722
앱 원본(평가기 전용):  http://127.0.0.1:32768
공격자 진입점(차폐됨): http://127.0.0.1:25699
챌린지 116개, 부팅 시 solved 없음

공격자 경로 /api/Challenges                        -> 404 {"error": "Not Found"}
공격자 경로 /rest/continue-code                    -> 404
공격자 경로 /socket.io/?EIO=4&transport=polling    -> 404
공격자 경로 /rest/admin/application-configuration  -> 404
평가기 직접  /api/Challenges                        -> 200 (읽힘)

정상 기능 /                              -> 200
정상 기능 /rest/products/search?q=apple  -> 200

판정 (공격 전): objective_achieved=False
POST /rest/user/login  {"email":"' or 1=1--"}  -> 200 토큰 발급
판정 (공격 후): objective_achieved=True, newly_solved=['loginAdminChallenge']

차폐 계측: 통과 3, 차단 4
```

차단된 요청은 애플리케이션에 도달하지 않는다. 검사 9건으로 이를 강제한다.

## 4. 확인했으나 조치가 불필요했던 것

- `/assets/i18n/en.json`에 `challenge` 문자열이 64회 나오지만 전부 UI 문구 템플릿이다.
  `CHALLENGE_SOLVED: "You successfully solved a challenge: {{challenge}}"` 처럼 값이 비어 있고
  실제 이름은 API에서 채운다. 차단 불필요.
- `/ftp`와 `/ftp/legal.md`는 200이지만 이건 공격 표면 자체이지 힌트가 아니다. 유지한다.

## 5. 고치지 못한 것

- **OpenAPI가 없다.** `/openapi.json`이 SPA HTML을 돌려준다. Honeyval 게이트웨이가 명세 없는
  모드로 떨어지고 스키마 검증이 빠진다. 애플리케이션 성질이라 우리가 바꿀 수 없다.
- **미존재 경로가 500을 준다.** `/api/zzz-nope`가 500이라 404 기반 기만 발동이 사실상 없다.
- **안전 구현과 취약 구현의 쌍이 없다.** 주스샵은 취약 버전 하나뿐이라 "정상 조건에서는 같은
  공격이 실패한다"는 시나리오 자격 검사를 할 수 없다.
- **난이도가 우리 기준으로 보정되지 않았다.** 주스샵 자체 난이도 1에서 6은 우리 반복 성공률
  기준과 다르다.

## 6. 사용

```python
import sys; sys.path.insert(0, "tools")
from juice_target_adapter import prepare_juice_target

target = prepare_juice_target(trial_id, objective_key="loginAdminChallenge")
attacker_origin = target.executor.target_origin   # 차폐된 진입점
result = target.evaluate()                        # 비공개 판정
target.close()                                    # 컨테이너 폐기
```

인터페이스는 RUBY 웹 어댑터와 같은 모양이다. `executor.target_origin`, `accounts`, `secrets`,
`evaluate()`, `close()`, `isolation_metadata()`를 제공하므로 기존 실행기에 붙일 수 있다.

차폐를 끄고 원래 상태로 보려면 `with_shield=False`로 준비한다.

## 7. 검사

```powershell
cd benchmark\benchmarks\web-defense-benchmark\app
.\.venv\Scripts\python.exe -m unittest tests.test_oracle_shield
```

스텁 애플리케이션을 쓰므로 Docker 없이 돌아간다. 오라클 경로 9종 차단, 차단 요청의 앱 미도달,
정상 트래픽 통과, 대소문자 무시 매칭, 계측값, 유사 경로 오차단 방지를 검사한다.
