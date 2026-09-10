# 2026-09-11 재검증 기록

## 결론

현재 소스로 이미지를 다시 빌드한 뒤 29개 RUBY 모듈과 원본 CVE 5개의 기능 쌍이 모두 통과했다. 강화된 릴리스 관문도 `PASS`했다. 이 판정은 취약판과 안전판 또는 수정판의 기능 차이, 실행 격리, 방어 연결 계약과 전체 회귀에 적용된다. XSS와 CSRF 탐지 효과 및 일반 방어 효과는 포함하지 않는다.

## 최종 근거

| 근거 | 결과 | SHA-256 |
| --- | --- | --- |
| [`pair-checks-complete-evidence/all-pair-checks.json`](pair-checks-complete-evidence/all-pair-checks.json) | 이미지 재빌드 통과, 검사기 18개 통과, 34개 대상 기능 쌍 통과 | `sha256:d7972caa9af283aa6945d2e95e8030d984aaa9829e53bb8a319c9264c400f5f5` |
| [`release-readiness-current-head-v2.json`](release-readiness-current-head-v2.json) | 릴리스 관문 `PASS`, pytest 286개와 하위 시험 50개 통과 | `sha256:622a0cbffbff6dfbdd81939e823df13b83c2cfc959c30b6026fe7e5904e3bfa9` |

릴리스 관문 실행 시점의 커밋은 `d7ddd02d08c14c708dd8f4f67b9d436095301b89`다. 쌍 검사 결과에는 각 모듈 ID, 조건, 개별 통과 값과 비공개 목표 판정이 들어 있다.

## 실패 이력

[`pair-checks-current-head/all-pair-checks.json`](pair-checks-current-head/all-pair-checks.json)은 첫 재실행의 실패 기록이며 SHA-256은 `sha256:30687eb9aecf0bcf9c1e58862bae429998de353dc9e398ab542e5ee99fa2c355`다. 검사기 18개 중 17개가 통과했고 GeoServer 파생 묶음만 실패했다. 실행기가 현재 소스를 빌드하지 않아 변경 전 API 이미지를 재사용한 것이 원인이었다.

실행기는 이후 검사 전에 `docker compose build`를 수행하도록 수정했다. 빌드를 생략한 실행은 릴리스 근거로 통과할 수 없다. 중간 디버그 실행과 필드 보강 전 중복 성공 실행은 최종 근거와 실패 원인을 추가로 설명하지 않아 저장소에서 제외했다.

## 남은 제한

- 저장형 XSS 계열 4개와 CSRF 1개는 기능 쌍이 통과했지만 현재 RUBY 탐지 또는 방어와 정상 입력 오탐 검증이 없다.
- 해당 5개 대상은 [`../../app/configs/defense-effect-exclusions-v1.json`](../../app/configs/defense-effect-exclusions-v1.json)에 등록돼 방어 효과 집계가 차단된다.
- DOM 기반 XSS와 반사형 XSS 전용 시나리오는 현재 34개 대상에 없다.
- Codex CLI 0.154.0 JSONL은 실제 모델 ID를 제공하지 않았다. 요청 모델을 관측 모델로 취급하지 않으며 모델 동일성이 필요한 효과 분석은 실패한다.
- 구현 비참여자의 독립 검토가 끝나기 전에는 `positive_effect_claim_allowed`가 `true`가 되지 않는다.
