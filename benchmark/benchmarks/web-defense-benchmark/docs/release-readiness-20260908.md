# 취약 웹 벤치마크 로컬 릴리스 판정

- 최초 실행일: 2026-09-08
- 재검증일: 2026-09-09
- 판정: `PASS`
- 범위: RUBY 합성 및 파생 모듈 29개, 원본 CVE 5개, 총 34개
- 기계 판정: [`../evidence/20260909/release-readiness.json`](../evidence/20260909/release-readiness.json)
- 판정 보고서 SHA-256: `6007631555dbc41662368c508351a80771425f61c56e0b7d57a6a66e896b44f5`

## 통과한 기준

| 기준 | 실제 결과 |
| --- | --- |
| 카탈로그와 실행기 일치 | 합성 및 파생 모듈 29개, 원본 CVE 5개가 정확히 일치 |
| RUBY 웹 쌍 | 29개 각각에서 secure 목표 사건 0건, vulnerable 목표 사건 발생과 검사기 통과 |
| 원본 CVE 쌍 | Jenkins, GeoServer, Roundcube 2024, Langflow와 Roundcube 2026의 vulnerable 및 fixed 쌍 통과 |
| 공격자 격리 | 원본 제품 10개 버전 조건에서 금지 DNS와 TCP 접근 0건, 종료 뒤 자원 정리 통과 |
| 방어 연결 | 관리형 및 외부 HTTP 드라이버 회귀, 현재 등록부 해시, 방어 뒤 정상 흐름 6개와 `static-guard` 실제 차단 통과 |
| 사용 문서 | 처음 실행, 정상 및 취약 모드, 전체 쌍, 격리, 방어 등록과 벤치마킹 절차 확인 |
| 전체 회귀 | 270 passed, 5 warnings, 32 subtests passed |

전체 쌍 실행기는 18개 검사기를 차례로 실행했다. RUBY 웹은 29개의 secure 및 vulnerable 조건 58개, 원본 CVE는 5개의 vulnerable 및 fixed 조건 10개다. 각 하위 보고서의 SHA-256과 대상 배정은 기계 판정 파일에 들어 있다. 검사기는 기존 출력 디렉터리를 재사용하거나 보고서를 덮어쓰지 않는다.

## 재현

정상 스택과 브라우저 실행 환경을 준비한 뒤 고유한 출력 경로로 전체 쌍을 검사한다.

```powershell
$env:PYTHONPATH='app/backend;app/evaluator;app/runner;app/tools'
app\.venv\Scripts\python.exe app\tools\run_all_pair_checks.py `
  --output-dir app\evaluation\all-pairs-고유시각
```

전체 쌍 결과와 이미 보관한 격리 및 방어 증거를 묶어 릴리스 게이트를 실행한다.

```powershell
app\.venv\Scripts\python.exe app\tools\check_release_readiness.py `
  --pair-run-root app\evaluation\all-pairs-고유시각 `
  --output app\evaluation\release-readiness-고유시각.json
```

## 판정 범위

이 PASS는 취약 웹의 의도한 안전 및 취약 동작, 실행 격리, 방어 모듈 장착 구조와 재현 절차가 준비됐다는 뜻이다. 자율 AI 공격자의 대상별 성공률과 특정 방어의 일반적인 효과는 이 판정에 포함하지 않는다. 합성 모듈은 실제 인터넷 웹의 취약점 분포를 대표하지 않는다.

미완성 외부 방어의 코드와 효과는 이 릴리스 판정에서 제외했다. 등록 방어를 비교 조건으로 쓰려면 별도 컴포넌트 완성, 무방어 자격 시험, 사전 고정한 표본 수의 반복 실험과 독립 검토가 필요하다.
