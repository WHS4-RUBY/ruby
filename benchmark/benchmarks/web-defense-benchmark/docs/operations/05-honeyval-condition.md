# Honeyval 조건 실행 절차

확인일: 2026-09-03

## 1. 이 조건이 무엇인가

무방어 Plain Claude R1과 **모든 조건을 같게 두고 방어 장치 하나만 추가한** 실행이다. 추가된
것은 `defense/honeyval-defense`의 Honeyval 기만 게이트웨이이며, 공격자는 애플리케이션 소켓 대신
게이트웨이 주소를 받는다.

방어 구현은 벤치마크 디렉터리에 복사하지 않고 가져다 쓴다. 실행기가 `defense/honeyval-defense/src`를
`sys.path`에 추가하고 `honeyval.gateway`만 import한다.

## 2. 무방어와 같게 유지한 조건

| 항목 | 값 |
|---|---|
| 대상 | 무방어와 동일한 24개 target_id |
| 공격자 | Claude Code `opus` 선택자 |
| 추론 수준 | medium |
| 공격 프롬프트 | Plain Claude R1과 동일한 `build_prompt` |
| 공격자 전용 안내 문서 | 사용하지 않음 |
| 취약점 정보 | 이름, 경로, 정답 페이로드 제공하지 않음 |
| 대상별 제한 시간 | 1,800초 |
| 초기화 | 시험마다 새 대상, 새 데이터, 새 세션, 새 작업공간 |
| 범위 통제 | 무방어와 동일한 `ScopedHTTPProxy`, 첫 시험부터 적용 |
| 성공 판정 | 무방어와 동일한 비공개 평가기 |
| HTTP 계수 | 무방어와 동일한 컨테이너 로그 계수기 |

## 3. 실행

```powershell
cd benchmark\benchmarks\web-defense-benchmark\app
.\.venv\Scripts\python.exe tools\run_honeyval_benchmark.py `
  --run-id honeyval-all24-r1-20260903 `
  --output evaluation\honeyval-all24-r1-20260903 `
  --repetition 1 `
  --timeout 1800 `
  --parallel 2 `
  --max-defense-calls 30 `
  --max-calls-per-template 5 `
  --defense-model haiku `
  --defense-effort low `
  --defense-concurrency 2
```

대상을 지정하지 않으면 등록부의 24개 전부를 실행한다. 특정 대상만 다시 돌리려면
`--targets`에 나열한다.

`--attacker-config-dir`와 `--defense-config-dir`는 구독 계정을 나누어 쓸 때 사용한다. 값은
`CLAUDE_CONFIG_DIR`로 전달된다.

## 4. 재개

실행기는 `trials/<대상>-r<반복>/result.json`이 이미 있으면 그 대상을 다시 호출하지 않고 저장된
결과를 반환한다. 결과 파일은 임시 파일에 쓰고 교체하는 방식으로 저장하므로 중간에 끊겨도 부분
파일이 남지 않는다. 같은 명령을 다시 실행하면 남은 대상만 이어서 수행한다.

## 5. 결과 정리

```powershell
.\.venv\Scripts\python.exe tools\make_honeyval_report.py `
  --run honeyval-all24-r1-20260903 `
  --output evaluation\honeyval-all24-r1-20260903-report

.\.venv\Scripts\python.exe tools\analyze_defense_ledgers.py `
  --run honeyval-all24-r1-20260903 `
  --output evaluation\honeyval-all24-r1-20260903-report\defense-activity.json
```

`make_honeyval_report.py`는 무방어 시험 기록을 읽기 전용으로 열어 대상별로 짝지어 비교하고,
`comparison.json`, `comparison.md`와 `manifest-sha256.json`을 만든다. 무방어 실행 디렉터리는
수정하지 않는다.

## 6. 산출물

| 경로 | 내용 |
|---|---|
| `run-seal.json` | 공격자와 방어 설정, 대상 목록, 방어 소스 파일별 SHA256 |
| `summary.json` | 대상별 결과와 합계, 각 대상 완료마다 갱신 |
| `trials/<대상>-r<반복>/result.json` | 요구된 전체 필드 |
| `trials/<대상>-r<반복>/prompt.txt` | 그 시험에서 실제 사용한 공격 프롬프트 |
| `trials/<대상>-r<반복>/events.jsonl` | 공격자 CLI 원본 스트림 |
| `trials/<대상>-r<반복>/defense-ledger.jsonl` | 방어 결정 감사 기록 |

## 7. 주의

- 방어 모델 호출은 공격자의 제한 시간 안에서 일어난다. 따라서 방어 지연이 공격자의 가용 시간을
  줄인다. 결과를 읽을 때 `defense_latency_seconds_total`을 반드시 함께 본다.
- 결과 해석은 `research/Honeyval/RUBY웹-벤치마크-결과-20260903.md`와
  `research/Honeyval/RUBY웹-공격방어-기록분석-20260903.md`를 따른다.
- `defense_model_calls`는 실제 CLI 호출 수이고 `defense_budget_used`는 기만 시도 횟수다.
  재생성이 있으면 앞의 값이 더 크다.
- 예산 상한에 닿은 뒤의 거절 응답은 기만 없이 그대로 전달된다.
