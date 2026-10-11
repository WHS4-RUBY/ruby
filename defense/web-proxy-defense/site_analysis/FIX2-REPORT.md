# 둘러보기 반복 결함 수정 보고

수정 범위는 `defense/web-proxy-defense/site_analysis/`다. 현재 상태와 방문 기록을 먼저 전달하고 최신 표본을 이어 넣도록 문맥을 바꿨다. 둘러보기에는 총 비용 상한의 기본 0.5를 배정했다. 모델이 관찰의 충분성을 판단해 멈추며, 가림 호출 없이도 결정 메타데이터가 즉시 저장된다. 원본 WordPress에서의 반복 감소와 축 분석 완료 여부는 재실행하지 않아 아직 확인하지 않았다.

## 원인 확인

제공된 두 JSON을 읽기 전용으로 집계했다. 원본 사이트와 중계에는 접속하지 않았다. 아래 수치는 파일을 읽은 시점의 기록이며, 진행 중인 2회차의 최종 결과를 뜻하지 않는다.

| 기록 | 확인한 내용 |
| --- | --- |
| `../../../.tmp/site-analysis/wordpress-analysis.failed-1.json` | `navigation` 호출 146회, 이동 이벤트 44개, 서로 다른 `route` 해시 13개, `group_*` 호출 0회, 축 51개 모두 `못 봄`. 비용 25.0219476달러, `stop_reason=cost_budget`. `model_decisions`의 146개 항목 모두 이유가 `cost_budget`인 가림 실패 표식이었다. |
| `../../../.tmp/site-analysis/wordpress-analysis.json` | 읽은 시점에 `navigation` 호출 25회, 이동 이벤트 25개, 서로 다른 `route` 해시 3개, `model_decisions` 0개, 축 51개 모두 `못 봄`. 페이지 상한은 25였다. |

1회차 `model_calls.input_context_chars`에서 이동 호출 입력의 최솟값은 208,492자, 최댓값은 534,270자였다. 2회차는 27,800~27,932자였다. 이는 저장된 입력 길이 계측값이며 실제 공급자 토큰 수와 같은 단위가 아니다. 표본 페이지와 글 하나를 번갈아 열었다는 현상은 사용자가 제공한 중계 관찰이다. 이 작업에서는 중계 요청 원문을 다시 분석하지 않았다.

수정 전 `observer.model_context()`는 전체 JSON이 창보다 길면 `context_snapshot[:limit // 3]`을 전달했다. `context()`의 키 순서는 초기 표본을 현재 이동, 열린 페이지와 예산보다 앞에 두었다. 따라서 큰 표본 하나가 창을 채우면 현재 상태가 사라지고 초기 페이지가 계속 보이는 구조였다. 최근 피드백 하나는 별도로 전달했지만 전체 방문 주소와 현재 페이지를 복구하지 못했다.

`model._call()`도 입력이 창보다 길면 전체 JSON의 앞부분으로 다시 교체했다. 실행 간 합치기는 `raw[:limit // 3]`, 표본 읽기는 창의 절반, 개인정보 가림 묶음도 창의 절반을 사용했다. 결정 전체는 관찰 종료와 축 처리 뒤에 가림 호출을 통과해야 기록됐고, 사실 가림이 축 분석보다 먼저 비용을 썼다. 둘러보기 비용과 축 분석 비용을 나누는 경계도 없었다.

이 코드 경로는 관찰된 반복 현상과 일치한다. 당시 모델이 각 주소를 고른 실제 이유는 남은 기록으로 복원할 수 없다.

## 바꾼 파일과 행

행 번호는 수정 후 소스의 시작행이다.

| 파일과 행 | 변경과 근거 |
| --- | --- |
| `observer.py:135` | 현재 실제 URL, 선택한 페이지 번호, 열린 페이지, 실제 이동 URL 전체와 횟수, 최근 피드백 상태와 참조, 요청과 페이지 및 시간 예산, 비용 예산, 축 질문을 먼저 구성한다. 방문 횟수는 관찰한 이동 이벤트를 세며 프레임 이동도 포함한다. 새 방문 집계는 모델 입력에만 있고 공개 기록에 추가하지 않는다. |
| `windows.py:11`, `windows.py:22` | 새 공통 창 구성 함수다. 큰 피드백과 교정 답은 원문 참조를 보존하고 먼저 전달한다. 이어 최신 표본부터 직렬화한 JSON 길이에 맞춰 넣는다. 전체 참조는 `sample_refs`, 빠진 표본은 `omitted_sample_refs`, 전달한 표본은 `included_samples`다. 일부만 들어가면 참조, offset, 길이, 전체 길이와 잘림 여부를 표시한다. 필수 상태와 참조를 앞부분 절단으로 대체하지 않는다. |
| `observer.py:158` | 응답, 요청, 실시간 관찰 같은 자원 목록은 각각 전체 목록 참조를 제공하며 최신 행을 앞에 둔다. 자원 행마다 긴 참조 메타데이터를 반복해 참조 목록만으로 창이 차는 것을 줄인다. 모든 행은 읽을 수 있고 웹 내용의 중요도를 코드가 판단하지 않는다. |
| `observer.py:170`, `observer.py:195`, `windows.py:68` | 원문과 원바이트는 메모리에 남긴다. 표본 JSON 참조와 원문 참조를 모두 `read_sample`로 읽는다. 바이트 미리보기의 고정 1/4 배분과 읽기 창의 고정 1/2 상한을 없앴다. 실제 JSON 이스케이프와 base64 확장 길이를 계산한다. UTF-8 창 끝의 불완전한 문자는 다음 바이트 창에 남기고, offset과 길이의 단위를 표시한다. |
| `model.py:95`, `model.py:107`, `model.py:127`, `model.py:217` | 이동 호출과 그 재시도의 비용을 `browse_spent`로 별도 합산한다. 각 호출과 재시도 전에 `ceiling * browse_share`와 비교한다. 상한에 도달하면 `browse_budget`을 반환하며 전체 모델의 `stop_reason`을 설정하지 않는다. 다른 목적의 비용은 이동 몫에 합산하지 않는다. |
| `analyze.py:35`, `analyze.py:67`, `analyze.py:597`, `analyze.py:628` | `--browse-share` 기본 0.5를 추가했다. 0보다 크고 1보다 작은 유한 숫자만 받는다. 모델에 전달하고 전체 기록의 `metrics.browse_share`, `browse_cost_usd`, `browse_max_usd`를 저장한다. 비용 몫은 모든 실행의 합계에 적용한다. |
| `observer.py:201`, `observer.py:478`, `observer.py:526` | 브라우저와 HTTP 대체 경로 모두 새 이동 호출을 끝내고 축 분석으로 넘긴다. `read_sample`만 수행한 뒤에는 같은 화면 표본을 다시 만들지 않는다. 이미 선택한 이동은 가능한 범위에서 마치고 결과를 관찰한다. |
| `observer.py:602` | HTTP 대체 경로에도 받은 실제 주소와 이동 이벤트를 넣는다. 브라우저 실패 뒤 HTTP 경로로 넘어갈 때 이전 브라우저 페이지를 현재 페이지로 쓰지 않도록 했다. |
| `prompts.py:25`, `prompts.py:42`, `analyze.py:240` | 관찰이 축 질문에 충분하거나 같은 종류의 페이지를 더 봐도 답이 실질적으로 달라지지 않는다고 모델이 판단하면 `stop`하도록 지시를 바꿨다. 둘러보기 입력에는 축의 ID와 질문만 짧게 제공한다. 코드로 중복 페이지를 금지하거나 관찰 충분성을 판정하지 않는다. |
| `observer.py:206`, `observer.py:233`, `observer.py:441`, `observer.py:526`, `analyze.py:254`, `analyze.py:260` | `decision_events`에 결정 번호, 도구 이름, 대상 URL의 route 해시, 결과 상태와 이유 유무만 남긴다. 도구 이름은 실행기가 제공하는 이름 또는 `unknown`이다. 행동 전에는 `pending`, 완료 뒤에는 `completed`, `rejected`, `failed`, 전송하지 못한 HTTP 이동에는 `not_sent`를 저장한다. 대상이 단일 경로가 아닌 읽기와 `stop`은 route가 null일 수 있다. 인자, selector, 실제 URL과 이유 원문은 쓰지 않는다. 결정 직후와 결과 후 체크포인트에 저장해 마지막 가림 호출을 기다리지 않는다. 기존 `model_decisions`는 전체 결정의 가림 결과로 따로 유지한다. |
| `analyze.py:240` | 관찰 뒤 모든 축 분석 묶음을 먼저 실행하고 축 답 가림, 사실 가림, 전체 결정 가림 순으로 진행한다. 예약한 비용이 사실 문자열 가림에서 먼저 소진되는 일을 막는다. 가림 전 축 답은 메모리에만 두며 체크포인트에는 공개하지 않는다. |
| `analyze.py:196`, `analyze.py:206`, `analyze.py:327` | 개인정보 묶음은 `cells` 포장까지 포함한 실제 JSON 길이로 전체 창을 사용한다. 축 교정은 같은 상태 우선 문맥과 원문 참조를 사용한다. 실행 간 합치기도 전체 대기 축과 최근 피드백을 먼저 보존하고 최신 실행부터 전달하며 빠진 축별 실행 답은 참조로 읽는다. 기존 의미 합의 정책은 유지한다. |
| `model.py:174` | 어댑터의 두 번째 앞부분 절단을 삭제했다. 이미 구성한 상태, 교정 진단이나 하나로 나눌 수 없는 개인정보 칸을 숨기지 않는다. 실제 전달 길이와 `context_window_exceeded`를 호출 장부에 표시한다. |
| `analyze.py:421`, `analyze.py:496` | 기존 dry-run에 이 결함의 회귀 확인을 넣었다. 별도 테스트 파일과 분석 결과 파일은 만들지 않았다. |
| `SCHEMA.md:7`, `SCHEMA.md:21`, `SCHEMA.md:29`, `SCHEMA.md:50`, `SCHEMA.md:64` | 모델의 충분성 판단, 상태와 참조의 문맥 구조, 이동 비용 몫, 결정 메타데이터와 저장 순서를 문서화했다. |
| `FIX2-REPORT.md:1` | 이번 변경의 근거와 실제 확인 범위를 작성했다. |

GET/HEAD, 폼 전송 금지, 외부 최상위 이동과 사람 확인 경계, 비용 및 같은 실패 반복 상한은 유지했다. 축의 답, 다음 표본 선택과 반복 페이지의 유용성은 모델이 판단한다. 원문 미리보기는 참조와 잘림 표시가 함께 있고 전체 원문을 읽을 수 있어 유지했다. 유효한 축을 보존하는 개인정보 실패 분할도 입력을 버리는 절단이 아니므로 유지했다.

## 실행한 확인

아래 명령의 작업 디렉터리는 저장소의 `defense/web-proxy-defense/`다. 소스 실행 검증은 `py_compile`과 `--dry-run`만 수행했다.

```powershell
python -B -m py_compile site_analysis/__init__.py site_analysis/catalog.py site_analysis/model.py site_analysis/prompts.py site_analysis/record.py site_analysis/windows.py site_analysis/observer.py site_analysis/analyze.py
python -B -m site_analysis.analyze --origin-url http://target.test/ --out site_analysis/offline-analysis.json --dry-run
python -B -m site_analysis.analyze --origin-url http://target.test/ --out site_analysis/offline-analysis.json --runs 2 --rates ../../.tmp/installer-targets/wordpress/settings.json --max-cost-usd 25 --browse-share 0.4 --context-chars 80000 --max-pages 25 --login-env SITE_ANALYSIS_DRY_RUN_UNSET --dry-run
python -B -m site_analysis.analyze --origin-url http://target.test/ --out site_analysis/offline-analysis.json --rates ../../.tmp/installer-targets/wordpress/settings.json --max-cost-usd 25 --browse-share 0.5 --context-chars 80000 --max-pages 25 --login-env SITE_ANALYSIS_DRY_RUN_UNSET --dry-run
```

모두 종료 코드 0이었다. 마지막 소스 수정 뒤에도 8개 모듈의 컴파일과 0.5, 80,000자, 25페이지 설정의 dry-run을 다시 실행해 통과했다. 단가 파일의 형식과 선택 모델의 설정은 확인했으며 공급자의 최신 가격은 조회하지 않았다.

`--browse-share 0`, `--browse-share 1`, `--browse-share nan`을 각각 같은 입구의 `--dry-run`으로 실행했다. 세 경우 모두 `ValueError`로 거부되고 비정상 종료했다.

최종 dry-run에서는 아래 항목이 통과했다.

- 현재 URL과 선택한 페이지, 전체 방문 주소 및 반복 횟수, 피드백, 예산, 축 질문 보존.
- 큰 초기 표본이 있어도 최신 표본을 먼저 넣고 80,000자 이내로 전달하며 빠진 표본 참조를 남김.
- 빠진 표본 JSON과 미리보기 밖 원문 뒤쪽을 실제 메모리 참조로 읽음.
- JSON 이스케이프, base64와 UTF-8 바이트 창의 길이 및 잘못된 범위 처리.
- 필수 상태조차 들어갈 수 없는 작은 창에서 상태와 전체 참조를 보존하고 초과를 표시함.
- 이동 비용 12.5달러에서 다음 이동 호출을 실행 전에 거부하며 전체 모델은 계속 사용할 수 있음. 축 분석 비용을 이동 비용에 합산하지 않음.
- 결정 메타데이터에 원본 인자와 이유 값이 포함되지 않음. 알 수 없는 도구 이름도 값이 그대로 기록되지 않음.
- 로컬 고정 응답 객체로 실제 이동 실행기 경로를 거쳐 `pending → rejected`, `pending → completed` 체크포인트와 모델의 `stop` 처리를 확인함. 공급자 호출은 하지 않음.
- 기존 51개 축 형식, 축 하나의 오류 격리, 의미 합의에 따른 합치기, 같은 실패 반복 상한, GET/HEAD와 POST 및 외부 최상위 이동 경계.

최종 출력의 `network_requests`, `model_calls`, `files_written`은 모두 0이고 `login_values_read=false`였다. 지정 dry-run 출력 파일과 `.dry-unused` 모델 디렉터리가 생성되지 않았음을 파일 존재 확인으로 확인했다. `py_compile`은 모듈 안의 `__pycache__`에 컴파일 파일을 만든다.

기존 기록은 PowerShell로 읽고 집계했으며 소스 검색과 확인에는 `rg`, `Get-Content`, 파일 존재 확인을 사용했다. 시작과 끝의 `git status --short`에서 범위 밖의 기존 변경 목록이 동일함을 확인했다. 기록 파일에는 쓰지 않았고 진행 중인 프로세스를 조작하지 않았다.

## 실행하지 않은 것과 남은 제한

원본 HTTP 접속, 중계 접속, Playwright 실행, 실제 모델 호출과 개인정보 가림, 로그인, Docker 명령, 의존성 설치, pytest와 별도 테스트 실행, git commit, push, stash는 하지 않았다. `site_analysis/` 밖의 코드를 수정하지 않았다. 별도 테스트 파일은 만들지 않았다.

실제 모델이 충분성을 판단해 멈추는지, WordPress에서 서로 다른 페이지를 얼마나 관찰하는지, 축 51개를 어느 정도 완성하는지, 실제 비용과 가림 정확성은 미확인이다. 시간 예산은 기존대로 관찰과 분석에 공통으로 적용한다. 이동 비용 몫은 전체 실행에 공통이며 실행별로 나누지 않는다.

공급자 사용량은 호출 후에 정산되므로 진행 중인 한 호출이 이동 몫이나 총 상한을 넘을 수 있다. 다음 이동 호출과 그 재시도는 막지만 한 호출 안의 과금을 강제로 끊지는 않는다. 필수 상태와 전체 참조만으로 창을 넘거나 하나의 개인정보 칸이 너무 크면 정보를 숨기지 않고 전체를 전달하며 초과를 표시한다. 이 경우 공급자 문맥 수용 여부는 실제 모델을 호출하지 않아 확인하지 않았다.

## 원본 WordPress 재실행 명령 한 줄

작업 디렉터리는 `defense/web-proxy-defense/`다. 진행 중인 결과 파일과 겹치지 않도록 별도 출력 이름을 사용한다. 아래 명령은 작성만 했으며 실행하지 않았다.

```powershell
$env:SITE_ANALYSIS_PROXY='http://127.0.0.1:18090'; python -B -m site_analysis.analyze --origin-url http://target.test/ --out ../../.tmp/site-analysis/wordpress-analysis.fix2.json --runs 2 --model gpt-6-sol --rates ../../.tmp/installer-targets/wordpress/settings.json --max-cost-usd 25 --browse-share 0.5 --context-chars 80000 --max-pages 25 --same-failure-limit 8
```
