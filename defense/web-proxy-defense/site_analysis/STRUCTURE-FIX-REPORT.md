# 분석기 구조 수정 보고

작성일: 2026-10-10

요청한 1~8번 구조 변경을 구현했다. 실행 검증은 `python -B -m py_compile`과 기존 분석기의 `--dry-run`으로 수행했다. 아래 합성 점검은 임의 문자열과 메모리 안의 모델, 브라우저 대체 객체를 사용했다. 실제 사이트 관찰 결과나 실제 모델 응답이 아니다.

## 바꾼 파일과 행

행 번호는 이 보고서를 작성할 때의 코드 기준이다. 모든 수정은 `defense/web-proxy-defense/site_analysis/` 안에 있다.

| 파일과 시작 행 | 변경 | 해결하는 원인 |
| --- | --- | --- |
| `windows.py:12` | `find_text`: 대소문자를 유지한 문자열 검색, 참조별 offset과 개수, 전체 개수, 0건 표시 | 긴 HTML이나 JSON의 뒤쪽 위치를 찾을 수 없었던 문제 |
| `windows.py:40` | `replace_leaves`: 문자열 값에만 정확한 부분 문자열 치환, 객체 키와 다른 자료형 보존 | 가림 모델이 답 전체를 다시 써서 근거, 해시, 기술 사실, 미독 표시를 잃는 문제 |
| `windows.py:111` | 문맥 색인을 먼저 배치하고 큰 색인은 부분 창으로 제공, 전체 참조 유지. 표본 URL, 원문 참조, 전체 길이, 보존 길이, 단위, 잘림과 route별 표본 수를 manifest에 추가 | 수집 묶음이 표본에 밀리고 원문의 범위가 드러나지 않았던 문제 |
| `observer.py:205` | 문서 요청의 `sent` 기록으로 방문 횟수 집계, 색인을 읽은 창과 표본보다 먼저 배치 | 화면 이동 이벤트와 실제 보낸 요청의 횟수가 달랐던 문제 |
| `observer.py:256` | 요청당 JSON 한 줄의 관찰 색인과 요청 원문 참조 생성 | 응답 코드, 헤더 이름, 쿠키 이름, 본문 참조를 모델이 쉽게 찾지 못했던 문제 |
| `observer.py:281` | 읽기와 찾기가 표본, 원문 버퍼, 수집 묶음, `provided-context`, 현재 대화 버퍼를 공통으로 사용 | 읽을 수 있는 관찰과 검색 대상이 달라지는 문제 |
| `observer.py:408`, `observer.py:431` | 요청 객체 식별자로 요청과 응답 연결, 연결용 필드는 비공개로 기록 | 같은 URL을 다시 요청했을 때 응답 기록이 섞일 수 있는 문제 |
| `observer.py:531`, `observer.py:918`, `analyze.py:998` | 표본 생성 이름을 `sample-N`으로 변경. 원문 버퍼의 `screen-N`, `source-N` 유지 | 표본과 원문 버퍼가 같은 참조 이름을 쓰던 문제 |
| `observer.py:600`, `observer.py:778` | 브라우저와 HTTP 둘러보기에서 `_find` 지원. `tool="find"`도 지원. click 결과와 inspect_form 결과를 피드백에 기록 | 둘러보기 도구 결과가 다음 판단에 전달되지 않았던 문제 |
| `analyze.py:217` | 가림의 읽기와 찾기를 답 처리 뒤에도 실행하고 다음 호출에 전달. `replacements`를 `value`보다 먼저 적용 | 가림 중 원문 확인과 부분 치환이 불가능했던 문제 |
| `analyze.py:383` | 축별 `final=false`를 부분 답으로 저장하고 pending으로 재질문. 읽기나 찾기가 있으면 확정을 미루고 결과를 다음 호출에 전달 | 유효한 답이 들어오는 순간 묶음이 끝나 추가 관찰이 반영되지 않았던 문제 |
| `analyze.py:389`, `observer.py:234` | 축 묶음의 읽기 버퍼와 창을 그 묶음 상태에 저장. 읽은 창과 도구 오류를 `observer.feedback`에 추가하지 않음 | 같은 창이 문맥에 두 번 들어가고 다음 묶음까지 전달되던 문제 |
| `analyze.py:661` | 회차별 축 답 직렬화 길이 합이 창의 1/3 안에 들도록 pending 분할, 최대 6축. 문맥 재조립 때 축 수를 다시 줄일 수 있게 처리 | 최대 16축을 한 번에 합치면서 사실이 누락되던 문제 |
| `analyze.py:672`, `analyze.py:2377` | 비공개 회차 관찰을 합치기에 전달. 회차별 색인, 버퍼를 `run:N:` 이름 공간으로 제공. `axis_run`에도 관찰 참조 추가 | 합치기 모델이 회차 원문을 다시 확인하지 못했던 문제 |
| `record.py:145` | `answers`와 대응하는 `run_indices`에 모든 회차를 남김 | union과 consensus가 일부 회차 답을 기록에서 버리던 문제 |
| `record.py:72` | `_private_`로 시작하는 관찰 내부 필드를 공개 사실에서 제외 | 요청 연결용 식별자 등 내부 기록이 공개 사실에 섞이는 문제 |
| `catalog.py:56`, `catalog.py:67` | 도구와 선택 필드를 안내 스키마에 추가. 축 상태, 설명, 근거, confidence의 모양을 검사해 답을 거부하는 처리 제거 | 모델 판단이 출력 형식 검사에 막히는 문제 |
| `analyze.py:43`, `analyze.py:2266`, `model.py:114`, `model.py:300` | `--reasoning-effort`, 기본값 `high`, Codex의 `-c model_reasoning_effort="값"` 인수 추가 | 추론 강도를 실행 옵션으로 전달할 수 없었던 문제 |
| `analyze.py:824`, `analyze.py:1085` | 기존 dry-run의 예전 기대값을 변경하고 1~6번 합성 점검 추가. 7번과 부분 답 재개도 점검 | 새 구조를 원본이나 모델 실행 없이 확인해야 하는 조건 |

`prompts.py`와 `axes.json`에는 이 작업에서 쓰기를 수행하지 않았다. 두 파일은 작업 중 외부에서 내용이 바뀌었고, 최종 dry-run은 당시 파일을 읽어 53축으로 통과했다. 별도 테스트 파일은 만들지 않았다.

## 동작과 보존 범위

찾기는 정규식을 사용하지 않는다. 겹치는 일치도 센다. `max`가 없으면 참조마다 앞쪽 20개 위치를 주고 전체 개수는 끝까지 센다. `max=0`이면 개수만 준다. 문자열 버퍼 offset은 문자 단위이며, 바이트 버퍼는 찾을 문자열을 UTF-8로 인코딩해서 바이트 위치를 반환한다. 찾기 결과에는 읽은 창이 추가되지 않는다. 결과가 크면 기존 문맥 조립기가 피드백의 전체 내용을 참조로 보존한다.

색인은 `observation:index`로 읽을 수 있다. 각 줄은 방법, URL, 전송 여부, 상태 코드, 기록된 리다이렉트 사슬 길이, Content-Type 값, 헤더 이름, Set-Cookie 이름, 요청 원문 참조, 응답 묶음 참조와 위치, route별 본문 참조와 보존 크기를 담는다. URL과 색인은 모델용 비공개 문맥에만 추가했다. 요청과 응답은 같은 요청 객체의 식별자로 연결한다. 본문 수집 기록에 요청 객체 식별자가 없는 경우에는 같은 route의 본문들을 `route_bodies`에 각각 남긴다. 같은 route를 여러 번 요청했다는 이유만으로 어느 본문이 특정 요청의 본문인지 단정하거나 크기를 합산하지 않는다. 없는 측정값은 `null`로 남긴다.

큰 색인은 창의 약 1/4까지 앞부분을 제공하고 전체 참조를 남긴다. 상태와 manifest 자체가 창을 넘으면 기존 `state_ref`, `manifest_ref` 처리를 유지한다. 표본의 `truncated`는 표본 JSON이 문맥에서 생략되거나 잘렸는지 나타낸다. `originals[].truncated`는 그 표본의 원문이 잘렸는지 나타내며, `total`, `retained`, `unit`도 같이 제공한다.

`final=false` 답은 폐기하지 않는다. `provisional_axes`, 부분 답, 묶음 메모, 읽은 창, 찾기 피드백을 체크포인트에 남긴다. 답과 도구 요청이 같이 오면 답을 보존하고 재검토 대상으로 둔다. 읽기나 찾기 없이 답이 오고 `final`이 없으면 기존처럼 확정한다. 누락된 축 식별자는 다시 묻지만, 존재하는 축 답의 모양은 거부하지 않는다. 실행할 도구의 참조와 offset 처리, 모델의 명시적인 공개 결정과 읽기 전용 결정은 계속 따른다.

가림에서 `safe=true`이고 `replacements`가 있으면 원래 칸 값의 문자열 잎에 순서대로 `str.replace`를 적용한다. `value`는 무시한다. 빈 치환 목록은 원문을 유지한다. `value`만 있거나 공개 여부만 판단한 응답은 기존 동작을 유지한다. `safe=false`는 비공개다. 치환 후에도 기존 자격정보 보호 처리를 거친다.

합치기는 한 축의 답 자체가 1/3 한도를 넘는 경우 그 축 하나를 대상으로 호출하고 원문 참조를 남긴다. `run:N:` 접두사는 회차별로 같은 `source-1`이나 `sample-1`이 서로 섞이지 않게 한다. 공개 기록의 `run`과 합치기 입력의 `axis_run.run`은 유지했다. record의 `answers`는 모든 회차를 보존하며, 기존 `disposition`과 최종 대표 답 선택 규칙은 유지했다.

기존 재개, 비용 상한, `model.py`의 문맥 크기 재조립, 파일 교체 재시도, 공개 여부만 확인하는 가림 응답, 권한별 합치기, 작업 메모, `_notes`, 회차 번호 전달을 유지했다. `resume.py`와 `session_prepare.py`는 수정하지 않았다. 추론 강도는 Codex 인수에만 들어간다. Claude 인수 목록은 별도로 구성하므로 이 옵션을 전달하지 않는다. 실제 공급자 실행은 하지 않았으며, 인수 전달은 코드를 검토했다.

## 프롬프트에 넣을 문장

아래는 감독자가 각 단계의 프롬프트에 넣을 수 있는 문장이다. 이 보고서에서는 프롬프트 파일을 수정하지 않았다.

### `_find`와 원문 읽기

> 문자열의 위치가 필요하면 `{"_find":{"text":"찾을 문자열","refs":["source-2"],"max":20}}`을 반환하라. `refs`를 생략하면 현재 읽을 수 있는 모든 참조를 검색한다. `max`를 생략하면 참조마다 앞쪽 20개 위치와 전체 개수를 받는다. 대소문자는 그대로 비교하며 정규식은 사용할 수 없다. 0건 결과도 명시된다.

> 찾기 결과는 원문을 읽은 창이 아니다. 근거를 확인하려면 반환된 참조와 offset으로 `_read_sample`을 요청하라. 문자열 offset은 문자 단위, 바이트 버퍼 offset은 바이트 단위다. 바이트 버퍼의 텍스트를 읽으려면 `_read_sample`에 필요한 encoding을 지정하라. 읽지 않은 범위를 없다고 판단하지 말라.

> 먼저 `observation_index_ref`의 요청 색인과 `sample_refs`의 원문 메타데이터를 확인하라. 일부만 들어온 색인과 생략된 수집 묶음은 참조로 다시 읽을 수 있다. 합치기에서는 `run_observations`와 각 `axis_run`의 `observation_index_ref`, `buffer_refs`를 사용하라. 제공된 `run:N:` 참조 이름을 그대로 사용하라.

> 둘러보기에서도 같은 `_find` 응답을 사용할 수 있다. 기존 행동 형식을 사용할 때는 `tool="find"`와 JSON으로 인코딩한 검색 인수를 반환하라. 읽기 전용 및 확인 플래그는 기존 행동 규칙을 따르라.

### `final`

> 추가 관찰이 필요한 축 답에는 `"final":false`를 붙여라. 그 답은 부분 답으로 보존되고 다음 호출의 pending 목록에 다시 들어간다. 읽기나 찾기를 함께 요청했다면 다음 호출에서 도구 결과와 읽은 창을 확인한 뒤 답을 갱신하라. 도구 요청이 없고 `final`이 없는 답은 확정된다.

### `replacements`

> 가림은 필요한 문자열 조각을 골라 `{"id":"칸 식별자","safe":true,"replacements":[{"find":"원문 조각","replace":"{자리표시}"}]}`로 반환할 수 있다. 치환은 원래 칸 값의 문자열 잎에만 정확히 적용되며 객체 키, 숫자, 다른 문자열은 유지된다. `replacements`가 있으면 `value`보다 우선한다. 참조, 해시, 기술 사실, 미독 표시를 보존하라. 비공개 칸은 `safe=false`로 표시하라.

### `sample-N`과 회차

> `sample-N`은 표본 전체의 참조이고 `screen-N`, `source-N`은 원문 버퍼의 참조다. 서로 다른 참조이므로 혼용하지 말라. 표본 URL, route별 표본 수, 원문 참조와 전체 길이는 `sample_refs`에서 확인하라. 회차 번호는 공개 회차 기록의 `run`과 합치기 입력의 `axis_run.run`에 있으므로 근거 문자열에 별도 회차 표기를 덧붙일 필요가 없다.

## 실행한 확인과 결과

실행 위치는 `defense/web-proxy-defense`다.

```powershell
python -B -m py_compile site_analysis/analyze.py site_analysis/catalog.py site_analysis/model.py site_analysis/observer.py site_analysis/record.py site_analysis/resume.py site_analysis/windows.py
python -B -m site_analysis.analyze --origin-url https://example.invalid/ --out site_analysis/structure-dry-unused.json --dry-run
python -B -m site_analysis.analyze --origin-url https://example.invalid/ --out site_analysis/structure-dry-unused.json --dry-run --provider claude --reasoning-effort medium --context-chars 16000 --sample-chars 16000
```

최종 세 명령 모두 종료 코드 0을 확인했다. 기본 실행의 출력은 `reasoning_effort="high"`, 다른 옵션 실행은 `provider="claude"`, `reasoning_effort="medium"`였다. 두 dry-run 모두 `structure_fix_synthetic_checks="passed"`, `network_requests=0`, `model_calls=0`, `files_written=0`을 출력했다. 지정한 `structure-dry-unused.json` 파일이 생성되지 않은 것도 확인했다. `py_compile`의 바이트코드 파일은 대상 디렉터리 안에 생성될 수 있다.

수정 중 dry-run은 예전 플래그 자료형 거부 기대값, 원문 메타데이터 점검 위치, 합성 점검의 함수 이름을 가린 지역 변수, 실제 카탈로그의 축 수에 의존한 분할 점검 때문에 실패했다. 해당 점검과 변수를 수정한 뒤 최종 기본 실행과 옵션 실행이 통과했다.

| 요청 | 합성 확인 | 결과 |
| --- | --- | --- |
| 1. 찾기 | 겹치는 일치, 대소문자, 앞부분 위치 제한과 전체 개수, 바이트 위치, 0건, 축 분석과 가림과 합치기와 둘러보기의 피드백, 찾기 결과가 읽은 창을 만들지 않음 | 통과 |
| 2. 문맥 | 색인이 첫 관찰 항목인지, 헤더 이름과 쿠키 이름과 본문 보존 크기, 표본 URL과 원문 길이와 route별 개수, 큰 색인의 전체 참조 보존, 다음 묶음으로 창이 넘어가지 않음 | 통과 |
| 3. 답 고정 | 모든 축 답과 도구 요청이 같이 온 뒤 재호출, 22,000자 뒤쪽의 찾기와 읽기, `final=false` 부분 답과 비용 중단 후 재개 | 통과 |
| 4. 치환 가림 | 중첩 객체와 배열 문자열의 정확한 치환, 반복 문자열 치환, value보다 치환 우선, 참조와 해시와 미독 표시와 숫자 보존, 빈 치환, 결정만 온 응답, 비공개 결정 | 통과 |
| 5. 참조 | `sample-1`과 `source-1`의 독립 읽기와 찾기, manifest의 원문 참조 | 통과 |
| 6. 합치기 | 최대 6축과 길이 1/3 분할, 실제 pending 호출의 6축과 1축 분리, 모든 회차 answers 유지, 회차별 같은 버퍼 이름 분리, 색인 참조 전달, 21,000자 뒤쪽 읽기 | 통과 |
| 7. 둘러보기 | click과 inspect_form 결과 피드백, 차단된 요청과 fetch와 화면 이벤트를 제외한 실제 문서 요청 횟수 | 통과 |

기존 dry-run의 재개와 비용 경계, 문맥 재조립, 가림 우선순위, 작업 메모 저장과 공개 처리, 권한별 합치기 점검도 통과했다. 실제 모델이 관찰을 더 잘 활용하는지는 이번 합성 점검으로 확인한 사실이 아니다.

## 실행하지 않은 것

원본 접속, 실제 HTTP 요청, 실제 브라우저 실행, 실제 모델 및 공급자 CLI 호출, Docker 명령을 실행하지 않았다. 실제 자격정보나 세션 파일 값을 읽지 않았다. git commit, push, stash를 실행하지 않았다. 별도 테스트 파일을 만들거나 대상 디렉터리 밖의 코드를 수정하지 않았다. 공급자별 실제 추론 강도 동작과 실제 사이트에서의 분석 품질은 실행 검증하지 않았다.
