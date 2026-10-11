# 작업 메모, 운영자 세션 관찰, 권한별 합치기 구현 보고

2026-10-10. 작업 메모의 전달과 비공개 저장, 운영자 세션 준비 도구, 세션 관찰, 권한별 합치기를 구현했다. 검증은 `py_compile`과 `--dry-run`으로 수행했다. 실제 원본이나 모델을 호출하지 않았다.

이번 작업에서 편집한 파일은 모두 `defense/web-proxy-defense/site_analysis/` 안에 있다. `prompts.py`, `axes.json`, `AXES.md`는 직접 편집하지 않았다. 작업 중 `axes.json`의 해시가 달라진 것을 읽기로 확인했으며, 최종 dry-run은 현재 카탈로그 1.1의 53개 축으로 통과했다. 기존 재개, 전체 비용 상한과 `cost_budget`, 시간 초과 비용 추정, 실패한 작업만 포기하는 처리, 가림 셀의 자료형 완화, `SITE_ANALYSIS_PROXY` 설정을 유지했다. 별도 테스트 파일은 만들지 않았다.

수정한 위치는 다음과 같다. 행 번호는 이 보고서를 작성할 때의 파일 기준이다.

| 파일과 행 | 변경 내용 |
| --- | --- |
| `catalog.py:47,51` | 답의 추가 키 허용을 명시하고 `working_notes` 문자열을 ACTION_SCHEMA의 선택 칸으로 추가했다. 필수 칸에는 넣지 않았다. |
| `observer.py:105,131,160,193,216,288` | 세션 파일 경로와 권한을 실행기에 전달한다. 받은 메모를 바꾸지 않고 다음 문맥과 비공개 관찰 스냅샷에 넣는다. 메모가 없는 결정은 직전 메모를 유지한다. |
| `observer.py:688,729` | 브라우저 문맥에 `storage_state` 경로를 전달한다. 세션 관찰의 HTTP 대체 실행은 거부한다. 기존 GET/HEAD 제한, 폼 제출 차단, 서비스워커와 외부 요청 차단은 유지한다. |
| `windows.py:99` | 큰 문맥을 읽기 참조로 전환할 때에도 권한과 작업 메모를 직접 전달한다. 메모 내용을 요약하거나 해석하지 않는다. |
| `session_prepare.py:15,29,49,127` | 비공개 출력 경로 검사, BOM 허용 설정 및 계정 읽기, 중계를 거친 로그인 폼 제출, 쿠키 storage state 저장, 값 없는 결과 출력과 dry-run을 구현했다. |
| `analyze.py:24,61,98,168` | `--session-file`, `--session-runs`와 검사를 추가했다. 익명 회차 뒤에 세션 회차를 독립 실행하며 남은 작업과 비용 문맥에도 반영한다. |
| `analyze.py:442,481,613` | 회차와 모델 문맥에 관찰 권한을 기록한다. 마지막 작업 메모를 별도 가림 셀로 검토한 뒤 `runs[].working_notes`에 공개한다. 거부되거나 미완료이면 null이며 가림 오류를 남긴다. |
| `analyze.py:625,671,692` | 서로 다른 권한의 의미 합치기를 거부한다. 비교 문맥에 각 회차의 원래 번호와 권한을 넣고, 세션 합치기의 반복 실패 집계를 익명과 구분한다. |
| `analyze.py:789,1561,1702,1868` | 기존 dry-run과 저장 묶음 재생에 세션 회차를 반영했다. 메모, 권한별 합치기, findings, 재개, 세션 준비의 합성 검사를 기존 dry-run 안에 추가했다. |
| `analyze.py:1994,2037,2058,2112` | 준비 세션이 바뀌거나 저장 회차의 권한이 달라지면 기존 관찰과 섞지 않는다. 권한별 합치기 상태와 최종 결과를 저장한다. 세션 내용은 기록과 모델 입력에 넣지 않으며 파일 내용의 해시만 비공개 재개 상태에 둔다. |
| `record.py:108,133,145,153` | 권한별로 묶고 서로 다른 권한의 합치기를 거부한다. 원래 회차 번호를 유지한다. 한 회차는 그대로 보존하고, 가림을 통과한 합친 답은 `combined_answer`에 보존한다. |
| `resume.py:249,259,267` | 작업 메모 가림의 재개 위치와 권한별 의미 합치기 및 합친 답 가림의 재개 위치를 계산한다. |
| `SESSION-NOTES-REPORT.md:1` | 변경 내용, 실행 방법, 실행한 확인과 실행하지 않은 작업을 기록했다. |

운영자 도구는 설정에 있는 `login_path`로 이동하고, `user_field`와 `password_field`를 HTML 입력 칸의 `name`으로 찾는다. `account_file`은 설정 파일과 같은 폴더의 파일만 허용한다. 계정은 `username`과 `password`를 사용하며, 사용자 칸 이름이 `email`이면 이메일을 먼저 사용하고 사용자명이 없으면 이메일을 사용한다. 설정과 계정은 `utf-8-sig`로 읽는다. 웹 이름이나 로그인 경로는 실행 코드에 고정하지 않았다.

설정한 두 칸이 같은 폼인지 확인하고 제출 버튼을 포함해 폼을 한 번 제출한다. 같은 원본의 해당 폼 action으로 가는 최상위 문서 POST 한 번만 예외로 허용한다. 추가 POST와 외부 원본 요청은 차단한다. 로그인 칸이 사라지고 화면 경로가 바뀌었는지를 값 없이 보고하며, 성공을 확인하지 못하면 세션을 저장하지 않는다. 이 확인으로 실제 계정 권한을 확정하지 않는다. MFA, CAPTCHA나 별도 확인 단계를 자동 처리하지 않는다.

세션 파일은 `%LOCALAPPDATA%/ruby-site-analysis/sessions/`의 하위 파일만 허용한다. `..`와 링크를 해석한 경로가 허용 범위를 벗어나거나 저장소 안이면 거부한다. 쿠키는 기존 소유 사용자 전용 권한 처리와 원자적 JSON 저장을 사용한다. storage state의 `origins`는 비워 로컬 스토리지를 저장하지 않는다. 계정 값과 쿠키 값은 출력하지 않는다.

최종 기록의 `merged`는 익명 회차가 두 개 이상일 때의 결과다. `merged_by_authority.anonymous`와 `merged_by_authority.session`에는 각 권한의 결과가 들어간다. 해당 권한의 회차가 하나이면 합친 형식을 만들지 않고 그 회차 기록을 그대로 둔다. 익명과 세션 관찰을 같은 사실의 두 번 확인으로 세지 않는다. 세션 관찰은 준비된 계정의 관찰 범위이며 모든 로그인 사용자에게 일반화하지 않는다.

합친 축의 `combined_answer.findings`는 가림을 통과한 모델 답을 보존한다. `both-runs`, `single-run`, `contradictory` 표시는 코드가 해석하거나 다시 붙이지 않는다. 기존 묶음 정책에 따라 선택된 `answers`와 `answer`도 유지한다. 합의가 없어 선택 답이 비어 있는 축에서도 `combined_answer`를 남겨 단일 회차 발견과 모순 표시를 잃지 않는다.

실행 예시는 다음과 같다. PowerShell에서 `defense/web-proxy-defense/`를 작업 폴더로 사용한다. 아래 실제 실행 명령은 이번 작업에서 실행하지 않았다. 로그인 설정과 선택 모델의 단가가 들어 있는 운영자 `settings.json`이 준비되어 있어야 한다. 예시의 달러 상한은 실행자가 선택하는 전체 상한이며 단계별 비용 몫은 없다.

```powershell
$env:SITE_ANALYSIS_PROXY = 'http://127.0.0.1:18090'
$sessionFile = Join-Path $env:LOCALAPPDATA 'ruby-site-analysis/sessions/wordpress.json'
$analysisFile = Join-Path $env:LOCALAPPDATA 'ruby-site-analysis/wordpress-session-analysis.json'

python -B -m site_analysis.session_prepare `
  --origin-url http://target.test/ `
  --login-config ../../.tmp/installer-targets/wordpress/session-login.json `
  --out $sessionFile

python -B -m site_analysis.analyze `
  --origin-url http://target.test/ `
  --out $analysisFile `
  --session-file $sessionFile `
  --runs 2 --session-runs 2 `
  --model gpt-6-sol `
  --rates ../../.tmp/installer-targets/wordpress/settings.json `
  --max-cost-usd 25
```

설정만 확인할 때도 같은 설정 파일을 사용한다.

```powershell
python -B -m site_analysis.session_prepare `
  --origin-url http://target.test/ `
  --login-config ../../.tmp/installer-targets/wordpress/session-login.json `
  --out $sessionFile --dry-run
```

세션 준비의 dry-run은 설정과 경로만 검사한다. 계정 파일 값, 실제 쿠키, 브라우저와 모델에 접근하지 않고 출력 파일도 쓰지 않는다. 분석기 dry-run은 세션 파일 경로만 검사하므로 실제 세션 파일 없이 아래 명령으로 오프라인 검사를 재현할 수 있다.

```powershell
$env:SITE_ANALYSIS_PROXY = 'http://127.0.0.1:18090'
$preparedSession = Join-Path $env:LOCALAPPDATA 'ruby-site-analysis/sessions/synthetic-unused.json'
python -B -m site_analysis.analyze `
  --origin-url http://target.test/ --out site_analysis/dry-unused.json `
  --runs 2 --session-runs 2 --session-file $preparedSession --dry-run
```

실행한 확인은 다음과 같다.

| 확인 | 관찰한 결과 |
| --- | --- |
| 변경한 Python 파일 7개의 `python -m py_compile` | 최종 실행 종료 코드 0. 컴파일 캐시는 분석기 폴더 안에 생성된다. |
| 분석기 `--dry-run`, 기본 익명 회차 | 종료 코드 0. 기존 스키마, 축 완전성, 재개, 비용 문맥, 요청 경계 검사가 통과했다. |
| 분석기 `--dry-run`, 익명 2회와 세션 2회, 위 재현 명령 | 최종 실행 종료 코드 0. 계획에 익명 1, 2회와 세션 3, 4회가 표시됐다. 원본 요청 0, 실제 모델 호출 0, 출력 파일 쓰기 0이었다. |
| 작업 메모 합성 검사 | 메모 원문이 다음 문맥과 비공개 스냅샷의 JSON 저장 및 복원 후 같았다. 선택 칸이 생략된 다음 결정도 메모를 유지했다. 공개 기록에는 대체 가림 응답이 돌려준 메모만 남았다. |
| 권한별 합치기와 재개 합성 검사 | 실제 실행 조율 함수와 의미 합치기 함수를 사용했다. 합치기 문맥에 한 권한만 포함됐다. 저장을 복원한 뒤 완료 회차와 완료 합치기를 다시 호출하지 않았다. 단일 회차 보존, 서로 다른 권한 거부, 변경된 준비 세션과 변경된 회차 권한 거부가 통과했다. |
| findings 보존 합성 검사 | 답 검사, 가림 검사, 최종 저장 호출 인자의 JSON 직렬화 및 복원 후 세 가지 표시와 추가 키가 그대로 남았다. 합의가 없는 답도 `combined_answer`에 보존됐다. |
| 카탈로그 1.0 호환 합성 검사 | 버전 1.0과 다른 축 목록으로 만든 저장 신원이 현재 카탈로그와 달라 `different_origin_catalog_or_output`가 됐다. 이전 회차와 비용 장부를 불러오지 않고 새 상태를 선택했다. 실제 과거 저장 파일을 실행한 결과는 아니다. 기존 저장 보관 처리는 유지했다. |
| 세션 준비 대체 브라우저 검사 | BOM 설정과 계정 읽기, 중계 옵션, 폼 POST 1회 허용, 두 번째 POST와 외부 요청 차단, 쿠키만 비공개 저장, 값 출력 금지가 통과했다. 세션 준비 main의 dry-run도 계정 읽기와 브라우저 시작 전에 끝났다. |
| 세션 관찰 대체 브라우저 검사 | 브라우저의 `storage_state` 옵션에 경로가 전달됐다. 폼 차단 초기 스크립트가 등록됐고 GET/HEAD만 허용됐다. 세션 상태 내용과 합성 쿠키 값이 관찰 스냅샷에 들어가지 않았다. 브라우저 없는 세션 관찰의 익명 HTTP 전환도 차단됐다. |
| 잘못된 CLI 입력의 dry-run | `--session-runs 1`에 세션 파일을 생략한 분석과, 세션 출력 경로를 저장소 내부로 지정한 준비 명령이 비정상 종료로 거부됐다. 실제 계정이나 쿠키 파일은 읽지 않았다. |

최종 dry-run 출력의 관련 부분은 다음과 같다. 이 검사의 응답, 로그인 화면, 계정과 쿠키는 모두 메모리 안에서 만든 합성 입력 또는 대체 객체다. **실제 모델 응답과 실제 웹 관찰 결과가 아니다.** 물리적 결과 파일 쓰기는 대체하고 기존 JSON 저장 코덱 및 최종 저장 호출 인자를 검사했다.

```json
{
  "working_notes_resume_and_privacy": "passed",
  "authority_separation": "passed",
  "single_run_not_merged": "passed",
  "findings_after_privacy_and_save": [
    "both-runs",
    "single-run",
    "contradictory"
  ],
  "catalog_1_0_restart": "passed",
  "authority_merge_resume": "passed",
  "changed_session_or_authority_rejected": "passed"
}
```

원본 접속, 실제 로그인과 폼 제출, 실제 세션 파일 및 계정 값 읽기, 실제 모델 호출, Docker 명령은 실행하지 않았다. git commit, push, stash와 단계 올리기도 하지 않았다. 실제 웹에서의 로그인 성공, 세션 유효성, Playwright 설치 및 브라우저 실행, 물리적 쿠키 파일의 Windows 권한, 모델 가림의 정확성은 이번 오프라인 검사로 확인하지 않았다.

현재 준비 도구는 일반 HTML 폼의 제출을 지원한다. AJAX 로그인이나 로그인 경로가 유지되는 화면은 성공을 확인하지 못할 수 있으며 그 경우 파일을 저장하지 않는다. 준비 세션 내용이나 이미 저장된 회차의 권한을 바꿔 관찰하려면 `--fresh`로 새 분석을 시작해야 한다. 카탈로그 신원이 달라진 이전 저장은 기존 재개 규칙에 따라 보관하고 새로 시작한다.
