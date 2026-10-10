# site_analysis: 원본 웹 분석기

격리 미끼 방어의 1단계다. 보호할 원본 웹을 읽기만 하면서 둘러보고, 미끼웹을 만들 때 필요한 사실을 축 53개로 정리한다. 미끼웹 생성 단계(`decoy_build`, 이 패키지에 포함되지 않음)가 이 기록을 읽어 원본 고유 정보를 지우고, 원본과 같은 모양으로 채우고, 검증한다. 이 패키지는 그 단계 없이 단독으로 실행된다.

## 설계 원칙

- 판단은 모델이 한다. 코드는 내용을 해석하지 않는다. 코드는 기계적인 일만 맡는다: 수집, 문자열 일치, 위치 계산, 순서 배치, 저장과 재개, 비용 상한.
- 모델 출력의 모양을 코드가 검사해서 거부하지 않는다. 모델이 붙인 표시(공개 여부, final 등)를 따른다.
- 웹별 값(경로, 필드 이름, 제품 이름)을 코드에 넣지 않는다. 웹마다 다른 것은 설정 파일과 분석 결과로 넘긴다.
- 원본에는 읽기 요청(GET, HEAD)만 보낸다. 폼 제출, 상태를 바꾸는 링크, 사람 확인 장치 우회, 관리 영역 열기를 하지 않는다.
- 원본 값(이름, 계정, 메일, 비밀값, 원문 인용)은 공개 기록에 남기지 않는다. 관찰 원문과 진행 상태는 저장소 밖 비공개 폴더에만 둔다.

## 단계

| 단계 | 하는 일 | 모델 프롬프트 |
| --- | --- | --- |
| 둘러보기 | 브라우저로 화면을 열고 화면, 소스, 요청과 응답을 기록한다. 작업 메모로 찾은 화면 종류와 열지 않은 종류를 이어 간다 | `prompts.NAVIGATE` |
| 축 분석 | 묶음 6개로 나눠 53개 축에 답한다. 관찰을 읽기(`_read_sample`)와 찾기(`_find`)로 직접 확인한다. 더 읽어야 하는 답은 `final:false`로 표시해 다시 받는다 | `prompts.group_prompt` |
| 공개 전 가림 | 답과 사실 칸마다 모델이 공개 여부를 정하고, 민감한 조각만 자리표시로 치환한다 | `prompts.PRIVACY` |
| 합치기 | 같은 관찰 권한의 두 회차를 축마다 비교하고, 사실마다 both-runs, single-run, contradictory를 표시한다. 메움은 both-runs만 근거로 쓴다 | `prompts.MERGE` |

회차는 기본으로 익명 2회다. 운영자가 준비한 일반 계정 세션으로 2회를 더 돌릴 수 있다. 권한이 다른 회차는 서로 확인으로 세지 않는다.

## 파일

| 파일 | 역할 |
| --- | --- |
| `analyze.py` | 명령 입구, 회차 실행, 축 분석, 가림, 합치기, 기록 저장, dry-run 점검 |
| `observer.py` | Playwright 둘러보기, 요청과 응답 기록, 요청 색인, 읽기와 찾기 대상 |
| `model.py` | Codex(또는 Claude) CLI 호출, 비용 장부, 문맥 크기 재조립, 자격 가림 |
| `windows.py` | 문맥 조립, 읽기 창, 찾기, 치환 |
| `record.py` | 공개 사실 정리, 원자적 저장, 권한별 합치기 |
| `resume.py` | 비공개 체크포인트, 중단 뒤 재개 |
| `catalog.py` | 축 목록 읽기, 응답 안내 스키마 |
| `session_prepare.py` | 운영자 도구: 일반 계정으로 한 번 로그인해 세션 쿠키만 비공개로 저장 |
| `prompts.py` | 모델 프롬프트 |
| `status.py` | 진행 상황 보기(장부만 읽음) |
| `console.py` | 로컬 웹 콘솔: 환경, AI 연결과 로그인, 비용, 대상, 일반 계정, 실행과 진행, 결과 개수를 한 화면에서 다룬다 |
| `run-console.cmd` | Windows 실행 파일: Python 3.13 이상을 찾아 콘솔을 띄우고 기본 브라우저로 연다 |
| `rates.example.json` | 비용 단가와 상한 예시 |
| `OUTPUTS.md` | 출력과 방어 모듈별 사용 |
| `axes.json` | 축 53개(뜻, 질문, 묶음, 받는 쪽, 합치기 정책)의 정본. `AXES.md`는 여기서 생성 |
| `SCHEMA.md` | 결과 기록 규격 |

## 준비

| 항목 | 준비 방법 |
| --- | --- |
| Python과 브라우저 | Python 3.13, `pip install playwright`, `python -m playwright install chromium` |
| AI 사용 권한 | 분석기는 API 키를 직접 받지 않고 이 PC에 로그인된 CLI를 호출한다. 기본은 Codex CLI(`codex login`으로 ChatGPT 구독 또는 OpenAI API 키 로그인)이고, `--provider claude`면 Claude CLI를 쓴다. `--model`은 그 CLI가 받는 모델 이름이다 |
| 비용 단가 | `rates.example.json`을 복사해 단가와 상한을 채운다. 단가는 운영자가 제공자 가격표에서 확인해 넣는다. 채우지 않으면 분석이 시작 전에 멈춘다 |
| 대상 웹 | `--origin-url`에 접속 가능한 주소를 준다. 분석기는 GET과 HEAD만 보낸다. 원본 대신 복사본을 분석하거나 원본에 직접 닿지 않으면, 그 대상만 전달하는 중계를 `SITE_ANALYSIS_PROXY`로 지정한다. 분석기 자체는 Docker가 필요 없다 |
| 일반 계정 회차(선택) | 대상 웹에 분석 전용 일반 계정을 만든다(관리자나 실제 사용자 계정은 쓰지 않는다). 비공개 폴더에 로그인 설정 `{"login_path", "user_field", "password_field", "account_file"}`과 같은 폴더의 계정 파일 `{"username" 또는 "email", "password"}`을 두고 `session_prepare`로 쿠키만 담은 세션 파일을 만든다 |
| 저장 위치 | 공개 기록은 저장소 `.tmp/` 아래, 관찰 원문과 진행 상태는 `%LOCALAPPDATA%/ruby-site-analysis/`(macOS와 Linux는 사용자 상태 폴더)에 생긴다 |

## 콘솔로 실행

`run-console.cmd`를 두 번 누르면 패키지 상위 폴더(`defense/web-proxy-defense`)에서 `python -B -m site_analysis.console --open`이 돌고 기본 브라우저에 콘솔이 열린다. Python은 py launcher(`py -3`)를 먼저 찾고, 없으면 PATH의 `python`을 쓴다. 둘 다 3.13 이상이 아니면 설치 안내를 띄우고 멈춘다. 다른 운영체제에서는 그 폴더에서 같은 명령을 실행한다. 콘솔은 `127.0.0.1`의 빈 포트에만 열리고, 실행 창에 찍힌 토큰 주소로만 들어갈 수 있다. 실행 창을 닫거나 Ctrl+C를 누르면 콘솔과 콘솔이 시작한 분석이 함께 멈춘다.

화면 왼쪽의 일곱 단계를 위에서부터 채운다. 단계마다 완료, 필요, 선택이 표시되고 버튼은 앞 조건이 갖춰져야 켜진다. 꺼진 버튼은 그 줄 아래에 꺼진 이유를 보여 준다.

| 단계 | 하는 일 |
| --- | --- |
| 1 환경 | Python 판, Playwright 패키지, Chromium 실행을 확인한다. Playwright와 Chromium은 버튼으로 설치하고 출력을 화면에 보여 준다. Python은 화면에서 설치하지 않는다 |
| 2 AI 연결 | Codex(기본) 또는 Claude CLI와 로그인 상태를 확인한다. Codex CLI가 없고 npm이 있으면 설치 버튼이 `npm install --global @openai/codex`를 실행한다. Codex는 구독 로그인(`codex login`)과 API 키 로그인(`codex login --with-api-key`의 표준 입력으로만 전달, 콘솔은 저장하지 않음)을 화면에서 한다. Claude 로그인 버튼은 `claude auth login`(Claude 구독, 기본) 또는 `claude auth login --console`을 터미널 없이 실행하고 출력과 주소를 화면에 보여 주며 취소할 수 있다. 브라우저가 열리지 않아 주소로 로그인하면 그 화면에 나온 코드를 붙여 넣는다. 코드는 실행 중인 로그인 프로세스의 표준 입력으로만 넘기고 저장하지 않는다. 연결 시험은 누를 때만 작은 요청 하나를 분석기의 모델 호출 코드로 보내며 소액 비용이 든다 |
| 3 비용 | 선택한 모델의 단가와 전체 상한을 넣는다. 값은 제공자 가격 페이지에서 확인한다. 구독으로 로그인했어도 채워야 분석이 시작된다. `model.cost_settings` 검사를 통과해야 `%LOCALAPPDATA%/ruby-site-analysis/console/rates.json`(소유자 전용)에 저장된다 |
| 4 분석할 웹 | 대상 주소, 중계, 추가 출처(줄마다 `--allow-origin`), 기록 이름을 정한다. 연결 확인은 대상 주소로 GET을 보내 상태 코드, 마지막 주소, 그 주소가 분석 범위 안인지 보여 준다. 범위 안의 이동은 5번까지 따라간다. 같은 이름의 기록 파일이 있으면 시작할 때 그 파일에 다시 쓴다고 알린다 |
| 5 일반 계정(선택) | 로그인 화면 설명과 계정 값을 `%LOCALAPPDATA%/ruby-site-analysis/accounts/<기록 이름>/`에 소유자 전용으로 저장한다. 세션 준비는 `session_prepare --dry-run`을 먼저 돌리고 확인을 받은 뒤 실제로 로그인한다. 계정 값은 화면으로 돌려보내지 않고, 세션은 쿠키 수, 만료 수, local storage 출처 수만 보여 준다. 저장한 계정 지우기는 확인을 받은 뒤 그 기록 이름의 계정 폴더를 지우고, 칸을 고르면 비공개 세션 폴더 안의 세션 파일도 지운다. 이 콘솔이 같은 기록 이름으로 시작한 분석이 실행 중이면 지우지 않는다 |
| 6 실행 | 회차, 화면 수, 문맥 크기, 모델을 정한다. 시작은 같은 설정으로 점검(`--dry-run`)을 통과한 뒤에만 켜지고 체크포인트가 있으면 이어서 돈다. 단계 표, 비용 막대, 호출 수, 마지막 기록 뒤 경과 시간, 멈춤 의심, 실패 호출, 로그 끝부분을 몇 초마다 갱신한다 |
| 7 결과 | 회차별 축 상태 개수, 합친 결과의 사실 표시(both-runs, single-run, contradictory) 개수, 비용, 기록 경로만 보여 준다. 축 설명과 원본 값은 보여 주지 않는다. 기록 폴더와 `OUTPUTS.md`, `INTEGRATION.md`를 여는 버튼이 있다 |

비밀이 아닌 설정(주소, 기록 이름, 회차, 모델, 단가 파일 경로)은 `%LOCALAPPDATA%/ruby-site-analysis/console/settings.json`에 남아 다음에 콘솔을 열 때 다시 채워진다. 주소에 넣은 사용자 이름과 비밀번호는 저장하지 않고, 중계 주소에 넣으면 거부한다. 아래 명령은 콘솔 없이 같은 일을 하는 방법이다.

## 실행

```powershell
# 원본에 직접 닿지 않으면 그 원본만 전달하는 중계를 지정한다
$env:SITE_ANALYSIS_PROXY = 'http://127.0.0.1:18095'

# (선택) 일반 계정 세션 준비: 설정 파일에는 로그인 경로와 칸 이름만, 계정 값은 같은 폴더의 계정 파일에
python -B -m site_analysis.session_prepare --origin-url http://target.test/ `
  --login-config <비공개폴더>/session-login.json --out $env:LOCALAPPDATA/ruby-site-analysis/sessions/<이름>.json

# 분석: 익명 2회와 계정 2회, 비용 상한은 전체 합
python -B -m site_analysis.analyze --origin-url http://target.test/ --out ../../.tmp/site-analysis/<이름>.json `
  --runs 2 --session-runs 2 --session-file <세션 파일> `
  --model gpt-6-sol --rates rates.json --context-chars 450000 --max-pages 40

# 네트워크와 모델 없이 설정과 내부 점검만
python -B -m site_analysis.analyze ... --dry-run

# 진행 상황(비공개 비용 장부만 읽음). --watch 60이면 1분마다 갱신
python -B -m site_analysis.status --out ../../.tmp/site-analysis/<이름>.json --origin-url http://target.test/ --watch 60
```

실행 중에는 묶음 진행 줄이 표준 오류로 나온다. `status`는 비용, 다음 단계, 남은 단계 수, 마지막 기록 시각, 실패 호출을 보여 주고, 남은 일이 있는데 20분 넘게 기록이 없으면 멈춤 의심을 표시한다. 실행 프로세스가 살아 있는지는 보지 않는다.

같은 명령을 다시 실행하면 비공개 체크포인트에서 이어서 돈다. 축 목록이나 출력 경로가 바뀌면 새로 시작한다.

## 결과

- 공개 기록: `--out` 경로. 저장소 루트의 `.tmp/` 아래에 두는 것을 전제로 한다(`.tmp/`는 `.gitignore` 대상). 코드가 이 위치를 강제하지는 않으므로 다른 경로를 주지 않는다. 회차별 축 답, 값 없는 사실, 응답 시간, 권한별 합친 결과(`merged_by_authority`), 사실 표시(`combined_answer.findings`), 소비자 안내.
- 비공개 체크포인트: `%LOCALAPPDATA%/ruby-site-analysis/<출력>-<해시>/`. 관찰 원문, 진행 상태, 비용 장부.
- 규격은 `SCHEMA.md`, 축은 `AXES.md`.

## 출력과 방어 모듈의 사용

분석기가 무엇을 내놓는지와 팀의 각 방어 모듈이 그 출력으로 무엇을 할 수 있는지는 `OUTPUTS.md`에 있다.
현재 요청 경로에서 분석기의 위치, 환경 가정, 환경 리팩터링 뒤의 연결 순서는 `INTEGRATION.md`에 있다.

## 의존과 라이선스

외부 코드는 복사해 넣지 않았다. 아래 의존은 저장소에 넣지 않고 운영자 PC에 설치한다. 판은 2026-10-11 작업 PC에서 확인한 값이다.

| 의존 | 판 | 출처와 라이선스 |
| --- | --- | --- |
| Python | 3.13 이상 | Python Software Foundation, PSF License |
| Playwright for Python | 1.62.0 | Microsoft, Apache-2.0 |
| Chromium(Playwright가 내려받음) | 151.0.7922.34 | Chromium 프로젝트, BSD 계열 라이선스와 제3자 고지 |
| Codex CLI(`@openai/codex`, 기본) | 0.162.1 | OpenAI, Apache-2.0 |
| Claude Code(선택) | 2.1.294 | Anthropic, 오픈소스가 아니며 Anthropic 이용 약관을 따른다 |
| 분석 모델 | `--model`로 지정(이번 실행은 `gpt-6-sol`) | 모델 제공자의 이용 약관을 따른다 |

## 검증과 한계

- 최신 실행, 재검토, 고친 결함, 한계: `RUN-20261011-REPORT.md`
- 이전 실행: `RUN-20261010-REPORT.md`, 구조 수정: `STRUCTURE-FIX-REPORT.md`. 그 밖의 `*-REPORT.md`는 개발 이력이며 현재 동작은 코드와 `SCHEMA.md`가 기준이다.
- 남은 한계: 모델이 관찰을 빠짐없이 읽는 것은 보장되지 않는다(재검토 중 문제의 주된 유형). 웹당 비용이 수백 달러까지 든다. 수정별 회귀 시험은 아직 없다.
