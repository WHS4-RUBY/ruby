# 분석 단계 저장과 재개 구현 보고

완료한 둘러보기, 축 분석 묶음, 가림 셀과 의미 비교를 저장하고 같은 `--out` 실행에서 재사용하도록 구현했다. 저장 위치는 `%LOCALAPPDATA%/ruby-site-analysis/<--out의 확장자를 포함한 파일 이름>/`이다. 비용 장부도 복원하므로 재개할 때 누적 사용액이 초기화되지 않는다. 회차 시간은 둘러보기와 축 분석에 적용하고 가림과 합치기는 별도 시간으로 진행한다.

## 바꾼 파일과 행

행 번호는 최종 소스의 시작행이다. 변경 범위는 `defense/web-proxy-defense/site_analysis/`다.

| 파일과 행 | 변경 내용 |
| --- | --- |
| `resume.py:17`, `resume.py:40`, `resume.py:54` | 원자료의 자료형 태그와 바이트 base64 직렬화, 저장소 밖 경로 검사, 원본 URL과 축 정본 및 출력 경로의 재개 식별자를 추가했다. |
| `resume.py:60`, `resume.py:101`, `resume.py:115`, `resume.py:131` | 저장 상태와 비용 장부 읽기, 새 시작 시 이전 JSON 보존, 원자적 저장, 호출 답 소비 확인과 dry-run 재개 위치 계산을 추가했다. 비공개 저장 실패는 전체 실행을 중단한다. |
| `observer.py:126`, `observer.py:138` | 관찰 전체, 원바이트, 문맥 버퍼, 읽기 창, 결정과 오류, 페이지 메타데이터, 요청 및 페이지 카운터의 저장과 복원을 추가했다. 자격 값과 브라우저 객체는 저장 대상에서 제외한다. |
| `observer.py:478`, `observer.py:519`, `observer.py:580` | 미완료 둘러보기의 현재 위치와 아직 실행하지 않은 결정을 이어 처리한다. 완료한 둘러보기는 실행기가 건너뛴다. 이미 비용을 지불한 이동 답도 저장 장부에서 소비한다. |
| `windows.py:19`, `windows.py:22` | 읽기 창의 고정 원문 참조, 순서와 범위를 저장하고 복원한다. |
| `model.py:111`, `model.py:115`, `model.py:119`, `model.py:172` | 호출 장부와 누적 비용, 상한, 둘러보기 및 축 분석 사용액, 반복 실패를 복원한다. 단계가 아직 소비하지 않은 모델 답은 추가 호출 없이 재사용한다. |
| `model.py:246`, `model.py:294`, `model.py:318` | 공급자 전송 직전 `inflight`와 추정용 입력량을 저장하고 정산 및 답 수신 뒤 장부를 갱신한다. 강제 종료로 남은 미정산 호출도 기존 시간 초과 추정식을 적용한다. |
| `analyze.py:22`, `analyze.py:47`, `analyze.py:640` | `--fresh`, `--privacy-seconds`, `--merge-seconds`와 시간 검증을 추가했다. dry-run은 저장 폴더, 재개 사유, 회차와 단계 및 대기 ID, 저장된 비용을 출력한다. |
| `analyze.py:141`, `analyze.py:280` | 가림 셀의 공개값과 보류 및 오류, 부분 축 답과 교정 문맥 및 읽기 창을 저장한다. 정상 셀과 정상 축은 재사용하고 미완료 부분만 처리한다. |
| `analyze.py:360` | 회차별 원자료와 묶음 답 및 오류, 셀 가림, 공개 기록과 완료 표식을 저장한다. 완료한 단계의 모델 호출을 건너뛰고 가림을 별도 시간으로 진행한다. 기존 비공개 묶음 답 파일 저장도 유지했다. |
| `analyze.py:506`, `analyze.py:1160` | 의미 비교 원답과 합친 답의 가림을 따로 저장한다. 원답을 얻었으면 합치기 모델을 다시 호출하지 않는다. 실행별 회차 시간 외에 전체 시간 상한을 겹쳐 적용하던 경로를 제거했다. |
| `analyze.py:969` | 기존 dry-run 안에 중단과 복원, 완료 단계 건너뛰기, 파일 형식 읽기, 비용 복원과 별도 가림 시간 검사를 추가했다. 별도 테스트 파일은 만들지 않았다. |
| `SCHEMA.md:19`, `SCHEMA.md:72` | 시간 적용 범위, 비공개 저장 형식과 재개 조건을 문서화했다. |
| `RESUME-REPORT.md:1` | 구현 결과와 확인 범위를 기록했다. |

FIX-REPORT, FIX2와 FIX3에서 수정한 현재 상태 우선 문맥, 읽기 기억, 부분 축 보존, 묶음별 비용 몫과 마지막 답변 호출, 셀 실패 분할과 공개 가림 경계는 유지했다. 브라우저와 HTTP 경로의 `SITE_ANALYSIS_PROXY` 처리도 유지했다(`observer.py:543`, `observer.py:588`). 시간 초과 호출의 비용 추정식도 유지했다. 기존 보고서 세 파일은 수정하지 않았다.

## 저장 형식과 시점

| 파일 | 저장 내용과 시점 |
| --- | --- |
| `state.json` | `site-analysis-resume/1` 형식이다. 원본과 축 및 출력 경로의 해시, 실행 식별자, 회차별 `observation`, `observation_complete`, `analysis_elapsed_seconds`, `groups`, `privacy`, `published`, `complete`, 의미 합치기 `merge`, 소비 확인한 호출 번호를 저장한다. 관찰 결정 전후, 관찰 종료, 묶음의 부분 답과 읽기 및 완료, 가림 처리 결과, 회차 완료와 합치기 결과마다 갱신한다. |
| `ledger.json` | 일반 JSON이다. 호출별 사용량과 비용, 누적 `spent_usd`, 비용 상한, 둘러보기 비율과 사용액, 축 분석 사용액, 반복 실패, `pending_answer`를 저장한다. 모델 전송 직전, 사용량 정산과 답 수신 직후 및 교정 재시도 사이에 갱신한다. |
| `run-<회차>-<묶음>.json` | 기존처럼 가림 전 묶음 `answers`와 `errors`를 따로 남긴다. 정본 재개 상태는 `state.json`과 `ledger.json`이다. |
| `archive-<시각>/` | `--fresh` 또는 원본과 축 및 출력 경로 불일치로 새로 시작할 때 이전 JSON을 옮겨 보존한다. |

`state.json`은 모든 딕셔너리, 목록과 스칼라를 `type`, `value` 태그로 감싼다. 바이트는 `type=bytes`와 base64 값으로 보존한다. 원문 자체가 같은 키를 갖더라도 디코딩과 충돌하지 않는다. 관찰에는 화면과 소스 표본, 응답과 요청, 전체 본문 버퍼, 실시간 수신, 폼 메타데이터, 이동, 원시 모델 결정과 피드백, 문맥 버퍼와 읽기 창이 포함된다. Observer가 확보하지 않은 인증 헤더 값이나 자격 값을 새로 수집하지 않는다.

가림은 범위별 `cell_ids`, `released`, `errors`, `terminal`, 문맥과 읽기 창, `complete`로 보존한다. 안전한 값과 확정 보류 셀은 재호출하지 않는다. 시간이나 전체 비용 때문에 처리하지 못한 셀은 미완료로 남긴다. 회차 완료 표식은 관찰과 모든 분석 묶음 및 가림 범위가 끝난 뒤 기록한다. 의미 합치기는 원답 `raw`와 가림을 마친 `judgments`를 따로 남긴다.

파일은 같은 폴더의 `.pending`에 쓴 뒤 교체한다. 단계 상태에 소비한 호출 번호를 먼저 저장하고 비용 장부의 답 영수증을 지운다. 두 저장 사이에 종료돼도 복원한 호출 번호로 이미 처리한 답을 구분한다. 모델 답이 먼저 저장됐지만 단계에 반영되지 않았다면 그 답을 다시 소비하며 모델 호출과 비용을 추가하지 않는다.

비공개 경로는 현재 저장소와 그 내부 `.tmp`를 거부하고 쓰기 직전에 경로와 대상 파일을 다시 확인한다. 모델 실행의 임시 작업 폴더도 같은 비공개 저장 폴더 아래 `.models`로 옮겼다. `--out`에는 기존처럼 가림을 통과한 결과와 숫자 계측 및 결정 메타데이터만 쓴다.

## 이어서 돌리는 조건과 시간 및 비용

1. `--fresh`가 없고 정규화한 원본 URL, 축 정본 전체와 출력 절대 경로의 해시가 모두 일치해야 재개한다. 같은 이름의 출력이라도 절대 경로가 다르면 새 실행이다.
2. 원본이나 축 또는 출력 경로가 다르거나 `--fresh`이면 이전 JSON을 보존하고 새 단계와 비용 장부를 시작한다. 손상된 저장이나 실행 식별자가 다른 장부는 비용을 0으로 추측하지 않고 오류로 중단한다.
3. 완료한 회차, 둘러보기, 묶음, 가림 셀과 의미 비교는 건너뛴다. 미완료 묶음은 정상 축과 읽기 창을 복원한다. 합치기 입력의 회차 수나 답이 바뀌면 기존 의미 비교를 무효화한다.
4. 재개하면 누적 비용과 둘러보기 및 축 분석 사용액, 둘러보기 비율, 저장된 비용 상한을 복원한다. `--max-cost-usd`를 다시 명시하면 사용액을 유지하고 그 상한으로 변경한다. 상한을 이미 소진했다면 추가 모델 호출은 하지 않는다. 이미 받은 답의 복원은 추가 과금 없이 진행한다.
5. 사용량을 받지 못한 시간 초과와 강제 종료 호출은 기존 입력 약 2자당 1토큰, 출력 16,000토큰 식으로 추정한다. 장부에 추정 비용과 표시를 남겨 다음 재개에서 반복 청구하지 않는다. 같은 실패 반복 횟수도 복원하고 현재 반복 실패 상한을 적용한다.
6. 둘러보기와 축 분석은 회차의 저장된 경과 시간을 이어 사용한다. 프로세스가 멈춰 있던 시간은 회차 시간에 더하지 않는다. 가림은 회차별 별도 시간 창, 의미 비교는 별도 시간 창을 사용한다. `--privacy-seconds`와 `--merge-seconds`는 각각 미지정 시 회차 초가 기본값이다. 합친 답 가림에 쓴 시간은 의미 비교 한도에서 제외한다. 가림과 합치기를 재개하면 별도 시간 창을 새로 받는다. 비용 한도는 모든 단계에 공통이다.

미완료 브라우저 관찰의 원자료와 현재 URL은 복원하지만 살아 있던 브라우저 객체와 쿠키 저장소는 직렬화하지 않는다. 재개 시 마지막 화면을 다시 열며 네트워크 요청은 요청 카운터와 남은 예산에 포함된다. HTTP 경로는 기존 표본과 현재 URL에서 이어서 모델 판단을 받는다. 완료한 둘러보기는 브라우저나 HTTP를 다시 실행하지 않는다.

이 변경 이전의 `<출력 stem>/run-<회차>-<묶음>.json`만으로는 원본과 축의 식별자, 관찰 원자료와 비용을 복원할 수 없어 자동 재개하지 않는다. 그 파일들은 수정하지 않았다. 현재 진행 중인 기존 분석 프로세스를 조작하거나 종료하지 않았다.

## 실행한 확인

소스 실행 확인은 `py_compile`과 `--dry-run`만 수행했다. 작업 디렉터리는 `defense/web-proxy-defense/`다.

```powershell
python -B -m py_compile site_analysis/__init__.py site_analysis/catalog.py site_analysis/model.py site_analysis/prompts.py site_analysis/record.py site_analysis/windows.py site_analysis/observer.py site_analysis/resume.py site_analysis/analyze.py
python -B -m site_analysis.analyze --origin-url http://target.test/ --out site_analysis/offline-resume-analysis.json --dry-run
python -B -m site_analysis.analyze --origin-url http://target.test/ --out site_analysis/offline-resume-analysis.json --runs 1 --rates ../../.tmp/installer-targets/wordpress/settings.json --max-cost-usd 4 --browse-share 0.5 --context-chars 80000 --max-pages 25 --max-seconds 1 --privacy-seconds 30 --merge-seconds 40 --login-env SITE_ANALYSIS_DRY_RUN_UNSET --fresh --dry-run
python -B -m site_analysis.analyze --origin-url http://target.test/ --out site_analysis/offline-resume-analysis.json --privacy-seconds 0 --dry-run
python -B -m site_analysis.analyze --origin-url http://target.test/ --out site_analysis/offline-resume-analysis.json --merge-seconds nan --dry-run
```

최종 소스에서 9개 모듈 컴파일과 4달러, `--fresh`, 별도 시간 설정의 dry-run은 종료 코드 0이었다. 기본 dry-run도 통과했다. 시간 0과 NaN을 준 마지막 두 명령은 시간 예산 `ValueError`로 거부됐다. 처음 기본 dry-run은 사용자 홈의 `.git`까지 저장 경로 검사에 포함해 실패했다. 요청한 LOCALAPPDATA 위치와 현재 프로젝트 저장소를 구분하도록 수정한 뒤 통과했다.

dry-run 내부에서는 원본과 공급자를 실행하지 않는 로컬 응답 객체와 메모리 저장기를 사용해 다음을 확인했다.

- 축 분석을 끝내고 첫 가림 셀을 저장한 뒤 중단시켜 JSON 직렬화와 역직렬화로 새 실행의 상태를 복원했다. 완료한 둘러보기와 축 묶음을 재호출하지 않았고 정상 가림 셀을 재사용했다. 완료한 회차를 다시 실행해도 모델 호출이 늘지 않았다.
- UTF-8 문자열과 원바이트 `0x00`, `0xff`가 복원됐다. 관찰 문맥의 비공개 원문이 공개 기록에 섞이지 않았다.
- 실제 ResumeStore 읽기 경로를 파일 API의 메모리 응답으로 확인했다. 저장 해시 일치, 원본 변경, 축 변경, `--fresh`, 저장 비용 읽기와 재개 단계가 기대한 결과였다.
- 의미 비교 원답을 저장하고 합친 답 가림 중단 후 복원했다. 이미 끝난 의미 비교를 다시 호출하지 않았다.
- 상한에 도달한 상태에서도 장부에 남은 미소비 답은 추가 호출과 비용 없이 반환했다. 소비 확인한 답은 재생하지 않았고 이후 모델 호출은 비용 상한으로 막혔다. `inflight` 호출의 추정 비용 복원도 확인했다.
- 회차 시계를 소진한 관찰을 넣어 축 모델 호출은 건너뛰고 별도 시간의 사실 가림 호출은 진행되는지 확인했다.
- 기존 51개 축의 형식, 부분 축 보존, GET/HEAD 경계, 결정 전후 체크포인트, 읽기 기억, 묶음 몫, 마지막 답변 호출과 의미 합치기 규칙도 기존 dry-run에서 통과했다.

정상 dry-run 출력은 `network_requests=0`, `model_calls=0`, `files_written=0`, `login_values_read=false`, `resume_check=passed`였다. 파일 존재 검사에서 지정 출력 파일, `.dry-unused`, 실제 `offline-resume-analysis.json` 체크포인트 폴더와 `resume-dry-unused.json` 체크포인트 폴더는 생성되지 않았다. `py_compile`은 `site_analysis/__pycache__/`에 컴파일 파일을 썼다.

자료 확인과 소스 검토에는 PowerShell 읽기, `rg`와 `git status --short`를 사용했다. 시작과 확인 시점의 범위 밖 기존 변경 목록이 같았다. `site_analysis/`는 작업 시작 때부터 git 미추적 상태라 일반 git diff로 이전 소스와 비교하지 못했다. 수정한 소스와 연결 경로를 다시 읽어 검토했다.

## 실행하지 않은 것과 남은 제한

원본과 중계 접속, 실제 모델 호출과 가림, Playwright 실행, 로그인, Docker 명령, 의존성 설치, 별도 테스트 실행, git commit, push와 stash는 하지 않았다. `site_analysis/` 밖은 수정하지 않았으며 별도 테스트 파일도 만들지 않았다.

실제 LOCALAPPDATA 파일 저장, 아카이브 이동, 저장 권한과 프로세스 강제 종료를 동반한 복구는 실행하지 않았다. 저장 형식과 재개 제어 흐름은 dry-run의 메모리 저장과 파일 읽기 대체로 확인했다. 실제 브라우저의 탭 재생성, 공급자 응답과 개인정보 가림의 정확성은 미검증이다. 공급자가 응답을 반환하기 전에 강제 종료된 호출은 완성된 답을 복원할 수 없으며 비용만 추정한다. 추정액은 실제 과금 보장이 아니고, 진행 중 한 호출이 전체 상한을 넘는 기존 제한도 남는다. 이 변경 전에 메모리에서 이미 사라진 관찰은 복구하지 못한다.
