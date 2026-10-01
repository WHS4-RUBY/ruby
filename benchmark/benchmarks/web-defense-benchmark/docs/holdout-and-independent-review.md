# 보류 표본 봉인과 독립 검토

보류 표본은 방어 규칙이나 프롬프트를 조정하기 전에 정한다. 공개 commitment에는 선택된 표적이 들어가지 않고, 실제 목록은 저장소 밖의 비공개 파일로 보관한다.

## 1. 보류 표본 만들기

입력은 `make_campaign_smoke_evidence.py`가 만든 무방어 자격 증거여야 한다. 완료, 격리, 실행 계획 검사가 모두 통과한 증거만 받으며 단순 캠페인 요약 파일은 거부한다. 표적과 공급자별 시험 수와 성공률은 증거에 포함된 개별 시험에서 다시 계산한다. 자격을 통과한 층이 6개보다 적으면 도구가 생성을 거부한다.

PowerShell에서 32바이트 비밀 파일을 저장소 밖에 만든다.

```powershell
$secret = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($secret)
[IO.File]::WriteAllBytes("$env:USERPROFILE\ruby-holdout-secret.bin", $secret)

$python = "app\.venv\Scripts\python.exe"
& $python app\tools\make_holdout_commitment.py create `
  --qualification app\evaluation\qualification-run\qualification-evidence.json `
  --secret-file "$env:USERPROFILE\ruby-holdout-secret.bin" `
  --public-output app\evaluation\qualification-run\holdout-commitment.json `
  --private-output "$env:USERPROFILE\ruby-holdout-private.json"
```

Linux와 macOS에서는 다음처럼 만든다.

```bash
openssl rand 32 > "$HOME/ruby-holdout-secret.bin"

app/.venv/bin/python app/tools/make_holdout_commitment.py create \
  --qualification app/evaluation/qualification-run/qualification-evidence.json \
  --secret-file "$HOME/ruby-holdout-secret.bin" \
  --public-output app/evaluation/qualification-run/holdout-commitment.json \
  --private-output "$HOME/ruby-holdout-private.json"
```

선택 수는 적격 층의 20%를 올림한 값, 6개와 관측된 상호작용 종류 수 중 가장 큰 값이다. HTTP, 브라우저, 동시 요청, multipart, SMTP, 피해자 세션과 다중 계정 종류를 각각 최소 한 번 포함한다. 같은 입력과 비밀 파일은 같은 선택을 만든다.

공개 파일의 생성 시각은 선택값 계산에 사용하지 않는다. 비공개 파일 전체의 정규 JSON SHA256만 공개 파일에 저장한다. 방어 조정이 끝날 때까지 비공개 목록을 열거나 결과를 생성하지 않는다.

## 2. commitment 확인

보류 평가를 시작할 때 공개 파일과 비공개 목록이 처음 봉인한 값과 같은지 확인한다.

```powershell
& $python app\tools\make_holdout_commitment.py verify `
  --public app\evaluation\qualification-run\holdout-commitment.json `
  --private "$env:USERPROFILE\ruby-holdout-private.json"
```

`verified`가 `true`여야 한다. 비공개 목록, 자격 결과 해시, 선택 정책, 알고리즘이나 공개 commitment가 달라지면 실패한다.

## 3. 독립 검토 기록

독립 검토자는 방어 구현에 참여하지 않은 팀원이나 팀 외 검토자여야 한다. 검토 기록은 [`../contracts/independent-review-record.schema.json`](../contracts/independent-review-record.schema.json)을 따른다. 이름, 역할, 검토 시각, 입력 종류와 상대 경로 및 SHA256, 여섯 검사 결과, 발견 사항과 최종 판정을 기록한다. 자격 및 확증 분석 계획, 공식 자격 증거, 확증 실행 봉인, 통계 분석, 공개 commitment와 비공개 보류 목록은 각각 정확히 한 번 포함해야 한다.

필수 검사는 다음과 같다.

1. 공격자에게 비공개 평가기와 정답이 노출되지 않았다.
2. 제외된 시험마다 사전 정의된 사유가 있다.
3. 조건 사이 `pair_id`, 모델, 시드, 계정 이름공간과 예산이 같다.
4. 방어 연결 후 정상 트래픽이 모두 성공하고 차단과 방어 오류가 없다.
5. 분석 계획과 통계 보고서의 수치가 원시 시험 파일에서 재계산된다.
6. 보류 표본이 방어 튜닝에 사용되지 않았다.

검토자가 작성한 파일은 다음 명령으로 형식, 입력 경로와 해시를 검사한다. 도구는 분석 계획과 보고서 해시, 확증 실행 봉인, 자격 증거와 보류 목록 commitment, 효과 판정 대상이 봉인된 층에 포함되는지도 교차 확인한다.

```powershell
& $python app\tools\validate_independent_review.py `
  --review app\evaluation\independent-review.json `
  --input-root . `
  --output app\evaluation\independent-review-validation.json
```

검토자 독립성은 작성자가 명시하고 책임지는 외부 사실이다. 자동 도구는 기록 형식과 증거 파일의 동일성은 확인하지만 실제 인적 관계를 대신 증명하지 않는다. 해결되지 않은 높은 심각도 발견 사항이 있거나 입력 해시가 하나라도 다르면 검토는 실패한다.
