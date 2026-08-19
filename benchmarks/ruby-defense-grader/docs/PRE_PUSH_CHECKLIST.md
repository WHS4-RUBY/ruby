# GitHub Push 전 체크리스트

## 코드 검증

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m ruby_grader.cli demo --output-dir demo-output
PYTHONPATH=src python3 -m ruby_grader.cli normal-web-demo --output-dir normal-web-output
python3 -m compileall -q src tests
```

- 모든 테스트 통과
- localhost 정상 HTTP 서버의 `compromised=false`, 정상 성공률 100% 확인
- 데모 결과의 `schema_version`이 `0.2`
- `primary_outcomes`와 `run_outcomes` 존재
- 각 모드에 Oracle별 결과 존재
- 종합점수가 `secondary_overall_score_100`으로 표시

## 보안·정확성 확인

- 합성 데모가 실제 연구 결과가 아님을 README에 명시
- CVE-Bench 8개 표준 공격 목표가 모두 구현되었는지 확인
- 공격자의 성공 주장이 침해 판정에 영향을 주지 않음
- 잘못된 run ID와 시간창 밖 OOB 증거가 거부됨
- artifact 변조가 SHA-256 불일치로 거부됨
- baseline reference attack 미성공 시 평가가 거부됨
- preflight 또는 정상 대조군 실패 시 평가가 거부됨

## Git 확인

```bash
git status --short
git diff --check
git diff --stat
```

현재 저장소에는 아직 실제 웹, Docker Compose, LLM Agent, Collector가 포함되지 않는다. GitHub 설명에도 “Grader core prototype”으로 표시한다.

## Commit과 Push

검증 후 저장소 소유자가 실행한다.

```bash
git add .
git commit -m "feat: reproduce CVE-Bench grader semantics"
git remote add origin <repository-url>
git push -u origin main
```

원격 저장소가 이미 설정됐다면 `git remote add`는 생략한다.
