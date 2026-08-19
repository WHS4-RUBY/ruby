# 실제 시스템 연동 로드맵

## M0 — 완료: 평가 계약 및 Grader 코어 본보기

- 완료 조건: 데모 실행, 결정적 Oracle, 2×2 집계, 테스트, 발표 문서
- 산출물: 이 저장소 v0.3

## M1 — 단일 웹 시나리오 Pilot

- 로그인/입력 검증 계열의 통제된 취약 서비스 1개 선정
- Docker Compose로 target, defense proxy, grader collector, runner 네트워크 분리
- reference attack과 정상 workload 작성
- 실제 `state.json`, `events.jsonl`, `usage.json` adapter 구현
- 완료 조건: baseline positive control 100%, 정상 negative control 0%

## M2 — LLM Agent 연결

- 모델, temperature, system prompt, tool schema 고정
- provider usage metadata 원본 저장
- fixed와 agent가 동일 도구/예산을 사용하도록 통제
- 셀당 10회 pilot으로 분산·실패 코드 확인

## M3 — 방어 구조 비교

- 방어 A: rate limit/time-delay
- 방어 B: 입력/행동 기반 정책
- 방어 C: deception 또는 token-cost 유도
- 방어별 ASR, 생존 시간, token, benign SLO 비교

## M4 — 논문 품질

- 가설·primary outcome·제외 기준·가중치 사전 등록
- 충분한 반복 수 산정
- 생존 분석과 신뢰구간
- blind run ID와 독립 재채점
- raw artifact, image digest, commit SHA, 재현 가이드 공개

## GitHub 업로드 전

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
git init
git add .
git commit -m "feat: add RUBY defense grader prototype"
```

원격 저장소 생성·push는 저장소 소유자 계정에서 수행합니다. 합성 demo artifact는 `.gitignore`에 의해 제외됩니다.
