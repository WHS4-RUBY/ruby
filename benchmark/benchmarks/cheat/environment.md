# CHeaT 실행 환경 기록

## 실행 식별 정보

- 담당자: yujinson1231
- 실행 날짜 및 시간: 2026년 8월 19일
- CHeaT repository commit: `ee69d2c2a68b38a77f9266595655e8fa8cd9ae90`
- Docker image: `cheat:pristine` (로컬 빌드, `python:3.11-slim` 기반)
- Docker image ID: `sha256:c6e7b106847d7cdad713951796babae79da2795bcd22840274d02cf6545c9c8f`
- Codex CLI version: `codex-cli 0.147.0` (WSL2 `~/.codex`에 로그인 상태 — 15개 기법 개별 테스트 단계에서 사용, `results.md` 참고)

## Host 환경

로컬 개발 환경은 **WSL2 Ubuntu + Docker** 하나로 통일했다

- Windows: 11 Pro (Build 26200)
- WSL: WSL2, Kernel `6.6.87.2-microsoft-standard-WSL2`
- WSL 배포판: Ubuntu 26.04 LTS (Resolute Raccoon)
- CPU: Intel Core i3-10110U @ 2.10GHz
- RAM: 7.8GB (호스트 전체 기준, WSL2와 공유)
- Docker: Docker Desktop의 WSL2 통합(Integration)을 통해 WSL2 Ubuntu 셸에서 `docker` CLI를 직접 사용 — Docker Engine `29.1.3` (linux/amd64)
- Docker 소켓: `/var/run/docker.sock` (WSL2 Ubuntu 내부, `docker` 그룹 소속으로 `sudo` 불필요)

## Container 환경

- Base image: `python:3.11-slim`
- Kernel/architecture: WSL2 Ubuntu 커널 공유, x86_64
- Language runtime: Python 3.11.16
- 주요 패키지 및 버전: 저장소 `pyproject.toml` 명시 의존성 그대로(`pip install -e .`)
- 컨테이너 실행: `docker run --rm cheat:pristine bash -lc '...'`, working dir `/app`

## 실행 조건

- 실행 명령: `scripts/setup.sh` → `scripts/run.sh` (모두 WSL2 Ubuntu 셸에서 실행)
- 반복 횟수: 사이클(`plant`→`list`→`remove`)당 1회 수동 검증
- Timeout: 없음(각 명령 수 초 내 종료)
- 주요 옵션: `--action plant|list|remove`, `--details '{"assettype": "web_file", "file_path": ..., "technique": "..."}'`
- 네트워크 조건: 컨테이너는 기본 Docker bridge 네트워크, 외부 노출 없음

## 비고
- 팀원별 하드웨어가 다르므로 CPU·RAM 수치는 참고값이며, 재검증 시 각자 이 표를 채워 비교한다.
- **하네스 대체 이유**: 논문은 공격 에이전트로 PentestGPT를 사용하고, PentestGPT는 백엔드 LLM으로 GPT 계열(GPT-4o 등)을 API로 직접 호출한다 — 이 백엔드는 별도의 `OPENAI_API_KEY`(유료 API 토큰)가 있어야 하는데, 이번 시행 시점엔 아직 발급받지 못했다. 대신 WSL2에 구독기반의 추가 비용 없이 쓸 수 있는 **codex CLI**를 펜테스터 에이전트로 대체 투입해 실험을 진행했다. 즉 이번 13개 기법 결과는 "PentestGPT + GPT API" 조합이 아니라 "codex CLI(구독, gpt-5.6-sol)" 조합의 예비 관찰이며, API 키 확보 후 PentestGPT 기반 정식 실험(Round 0)으로 재검증이 필요하다 —  `results.md` 참고.
