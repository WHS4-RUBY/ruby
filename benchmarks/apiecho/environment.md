# APIEcho 실행 환경 기록

## 실행 식별 정보

- 담당자: 김우민
- 실행 날짜 및 시간: 2026년 8월 19일 01:47:08~01:49:47 UTC
- APIEcho repository commit: `cb0990f4823a6ba6d927e3fe4a22ef9b00325b28`
- 대상 Docker image: `python:3.12-slim` 기반 로컬 빌드
- Sysdig capture image: `sysdig/sysdig:latest`
- 대상 image ID: `sha256:9b242c9de5a6e03bd035e6b6e842ef9acab82adf5396591639c4c51d1c698125`
- Sysdig image digest: `sysdig/sysdig@sha256:740a122ba3ab923467c09a25725cdc5b530d93345f00cc1ced1b4a32bd9c52a9`
- Codex CLI: 사용하지 않음

## Host 환경

- OS: Windows WSL2의 Ubuntu
- Kernel: `5.15.167.4-microsoft-standard-WSL2`
- Architecture: x86_64
- CPU: Intel Core Ultra 5 125H
- RAM: 실행 당시 별도 기록하지 않음
- GPU: Microsoft Corporation Device 008e
- Docker: Docker Desktop 29.2.1
- Python: 3.12.13
- Poetry: 2.4.1
- Host Sysdig reader: 0.41.4

## Container 환경

- 대상 애플리케이션 base image: `python:3.12-slim`
- 대상 container: `apiecho-target`
- 대상 container ID: `dd7b30e4fbd8`
- Kernel/architecture: Docker Desktop Linux context, x86_64
- Language runtime: Python 3.12
- 주요 패키지: FastAPI 0.116.1, Uvicorn 0.35.0
- Uvicorn worker: 1개
- Capture backend: privileged `sysdig/sysdig@sha256:740a122ba3ab923467c09a25725cdc5b530d93345f00cc1ced1b4a32bd9c52a9` modern eBPF helper

## 실행 조건

- 실행 명령: `./scripts/setup.sh`, `./scripts/start-target.sh`, `./scripts/run-experiment.sh`
- 정상 요청: endpoint 2개에 각각 25회, 총 50회
- 이상 요청: `GET /api/users/1?experiment=anomaly` 1회
- 요청 방식: 순차 실행, 요청 간격 0.05초
- Capture duration: 105초
- Capture chunk: 1 MB
- Partition grace period: 65초
- API category window: 20
- Window step: 1
- 탐지 threshold: 2.0
- 네트워크: 대상 API를 `127.0.0.1:8000`에만 바인딩
- 이상 행위 범위: 대상 container 내부 파일·process 및 loopback 접근으로 제한

## 비고

WSL2 host에서 직접 실행한 modern eBPF capture는 Docker Desktop 내부 Uvicorn syscall을 완전하게 관찰하지 못했다. 따라서 Docker Desktop Linux context의 privileged Sysdig helper로 capture하고, Ubuntu host의 APIEcho와 Sysdig reader가 생성된 scap chunk를 처리했다. APIEcho 자체는 host에서 실행했다.

Native Ubuntu에서는 privileged helper 없이 host Sysdig를 직접 사용하는 구성이 권장된다. `latest` 태그는 재현성이 낮으므로 공통 서버 재실험 시 Sysdig image digest를 함께 기록해야 한다. 실행 시간과 탐지 점수는 하드웨어, 커널, capture backend 및 이벤트 순서의 영향을 받을 수 있다.
