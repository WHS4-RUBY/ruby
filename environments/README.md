# Environments

팀 공통 Dockerfile, Compose 파일과 환경 구성 문서를 저장합니다.

환경 파일에는 다음 정보를 함께 기록합니다.

- Ubuntu 및 Docker 이미지 버전
- 이미지 digest
- Codex CLI 버전
- 언어 런타임과 패키지 버전
- 볼륨, 포트, 환경 변수 이름
- 빌드와 실행 명령

실제 토큰이나 비밀번호 대신 `.env.example`에 변수 이름과 예시 형식만 작성합니다.
