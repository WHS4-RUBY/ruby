#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_DIR="$ROOT_DIR/upstream/apiecho"
missing=0

check_command() {
  local command_name="$1"
  local description="$2"
  if command -v "$command_name" >/dev/null 2>&1; then
    printf '[성공] %s: ' "$description"
    "$command_name" --version 2>/dev/null || true
  else
    printf '[누락] %s (%s)\n' "$description" "$command_name"
    missing=1
  fi
}

if command -v python3.12 >/dev/null 2>&1; then
  printf '[성공] Python: '
  python3.12 --version
else
  printf '[누락] Python 3.12\n'
  printf '  사용 중인 Ubuntu 버전에 맞는 신뢰할 수 있는 패키지 저장소에서 설치하세요.\n'
  missing=1
fi

if command -v poetry >/dev/null 2>&1; then
  printf '[성공] Poetry: '
  poetry --version
  printf '[실행] poetry.lock을 기준으로 APIEcho 의존성을 설치합니다.\n'
  poetry --directory "$UPSTREAM_DIR" install --no-interaction
else
  printf '[누락] Poetry\n'
  printf '  Official installer: curl -sSL https://install.python-poetry.org | python3.12 -\n'
  printf '  설치 스크립트를 검토한 후 실행하세요. 이 점검 스크립트는 사용자 환경을 변경하지 않습니다.\n'
  missing=1
fi

check_command docker Docker
if command -v docker >/dev/null 2>&1; then
  if docker compose version >/dev/null 2>&1; then
    printf '[성공] Docker Compose: '
    docker compose version
  else
    printf '[누락] Docker Compose 플러그인\n'
    missing=1
  fi
  if ! docker info >/dev/null 2>&1; then
    printf '[오류] 현재 사용자 권한으로 Docker daemon에 연결할 수 없습니다.\n'
    missing=1
  fi
fi

if command -v sysdig >/dev/null 2>&1; then
  printf '[성공] Sysdig: '
  sysdig --version
else
  printf '[누락] Sysdig\n'
  printf '  Upstream installation command: curl -s https://download.sysdig.com/stable/install-sysdig | sudo bash\n'
  printf '  내려받은 설치 스크립트를 먼저 검토하세요. Kernel driver 또는 eBPF 지원이 필요합니다.\n'
  missing=1
fi

if grep -qi microsoft /proc/version; then
  printf '[경고] WSL 커널을 감지했습니다. Docker Desktop 컨테이너와 Sysdig의 driver/kernel 환경이 달라 이벤트가 보이지 않을 수 있습니다.\n'
fi

if (( missing != 0 )); then
  printf '[중단] 누락된 필수 도구를 설치한 후 이 스크립트를 다시 실행하세요.\n'
  exit 1
fi

printf '[성공] APIEcho 실행 환경 준비가 완료되었습니다.\n'
