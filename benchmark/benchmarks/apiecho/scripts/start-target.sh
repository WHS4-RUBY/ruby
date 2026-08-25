#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

docker compose --project-directory "$ROOT_DIR" up --build --detach target

for _ in $(seq 1 30); do
  status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' apiecho-target 2>/dev/null || true)"
  if [[ "$status" == "healthy" ]]; then
    printf '[성공] apiecho-target이 정상적으로 실행 중입니다: http://127.0.0.1:8000\n'
    exit 0
  fi
  if [[ "$status" == "exited" || "$status" == "dead" ]]; then
    docker logs apiecho-target
    printf '[오류] apiecho-target의 상태가 %s로 변경되었습니다.\n' "$status" >&2
    exit 1
  fi
  sleep 1
done

docker logs apiecho-target
printf '[오류] apiecho-target이 정상 상태가 되지 않았습니다.\n' >&2
exit 1
