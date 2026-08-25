#!/usr/bin/env bash
set -euo pipefail

if ! docker inspect apiecho-target >/dev/null 2>&1; then
  printf '[오류] apiecho-target 컨테이너가 없습니다. scripts/start-target.sh를 먼저 실행하세요.\n' >&2
  exit 1
fi

running="$(docker inspect --format '{{.State.Running}}' apiecho-target)"
if [[ "$running" != "true" ]]; then
  printf '[오류] apiecho-target 컨테이너가 실행 중이 아닙니다.\n' >&2
  exit 1
fi

full_id="$(docker inspect --format '{{.Id}}' apiecho-target)"
printf '%s\n' "${full_id:0:12}"
