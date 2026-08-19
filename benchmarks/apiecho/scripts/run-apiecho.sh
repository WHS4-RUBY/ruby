#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_DIR="$ROOT_DIR/upstream/apiecho"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$ROOT_DIR/results/runs/$RUN_ID"
mkdir -p "$RUN_DIR"

if ! command -v poetry >/dev/null 2>&1; then
  printf '[오류] Poetry가 필요합니다. 설치 안내는 scripts/setup.sh를 실행해 확인하세요.\n' >&2
  exit 1
fi
if ! command -v sysdig >/dev/null 2>&1; then
  printf '[오류] Sysdig가 필요합니다. 설치 안내는 scripts/setup.sh를 실행해 확인하세요.\n' >&2
  exit 1
fi

TARGET_ID="$($ROOT_DIR/scripts/get-container-id.sh)"
"$ROOT_DIR/scripts/generate-config.sh" "$TARGET_ID"

cat >"$RUN_DIR/metadata.txt" <<EOF
started_at_utc=$RUN_ID
container_id=$TARGET_ID
config=$ROOT_DIR/configs/config.yaml
raw_capture=$ROOT_DIR/results/captured
EOF

IS_WSL=0
SYSDIG_LIVE_ARGS=()
if grep -qi microsoft /proc/version; then
  IS_WSL=1
  SYSDIG_LIVE_ARGS+=(--modern-bpf)
  export APIECHO_SYSDIG_MODERN_BPF=1
  export APIECHO_SYSDIG_DOCKER=1
  if ! docker image inspect sysdig/sysdig:latest >/dev/null 2>&1; then
    docker pull sysdig/sysdig:latest
  fi
fi
if (( IS_WSL == 0 )); then
  printf '[확인] Sysdig 실행에 필요한 sudo 인증을 요청합니다.\n'
  if [[ "${APIECHO_SUDO_READY:-0}" != "1" ]]; then
    sudo -v
  fi
  if ! sudo -n true; then
    printf '[오류] 현재 터미널에 유효한 sudo 인증이 없습니다. sudo -v를 먼저 실행하세요.\n' >&2
    exit 1
  fi
fi

wait_for_target() {
  for _ in $(seq 1 30); do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' apiecho-target 2>/dev/null || true)"
    if [[ "$status" == "healthy" ]]; then
      return 0
    fi
    sleep 1
  done
  printf '[오류] apiecho-target 컨테이너가 정상 상태가 되지 않았습니다.\n' >&2
  return 1
}

SMOKE_LOG="$RUN_DIR/sysdig-smoke.log"
printf '[확인] Sysdig가 컨테이너 %s의 이벤트를 수집하는지 검사합니다.\n' "$TARGET_ID"
if (( IS_WSL == 1 )); then
  docker rm -f apiecho-sysdig-smoke >/dev/null 2>&1 || true
  sleep 3
  docker run --detach --name apiecho-sysdig-smoke \
    --privileged --net=host \
    -v /var/run/docker.sock:/host/var/run/docker.sock \
    -v /dev:/host/dev \
    -v /proc:/host/proc:ro \
    -v /boot:/host/boot:ro \
    -v /lib/modules:/host/lib/modules:ro \
    -v /usr:/host/usr:ro \
    -v /etc:/host/etc:ro \
    --entrypoint sysdig \
    sysdig/sysdig:latest \
    --modern-bpf -M 20 \
    -p '%container.id %proc.name %thread.vtid %evt.type %fd.name %evt.arg.data' \
    "container.id='$TARGET_ID' or (evt.type=write and evt.arg.data contains request_)" >/dev/null
  sleep 5
  docker restart apiecho-target >/dev/null
  wait_for_target
  python3.12 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/users/1', timeout=3).read()"
  docker wait apiecho-sysdig-smoke >/dev/null
  docker logs apiecho-sysdig-smoke >"$SMOKE_LOG"
  docker rm apiecho-sysdig-smoke >/dev/null
  sleep 5
else
  sudo -n sysdig "${SYSDIG_LIVE_ARGS[@]}" -M 10 \
    -p '%container.id %proc.name %thread.vtid %evt.type %fd.name %evt.arg.data' \
    "container.id='$TARGET_ID' or (evt.type=write and evt.arg.data contains request_)" >"$SMOKE_LOG" &
  SYSDIG_PID=$!
  sleep 1
  python3.12 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/users/1', timeout=3).read()"
  wait "$SYSDIG_PID"
fi

if ! grep -q "$TARGET_ID" "$SMOKE_LOG"; then
  printf '[오류] Sysdig가 apiecho-target의 이벤트를 수집하지 못했습니다. 확인 파일: %s\n' "$SMOKE_LOG" >&2
  exit 1
fi
if ! grep -Eq "^$TARGET_ID .*python request_start " "$SMOKE_LOG" ||
  ! grep -Eq "^$TARGET_ID .*python request_end " "$SMOKE_LOG"; then
  printf '[오류] Sysdig가 컨테이너 이벤트는 수집했지만 APIEcho 요청 시작·종료 표시는 모두 수집하지 못했습니다. 확인 파일: %s\n' "$SMOKE_LOG" >&2
  exit 1
fi
printf '[성공] Sysdig가 대상 컨테이너의 이벤트를 수집했습니다. 확인 파일: %s\n' "$SMOKE_LOG"
printf '[성공] Sysdig가 요청 시작·종료 표시를 모두 수집했습니다.\n'

collect_results() {
  cp "$ROOT_DIR/configs/config.yaml" "$RUN_DIR/config.yaml" 2>/dev/null || true
  cp "$UPSTREAM_DIR"/sysdig_output.log "$UPSTREAM_DIR"/sysdig_error.log "$UPSTREAM_DIR"/output.jsonl "$RUN_DIR" 2>/dev/null || true
  if [[ -d "$UPSTREAM_DIR/dump_results" ]]; then
    cp -R "$UPSTREAM_DIR/dump_results" "$RUN_DIR/" 2>/dev/null || true
  fi
  date -u +finished_at_utc=%Y%m%dT%H%M%SZ >>"$RUN_DIR/metadata.txt"
}

APIECHO_PID=""
CAPTURE_READY_PID=""
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$CAPTURE_READY_PID" ]] && kill -0 "$CAPTURE_READY_PID" 2>/dev/null; then
    kill -TERM "$CAPTURE_READY_PID" 2>/dev/null || true
    wait "$CAPTURE_READY_PID" 2>/dev/null || true
  fi
  if [[ -n "$APIECHO_PID" ]] && kill -0 "$APIECHO_PID" 2>/dev/null; then
    kill -INT "$APIECHO_PID" 2>/dev/null || true
    for _ in $(seq 1 10); do
      if ! kill -0 "$APIECHO_PID" 2>/dev/null; then
        break
      fi
      sleep 1
    done
    if kill -0 "$APIECHO_PID" 2>/dev/null; then
      kill -TERM "$APIECHO_PID" 2>/dev/null || true
    fi
    wait "$APIECHO_PID" 2>/dev/null || true
  fi
  if (( IS_WSL == 1 )); then
    docker rm -f apiecho-sysdig-capture >/dev/null 2>&1 || true
  fi
  collect_results
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '[실행] APIEcho를 시작합니다. 다른 터미널에서 요청을 순차적으로 전송하세요.\n'
printf '[안내] APIEcho는 완료된 요청 단위를 약 60초 후에 확정합니다.\n'
rm -f "$UPSTREAM_DIR/sysdig_output.log" "$UPSTREAM_DIR/sysdig_error.log"
if (( IS_WSL == 1 )); then
  docker rm -f apiecho-sysdig-capture >/dev/null 2>&1 || true
  sleep 3
fi
(
  capture_started=0
  for _ in $(seq 1 60); do
    if (( IS_WSL == 1 )); then
      if [[ "$(docker inspect --format '{{.State.Running}}' apiecho-sysdig-capture 2>/dev/null || true)" == "true" ]]; then
        capture_started=1
        break
      fi
    elif [[ -f "$UPSTREAM_DIR/sysdig_error.log" ]]; then
      capture_started=1
      break
    fi
    sleep 1
  done
  if (( capture_started == 0 )); then
    printf '[오류] APIEcho가 Sysdig 수집 기능을 시작하지 못했습니다.\n' >&2
    exit 1
  fi
  if (( IS_WSL == 1 )); then
    sleep 5
    docker restart apiecho-target >/dev/null
    wait_for_target
  fi
  printf '[성공] APIEcho 이벤트 수집 준비가 완료되었습니다.\n'
) &
CAPTURE_READY_PID=$!
set +e
(
  trap - INT TERM
  cd "$UPSTREAM_DIR"
  exec poetry run python main.py run
) > >(tee "$RUN_DIR/apiecho.log") 2>&1 &
APIECHO_PID=$!
wait "$CAPTURE_READY_PID"
capture_ready_status=$?
CAPTURE_READY_PID=""
if (( capture_ready_status != 0 )); then
  exit "$capture_ready_status"
fi
wait "$APIECHO_PID"
status=$?
APIECHO_PID=""
set -e
exit "$status"
