#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPERIMENT_ID="$(date -u +%Y%m%dT%H%M%SZ)"
EXPERIMENT_LOG="$ROOT_DIR/results/experiment-$EXPERIMENT_ID.log"

cleanup() {
  if [[ -n "${APIECHO_PID:-}" ]] && kill -0 "$APIECHO_PID" 2>/dev/null; then
    kill -TERM "$APIECHO_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if ! grep -qi microsoft /proc/version; then
  printf '[확인] Sysdig 실행에 필요한 sudo 인증을 진행합니다.\n'
  sudo -v
fi

printf '[실행] APIEcho를 시작합니다.\n'
APIECHO_SUDO_READY=1 "$ROOT_DIR/scripts/run-apiecho.sh" >"$EXPERIMENT_LOG" 2>&1 &
APIECHO_PID=$!

ready=0
for _ in $(seq 1 60); do
  if grep -q '\[성공\] APIEcho 이벤트 수집 준비가 완료되었습니다' "$EXPERIMENT_LOG" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$APIECHO_PID" 2>/dev/null; then
    printf '[오류] APIEcho가 시작 중 종료되었습니다. 실행 기록: %s\n' "$EXPERIMENT_LOG" >&2
    exit 1
  fi
  sleep 1
done
if (( ready == 0 )); then
  printf '[오류] APIEcho가 준비 상태가 되지 않았습니다. 실행 기록: %s\n' "$EXPERIMENT_LOG" >&2
  exit 1
fi

printf '[실행] 정상 요청을 전송합니다.\n'
python3.12 "$ROOT_DIR/scripts/generate-normal-traffic.py" --count 25 --interval 0.05 --flush-delay 0

printf '[실행] 같은 /api/users/1 범주에 이상 요청을 전송합니다.\n'
python3.12 "$ROOT_DIR/scripts/generate-anomaly-traffic.py" --flush-delay 0

printf '[대기] 요청별 시스템 이벤트를 확정하기 위해 65초 동안 기다립니다.\n'
sleep 65
python3.12 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/products/1', timeout=3).read()"

# Let the 1 MB capture chunk rotate so APIEcho can consume the flush event.
printf '[대기] 수집 파일 교체와 이상 탐지를 기다립니다.\n'
sleep 20

printf '[대기] APIEcho가 남은 이벤트 처리와 결과 저장을 마칠 때까지 기다립니다.\n'
for _ in $(seq 1 40); do
  if ! kill -0 "$APIECHO_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done
if kill -0 "$APIECHO_PID" 2>/dev/null; then
  printf '[오류] APIEcho가 설정된 수집 시간이 지난 후에도 종료되지 않았습니다.\n' >&2
  kill -TERM "$APIECHO_PID" 2>/dev/null || true
fi
wait "$APIECHO_PID" || true
APIECHO_PID=""

python3.12 "$ROOT_DIR/scripts/summarize-results.py"
printf '[성공] 실험이 완료되었습니다. 실행 기록: %s\n' "$EXPERIMENT_LOG"
