#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ID="${1:-$($ROOT_DIR/scripts/get-container-id.sh)}"
CAPTURE_DIR="$ROOT_DIR/results/captured"
CONFIG_PATH="$ROOT_DIR/configs/config.yaml"

mkdir -p "$CAPTURE_DIR"

cat >"$CONFIG_PATH" <<EOF
enabled_features:
  - syscalls
  - syscall_categories
  - syscall_sequenced
  - directories
  - filenames
  - fd_types
  - n_ips
  - n_ports
  - proc_paths

detect:
  detector: DistanceDetector
  args:
    threshold: 2.0
  cat_batch_size: 20
  cat_batch_step: 1
  remove_abnormal: true
  visualize: false
  enable_normalize: true
partition:
  enabled_partitioners:
    - PythonAsyncioRequestPartitionHandler
  partitioner_config: {}
capture:
  output: "$CAPTURE_DIR"
  chunk: 1
  duration: 105
  filter_rule: "container.id='$TARGET_ID'"
  combine: true
  read_only: false
  keep_scap: true
output_parsers:
  - save
parsers_output_dir: "$ROOT_DIR/results/parsers_output"
save_original_log: jsonl
log_sources:
  queue_size: 100000
evaluator:
  unit_events_only: true
dumper:
  enable: true
  errors_only: false
categorize:
  export_api_catelog: true
  import_api_catelog: null
load_logs_dirs: null
EOF

ln -sfn ../../configs/config.yaml "$ROOT_DIR/upstream/apiecho/config.yaml"
printf '[성공] 컨테이너 %s의 설정을 %s에 저장했습니다.\n' "$TARGET_ID" "$CONFIG_PATH"
