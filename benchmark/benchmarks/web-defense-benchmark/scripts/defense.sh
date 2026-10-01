#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
python_bin="$project_root/app/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
  python_bin="${PYTHON_BIN:-python3}"
fi
registry="${RUBY_DEFENSE_REGISTRY:-$project_root/app/configs/stage3a-defense-runtime-registry-v2.json}"

if [[ $# -lt 1 ]]; then
  set -- list
fi

case "$1" in
  list|validate|smoke|serve)
    ;;
  *)
    echo "Usage: $0 {list|validate|smoke|serve} [options]" >&2
    exit 2
    ;;
esac

PYTHONPATH="$project_root/app/tools${PYTHONPATH:+:$PYTHONPATH}" \
  "$python_bin" "$project_root/app/tools/manage_defense.py" --registry "$registry" "$@"
