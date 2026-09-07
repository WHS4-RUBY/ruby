#!/usr/bin/env bash
set -euo pipefail

action="${1:-start}"
mode="${2:-normal}"
modules="${3:-sql-injection.product-search}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
app_dir="$project_root/app"
compose=(docker compose --project-directory "$app_dir" -f "$app_dir/compose.yaml")

case "$action" in
  start)
    case "$mode" in
      normal)
        RUBY_WEB_VULNERABILITY_MODULES="" RUBY_WEB_TRIAL_ID="" \
          "${compose[@]}" up -d --build --wait
        ;;
      vulnerable)
        if [[ -z "$modules" ]]; then
          echo "A comma-separated module list is required in vulnerable mode." >&2
          exit 2
        fi
        printf -v trial_id '%04x%04x%04x%04x%04x%04x%04x%04x' \
          "$RANDOM" "$RANDOM" "$RANDOM" "$RANDOM" \
          "$RANDOM" "$RANDOM" "$RANDOM" "$RANDOM"
        RUBY_WEB_VULNERABILITY_MODULES="$modules" RUBY_WEB_TRIAL_ID="$trial_id" \
          "${compose[@]}" up -d --build --wait
        ;;
      *)
        echo "Mode must be normal or vulnerable." >&2
        exit 2
        ;;
    esac
    echo "RUBY benchmark is ready at http://127.0.0.1:18080"
    echo "Mode: $mode"
    if [[ "$mode" == "vulnerable" ]]; then
      echo "Modules: $modules"
    fi
    ;;
  stop)
    "${compose[@]}" down
    ;;
  clean)
    "${compose[@]}" down --volumes --remove-orphans
    ;;
  status)
    "${compose[@]}" ps
    ;;
  logs)
    "${compose[@]}" logs --tail 200
    ;;
  *)
    echo "Usage: $0 {start|stop|clean|status|logs} [normal|vulnerable] [module1,module2]" >&2
    exit 2
    ;;
esac
