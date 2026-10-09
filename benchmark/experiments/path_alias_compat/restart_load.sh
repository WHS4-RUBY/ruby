#!/bin/sh
# restart_load.sh KEY=VALUE... : recreate the 4-worker load Defense with a fresh SQLite volume
export MSYS_NO_PATHCONV=1 MSYS2_ENV_CONV_EXCL="*"
cd "$(dirname "$0")/../../.." || exit 1
docker rm -f ruby-load-defense >/dev/null 2>&1; docker volume rm -f ruby-load-alias >/dev/null 2>&1
extra=""; for kv in "$@"; do extra="$extra -e $kv"; done
docker run -d --name ruby-load-defense -p 127.0.0.1:18090:8080 --add-host host.docker.internal:host-gateway \
 -v ruby-load-alias:/app/alias-data -v "$(pwd -W)/defense/app":/app/app -v "$(pwd -W)/defense/config":/app/config:ro \
 -e TARGET_CHOICES=legacy=http://host.docker.internal:3000 -e TARGET_DEFAULT_ID=legacy -e TARGET_SELECTION_FILE=/tmp/sel.json \
 -e PATH_ALIAS_MODE=enforce -e PATH_ALIAS_ROUTES_FILE=/app/config/juice-shop-routes.verify.json -e PATH_ALIAS_PREFIXES=/rest/,/api/,/b2b/ \
 -e PATH_ALIAS_DB_PATH=/app/alias-data/path-alias.sqlite3 -e DEFENSE_DASHBOARD_ENABLED=false -e DEFENSE_DASHBOARD_PASSWORD=x \
 -e ALLOW_INSECURE_DASHBOARD_HTTP=true $extra \
 ruby-verify-defense uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 4 --no-proxy-headers --log-level warning >/dev/null
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:18090/healthz && break; sleep 1; done
