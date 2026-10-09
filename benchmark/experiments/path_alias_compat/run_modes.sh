#!/bin/sh
# Restart only Defense with each alias mode and print the mode matrix rows.
export MSYS_NO_PATHCONV=1 MSYS2_ENV_CONV_EXCL="*"
cd "$(dirname "$0")/../../.." || exit 1
PY=${PY:-python}
# juice-unready.tmp.json: a copy of juice-shop-routes.json with enforce_ready=false (see README)
for spec in "off juice-shop-routes.json" "audit juice-shop-routes.json" \
            "observe juice-shop-routes.json" "enforce juice-shop-routes.json" \
            "enforce juice-unready.tmp.json"; do
  set -- $spec
  PATH_ALIAS_MODE=$1 PATH_ALIAS_ROUTES_FILE=/app/config/$2 PATH_ALIAS_APP_ID="matrix-$1-$2" \
    docker compose -p ruby-verify --env-file ${VERIFY_ENV:-verify.env} -f docker-compose.local.yml \
    up -d --wait --wait-timeout 120 defense >/dev/null 2>&1 || { echo "start failed $1"; exit 1; }
  echo "# mode=$1 file=$2"
  $PY benchmark/experiments/path_alias_compat/mode_matrix.py "$1:$2"
done
