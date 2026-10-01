#!/usr/bin/env bash
set -Eeuo pipefail

benchmark_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repository_root="$(cd "${benchmark_root}/../../.." && pwd)"
app_root="${benchmark_root}/app"

project="${RUBY_TARGET_SWITCH_PROJECT:-ruby-web-target-switch-check}"
pipeline_network="${RUBY_TARGET_SWITCH_NETWORK:-ruby_web_target_switch_check_pipeline}"
defense_container="${project}-defense-probe"
juice_container="${project}-juice-probe"
image_prefix="local"
image_tag="target-switch-check"

export RUBY_BENCHMARK_IMAGE_PREFIX="${image_prefix}"
export RUBY_BENCHMARK_IMAGE_TAG="${image_tag}"
export RUBY_BENCHMARK_PIPELINE_NETWORK="${pipeline_network}"
export RUBY_WEB_PUBLIC_ORIGIN="http://target-switch-check.invalid"
export RUBY_WEB_VULNERABILITY_MODULES=""
export RUBY_WEB_TRIAL_ID=""
export RUBY_WEB_PREPARATION_SEED=""
export POSTGRES_PASSWORD="c1b2c3d4e5f60123456789abcdef0001"
export POSTGRES_APP_PASSWORD="c1b2c3d4e5f60123456789abcdef0002"
export POSTGRES_UNTRUSTED_PASSWORD="c1b2c3d4e5f60123456789abcdef0003"
export POSTGRES_VERIFIER_PASSWORD="c1b2c3d4e5f60123456789abcdef0004"
export RUBY_WEB_OBJECT_ACCESS_KEY="switchcheckaccess"
export RUBY_WEB_OBJECT_SECRET_KEY="switchchecksecret"
export RUBY_WEB_RESET_TOKEN="switchcheckreset"
export RUBY_EVALUATOR_TOKEN="switchcheckevaluator"
export RUBY_WEB_OPERATIONS_DIAGNOSTIC_KEY="switchcheckdiagnostic"

compose=(
  docker compose
  -p "${project}"
  -f "${app_root}/compose.production.yaml"
)

container_exists() {
  docker container inspect "$1" >/dev/null 2>&1
}

cleanup() {
  set +e
  for container in "${defense_container}" "${juice_container}"; do
    if container_exists "${container}"; then
      docker rm -f "${container}" >/dev/null
    fi
  done
  "${compose[@]}" down --volumes --remove-orphans >/dev/null
  if docker network inspect "${pipeline_network}" >/dev/null 2>&1; then
    attached="$(docker network inspect --format '{{len .Containers}}' "${pipeline_network}")"
    if [[ "${attached}" == "0" ]]; then
      docker network rm "${pipeline_network}" >/dev/null
    fi
  fi
}
trap cleanup EXIT

if docker network inspect "${pipeline_network}" >/dev/null 2>&1; then
  echo "refusing existing network: ${pipeline_network}" >&2
  exit 1
fi
for container in "${defense_container}" "${juice_container}"; do
  if container_exists "${container}"; then
    echo "refusing existing container: ${container}" >&2
    exit 1
  fi
done

image_contexts=(
  "benchmark-web-postgres:postgres"
  "benchmark-web-redis:redis"
  "benchmark-web-object-store:object-store"
  "benchmark-web-mock-integration:mock-integration"
  "benchmark-web-api:backend"
  "benchmark-web-evaluator:evaluator"
  "benchmark-web-frontend:frontend"
)

for image_context in "${image_contexts[@]}"; do
  image="${image_context%%:*}"
  context="${image_context#*:}"
  docker build --quiet \
    --tag "${image_prefix}/${image}:${image_tag}" \
    "${app_root}/${context}" >/dev/null
done
docker build --quiet \
  --tag "ruby-target-switch-defense:${image_tag}" \
  "${repository_root}/defense" >/dev/null

docker network create --driver bridge "${pipeline_network}" >/dev/null
"${compose[@]}" up -d --wait >/dev/null

RUBY_COMPOSE_PROJECT="${project}" \
RUBY_COMPOSE_FILE="${app_root}/compose.production.yaml" \
python "${app_root}/tools/check_private_evaluator.py"

docker run -d \
  --name "${defense_container}" \
  --network "${pipeline_network}" \
  --network-alias defense \
  -e BENCHMARK_TARGET_URL=http://ruby-web-target:8080 \
  "ruby-target-switch-defense:${image_tag}" >/dev/null

docker run --rm --network "${pipeline_network}" alpine:3.23 sh -ec '
  for attempt in $(seq 1 30); do
    body=$(wget -T 2 -qO- http://defense:8080/ 2>/dev/null || true)
    case "$body" in
      *"id=\"root\""*) echo RUBY_WEB_TARGET_OK; exit 0 ;;
    esac
    sleep 1
  done
  exit 1
'

docker rm -f "${defense_container}" >/dev/null
docker run -d \
  --name "${juice_container}" \
  --network "${pipeline_network}" \
  --network-alias benchmark-target \
  bkimminich/juice-shop:latest >/dev/null
docker run -d \
  --name "${defense_container}" \
  --network "${pipeline_network}" \
  --network-alias defense \
  -e BENCHMARK_TARGET_URL=http://benchmark-target:3000 \
  "ruby-target-switch-defense:${image_tag}" >/dev/null

docker run --rm --network "${pipeline_network}" alpine:3.23 sh -ec '
  for attempt in $(seq 1 60); do
    body=$(wget -T 2 -qO- http://defense:8080/ 2>/dev/null || true)
    case "$body" in
      *"OWASP Juice Shop"*) echo JUICE_SHOP_TARGET_OK; exit 0 ;;
    esac
    sleep 1
  done
  exit 1
'

echo TARGET_SWITCH_CHECK_OK
