#!/usr/bin/env bash
# CHeaT 벤치마크 — clone + Docker 이미지 빌드
set -euo pipefail

CHEAT_COMMIT="ee69d2c2a68b38a77f9266595655e8fa8cd9ae90"
UPSTREAM_DIR="upstream/cheat"

if [ ! -d "${UPSTREAM_DIR}" ]; then
  git clone https://github.com/Daniel-Ayz/CHeaT.git "${UPSTREAM_DIR}"
fi
git -C "${UPSTREAM_DIR}" checkout "${CHEAT_COMMIT}"

cp "$(dirname "$0")/Dockerfile" "${UPSTREAM_DIR}/Dockerfile"

docker build -t cheat:pristine "${UPSTREAM_DIR}"

echo "빌드 완료: cheat:pristine"
docker images --digests cheat:pristine
