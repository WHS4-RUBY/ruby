#!/usr/bin/env bash
# CHeaT 벤치마크 — plant -> list -> remove 전체 사이클 실행
set -euo pipefail

docker run --rm cheat:pristine bash -lc '
  set -e
  echo "<html><body>test</body></html>" > ./test.html

  echo "=== plant ==="
  cheat --action plant --details "{\"assettype\": \"web_file\", \"file_path\": \"./test.html\", \"technique\": \"random\"}"

  echo "=== list (installed) ==="
  cheat --action list --type installed

  echo "=== list (available, 15 techniques / 37 catalog entries, 26 distinct codes) ==="
  cheat --action list --type available

  echo "=== remove ==="
  INSTALLED_ID=$(cheat --action list --type installed | grep -oE "\"id\": *\"[^\"]+\"" | head -1 | sed -E "s/.*\"([^\"]+)\"$/\1/")
  if [ -n "${INSTALLED_ID:-}" ]; then
    cheat --action remove --id "${INSTALLED_ID}"
  else
    echo "설치된 payload id를 찾지 못했습니다 — list 출력 형식을 확인하세요." >&2
  fi
'
