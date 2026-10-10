#!/usr/bin/env sh
# shared/ 의 편집 원본을 각 서비스 트리의 사본으로 복사한다.
#
# 루트 shared/ 는 네 Dockerfile 어디서도 COPY 할 수 없다(전부 하위 빌드 컨텍스트이고
# Docker 는 COPY ../ 를 금지한다). 그래서 편집 원본은 하나로 두고 서비스별 사본을
# 커밋하며, 동일성은 defense/tests/test_shared_sources.py 가 CI 에서 강제한다.
#
#     scripts/sync-shared.sh            # 원본 -> 사본 복사
#     scripts/sync-shared.sh --check    # 불일치하면 종료코드 1
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# "원본경로 사본경로" 한 쌍씩. 사본은 각 이미지의 기존 COPY 로 들어간다
# (CHeaT 만 .dockerignore 가 allowlist 라 파일 이름을 명시한다).
PAIRS="
shared/decoy-catalog.json detection/config/decoy-catalog.json
shared/decoy-catalog.json defense/account-response-overlay/config/decoy-catalog.json
shared/py/store.py defense/app/store.py
shared/py/store.py defense/account-response-overlay/defense/store.py
shared/py/store.py defense/CHeat-defense-proxy/defense_proxy_v2/store.py
"

check=0
[ "${1:-}" = "--check" ] && check=1

status=0
count=0
echo "$PAIRS" | while read -r source copy; do
    [ -n "$source" ] || continue
    [ -f "$ROOT/$source" ] || { echo "원본이 없다: $source" >&2; exit 1; }
    if [ "$check" -eq 1 ]; then
        if ! cmp -s "$ROOT/$source" "$ROOT/$copy"; then
            echo "사본이 원본과 다르다: $copy (원본 $source)" >&2
            exit 1
        fi
    else
        mkdir -p "$(dirname -- "$ROOT/$copy")"
        cp "$ROOT/$source" "$ROOT/$copy"
        echo "갱신: $copy"
    fi
    count=$((count + 1))
done || status=1

if [ "$status" -eq 0 ] && [ "$check" -eq 1 ]; then
    echo "공용 원본 사본이 모두 원본과 같다"
fi
exit "$status"
