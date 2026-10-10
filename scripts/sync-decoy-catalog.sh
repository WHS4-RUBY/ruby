#!/usr/bin/env sh
# shared/decoy-catalog.json 을 각 서비스 트리의 사본으로 복사한다.
#
# 루트 shared/ 는 네 Dockerfile 어디서도 COPY 할 수 없다(전부 하위 빌드 컨텍스트이고
# Docker 는 COPY ../ 를 금지한다). 그래서 편집 원본은 하나로 두고 서비스별 사본을
# 커밋하며, 동일성은 defense/tests/test_decoy_catalog_contract.py 가 CI 에서 강제한다.
#
#     scripts/sync-decoy-catalog.sh            # 원본 -> 사본 복사
#     scripts/sync-decoy-catalog.sh --check    # 불일치하면 종료코드 1
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE="$ROOT/shared/decoy-catalog.json"
COPIES="detection/config/decoy-catalog.json
defense/account-response-overlay/config/decoy-catalog.json"

[ -f "$SOURCE" ] || { echo "원본이 없다: $SOURCE" >&2; exit 1; }

if [ "${1:-}" = "--check" ]; then
    status=0
    for rel in $COPIES; do
        if ! cmp -s "$SOURCE" "$ROOT/$rel"; then
            echo "미끼 카탈로그 사본이 원본과 다르다: $rel" >&2
            status=1
        fi
    done
    [ "$status" -eq 0 ] && echo "미끼 카탈로그 사본 2개가 원본과 같다"
    exit "$status"
fi

for rel in $COPIES; do
    cp "$SOURCE" "$ROOT/$rel"
    echo "갱신: $rel"
done
