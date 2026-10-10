#!/usr/bin/env sh
# MANIFEST.sha256 을 만들거나 검증한다. 이 패키지 루트에서 실행한다.
#
# 이 파일은 릴리스에 들어가는 파일 목록과 해시다. 예전에는 생성 스크립트도 검증도
# 없어서 손으로 갱신해야 했고, 실제로 61개 중 7개 해시가 틀리고 추적 중인 7개
# 파일이 아예 빠진 상태로 오래 방치됐다 — 있으나 마나 한 무결성 신호였다.
#
#     scripts/gen_manifest.sh            # MANIFEST.sha256 다시 만들기
#     scripts/gen_manifest.sh --check    # 해시와 커버리지 검증 (CI 가 쓴다)
#
# 커버 대상은 git 이 추적하는 모든 파일(자기 자신 제외)이다. 파일을 추가하거나
# 지웠으면 다시 만들어야 한다. RELEASE.json 이 매니페스트에 해시로 들어가므로
# RELEASE.json 을 먼저 고치고 그 다음에 이 스크립트를 돌린다.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
MANIFEST=MANIFEST.sha256

tracked() {
    git ls-files -z | tr '\0' '\n' | grep -v "^${MANIFEST}\$" | LC_ALL=C sort
}

generate() {
    tracked | while IFS= read -r path; do
        [ -n "$path" ] || continue
        sha256sum "$path"
    done
}

if [ "${1:-}" = "--check" ]; then
    [ -f "$MANIFEST" ] || { echo "$MANIFEST 가 없다. scripts/gen_manifest.sh 로 만들 것." >&2; exit 1; }
    status=0
    # 1) 적힌 해시가 맞는가
    sha256sum -c --quiet "$MANIFEST" || status=1
    # 2) 추적 파일과 적힌 목록이 같은가 (빠진 파일·사라진 파일)
    listed=$(sed 's/^[0-9a-f]\{64\}  //' "$MANIFEST" | LC_ALL=C sort)
    missing=$(printf '%s\n' "$listed" | comm -13 - "$(printf '%s\n' "$(tracked)" > /tmp/_gm_tracked; echo /tmp/_gm_tracked)")
    extra=$(printf '%s\n' "$listed" | comm -23 - /tmp/_gm_tracked)
    rm -f /tmp/_gm_tracked
    if [ -n "$missing" ]; then
        echo "매니페스트에 빠진 추적 파일:" >&2; printf '%s\n' "$missing" >&2; status=1
    fi
    if [ -n "$extra" ]; then
        echo "매니페스트에만 있고 추적되지 않는 파일:" >&2; printf '%s\n' "$extra" >&2; status=1
    fi
    if [ "$status" -eq 0 ]; then
        echo "$MANIFEST: $(wc -l < "$MANIFEST")개 파일 모두 일치"
    else
        echo "" >&2
        echo "고치는 방법: RELEASE.json 을 먼저 확인한 뒤" >&2
        echo "  cd defense/account-response-overlay && scripts/gen_manifest.sh" >&2
        echo "를 돌리고 바뀐 MANIFEST.sha256 을 같은 커밋에 넣는다." >&2
    fi
    exit "$status"
fi

generate > "$MANIFEST.tmp"
mv "$MANIFEST.tmp" "$MANIFEST"
echo "$MANIFEST 를 다시 만들었다: $(wc -l < "$MANIFEST")개 파일"
