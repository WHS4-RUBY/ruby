#!/usr/bin/env bash
# local.sh — docker-compose.local.yml 로컬 스택 실행 도우미.
#
# 로컬 Compose 는 소스를 직접 빌드하고(.env 없이 기본값만으로 기동) 프로젝트 이름은
# 파일의 `name: ruby-local` 을 그대로 쓴다. 이 스크립트는 설정을 만들어 내지 않는다 —
# .env 를 만들지 않고, 비밀값이나 키를 생성하지 않고, 대상 목록을 임의로 정하지 않는다.
# 볼륨 삭제는 `reset` 한 곳에서만, 확인을 받고 한다.
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR"

COMPOSE_FILE="docker-compose.local.yml"
ENV_FILE=".env"
DEFAULT_TARGET_PORT=3000
DEFAULT_TIMEOUT=180
LOG_TAIL=80

OPT_NO_BUILD=0
OPT_PULL=0
OPT_YES=0
OPT_TIMEOUT="$DEFAULT_TIMEOUT"
OPT_FOLLOW=0

TMP_DIR=""
EXIT_HINT=""

# ---------------------------------------------------------------- 출력 --------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

step() { printf '%s\n' "${C_BOLD}${C_BLUE}▶ $*${C_RESET}"; }
info() { printf '%s\n' "  $*"; }
dim()  { printf '%s\n' "  ${C_DIM}$*${C_RESET}"; }
ok()   { printf '%s\n' "  ${C_GREEN}PASS${C_RESET} $*"; }
warn() { printf '%s\n' "  ${C_YELLOW}WARN${C_RESET} $*"; }
fail() { printf '%s\n' "  ${C_RED}FAIL${C_RESET} $*"; }
note() { printf '%s\n' "${C_YELLOW}! $*${C_RESET}" >&2; }
die()  { printf '%s\n' "${C_RED}✗ $1${C_RESET}" >&2; exit "${2:-1}"; }

# ------------------------------------------------------------ 트랩/임시 ------

cleanup() {
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi
  TMP_DIR=""
}

on_err() {
  local code=$1 line=$2
  printf '%s\n' "${C_RED}✗ 실패: ${0##*/} ${line}행 (종료 코드 ${code})${C_RESET}" >&2
  if [ -n "$EXIT_HINT" ]; then printf '%s\n' "  다음에 할 일: ${EXIT_HINT}" >&2; fi
}

on_signal() {
  local signal=$1
  printf '\n%s\n' "${C_YELLOW}중단됨 (${signal}). 컨테이너는 그대로 둡니다 — 상태는 ./local.sh ps 로 확인하세요.${C_RESET}" >&2
  cleanup
  case "$signal" in
    INT) exit 130 ;;
    *)   exit 143 ;;
  esac
}

trap 'on_err $? $LINENO' ERR
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
trap cleanup EXIT

tmpdir() {
  if [ -z "$TMP_DIR" ]; then
    local old_umask
    old_umask=$(umask)
    umask 077
    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/local-sh.XXXXXX")
    umask "$old_umask"
  fi
  printf '%s' "$TMP_DIR"
}

# -------------------------------------------------------------- 도움말 -------

usage() {
  cat <<'USAGE'
ruby 로컬 스택 실행 도우미 (docker-compose.local.yml)

사용법:
  ./local.sh [옵션] [명령] [인자...]

명령:
  up                 사전 점검 후 전체 스택을 빌드·기동하고 접속 주소를 요약한다 (기본 명령)
  down               컨테이너만 내린다. 볼륨은 지우지 않는다
  restart [서비스…]  서비스를 재시작한다
  build  [서비스…]   이미지를 빌드한다
  logs   [-f] [서비스…]  로그를 본다 (-f 는 따라가기)
  ps                 컨테이너 상태를 본다
  reset              볼륨까지 삭제한다 (확인 필요). 격리 이력·탐지 저장소·경로 별칭이 사라진다
  test               .github/workflows/ci.yml 과 같은 방식으로 단위 테스트를 돌린다

옵션:
  --no-build         up 에서 이미지를 다시 빌드하지 않는다
  --pull             빌드 전에 베이스 이미지를 새로 받는다
  --timeout <초>     up --wait 대기 시간 (기본 180)
  -y, --yes          reset 확인 프롬프트를 건너뛴다
  -h, --help         이 도움말

참고:
  * 보호 대상 앱은 이 Compose 밖에서 호스트의 TARGET_PORT(기본 3000)에 먼저 떠 있어야 한다.
      docker run -d -p 3000:3000 bkimminich/juice-shop
  * .env 는 필요 없다. 있으면 Compose 가 알아서 읽는다 (이 스크립트는 만들지 않는다).
  * 공개 포트는 테스트 트래픽용, 관리 포트는 127.0.0.1 전용이다.
USAGE
}

# ------------------------------------------------------------ 작은 도구 ------

have() { command -v "$1" >/dev/null 2>&1; }

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

tcp_open() { (exec 3<>"/dev/tcp/$1/$2") >/dev/null 2>&1; }

http_code() {
  # 연결 실패도 000 으로 돌려주고 호출부가 판단한다.
  curl --silent --output /dev/null --max-time "${2:-10}" --write-out '%{http_code}' "$1" 2>/dev/null || printf '000'
}

# 셸 환경변수 > .env > 기본값 — Compose 의 ${VAR:-기본값} 해석과 같은 순서다.
# .env 는 source 하지 않고 한 줄씩 읽는다. 셸에 비어 있는 값이 있으면 .env 가 아니라
# 기본값으로 떨어지는 것도 Compose 와 같다.
env_value() {
  local name=$1 fallback=$2 value="" marker line
  eval "marker=\${$name+set}"
  if [ "${marker:-}" = "set" ]; then
    eval "value=\${$name}"
  elif [ -f "$ENV_FILE" ]; then
    line=$(grep -E "^[[:space:]]*(export[[:space:]]+)?${name}[[:space:]]*=" "$ENV_FILE" 2>/dev/null | tail -n 1 || true)
    if [ -n "$line" ]; then
      value=${line#*=}
      value=${value#"${value%%[![:space:]]*}"}   # 앞 공백 제거
      value=${value%"${value##*[![:space:]]}"}   # 뒤 공백 제거
      case "$value" in
        \"*\") value=${value#\"}; value=${value%\"} ;;
        \'*\') value=${value#\'}; value=${value%\'} ;;
        *" #"*) value=${value%% \#*} ;;          # 값 뒤의 주석 (Compose 와 같은 규칙)
      esac
      value=${value%"${value##*[![:space:]]}"}
    fi
  fi
  if [ -n "$value" ]; then printf '%s' "$value"; else printf '%s' "$fallback"; fi
}

# 값의 내용은 쓰지 않고 "설정됐는지" 만 본다 (비밀번호를 출력하거나 넘기지 않는다).
env_is_set() {
  local value
  value=$(env_value "$1" "")
  [ -n "$value" ]
}

# ------------------------------------------------- compose 설정 읽기 ---------

# config --format json 에서 서비스별 publish 포트와 environment 를 뽑는다.
# "PORT<TAB>서비스<TAB>컨테이너포트<TAB>호스트포트<TAB>host_ip" / "ENV<TAB>서비스<TAB>키<TAB>값"
parse_compose_json() {
  awk '
    /^    "[^"]+": \{$/ {
      svc = $0; sub(/^    "/, "", svc); sub(/": \{$/, "", svc)
      inports = 0; inenv = 0; next
    }
    svc != "" && /^      "ports": \[$/ { inports = 1; next }
    svc != "" && /^      "environment": \{$/ { inenv = 1; next }
    inports && /^      \],?$/ { inports = 0; next }
    inenv  && /^      \},?$/ { inenv = 0; next }
    inports && /^        \{$/ { t = ""; p = ""; h = ""; next }
    inports && /^        \},?$/ {
      if (p != "") printf "PORT\t%s\t%s\t%s\t%s\n", svc, t, p, h
      next
    }
    inports || inenv {
      key = $0; sub(/^[ \t]*"/, "", key); sub(/".*$/, "", key)
      val = $0; sub(/^[^:]*:[ \t]*/, "", val); sub(/,$/, "", val); gsub(/"/, "", val)
      if (inports) {
        if (key == "target") t = val
        else if (key == "published") p = val
        else if (key == "host_ip") h = val
      } else {
        printf "ENV\t%s\t%s\t%s\n", svc, key, val
      }
      next
    }
  '
}

PROJECT_NAME=""
PUBLIC_HOST=""; PUBLIC_PORT=""
ADMIN_HOST=""; ADMIN_PORT=""
ALL_HOST_PORTS=""

url_host() {
  case "$1" in
    ""|"0.0.0.0"|"::"|"[::]") printf '127.0.0.1' ;;
    *) printf '%s' "$1" ;;
  esac
}

load_compose_layout() {
  local dir json parsed
  dir=$(tmpdir)
  json="$dir/config.json"
  parsed="$dir/config.tsv"

  if ! compose config --format json >"$json" 2>"$dir/config.err"; then
    sed 's/^/  /' "$dir/config.err" >&2 || true
    die "compose 설정을 읽지 못했습니다. 위 오류를 먼저 해결하세요." 1
  fi
  parse_compose_json <"$json" >"$parsed"
  awk -F'\t' '$1 == "PORT"' "$parsed" >"$dir/ports.tsv"
  awk -F'\t' '$1 == "ENV"' "$parsed" >"$dir/env.tsv"

  PROJECT_NAME=$(sed -n 's/^  "name": "\(.*\)",\{0,1\}$/\1/p' "$json" | head -n 1)
  PROJECT_NAME=${PROJECT_NAME%\"}

  ALL_HOST_PORTS=$(awk -F'\t' '{ print $4 }' "$dir/ports.tsv" | sort -un | tr '\n' ' ')

  # 공개/관리 구분은 하드코딩하지 않는다 — 서비스의 PORT/ADMIN_PORT 환경값과
  # 컨테이너 포트를 맞춰 본다. 못 맞추면 127.0.0.1 바인딩 쪽을 관리로 본다.
  local _kind svc target published host_ip container_public container_admin
  while IFS=$'\t' read -r _kind svc target published host_ip; do
    container_public=$(awk -F'\t' -v s="$svc" '$2==s && $3=="PORT" { print $4 }' "$dir/env.tsv" | head -n 1)
    container_admin=$(awk -F'\t' -v s="$svc" '$2==s && $3=="ADMIN_PORT" { print $4 }' "$dir/env.tsv" | head -n 1)
    if [ -n "$container_public" ] && [ "$target" = "$container_public" ]; then
      PUBLIC_HOST=$(url_host "$host_ip"); PUBLIC_PORT=$published
    elif [ -n "$container_admin" ] && [ "$target" = "$container_admin" ]; then
      ADMIN_HOST=$(url_host "$host_ip"); ADMIN_PORT=$published
    elif [ "$host_ip" = "127.0.0.1" ] && [ -z "$ADMIN_PORT" ]; then
      ADMIN_HOST=$(url_host "$host_ip"); ADMIN_PORT=$published
    elif [ -z "$PUBLIC_PORT" ]; then
      PUBLIC_HOST=$(url_host "$host_ip"); PUBLIC_PORT=$published
    fi
  done < "$dir/ports.tsv"
}

# ---------------------------------------------------------- 사전 점검 --------

require_docker() {
  have docker || die "docker 명령을 찾을 수 없습니다. Docker Desktop 또는 Docker Engine 을 설치하세요." 1

  if ! docker compose version >/dev/null 2>&1; then
    die "docker compose v2 플러그인이 없습니다. Docker Desktop 최신판 또는 docker-compose-plugin 을 설치하세요." 1
  fi

  if ! docker info >/dev/null 2>&1; then
    die "Docker 데몬에 접근할 수 없습니다. Docker Desktop 을 켜거나 현재 사용자를 docker 그룹에 넣으세요." 1
  fi

  local version major minor numeric=1
  version=$(docker compose version --short 2>/dev/null | tr -d 'v' || true)
  major=${version%%.*}
  minor=${version#*.}; minor=${minor%%.*}
  case "$major" in ''|*[!0-9]*) numeric=0 ;; esac
  case "$minor" in ''|*[!0-9]*) numeric=0 ;; esac
  if [ "$numeric" -eq 0 ]; then
    note "compose 버전을 확인하지 못했습니다(${version:-알 수 없음}). --wait-timeout 지원 여부를 확인하지 않고 진행합니다."
  elif [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 17 ]; }; then
    die "compose ${version} 에는 up --wait-timeout 이 없습니다 (2.17 이상 필요). Docker Desktop 또는 compose 플러그인을 올리세요." 1
  fi
}

port_owner_projects() {
  docker ps --filter "publish=$1" --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null || true
}

check_port_conflicts() {
  local port owners conflict=0
  for port in $ALL_HOST_PORTS; do
    if ! tcp_open 127.0.0.1 "$port"; then
      continue
    fi
    owners=$(port_owner_projects "$port")
    if printf '%s\n' "$owners" | grep -qx "$PROJECT_NAME"; then
      dim "포트 ${port} 은 이미 이 프로젝트(${PROJECT_NAME})가 쓰고 있습니다 — 충돌 아님."
      continue
    fi
    conflict=1
    if [ -n "$(printf '%s' "$owners" | tr -d '[:space:]')" ]; then
      fail "포트 ${port} 을 다른 Compose 프로젝트가 쓰고 있습니다: $(printf '%s' "$owners" | tr '\n' ' ')"
    else
      fail "포트 ${port} 이 이미 사용 중입니다 (이 프로젝트 밖의 프로세스)."
    fi
  done
  if [ "$conflict" -eq 1 ]; then
    EXIT_HINT="해당 포트를 쓰는 프로세스를 내리거나(docker ps / lsof -i :포트) 그 쪽을 먼저 정리한 뒤 다시 실행하세요."
    die "호스트 포트 충돌로 기동을 중단합니다." 1
  fi
  ok "호스트 포트 ${ALL_HOST_PORTS% } 사용 가능"
}

TARGET_PORT_VALUE=""

check_target_reachable() {
  local raw code
  raw=$(env_value TARGET_PORT "$DEFAULT_TARGET_PORT")
  case "$raw" in
    ''|*[!0-9]*)
      note "TARGET_PORT 값 '${raw}' 을 숫자로 읽을 수 없어 기본값 ${DEFAULT_TARGET_PORT} 으로 점검합니다."
      raw=$DEFAULT_TARGET_PORT
      ;;
  esac
  TARGET_PORT_VALUE=$raw

  if tcp_open 127.0.0.1 "$TARGET_PORT_VALUE"; then
    if have curl; then
      code=$(http_code "http://127.0.0.1:${TARGET_PORT_VALUE}/" 5)
      ok "보호 대상 앱이 호스트 포트 ${TARGET_PORT_VALUE} 에서 응답합니다 (HTTP ${code})"
    else
      ok "보호 대상 앱이 호스트 포트 ${TARGET_PORT_VALUE} 에서 TCP 연결을 받습니다"
    fi
    dim "컨테이너는 host.docker.internal:${TARGET_PORT_VALUE} 로 접근합니다 — 대상이 127.0.0.1 전용으로 바인딩돼 있으면 컨테이너에서는 닿지 않습니다."
    return 0
  fi

  warn "호스트 포트 ${TARGET_PORT_VALUE} 에 보호 대상 앱이 없습니다. 스택은 뜨지만 공개 경로는 502 가 됩니다."
  info "해결: docker run -d -p ${TARGET_PORT_VALUE}:3000 bkimminich/juice-shop"
  info "다른 포트를 쓰려면 셸의 TARGET_PORT 또는 .env 의 TARGET_PORT 를 바꾸세요 (현재 기준값 ${TARGET_PORT_VALUE})."
  return 1
}

# ----------------------------------------------------------- up 검증 ---------

VERIFY_FAILED_SERVICES=""

record_failure() {
  case " $VERIFY_FAILED_SERVICES " in
    *" $1 "*) ;;
    *) VERIFY_FAILED_SERVICES="$VERIFY_FAILED_SERVICES $1" ;;
  esac
}

expect_code() { # 설명 URL 기대코드 서비스
  local label=$1 url=$2 want=$3 svc=$4 code
  code=$(http_code "$url")
  if [ "$code" = "$want" ]; then
    ok "${label} → ${code}"
  else
    fail "${label} → ${code} (기대 ${want})"
    record_failure "$svc"
  fi
}

verify_stack() {
  local code target_up=$1

  if ! have curl; then
    warn "curl 이 없어 기동 후 검증을 건너뜁니다. 수동 확인: http://${PUBLIC_HOST}:${PUBLIC_PORT}/healthz"
    return 0
  fi

  local public="http://${PUBLIC_HOST}:${PUBLIC_PORT}"
  local admin="http://${ADMIN_HOST}:${ADMIN_PORT}"

  expect_code "공개 ${public}/healthz" "${public}/healthz" 200 detection

  code=$(http_code "${public}/")
  case "$code" in
    2??|3??) ok "공개 ${public}/ → ${code}" ;;
    *)
      if [ "$target_up" -eq 0 ]; then
        warn "공개 ${public}/ → ${code}: 호스트 포트 ${TARGET_PORT_VALUE} 에 보호 대상 앱이 없어 전달할 원본이 없습니다. 대상을 띄우면 해소됩니다."
      else
        fail "공개 ${public}/ → ${code} (2xx/3xx 기대)"
        record_failure detection
        record_failure defense
      fi
      ;;
  esac

  expect_code "공개 ${public}/__detection/api/sessions 비공개 확인" "${public}/__detection/api/sessions" 404 detection
  expect_code "공개 ${public}/__defense/dashboard 비공개 확인" "${public}/__defense/dashboard" 404 detection
  expect_code "관리 ${admin}/" "${admin}/" 404 detection

  # 관리 API 의 비인증 응답은 대시보드 비밀번호 설정 여부로 갈린다
  # (detection/lib/dashboardAuth.js: 비밀번호가 비면 인증이 꺼진다).
  # 로컬 기본값은 비어 있으므로 200 이 정상이다. 비밀번호 값은 읽지도 넘기지도 않는다.
  if env_is_set DETECTION_DASHBOARD_PASSWORD; then
    expect_code "관리 ${admin}/__detection/api/sessions 비인증 (비밀번호 설정됨)" \
      "${admin}/__detection/api/sessions" 401 detection
  else
    expect_code "관리 ${admin}/__detection/api/sessions 비인증 (비밀번호 미설정 → 인증 비활성)" \
      "${admin}/__detection/api/sessions" 200 detection
  fi

  if [ -n "$VERIFY_FAILED_SERVICES" ]; then
    local svc
    for svc in $VERIFY_FAILED_SERVICES; do
      printf '\n%s\n' "${C_BOLD}--- ${svc} 로그 마지막 ${LOG_TAIL}줄 ---${C_RESET}"
      compose logs --no-color --tail "$LOG_TAIL" "$svc" 2>&1 | sed 's/^/  /' || true
    done
    return 1
  fi
  return 0
}

print_summary() {
  local public="http://${PUBLIC_HOST}:${PUBLIC_PORT}"
  local admin="http://${ADMIN_HOST}:${ADMIN_PORT}"
  printf '\n%s\n' "${C_BOLD}접속 주소${C_RESET}"
  info "공개(테스트 트래픽)  ${public}/"
  info "  상태 확인          ${public}/healthz"
  info "  텔레메트리(공개)   ${public}/__detection/static/telemetry.js, ${public}/__detection/telemetry"
  info "관리(로컬 전용)      ${admin}/"
  info "  탐지 대시보드      ${admin}/__detection/dashboard"
  info "  방어 대시보드      ${admin}/__defense/dashboard"
  if env_is_set DETECTION_DASHBOARD_PASSWORD || env_is_set DEFENSE_DASHBOARD_PASSWORD; then
    dim "대시보드 비밀번호가 설정돼 있습니다 — 로그인 화면에서 직접 입력하세요."
  else
    dim "로컬 기본값에서 대시보드 비밀번호는 비어 있어 로그인 없이 열립니다."
  fi
  printf '\n%s\n' "${C_BOLD}다음 명령${C_RESET}"
  info "상태  ./local.sh ps        로그  ./local.sh logs -f defense"
  info "종료  ./local.sh down      (볼륨 보존)"
}

# ------------------------------------------------------------- 명령 ----------

cmd_up() {
  [ $# -eq 0 ] || die "up 은 인자를 받지 않습니다: $*" 2

  step "사전 점검"
  require_docker
  ok "docker / docker compose v2 / 데몬 접근 확인"

  if compose config --quiet; then
    ok "${COMPOSE_FILE} 설정 검증 통과"
  else
    EXIT_HINT="${COMPOSE_FILE} 또는 docker-compose.common.yml 의 문법·변수 참조를 확인하세요."
    die "compose 설정 검증 실패" 1
  fi

  load_compose_layout
  info "프로젝트 이름: ${PROJECT_NAME} (compose 파일의 name 을 그대로 사용)"
  check_port_conflicts

  local target_up=1
  if ! check_target_reachable; then target_up=0; fi

  if [ "$OPT_NO_BUILD" -eq 0 ]; then
    dim "첫 Detection 빌드는 ModSecurity/CRS 를 준비하므로 수 분 이상 걸릴 수 있습니다 (이후에는 캐시 사용)."
  fi

  if [ "$OPT_PULL" -eq 1 ]; then
    step "베이스 이미지 갱신 후 빌드"
    compose build --pull
  fi

  step "기동 (최대 ${OPT_TIMEOUT}초 대기)"
  local up_args
  up_args="-d --wait --wait-timeout $OPT_TIMEOUT"
  if [ "$OPT_NO_BUILD" -eq 0 ]; then up_args="$up_args --build"; fi
  # shellcheck disable=SC2086
  if ! compose up $up_args; then
    printf '\n%s\n' "${C_RED}기동이 완료되지 않았습니다. 아래는 최근 로그입니다.${C_RESET}"
    compose logs --no-color --tail "$LOG_TAIL" 2>&1 | sed 's/^/  /' || true
    EXIT_HINT="로그의 첫 오류를 보고 고친 뒤 ./local.sh up 을 다시 실행하세요. 빌드가 길어 시간 초과라면 --timeout 600 을 주세요."
    die "docker compose up 실패" 1
  fi

  step "검증"
  local verify_rc=0
  verify_stack "$target_up" || verify_rc=1

  if [ "$verify_rc" -ne 0 ]; then
    printf '\n%s\n' "${C_RED}일부 검증 항목이 실패했습니다.${C_RESET}"
    info "컨테이너는 그대로 둡니다. 로그를 더 보려면: ./local.sh logs -f detection"
    exit 1
  fi

  print_summary
}

cmd_down() {
  [ $# -eq 0 ] || die "down 은 인자를 받지 않습니다: $*" 2
  require_docker
  step "컨테이너 종료 (볼륨 보존)"
  compose down
  ok "종료 완료. 볼륨은 남아 있습니다 — docker volume ls 로 확인할 수 있습니다."
}

cmd_restart() {
  require_docker
  step "재시작${1+: $*}"
  compose restart ${1+"$@"}
}

cmd_build() {
  require_docker
  step "빌드${1+: $*}"
  if [ "$OPT_PULL" -eq 1 ]; then
    compose build --pull ${1+"$@"}
  else
    compose build ${1+"$@"}
  fi
}

cmd_logs() {
  require_docker
  if [ "$OPT_FOLLOW" -eq 1 ]; then
    compose logs --tail "$LOG_TAIL" -f ${1+"$@"}
  else
    compose logs --tail "$LOG_TAIL" ${1+"$@"}
  fi
}

cmd_ps() {
  [ $# -eq 0 ] || die "ps 는 인자를 받지 않습니다: $*" 2
  require_docker
  compose ps
}

cmd_reset() {
  [ $# -eq 0 ] || die "reset 은 인자를 받지 않습니다: $*" 2
  require_docker

  printf '%s\n' "${C_YELLOW}${C_BOLD}경고: reset 은 이 프로젝트의 볼륨을 삭제합니다.${C_RESET}"
  info "사라지는 것: 오버레이 격리 이력, Detection 저장소(XSS 후보·증거·스키마 학습), 경로 별칭 테이블, 대상 선택 상태."
  info "되돌릴 수 없습니다. 컨테이너만 내리려면 ./local.sh down 을 쓰세요."

  if [ "$OPT_YES" -ne 1 ]; then
    local answer=""
    printf '%s' "계속하려면 reset 이라고 입력하세요: "
    if ! IFS= read -r answer; then
      printf '\n'
      die "확인 입력을 받지 못했습니다(비대화형). 정말 삭제하려면 -y 를 주세요. 볼륨은 그대로입니다." 1
    fi
    if [ "$answer" != "reset" ]; then
      die "입력이 reset 이 아니라 취소했습니다. 볼륨은 그대로입니다." 1
    fi
  fi

  step "컨테이너·볼륨 삭제"
  compose down -v
  ok "삭제 완료. 다음 ./local.sh up 은 빈 상태에서 시작합니다."
}

cmd_test() {
  [ $# -eq 0 ] || die "test 는 인자를 받지 않습니다: $*" 2
  local rc=0

  # .github/workflows/ci.yml 의 detection-check: npm ci 뒤 npm test (node --test).
  step "Detection 단위 테스트 (npm test)"
  if ! have npm; then
    info "npm 이 없어 건너뜁니다. Node.js 22 를 설치하면 실행됩니다."
  elif [ ! -d detection/node_modules ]; then
    info "detection/node_modules 가 없어 건너뜁니다. 먼저 (cd detection && npm ci) 를 실행하세요."
  else
    if ( cd detection && npm test ); then
      ok "Detection 테스트 통과"
    else
      fail "Detection 테스트 실패"
      rc=1
    fi
  fi

  # ci.yml 의 python-check: pytest 가 아니라 unittest discover 다.
  step "Defense 단위 테스트 (python -m unittest discover -s defense/tests)"
  local python_bin=""
  if have python3; then python_bin=python3; elif have python; then python_bin=python; fi
  if [ -z "$python_bin" ]; then
    info "python3 가 없어 건너뜁니다. Python 3.12 를 설치하면 실행됩니다."
  elif ! "$python_bin" -c "import fastapi" >/dev/null 2>&1; then
    info "defense 의존성이 설치돼 있지 않아 건너뜁니다. 먼저 ${python_bin} -m pip install -r defense/requirements.txt 를 실행하세요."
  else
    if "$python_bin" -m unittest discover -s defense/tests -p 'test_*.py'; then
      ok "Defense 테스트 통과"
    else
      fail "Defense 테스트 실패"
      rc=1
    fi
  fi

  if [ "$rc" -ne 0 ]; then
    EXIT_HINT="실패한 테스트의 출력을 먼저 읽으세요. CI 와 같은 명령이라 여기서 실패하면 CI 도 실패합니다."
  fi
  return "$rc"
}

# ------------------------------------------------------------- 인자 ----------

main() {
  local command="" args_seen=0
  ARGS=()

  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --no-build) OPT_NO_BUILD=1; shift ;;
      --pull) OPT_PULL=1; shift ;;
      -y|--yes) OPT_YES=1; shift ;;
      --timeout)
        [ $# -ge 2 ] || die "--timeout 에 초 단위 값이 필요합니다." 2
        case "$2" in
          ''|*[!0-9]*) die "--timeout 값이 올바르지 않습니다: $2" 2 ;;
        esac
        [ "$2" -gt 0 ] || die "--timeout 값은 1 이상이어야 합니다." 2
        OPT_TIMEOUT=$2; shift 2 ;;
      --timeout=*)
        local value=${1#--timeout=}
        case "$value" in
          ''|*[!0-9]*) die "--timeout 값이 올바르지 않습니다: $value" 2 ;;
        esac
        [ "$value" -gt 0 ] || die "--timeout 값은 1 이상이어야 합니다." 2
        OPT_TIMEOUT=$value; shift ;;
      -f|--follow)
        if [ "$command" = "logs" ]; then OPT_FOLLOW=1; shift
        else die "알 수 없는 옵션입니다: $1 (-f 는 logs 에서만 씁니다)" 2; fi ;;
      --) shift; while [ $# -gt 0 ]; do ARGS+=("$1"); shift; done ;;
      -*) die "알 수 없는 옵션입니다: $1 (./local.sh --help)" 2 ;;
      *)
        if [ "$args_seen" -eq 0 ] && [ -z "$command" ]; then
          command=$1
        else
          ARGS+=("$1")
        fi
        args_seen=1
        shift ;;
    esac
  done

  [ -n "$command" ] || command=up

  case "$command" in
    up)      cmd_up      ${ARGS[@]+"${ARGS[@]}"} ;;
    down)    cmd_down    ${ARGS[@]+"${ARGS[@]}"} ;;
    restart) cmd_restart ${ARGS[@]+"${ARGS[@]}"} ;;
    build)   cmd_build   ${ARGS[@]+"${ARGS[@]}"} ;;
    logs)    cmd_logs    ${ARGS[@]+"${ARGS[@]}"} ;;
    ps)      cmd_ps      ${ARGS[@]+"${ARGS[@]}"} ;;
    reset)   cmd_reset   ${ARGS[@]+"${ARGS[@]}"} ;;
    test)    if ! cmd_test ${ARGS[@]+"${ARGS[@]}"}; then exit 1; fi ;;
    *)       printf '%s\n' "${C_RED}✗ 알 수 없는 명령입니다: ${command}${C_RESET}" >&2
             printf '%s\n' "  사용 가능: up down restart build logs ps reset test (./local.sh --help)" >&2
             exit 2 ;;
  esac
}

main "$@"
