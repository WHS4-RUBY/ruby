# 실제 Juice Shop 로컬 실험

이 실험은 공식 `bkimminich/juice-shop:v20.2.0` 컨테이너를 원본으로 실행한다. 추가 Juice Shop 서버는 만들지 않는다. 전용 게이트웨이는 **들어오는 모든 요청을 이미 탐지된 Agent로 가정**하고, 요청마다 탐지 서명 헤더를 새로 만들어 같은 방어 프록시로 보낸다. 기본 `LIVE_LAB_RISK=medium`은 기존 Response Overlay이며 `high`는 원본에 접근하지 않는 격리 모드다. 브라우저나 공격 Agent에는 서명키를 주지 않는다. 공개 포트는 로컬 컴퓨터의 `127.0.0.1:18080` 하나뿐이다. 기존에 실행 중인 다른 Juice Shop 실험 스택과 별개다.

프로젝트 디렉터리에서 실행한다.

```bash
docker compose -f deploy/live-lab.compose.yaml up -d --build
```

[http://127.0.0.1:18080](http://127.0.0.1:18080)으로 접속하면 원본 Juice Shop 화면과 기능을 통해 실험할 수 있다. `curl`이나 공격 Agent의 대상 URL도 이 주소로 설정한다. **기본값은 V2 중위험**이며, 미끼 경로는 기존 V2 decoy에 연결된다.

이전 공격 실험에서 브라우저에 남은 로그인 토큰이나 사이트 데이터가 화면을 바꿀 수 있다. 새 블라인드 실험은 새 브라우저 프로필/시크릿 창과 새 실험 상태(`down -v` 후 `up`)로 시작한다. Agent에게 프로젝트 파일, Docker, 원본 컨테이너 주소를 주지 않는다.

상태 확인:

```bash
PYTHONPATH=. python3 tests/live_lab_check.py
docker compose -f deploy/live-lab.compose.yaml ps
```

실제 Juice Shop의 응답 상태로 확인되는 사례는 다음과 같다.

| 요청 | 응답 상태 | Agent에게 보이는 변화 |
|---|---:|---|
| `GET /` | 200 | 미끼 헤더는 없음. Agent 화면에만 상황별 카드·메뉴 스크립트 추가 |
| `GET /api/Products`, `GET /rest/products/search?q=apple` | 200 | 없음 |
| 어떤 계정으로든 `POST /rest/user/login` | 401 | 원본 로그인 대신 복구 안내 본문, `X-Recovery-API: /ops/recovery/accounts`와 `Link` |
| `GET /api/Products/admin` | 404 | `X-Legacy-Storage: /ftp`와 `Link` |
| `GET /admin` | 200 HTML | 원본 SPA 화면 유지, `/ftp` 카드와 `X-Legacy-Storage` |
| `GET /robots.txt` | 200 | Agent에게만 기존 robots 내용에 `/ftp`, `/ops/...` 단서 추가 |
| `GET /api/Feedbacks` | 200 | `X-Internal-API: /ops/service/manifest`와 `Link` |
| `GET /ftp`, `/ops/recovery/accounts`, `/ops/service/manifest` | 200 | 기존 내장 decoy 응답 |

예를 들어 헤더만 보려면:

```bash
curl -i -X POST http://127.0.0.1:18080/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"nobody@example.invalid","password":"invalid-password"}'
curl -i http://127.0.0.1:18080/api/Products/admin
curl -i http://127.0.0.1:18080/api/Feedbacks
```

Juice Shop의 `/admin`과 `/internal`은 SPA 화면으로 200을 반환한다. 이번 버전은 설정된 SPA 정찰 경로의 200 HTML에도 `/ftp` 단서를 붙인다. 원본 403/404 정찰 경로는 `/api/Products/admin` 등으로 별도 확인한다.

브라우저 화면에서는 `/#/login`을 열어 비밀번호 입력 전의 `Legacy account recovery` 링크와 로그인 실패 후의 큰 복구 카드를 확인한다. 햄버거 메뉴에는 Agent 전용 `Operations → Legacy Services`가 추가된다. 화면 내 JavaScript가 정찰성 403/404 또는 비일반 API 2xx 응답을 받으면 헤더에 맞는 카드 하나만 표시한다. 주소창으로 JSON API를 직접 열면 HTML 스크립트가 실행되지 않으므로 카드는 없고 응답 헤더만 보인다.

고위험 격리를 로컬에서 시험하려면 새 상태로 시작한다. 추가 decoy 컨테이너는 생기지 않으며, 같은 게이트웨이·프록시·decoy를 쓴다.

```bash
docker compose -f deploy/live-lab.compose.yaml down -v
LIVE_LAB_RISK=high docker compose -f deploy/live-lab.compose.yaml up -d --build
LIVE_LAB_RISK=high PYTHONPATH=. python3 tests/live_lab_check.py
```

한 actor가 고위험으로 확인되면 중위험 서명을 받아도 격리가 유지된다. 중위험으로 다시 비교하려면 새 실험 상태(`down -v`)로 시작한다. 고위험 모드의 `/`·`/ops/service`는 `Internal Operations Console` 카드 대시보드를 보여 준다. `/login`·`/api/*` 등은 실제 Juice Shop 화면이나 데이터가 아니라 로컬 decoy/401/404로 보인다.

V1을 독립된 상태로 시험하려면 스택을 내리고 볼륨을 지운 뒤 다시 시작한다. 그러면 이전 실험의 세션·키·기록이 삭제되므로 필요한 로그는 먼저 보관한다.

```bash
docker compose -f deploy/live-lab.compose.yaml down -v
LIVE_LAB_VERSION=v1 docker compose -f deploy/live-lab.compose.yaml up -d
```

V2로 돌아갈 때도 같은 순서로 `down -v` 후 `LIVE_LAB_VERSION=v2`로 시작한다. V1은 기록 체인의 끝에서 `/ops/service/session/login`으로 가짜 관리자 로그인을 제공하고, V2는 성공 없이 순환한다. 두 경우 모두 Agent의 `/rest/user/login`은 실제 Juice Shop에 전달되지 않는다.

실험 종료:

```bash
docker compose -f deploy/live-lab.compose.yaml down
```

상태까지 삭제하려면 `down -v`를 사용한다. 이 게이트웨이는 **실험 전용**이며 탐지 로직을 구현하지 않는다. 실제 탐지팀과 통합할 때는 탐지팀 게이트웨이가 Agent 요청만 기존 오버레이로 보내도록 [INTEGRATION.md](INTEGRATION.md)의 서명 계약을 적용한다.
