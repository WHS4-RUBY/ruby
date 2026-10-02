# 서버 벤치마크 대상 전환

RUBY 공개 경로는 `방문자 → Gateway → Detection(정책 포함) → Defense → Target`입니다. 한 번에 **하나의 대상**을 고릅니다. 기본은 Juice Shop이고, RUBY Market으로 바꾸면 공개 화면 경로·탐지 프로필·Defense 전달 주소가 함께 바뀝니다. 이 변경은 전체 파이프라인을 재생성해야 하며 운영 서버에서는 결과 검토 뒤 별도로 수행합니다.

| 선택 | 공개 화면 | Detection 프로필 | Defense 대상 |
| --- | --- | --- | --- |
| 기본 Juice Shop | `/juice-shop/` | 기존 기본 규칙 | `benchmark-target:3000` |
| RUBY Market | `/ruby-market/` | `target-profiles/ruby-market.json` | `ruby-web-target:8080` |

`/`는 선택한 화면으로 이동하고 선택되지 않은 기본 화면 경로는 404입니다. `/api/`, `/rest/`, `/assets/` 등 앱의 루트 절대 경로는 동일한 활성 파이프라인을 통과합니다. 대시보드는 대상에 관계없이 `/__detection/dashboard`, `/__defense/dashboard`입니다. 접두사를 제거한 원래 경로가 Detection 규칙과 기록에 사용됩니다.

## 사전 조건

- 저장소 루트의 `.env`에 필수 배포값을 설정하고 비밀번호·키는 커밋하지 않습니다. 운영 HTTPS 및 쿠키 설정은 [루트 안내](../../../../../README.md)를 따릅니다.
- RUBY Market 운영 스택의 웹 서비스만 파이프라인 네트워크에 `ruby-web-target` 별칭으로 연결합니다. 루트의 `RUBY_PIPELINE_NETWORK`와 Market의 `RUBY_BENCHMARK_PIPELINE_NETWORK`가 같아야 합니다. 기본값은 `ruby_ai-defense-net`입니다. 내부 API·평가기·데이터 서비스는 이 네트워크에 직접 노출하지 않습니다.
- 대시보드와 CSRF가 사용하는 공개 origin을 `CSRF_ALLOWED_ORIGINS`에 지정합니다. 내부 `ruby-web-target` 주소가 아닙니다.
- Market은 자체 프런트엔드의 원본 주소와 공개 경로에서 사용할 로그인·쿠키·리다이렉트 동작을 먼저 확인합니다.

## RUBY Market 선택

Market의 `compose.production.yaml`은 파이프라인 네트워크를 **외부 네트워크**로 참조합니다. 새 서버에서 Market을 먼저 실행하면 네트워크가 없어 실패합니다. 저장소 루트의 `.env`에 RUBY 배포값을, `benchmark/benchmarks/web-defense-benchmark/app/.env.production`에 Market 배포값을 준비하고 네트워크 이름을 일치시키세요. 처음 설치할 때만 다음 명령으로 루트 Compose의 컨테이너와 네트워크를 **생성만** 합니다. 이 단계에서는 공개 서비스를 시작하지 않습니다. 이미 루트 RUBY 스택이 실행 중이고 두 Compose가 같은 네트워크를 사용한다면 건너뜁니다.

```bash
docker compose -f docker-compose.yml -f docker-compose.target.ruby-web.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.target.ruby-web.yml \
  create --no-recreate
```

`RUBY_BENCHMARK_IMAGE_TAG`에는 현재 루트 RUBY 배포 커밋이 아니라, **Market 이미지 7종이 실제로 발행된 커밋 SHA**를 적습니다. `Web Defense Benchmark`의 `runtime-images`는 관련 경로 변경으로 시작된 `main` push에서만 GHCR에 이미지를 올립니다. PR 실행이나 관련 경로 변경이 없는 `main` 커밋은 그 SHA의 Market 태그를 만들지 않습니다. GitHub Actions에서 성공한 `main`의 `push` 실행을 고르거나 다음 명령의 `headSha`를 확인하세요. 해당 SHA 태그가 GHCR에 존재하고 이미지에 접근할 권한이 있어야 `pull`이 됩니다. RUBY 이미지의 `IMAGE_TAG`와 Market 이미지의 `RUBY_BENCHMARK_IMAGE_TAG`는 서로 달라도 됩니다.

```bash
gh run list --repo WHS4-RUBY/ruby --workflow web-defense-benchmark.yml \
  --branch main --event push --status success --limit 5 --json headSha,url
```

그다음 저장소 루트에서 Market 운영 스택을 시작합니다. 비밀값은 환경 파일에만 보관하고 명령 출력이나 PR에 남기지 않습니다.

```bash
docker compose \
  --env-file benchmark/benchmarks/web-defense-benchmark/app/.env.production \
  -f benchmark/benchmarks/web-defense-benchmark/app/compose.production.yaml \
  pull
docker compose \
  --env-file benchmark/benchmarks/web-defense-benchmark/app/.env.production \
  -f benchmark/benchmarks/web-defense-benchmark/app/compose.production.yaml \
  up -d --wait
```

그 다음 루트 스택을 **Market 오버레이와 함께 전체 갱신**합니다. 오버레이는 번들 Juice Shop을 비활성화하고 Detection에 Market 프로필을 읽기 전용으로 마운트합니다. 이전에 쓰던 `--no-deps`로 Defense만 교체하는 명령은 공개 이름과 탐지 규칙을 전환하지 못하므로 사용하지 않습니다.

```bash
docker compose -f docker-compose.yml -f docker-compose.target.ruby-web.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.target.ruby-web.yml \
  up -d --wait --remove-orphans --force-recreate
docker compose -f docker-compose.yml -f docker-compose.target.ruby-web.yml \
  --profile bundled-juice-shop stop benchmark-target
```

기존 실행에서 번들 Juice Shop 컨테이너가 이미 있었다면 Compose 프로필만 바꾸어도 실행 중으로 남을 수 있어 마지막 명령으로 정지합니다. 처음부터 Market을 선택한 설치에서는 정지할 컨테이너가 없습니다. Detection의 메모리 점수·식별 상태는 재생성으로 분리됩니다. 스키마 학습 파일은 volume에 남으므로 대상별로 별도 volume을 쓰거나 시험 전에 어떤 상태를 유지할지 명시해야 합니다. `X-Experiment-Run-ID`는 기록 구분값이며 상태 초기화 수단이 아닙니다.

## Juice Shop 복귀

```bash
docker compose -f docker-compose.yml -f docker-compose.target.juice-shop.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.target.juice-shop.yml \
  up -d --wait --remove-orphans --force-recreate
```

기본 구성은 기존 Juice Shop 경로 규칙을 사용합니다. Market 스택이 더 이상 필요 없다면 별도로 종료합니다. 데이터를 지울 목적이 있을 때만 `--volumes`를 추가합니다.

```bash
docker compose \
  --env-file benchmark/benchmarks/web-defense-benchmark/app/.env.production \
  -f benchmark/benchmarks/web-defense-benchmark/app/compose.production.yaml \
  down
```

## 공개 진입점 검사

별도 공개 `:8088`의 Market 화면이 열리는지만으로 전환을 판단하지 않습니다. **RUBY 공개 origin**에서 선택한 이름 경로의 화면과 고유한 읽기 전용 API 응답을 확인하세요. 아래 예시의 `localhost`는 해당 서버에서 실행할 때의 주소입니다.

```bash
curl -i http://127.0.0.1/ruby-market/
curl -i http://127.0.0.1/api/products
curl -i http://127.0.0.1/__detection/api/sessions
curl -i http://127.0.0.1/__defense/api/snapshot
```

두 관리 API는 익명 요청에서 인증을 요구해야 합니다. 같은 요청의 ID와 경로를 Detection·Defense 대시보드와 대상 웹의 읽기 전용 로그에서 대조합니다. 비밀번호나 쿠키는 검사 기록에 남기지 않습니다. `/ruby-market/`이 200이어도 API, 로그인, WebSocket 업그레이드와 프레임의 동작은 별도로 확인해야 합니다.

`main`의 Deploy workflow는 기본 Juice Shop 구성을 자동 선택합니다. 수동 Market 전환 이후 다음 자동 배포는 Juice Shop으로 복귀할 수 있으므로 지속 운영에는 배포 자동화의 대상 선택도 함께 설정해야 합니다. 새 게이트웨이 파일·Market 프로필이 서버로 복사되도록 workflow에 포함되어 있습니다. 이 문서와 브랜치 변경만으로 운영 전환이 발생하지는 않습니다.

로컬의 기존 내부 대상 왕복 검사는 벤치마크 루트의 `./scripts/check_target_switch.sh`입니다. 이 스크립트는 Defense 주소에서 두 대상과 평가기 격리를 확인하며 **게이트웨이의 공개 경로 검사는 별도**입니다. 소규모 공개 서버 관측과 한계는 [2026-10-02 검증 기록](../team-pipeline-validation-20261002.md)에 있습니다.
