# 서버 벤치마크 대상 전환

팀 루트 스택은 기본적으로 Juice Shop을 사용합니다. 자체 취약점 웹은 별도 8개 서비스
스택으로 실행하고 Defense의 전달 주소만 바꿉니다. 두 대상은 함께 실행할 수 있지만 한
시험에서는 하나만 선택하고, 사용한 오버레이와 이미지 태그를 시험 설정에 기록합니다.

## 사전 조건

- 루트 스택의 `ruby_ai-defense-net` 네트워크가 실행 중이어야 합니다.
- 자체 웹의 `.env.production`에는 실제 운영 비밀값과 커밋 SHA 이미지 태그를 넣습니다.
- 실제 `.env`와 `.env.production`은 커밋하지 않습니다.

## 자체 취약점 웹 선택

저장소 루트에서 자체 웹 운영 스택을 먼저 실행합니다.

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

Defense만 자체 웹 주소로 다시 만듭니다.

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.target.ruby-web.yml \
  up -d --no-deps --force-recreate defense
```

## Juice Shop 복귀

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.target.juice-shop.yml \
  up -d --no-deps --force-recreate defense
```

자체 웹이 더 필요하지 않으면 해당 스택만 종료합니다. 데이터까지 지울 때만 `--volumes`를
추가합니다.

```bash
docker compose \
  --env-file benchmark/benchmarks/web-defense-benchmark/app/.env.production \
  -f benchmark/benchmarks/web-defense-benchmark/app/compose.production.yaml \
  down
```

## 격리 조건

외부 공개 진입점은 Detection입니다. 자체 웹의 `web` 서비스만 공유망에
`ruby-web-target`으로 연결합니다. API, 평가기, 데이터 서비스와 관리 UI는 이 경로에
연결하지 않습니다. 초기화와 판정 요청은 운영 제어 경로에서만 실행합니다.

배포 전 로컬 왕복 검사는 벤치마크 루트에서 `./scripts/check_target_switch.sh`로 실행합니다.
검사는 초기화, 비공개 성공 판정, 판정기 읽기 전용 권한과 네트워크 격리를 확인하고
Defense를 자체 웹과 Juice Shop에 차례로 연결한 뒤 자신이 만든 임시 자원을 정리합니다.
