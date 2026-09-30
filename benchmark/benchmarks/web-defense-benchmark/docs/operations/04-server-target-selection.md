# 서버 벤치마크 대상 전환

팀 루트 스택은 기본적으로 Juice Shop을 사용합니다. 자체 취약점 웹은 별도 8개 서비스
스택으로 실행하고 Defense의 전달 주소만 바꿉니다. 두 대상은 함께 실행할 수 있지만 한
시험에서는 하나만 선택하고, 사용한 오버레이와 이미지 태그를 시험 설정에 기록합니다.

## 사전 조건

- 현재 경로는 `Detection -> Defense -> Target`입니다. 별도
  Policy 서비스는 없으며 Detection이 `X-Defense-Plan`을 만들어 Defense로 전달합니다.
- 루트 `.env`의 `RUBY_PIPELINE_NETWORK`와 자체 웹 `.env.production`의
  `RUBY_BENCHMARK_PIPELINE_NETWORK`를 같은 값으로 둡니다. 기본값은 둘 다
  `ruby_ai-defense-net`입니다.
- 루트 스택의 해당 파이프라인 네트워크가 실행 중이어야 합니다.
- 루트 운영 스택은 `main`의 #22와 #25 이후 두 대시보드 비밀번호, Detection의
  `PAYLOAD_FINGERPRINT_KEY`, `DCID_HMAC_SECRET`, `ACCOUNT_ID_HASH_KEY` 및
  대시보드 HTTPS·쿠키 설정이 필요합니다. HTTP 실험 환경은
  `ALLOW_INSECURE_DASHBOARD_HTTP=true`와 두 대시보드의 HTTPS/Secure 쿠키 설정을
  명시적으로 꺼야 합니다. 비밀값은 저장소에 기록하지 않습니다.
- 자체 웹의 `.env.production`에는 실제 운영 비밀값과 커밋 SHA 이미지 태그를 넣습니다.
- 외부 사용자가 보는 Detection 주소를 `CSRF_ALLOWED_ORIGINS`에 넣습니다. 내부 대상
  주소인 `ruby-web-target`을 넣는 항목이 아닙니다.
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

Defense를 자체 웹 주소로 다시 만든 뒤 Detection도 다시 만듭니다. Session,
Resolved Actor와 Client Flow 상태는 Detection 메모리에 누적되므로 대상을 바꾸면서
기존 프로세스를 재사용하면 이전 대상의 점수와 식별 상태가 섞입니다.

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.target.ruby-web.yml \
  up -d --no-deps --force-recreate defense
docker compose \
  -f docker-compose.yml \
  up -d --no-deps --force-recreate detection
```

## Juice Shop 복귀

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.target.juice-shop.yml \
  up -d --no-deps --force-recreate defense
docker compose \
  -f docker-compose.yml \
  up -d --no-deps --force-recreate detection
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

`X-Experiment-Run-ID`는 실행 기록을 구분하는 관측값이며 Detection의 누적 상태를
초기화하지 않습니다. 공식 시험은 실행별 격리 스택을 사용하거나 Detection을 재생성해
이전 시험의 점수가 다음 시험에 들어가지 않게 합니다. 스키마 학습 파일은 별도 volume에
남으므로 어떤 학습 파일을 사용했는지도 시험 설정에 기록합니다.

루트 Deploy workflow는 기본 Juice Shop 파이프라인을 갱신하고 자체 웹 Compose와
오버레이 파일을 서버에 복사합니다. 자체 웹 활성화와 취약점 모듈 선택은 자동으로 하지
않습니다. `Web Defense Benchmark` workflow가 같은 커밋 SHA의 자체 웹 이미지 7종을
발행한 뒤 위 절차로 명시적으로 전환합니다.

현재 별도 호스트 포트로 열린 RUBY Market 화면이 보여도 Detection 진입점의 기본
대상이 바뀐 것은 아닙니다. 외부 포트의 응답만으로 `Detection -> Defense -> RUBY Market`
연결이나 내부 평가기 격리를 확인할 수 없습니다. 대상 전환 후 Detection 공개 주소에서
RUBY Market 화면을 확인하고, 익명 요청의
`/__detection/api/sessions`와 `/__defense/api/snapshot`이 각각 인증을 요구하는지,
정상 웹 요청이 계속 전달되는지 확인합니다. 대시보드 로그인에 필요한 비밀번호와 세션
쿠키는 검사 기록에 남기지 않습니다.

배포 전 로컬 왕복 검사는 벤치마크 루트에서 `./scripts/check_target_switch.sh`로 실행합니다.
검사는 초기화, 비공개 성공 판정, 판정기 읽기 전용 권한과 네트워크 격리를 확인하고
Defense를 자체 웹과 Juice Shop에 차례로 연결한 뒤 자신이 만든 임시 자원을 정리합니다.
`scripts/check_team_pipeline_runtime.py`는 격리된 운영 모드 Detection에서 익명 관리 API
거부, 로그인 후 접근, 정상 요청 전달과 지연 실행을 함께 검사합니다. Docker 엔진과
이미지 빌드가 필요하며, 과거 실행 기록의 실패 판정을 소급 변경하지 않습니다.
