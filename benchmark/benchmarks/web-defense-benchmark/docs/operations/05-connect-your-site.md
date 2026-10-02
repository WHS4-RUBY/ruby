# 자신의 웹사이트에 RUBY 연결

RUBY의 공개 경로는 `방문자 → Gateway → Detection → Defense → 웹 프런트엔드`입니다. 기본
`docker-compose.yml`은 기존 배포와 CI를 위해 Juice Shop을 계속 대상으로 사용합니다.
`docker-compose.target.site.yml`을 추가하면 자신의 웹사이트 주소와 탐지 규칙 파일을
설정할 수 있습니다. 이 오버레이에서 번들 Juice Shop은 시작하지 않습니다.

## 1. 대상과 공개 주소 정하기

- `RUBY_TARGET_URL`: **Defense 컨테이너에서 접근 가능한** 웹 프런트엔드 origin.
  예를 들어 `https://shop.example.test` 또는 같은 Docker 네트워크의
  `http://web:8080`입니다. API·데이터베이스·평가기·관리 UI를 지정하지 마세요.
- `RUBY_PUBLIC_NAME`: 공개 화면의 이름 경로. 기본은 `/site/`이고 예를 들어
  `my-shop`으로 지정하면 `/my-shop/`이 됩니다. 소문자로 시작하고 소문자·숫자·
  하이픈만 사용하는 최대 40자 이름이어야 합니다. `api`, `assets`, `rest`,
  `healthz`, `__detection`, `__defense`는 사용할 수 없습니다. 게이트웨이는 이름
  접두사를 제거하고 Detection에 보내므로 대상 앱과 탐지 프로필에는 원래 경로가
  보입니다. 앱이 쓰는 `/api/`, `/assets/` 같은 절대 경로도 같은 대상에 전달됩니다.
  같은 공개 origin에서 두 대상을 동시에 구분해 운영하는 구성은 아닙니다.
  대상 앱이 루트 절대 화면 링크나 `/` 리다이렉트를 사용하면 브라우저 주소에서
  이름 경로가 사라질 수 있으므로 화면·로그인·리다이렉트를 직접 확인하세요.
- RUBY의 공개 주소: 방문자가 실제로 접근하는 Gateway 주소입니다. 대상의 원래
  주소와 분리할 수 있지만, 로그인·리다이렉트·쿠키·CORS·CSRF에 사용하는 origin은
  이 공개 주소를 기준으로 대상 앱에서도 허용해야 합니다. Detection의
  `CSRF_ALLOWED_ORIGINS`에도 공개 origin을 설정합니다. `RUBY_TARGET_URL`에 RUBY
  공개 주소를 넣으면 자기 자신으로 전달되므로 사용하지 않습니다.
- Detection은 공개 origin의 `dlsid`·`dcid` 쿠키 이름을 사용합니다. 대상 웹도 같은
  이름의 쿠키를 발급한다면 대상 쪽 이름을 바꾸세요. RUBY는 두 이름의 원본
  `Set-Cookie`를 전달하지 않으므로 그대로 두면 대상 로그인 연속성이 끊길 수 있습니다.
- 외부에서 원본 웹에도 계속 접근할 수 있다면 방문자가 RUBY를 우회할 수 있습니다.
  방어 적용이 필요한 경로는 원본의 직접 접근을 운영자 네트워크에서 제한하세요.
  RUBY의 기본 Compose는 포트 80이므로 실제 공개 배포에는 TLS 종료 프록시와
  대시보드 쿠키·HTTPS 설정이 필요합니다.

`shop.example.test`는 설정 형식을 보여주는 예약 예시 도메인이며 실제 서버가
아닙니다. 새 사이트에서는 자신이 관리하는 주소로 바꾸세요.

## 2. 경로·권한 관측·미끼 규칙 작성

`target-profiles/site.example.json`을 복사해 사이트에 맞게 바꿉니다. 실제 계정,
토큰, 비밀번호는 이 파일에 넣지 않습니다. 파일은 Detection 컨테이너의
`/app/config/target.json`에 읽기 전용으로 마운트되며, 잘못된 JSON·필드·경로는
Detection 시작 오류로 처리됩니다. Compose 실행 전에 호스트 파일이 실제로 있는지
확인하세요. 프로필을 지정하지 않은 기존 실행은 기존 Juice
Shop 규칙을 사용합니다. 프로필을 지정하면 대상 전용 규칙과 범용 탐지 신호를
사용하고 Juice Shop 전용 경로 규칙을 적용하지 않습니다.

| 필드 | 의미 |
|---|---|
| `version` | 현재 `1` |
| `routes.login` | 로그인 요청의 `method`, `path`, 계정 식별 필드 `accountField`, 실패 HTTP 코드 `failureStatuses`. 반복 실패 탐지의 입력입니다. |
| `routes.passwordReset`, `routes.securityQuestion` | 해당 기능이 있으면 요청 경로와 계정 필드를 지정합니다. 없는 기능은 생략합니다. |
| `permissions` | `method`·`path`·`requiredRoles` 목록. JWT 역할 claim을 읽어 의심 신호로만 사용합니다. 원본 앱의 권한 검사를 대체하지 않습니다. |
| `bait.traps` | 실제 서비스와 충돌하지 않는 미끼 요청 경로와 응답(`status`, `contentType`, `body`). 매칭 요청은 원본 대신 Detection이 응답합니다. |
| `bait.htmlPaths`, `bait.plaintextPaths` | 미끼 링크를 넣을 응답 경로. 원본 HTML·텍스트가 변하므로 먼저 스테이징에서 화면·CSP·캐시를 확인합니다. 빈 목록이면 삽입하지 않습니다. |

응답 본문 삽입은 전체 본문이 기본 4MiB·250ms 검사 대기 범위 안에 있을 때만
수행합니다. 느리게 내려오는 HTML·텍스트나 SSE·큰 응답은 원본을 스트리밍하므로
telemetry와 본문 미끼가 빠질 수 있습니다. 이 요청도 본문 검사 생략 여부를 탐지
기록에 남기므로, 설치 검증에서 실제 페이지 응답을 확인하세요.

`routes`와 `permissions`의 경로는 탐지기의 정규화된 경로와 비교합니다. 숫자
세그먼트는 `:id`, UUID 세그먼트는 `:uuid`로 적습니다. `bait.traps`는 실제
요청 경로와 정확히 일치해야 합니다.

예제 프로필은 `target-profiles/juice-shop.json`, `ruby-market.json`,
`site.example.json`에 있습니다. Juice Shop 예제는 새 형식의 최소 규칙 예시이며
프로필 없이 실행하는 기존 Juice Shop 전용 탐지·미끼와 동등하지 않습니다. 기존
실험 조건을 재현할 때는 프로필 없는 기본 Compose를 사용하세요. RUBY Market은
opaque 세션을 쓰므로
`ruby-market.json`의 `permissions`는 비워 두었습니다. JWT 역할을 읽는 현재
권한 신호는 서명 검증을 통한 실제 인가 판정이 아니며, opaque 세션 기반 사이트의
정상 관리자 요청을 분류할 수 없습니다. 새 사이트의 역할 정보가 이 방식과
맞지 않으면 `permissions`도 빈 목록으로 두세요.

## 3. 실행 설정

저장소 루트에서 `.env.example`을 `.env`로 복사하고 기존 운영 필수값을
설정합니다. 실제 `.env`는 커밋하지 않습니다. 아래 세 항목은 자신의 사이트에
맞게 바꾸는 예시입니다.

```dotenv
RUBY_TARGET_URL=https://shop.example.test
RUBY_TARGET_PROFILE_FILE=./target-profiles/site.example.json
RUBY_PUBLIC_NAME=my-shop
CSRF_ALLOWED_ORIGINS=https://ruby.shop.example.test
RUBY_FORWARDED_PROTO=https
```

대상 프로필 경로는 저장소 루트 기준 파일 경로입니다. 상대 경로를 쓸 때는 저장소
루트에서 Compose 명령을 실행하세요. 대상과 RUBY가 같은 Docker 네트워크에 있는
경우 웹 서비스만 그 네트워크에 연결하고 내부 API·데이터·제어 서비스는 격리합니다.

예를 들어 로컬 Compose(`docker-compose.local.yml`)의 기본 프로젝트 이름은
`ruby-local`이며 파이프라인 네트워크는 `ruby-local_ai-defense-net`입니다. 다음은
**자신의 사이트 Compose에 추가할 웹 서비스 연결 예시**입니다. `image`와 서비스의
내부 포트는 실제 사이트 값으로 바꾸고, 기존 API·DB가 쓰는 사설 네트워크는
그대로 유지하세요. API·DB 자체를 `pipeline`에 연결하지 않습니다.

```yaml
services:
  web:
    image: your-web-image:known-tag
    expose: ["8080"]
    networks:
      pipeline:
        aliases: [site-web-target]
      app-private:
networks:
  pipeline:
    external: true
    name: ruby-local_ai-defense-net
  app-private:
    internal: true
```

이 예시의 사이트를 연결할 때는 루트 `.env`에
`RUBY_TARGET_URL=http://site-web-target:8080`,
`RUBY_TARGET_PROFILE_FILE=./target-profiles/site.example.json`,
`RUBY_PUBLIC_NAME=my-shop`, `CSRF_ALLOWED_ORIGINS=http://localhost:8081`을
설정합니다. 실제 로그인·API 경로와 미끼 규칙은 예제 프로필을 수정해 지정하세요.
처음 설치라면 **루트 Compose가 네트워크를 먼저 생성**해야 외부 네트워크를 참조하는
사이트 Compose가 시작됩니다. 저장소 루트에서 `config --quiet`로 설정을 확인한 후
다음 순서로 실행하세요. `create`는 RUBY 컨테이너를 만들지만 시작하지 않습니다.
이미 루트 스택이 실행 중이면 `create`는 건너뜁니다.

```bash
docker compose -f docker-compose.local.yml -f docker-compose.target.site.yml config --quiet
docker compose -f docker-compose.local.yml -f docker-compose.target.site.yml \
  create --build --no-recreate
docker compose -f /path/to/your-site/compose.yaml up -d --wait
docker compose -f docker-compose.local.yml -f docker-compose.target.site.yml \
  up -d --build --wait --remove-orphans --force-recreate
docker compose -f docker-compose.local.yml -f docker-compose.target.site.yml \
  --profile bundled-juice-shop stop benchmark-target
```

이렇게 연결하면 Defense가 `site-web-target`을 컨테이너 DNS로 찾고, 방문자는
`http://localhost:8081/my-shop/`을 사용합니다. 이 네트워크 이름은 로컬 기본값이며
운영 루트 Compose의 기본 이름은 `ruby_ai-defense-net`입니다. 운영에서 사이트
Compose의 외부 네트워크 이름은 루트 `RUBY_PIPELINE_NETWORK`와 일치시키세요.

이미 자신의 사이트가 별도의 URL로 배포되어 Defense에서 접근 가능하면 외부
Docker 네트워크와 별칭은 필요 없습니다. 이때는 `RUBY_TARGET_URL`에 그 원본
origin을 지정하고 원본 사이트의 직접 공개 접근을 운영 환경에서 제한합니다.

운영 서버에서는 위 로컬 값 대신 앞의 HTTPS 공개 origin·운영 대상 주소·운영
프로필을 `.env`에 설정한 뒤 다음 명령을 사용합니다.

```bash
docker compose -f docker-compose.yml -f docker-compose.target.site.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.target.site.yml up -d --wait --remove-orphans --force-recreate
docker compose -f docker-compose.yml -f docker-compose.target.site.yml --profile bundled-juice-shop stop benchmark-target
```

Defense는 번들 대상의 존재를 필수 시작 조건으로 삼지 않습니다. 대신 `/readyz`가
설정한 대상 주소의 TCP 연결을 확인하고, Detection은 Defense의 준비 확인 뒤
시작합니다. 대상 사이트를 먼저 실행한 다음 `up --wait`가 완료될 때까지 기다리고,
완료 뒤 공개 진입점에서 실제 화면을 확인하세요. 준비 검사는 사이트의 업무 경로·
인증·응답 정확도까지 검증하지 않으며, 이후 대상이 중단되면 요청은 502가 될 수
있습니다.

소스를 직접 빌드하는 로컬 환경에서는 첫 파일을 `docker-compose.local.yml`로
바꿉니다. 로컬 Compose는 기본적으로 포트 8081을 사용합니다. 대상 교체 시에는
Detection과 Gateway를 재생성해 이전 사이트에서 누적된 세션·Flow 점수가 섞이지 않게
합니다. 스키마 학습 파일은 volume에 남으므로 서로 다른 사이트 실험에서는
그 파일을 분리하거나 초기화해야 합니다. 프로필 변경만으로 학습 상태가 자동
초기화되지는 않습니다.

## 4. 공개 진입점에서 확인

대상 사이트에 고유한 무해한 화면 문구 또는 읽기 전용 경로를 정한 뒤, **RUBY의
공개 진입점**에서 응답을 확인합니다. Defense 컨테이너의 직접 주소나 원본 웹의
별도 공개 포트에만 접속해서는 전달 경로가 확인되지 않습니다. 같은 요청을 두
대시보드에서 시간·경로·클라이언트 ID로 대조하고, Defense의 전달 결과와 대상
웹의 읽기 전용 접근 로그를 대조합니다. 자격증명·세션 쿠키는 검사 기록에
남기지 않습니다.

```bash
curl -i https://ruby.shop.example.test/my-shop/
curl -i https://ruby.shop.example.test/api/products
curl -i https://ruby.shop.example.test/__detection/api/sessions
curl -i https://ruby.shop.example.test/__defense/api/snapshot
```

뒤의 두 관리 API는 익명 요청에서 인증을 요구해야 합니다. 미끼 경로는 원본에
없는 경로를 선택하고, 스테이징에서만 소량 요청해 원본의 접근 로그에 남지
않는지 확인합니다. HTTP 정상 요청과 WebSocket 업그레이드·프레임은 따로
시험하세요. 현재 설정 프로필은 HTTP 경로와 응답 삽입 범위를 설명하며,
WebSocket 프레임 내용의 탐지·변형을 보장하지 않습니다.

## 5. 대상 전환과 배포 자동화

Juice Shop/RUBY Market 오버레이는 화면 이름·대상 규칙·전달 주소를 함께 전환합니다. 현재
`main` 배포 workflow는 기본 Juice Shop Compose를 실행합니다. 새 사이트
오버레이는 운영자가 명시적으로 선택해야 하고, 이후 자동 배포에서도 같은
오버레이·프로필을 유지하도록 배포 절차를 조정해야 합니다. 자동 배포가 새
사이트 설정을 지속한다고 가정하지 마세요. RUBY Market의 내부 연결과 두
기본 대상의 전환 순서는 [서버 대상 전환](04-server-target-selection.md)을
참고하세요.

대상별 관측 정확도는 사이트의 API·인증 방식에 달려 있습니다. 이 설정만으로
새 사이트에 대한 방어 효과가 검증된 것은 아닙니다. 공격 성공 여부는 해당
사이트의 독립 판정 기준으로 확인하고, 공격 시간·요청·토큰, 방어 측 비용과
정상 사용자 지연을 분리해 기록하세요.
