# RUBY

RUBY는 웹 요청의 공격 가능성을 탐지하고, 위험도와 정책에 따라 대응 전략을 선택해 방어 기법을 적용하며, 그 성능과 재현성을 검증하는 프로젝트입니다. 탐지, 정책 판단, 방어, 벤치마크에 필요한 코드와 문서를 함께 관리합니다.

## 처음 실행해 볼 로컬 웹

[`RUBY Market 취약점 웹`](benchmark/benchmarks/web-defense-benchmark/README.md)은 정상 쇼핑몰을 먼저 사용한 뒤 원하는 취약점만 켜서 결과를 비교하는 로컬 실습 환경입니다. README의 `처음 10분 사용 순서`부터 따르면 Docker 실행, 화면 체험, 개발 계정 로그인, SQL 주입 확인과 정리까지 진행할 수 있습니다.

이 웹은 로컬 검증용으로 외부 업로드를 보류하고 있습니다. Honeyval 방어는 개발 중이며 역시 업로드하지 않습니다. 공인 주소나 외부 네트워크에 취약 웹을 공개하지 마십시오.

## 저장소 구조

```text
RUBY/
├── benchmark/   # 실험 대상, 실행 환경, 결과 및 재현 자료
├── defense/     # 차단, 변환, 지연, 기만 등 방어 계층
├── detection/   # 요청 분석, 공격 탐지 및 위험도 산정 계층
└── policy/      # 위험도와 정책에 따른 처리 전략 판단 계층
```

### `benchmark/`

논문과 오픈소스 프로젝트의 실행 가능성 및 결과 재현성을 검증합니다. 프로젝트별 실험 문서, 공통 실행 환경, 결과 요약과 작성 템플릿을 관리합니다.

자세한 내용은 [`benchmark/README.md`](benchmark/README.md)를 참고하세요.

### `defense/`

탐지 결과에 따라 요청을 차단, 변환, 지연하거나 기만하는 방어 계층을 개발합니다. 방어 정책, 계층 간 인터페이스, 로그와 테스트를 관리합니다.

자세한 내용은 [`defense/README.md`](defense/README.md)를 참고하세요.

### `detection/`

요청의 특징을 추출하고 공격 가능성을 분석합니다. 규칙과 모델 기반 탐지, 위험도 점수를 관리합니다.

자세한 내용은 [`detection/README.md`](detection/README.md)를 참고하세요.

### `policy/`

Detection이 산정한 위험도 점수를 정책에 따라 해석하고, 정상 전달 또는 Defense에서 적용할 대응 전략을 선택합니다.

자세한 내용은 [`policy/README.md`](policy/README.md)를 참고하세요.

## 작업 방법

1. 최신 `main`에서 작업 브랜치를 만듭니다.
2. 변경 대상에 따라 `benchmark/`, `defense/`, `detection/`, `policy/`에서 작업합니다.
3. 관련 테스트와 재현 절차를 확인하고 문서화합니다.
4. 비밀 정보와 개인정보가 포함되지 않았는지 확인합니다.
5. Pull Request를 생성해 검토받은 뒤 병합합니다.

세부 규칙은 [`CONTRIBUTING.md`](CONTRIBUTING.md)를 참고하세요.

## 서버 배포

서버 배포 운영자는 저장소 루트에 `.env`를 만들고 `IMAGE_PREFIX`에 배포 레지스트리 경로를, `IMAGE_TAG`에 배포할 태그를 설정합니다. `BENCHMARK_*` 변수는 기동할 벤치마크와 Defense의 내부 타깃 주소를 정합니다.

```bash
# .env에 IMAGE_PREFIX와 IMAGE_TAG를 배포 값으로 설정
docker network create ai-defense-net
docker compose pull
docker compose up -d
```

## 로컬 테스트

Docker Desktop을 실행한 뒤, 아래 명령으로 로컬 소스를 빌드해 전체 요청 경로를 띄웁니다. 배포용 `docker-compose.yml`과 달리 레지스트리 설정이나 `.env` 파일이 필요 없습니다.

```bash
docker compose -f docker-compose.local.yml up --build
```

브라우저에서 `http://localhost:8081`로 접속하거나, 다음처럼 Detection → Policy → Defense → 벤치마크 대상의 전체 경로를 확인합니다.

```bash
curl http://localhost:8081/healthz
curl -I http://localhost:8081
```

`detection/app`, `policy/app`, `policy/config.yaml`, `defense/app` 변경은 컨테이너가 자동으로 다시 불러옵니다. 종료 및 컨테이너 정리는 다음 명령을 사용합니다.

```bash
docker compose -f docker-compose.local.yml down
```

## 보안 주의사항

API 키, 토큰, 비밀번호, 실제 서버 식별 정보, 개인정보가 포함된 로그를 커밋하지 않습니다. 필요한 환경 변수는 실제 값이 없는 `.env.example`로만 공유합니다.
