# RUBY

RUBY는 웹 요청의 공격 가능성을 탐지하고, 위험도와 정책에 따라 대응 전략을 선택해 방어 기법을 적용하며, 그 성능과 재현성을 검증하는 프로젝트입니다. 탐지, 정책 판단, 방어, 벤치마크에 필요한 코드와 문서를 함께 관리합니다.

## 저장소 구조

```text
RUBY/
├── benchmark/   # 실험 대상, 실행 환경, 결과 및 재현 자료
├── defense/     # 차단·변환·지연·기만 등 방어 계층
├── detection/   # Node.js 탐지 프록시, ModSecurity/CRS, 대시보드, Policy
```

### `benchmark/`

논문과 오픈소스 프로젝트의 실행 가능성 및 결과 재현성을 검증합니다. 프로젝트별 실험 문서, 공통 실행 환경, 결과 요약과 작성 템플릿을 관리합니다.

자세한 내용은 [`benchmark/README.md`](benchmark/README.md)를 참고하세요.

자체 취약점 웹은 [RUBY Market 구조 안내](benchmark/benchmarks/web-defense-benchmark/README.md)에서 시작하세요. 웹 화면, 8개 서비스, 별도 관리 UI, 성공 판정기, 측정 기록과 격리 구조를 트리로 설명합니다. 기본 Juice Shop을 유지하면서 자체 웹을 선택하는 방법은 [서버 대상 전환](benchmark/benchmarks/web-defense-benchmark/docs/operations/04-server-target-selection.md)에 있습니다.

### `defense/`

탐지 결과에 따라 요청을 차단·변환·지연·기만하는 방어 계층을 개발합니다. 방어 정책, 계층 간 인터페이스, 로그와 테스트를 관리합니다.

자세한 내용은 [`defense/README.md`](defense/README.md)를 참고하세요.

### `detection/`

요청의 특징을 추출해 Automation/Attack 점수를 계산하고 `X-Risk-Score`로 변환합니다.
ModSecurity/OWASP CRS, 행동 기반 휴리스틱, Honey/Deception 신호와 실시간 대시보드를 포함합니다.
위험도 점수를 정책에 따라 해석하고 Defense에서 적용할 대응 전략을 선택합니다.


## 작업 방법

1. 최신 `main`에서 작업 브랜치를 만듭니다.
2. 변경 대상에 따라 `benchmark/`, `defense/`, `detection/`에서 작업합니다.
3. 관련 테스트와 재현 절차를 확인하고 문서화합니다.
4. 비밀 정보와 개인정보가 포함되지 않았는지 확인합니다.
5. Pull Request를 생성해 검토받은 뒤 병합합니다.

세부 규칙은 [`CONTRIBUTING.md`](CONTRIBUTING.md)를 참고하세요.

## 서버 배포

서버에서는 [`.env.example`](.env.example)을 `.env`로 복사한 뒤 `IMAGE_PREFIX`에 배포 레지스트리 경로를, `IMAGE_TAG`에 배포할 태그를 설정합니다. `BENCHMARK_*` 변수는 기동할 벤치마크와 Defense의 내부 타깃 주소를 정합니다.

```bash
cp .env.example .env
# .env의 IMAGE_PREFIX와 IMAGE_TAG를 배포 값으로 수정
docker network create ai-defense-net
docker compose pull
docker compose up -d
```

## 로컬 테스트

Docker Desktop을 실행한 뒤, 아래 명령으로 로컬 소스를 빌드해 전체 요청 경로를 띄웁니다. 배포용 `docker-compose.yml`과 달리 레지스트리 설정이나 `.env` 파일이 필요 없습니다.

```bash
docker compose -f docker-compose.local.yml up --build
```

브라우저에서 `http://localhost:8081`로 접속하거나, 다음처럼 Detection → Defense → 벤치마크 대상의 전체 경로를 확인합니다.

```bash
curl http://localhost:8081/healthz
curl -I http://localhost:8081
```

`defense/app` 변경은 컨테이너가 자동으로 다시 불러옵니다. Detection은 Node.js와 네이티브 CRS scanner를
포함하므로 변경 후 이미지를 다시 빌드해야 합니다. 첫 Detection 빌드는 ModSecurity와 CRS를 준비하므로 시간이 걸릴 수
있습니다. 실시간 탐지 화면은 `http://localhost:8081/__detection/dashboard`에서 확인합니다.
종료 및 컨테이너 정리는 다음 명령을 사용합니다.

```bash
docker compose -f docker-compose.local.yml down
```

## 보안 주의사항

API 키, 토큰, 비밀번호, 실제 서버 식별 정보, 개인정보가 포함된 로그를 커밋하지 않습니다. 필요한 환경 변수는 실제 값이 없는 `.env.example`로만 공유합니다.
