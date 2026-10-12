# RUBY Benchmark

RUBY에서 논문과 오픈소스 프로젝트의 벤치마킹 과정, 실행 환경, 결과를 관리하는 영역입니다.

현재 단계의 목표는 서로 다른 로컬 장비에서 완전히 동일한 성능을 측정하는 것이 아니라, 공통 절차와 Docker 환경을 이용해 다음 내용을 검증하는 것입니다.

- 논문 또는 오픈소스의 실행 가능 여부
- 주요 기능과 결과의 재현 가능 여부
- 실행 과정에서 발견한 오류와 제약사항
- 이후 공통 서버 실험에 필요한 환경 조건

## 저장소 구조

```text
benchmark/
├── benchmarks/     # 프로젝트별 벤치마크 문서와 실행 자료
├── experiments/    # RUBY 자체 방어 기법의 A/B·호환성 실험 하니스
└── templates/      # 새 벤치마크 작성용 템플릿
```

프로젝트 종료 시점 기준으로 `benchmarks/` 에는 벤치마크 4건, `experiments/` 에는 실험 하니스
2건이 들어 있습니다. 팀 공통 실행 환경(`environments/`)과 통합 결과 요약(`results/`)은 계획에만
있었고 실제로 만들어지지 않았습니다 — 각 실험은 자기 폴더 안에서 환경과 결과를 함께 기록하는
방식으로 끝났습니다.

## 들어 있는 것

### `benchmarks/` — 외부 논문·오픈소스 검증 (4건, 모두 종료)

| 폴더 | 대상 | 확인 날짜 | 결과 |
|---|---|---|---|
| [`agentcyberrange-webexploitbench/`](benchmarks/agentcyberrange-webexploitbench/README.md) | AgentCyberRange — WebExploitBench / CAGE | 2026-08-20 | 모델별 결과 분리 기록. Codex 회차는 평가 불성립, Claude Opus 회차는 채점 완료(0/6) |
| [`apiecho/`](benchmarks/apiecho/README.md) | APIEcho (IEEE S&P 2026 게재 예정) | 2026-08-16 | 성공 — 52 unit 중 이상 1건을 탐지 |
| [`cheat/`](benchmarks/cheat/README.md) | CHeaT — Cloak, Honey, Trap (USENIX Security 2025) | 2026-08-19 | 성공 — 검증 단계 A~D 통과, 15개 기법 중 13개를 codex CLI 로 시행 |
| [`ruby-defense-grader/`](benchmarks/ruby-defense-grader/README.md) | CVE-Bench Grader 의미·인터페이스 재현(RUBY 자체 구현, v0.3.0) | — | 합성 데이터 기반 판정 로직까지. **Detection·Defense 파이프라인과 연동되지 않았고 CI 에서도 실행되지 않습니다** |

CHeaT 는 이 저장소에서 두 군데에 나옵니다. 여기 `benchmarks/cheat/` 는 **원본 논문 구현의 재현
검증**이고, [`defense/CHeat-defense-proxy/`](../defense/CHeat-defense-proxy/README.md) 는 그 아이디어를
리버스 프록시로 옮긴 **RUBY 자체 구현**입니다.

### `experiments/` — RUBY 방어 기법 실험 (2건)

| 폴더 | 내용 |
|---|---|
| [`experiments/path_alias_ab/`](experiments/path_alias_ab/) | 경로 별칭 A/B 실행·분석 스크립트. 결과 기록은 [`results-rediscovery-20261007.md`](experiments/path_alias_ab/results-rediscovery-20261007.md)(재발견 A/B, 90분 6구간) |
| [`experiments/path_alias_compat/`](experiments/path_alias_compat/README.md) | 경로 별칭 v4 호환성·부하 검증 도구. [경로 별칭 운영 가이드 7절](../defense/docs/path-alias-operations.md#7-검증-결과)의 결과를 재현한다 |

## 방어 파이프라인과의 관계

이 영역의 실험 문서와 결과 파일은 Detection·Defense 파이프라인의 실행에 필요하지 않습니다. 다만 실제 공격 실험에서는 별도로 실행한 벤치마크 서비스를 보호 대상으로 연결합니다. 현재 운영 Compose는 `.env`의 `TARGET_CHOICES`에 `juice-shop=http://juice-shop-target:3000`과 `ruby-shop=http://ruby-web-target:8080`을 등록하고, `TARGET_DEFAULT_ID`를 등록된 ID로 지정합니다. 활성 대상은 관리 화면에서 선택합니다. 연결 방식은 [`defense/README.md`](../defense/README.md#target-연결)를 참고하세요.

공격 실험은 서버의 공개 포트 80으로 요청을 보내야 `Detection → Defense → 대상별 CHeaT sidecar → 벤치마크 대상`을 지나며 두 대시보드에 기록됩니다. 포트 3020의 벤치마크 선택 화면과 그 하위 앱 주소는 서비스에 직접 접속하는 경로라 탐지·방어 기록에 나타나지 않습니다. 관리자 화면은 서버의 `127.0.0.1:8088`에만 열려 있으며 SSH 터널로 접속합니다. 단일 대상을 호스트 포트에 연결하는 독립 실행/legacy 구성에서는 `.env`의 `TARGET_PORT`를 사용합니다.

각 벤치마크는 다음 형태로 추가합니다.

```text
benchmarks/<project-name>/
├── README.md       # 대상과 실행 방법
├── environment.md  # OS, Docker, 도구 및 버전
└── results.md      # 실행 결과와 해석
```

세 문서의 역할은 다음과 같습니다.

```text
environment.md = 어떤 조건에서 실행했는가
README.md      = 무엇을 어떻게 검증하려 했는가
results.md     = 실제로 무엇을 확인했는가
```

## 폴더별 사용 방법

### `benchmarks/` — 프로젝트별 실제 작업 공간

논문이나 오픈소스 프로젝트 하나당 폴더 하나를 만듭니다. 실험 과정과 개별 결과를 가장 자세하게 기록하는 중심 폴더입니다.

```text
benchmarks/apiecho/          # 실제 예시
├── README.md
├── environment.md
├── results.md
├── docker-compose.yml
├── scripts/
├── patches/
└── target/
```

- `README.md`: 원본 URL, 논문, 검증 commit/tag, 목표, 설치 및 실행 명령
- `environment.md`: 해당 실험 당시의 Host OS, Docker 이미지, Codex 및 도구 버전
- `results.md`: 성공·부분 성공·실패 여부, 확인한 기능, 오류, 논문 결과와의 차이
- `scripts/`: 반복 실행에 필요한 `setup.sh`, `run.sh` 등의 스크립트
- `patches/`: 원본 프로젝트를 실행하기 위해 적용한 패치와 변경 설명

원본 오픈소스 전체를 복사하기보다는 원본 URL과 검증한 commit 또는 tag를 기록합니다. 문서는 [`templates/benchmark-report.md`](templates/benchmark-report.md)와 [`templates/environment-record.md`](templates/environment-record.md)를 복사해 시작합니다.

### `experiments/` — RUBY 자체 방어 기법 실험

외부 프로젝트 검증이 아니라 RUBY 의 방어 기법(현재는 경로 별칭)을 A/B 로 재는 하니스입니다.
실행 스크립트와 결과 문서를 같은 폴더에 둡니다.

- 결과 문서는 날짜를 파일명에 넣습니다(`results-rediscovery-20261007.md`).
- 측정 방법·구간 수·통계적 한계를 결과와 같은 문서에 적습니다. 두 하니스 모두 N 이 작아
  수치를 방향성으로만 읽도록 문서에 명시해 두었습니다.
- 공격 대상은 로컬 일회용 컨테이너로 한정합니다.

### 환경 기록과 결과 비교 규칙

원래는 팀 공통 실행 환경을 `environments/` 에, 여러 벤치마크의 통합 요약을 `results/` 에 두려고
했지만 두 폴더는 끝까지 비어 있었습니다. 실제로는 각 실험이 자기 폴더의 `environment.md` ·
`results.md` 에 환경과 결과를 함께 기록하는 방식으로 끝났습니다. 아래 규칙은 그 두 파일에
적용합니다.

`environment.md` 에 적을 것:

- Ubuntu 와 Docker 이미지 버전 및 digest
- Python, Node.js 등 언어 런타임과 패키지 버전
- Codex 등 에이전트 CLI 버전
- 이미지 빌드 및 컨테이너 실행 명령
- 볼륨, 포트와 환경 변수 **이름**

실제 API 키·토큰·비밀번호는 `.env` 에만 두고 Git 에 올리지 않습니다. 저장소에는 변수 이름과
예시 형식만 있는 `.env.example` 을 둡니다.

`results.md` 에 적을 것:

- 성공·부분 성공·실패 여부와 그 판정 근거
- 확인한 기능, 발생한 오류, 논문·원본 결과와의 차이
- 재현 횟수(N)와 그 수치로 주장할 수 없는 것

성능 수치를 비교할 때는 실행 환경과 반복 횟수를 반드시 함께 적습니다. 팀원별 하드웨어가 다른
단계의 실행 시간은 참고값으로 취급합니다.

## 새 벤치마크 진행 순서

```text
1. 최신 main에서 개인 브랜치 생성
2. benchmarks/<project-name>/ 폴더 생성
3. templates/의 문서를 복사해 대상과 환경 기록
4. 그 폴더 안에 실행 환경(Dockerfile·compose·scripts)을 함께 두고 실행
5. 명령, 결과, 오류와 해결 시도를 계속 기록
6. benchmarks/<project-name>/results.md에 결과와 한계 작성
7. 위 "들어 있는 것" 표에 새 폴더 한 줄 추가
8. 브랜치 push 후 Pull Request 생성
9. 관리자 검토와 승인 후 Squash merge
```

## 작업 방법

1. 최신 `main`에서 개인 브랜치를 생성합니다.
2. `templates/`의 양식을 복사해 벤치마크 내용을 작성합니다.
3. 인증 정보와 대용량 원본 데이터가 포함되지 않았는지 확인합니다.
4. 저장소에 브랜치를 push하고 `main`을 대상으로 Pull Request를 만듭니다.
5. 관리자 검토와 승인을 받은 뒤 병합합니다.

자세한 규칙은 [루트 CONTRIBUTING.md](../CONTRIBUTING.md)를 참고하세요.

## 보안 주의사항

다음 항목은 저장소에 올리지 않습니다.

- API 키, 액세스 토큰, 비밀번호
- `.env`와 Codex 인증 파일
- 개인 식별 정보 또는 외부 공개가 제한된 데이터
- 라이선스상 재배포할 수 없는 데이터셋과 모델 파일

실수로 비밀 정보를 커밋했다면 해당 값을 즉시 폐기·재발급하고 관리자에게 알립니다. 파일을 삭제하는 것만으로는 Git 기록에서 제거되지 않습니다.
