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
├── environments/   # Docker 및 실행 환경 설정
├── results/        # 공통 결과 양식과 요약
└── templates/      # 새 벤치마크 작성용 템플릿
```

## 방어 파이프라인 연결 실행

컨테이너로 제공되는 벤치마크는 루트 [`.env.example`](../.env.example)을 복사해 만든 `.env`에서 선택합니다. 기본 선택은 OWASP Juice Shop이며, 이 설정은 컨테이너 이미지·서비스 포트와 Defense가 요청을 전달할 내부 주소를 함께 지정합니다.

```bash
# 최초 한 번: 파이프라인이 공유할 Docker 네트워크 생성
docker network create ai-defense-net

# .env에 선택된 벤치마크와 파이프라인을 함께 기동
docker compose pull
docker compose up -d
```

선택된 profile의 컨테이너만 생성됩니다. 모든 계층과 선택된 벤치마크는 `ai-defense-net`에 연결되므로 Defense는 `BENCHMARK_TARGET_URL`에 설정된 서비스 이름(기본값: `benchmark-target`)으로 타깃에 접근합니다. 다른 컨테이너형 벤치마크로 바꿀 때는 `.env`의 profile, 이미지, 포트와 URL만 함께 갱신합니다.

각 벤치마크는 다음 형태로 추가합니다.

```text
benchmarks/<project-name>/
├── README.md       # 대상과 실행 방법
├── environment.md  # OS, Docker, 도구 및 버전
└── results.md      # 실행 결과와 해석
```

세 폴더의 관계는 다음과 같습니다.

```text
environments = 어떤 조건에서 실행했는가
benchmarks   = 무엇을 어떻게 검증했는가
results      = 여러 실험에서 무엇을 확인했는가
```

## 폴더별 사용 방법

### `benchmarks/` — 프로젝트별 실제 작업 공간

논문이나 오픈소스 프로젝트 하나당 폴더 하나를 만듭니다. 실험 과정과 개별 결과를 가장 자세하게 기록하는 중심 폴더입니다.

```text
benchmarks/agent-webcloak/
├── README.md
├── environment.md
├── results.md
├── scripts/
└── patches/
```

- `README.md`: 원본 URL, 논문, 검증 commit/tag, 목표, 설치 및 실행 명령
- `environment.md`: 해당 실험 당시의 Host OS, Docker 이미지, Codex 및 도구 버전
- `results.md`: 성공·부분 성공·실패 여부, 확인한 기능, 오류, 논문 결과와의 차이
- `scripts/`: 반복 실행에 필요한 `setup.sh`, `run.sh` 등의 스크립트
- `patches/`: 원본 프로젝트를 실행하기 위해 적용한 패치와 변경 설명

원본 오픈소스 전체를 복사하기보다는 원본 URL과 검증한 commit 또는 tag를 기록합니다. 문서는 [`templates/benchmark-report.md`](templates/benchmark-report.md)와 [`templates/environment-record.md`](templates/environment-record.md)를 복사해 시작합니다.

### `environments/` — 팀 공통 실행 환경

여러 벤치마크에서 재사용할 Docker 환경과 설정을 저장합니다.

```text
environments/ubuntu-22.04/
├── Dockerfile
├── compose.yaml
├── requirements.txt
├── .env.example
└── README.md
```

다음 내용을 포함합니다.

- Ubuntu와 Docker 이미지 버전 및 digest
- Python, Node.js 등 언어 런타임과 패키지 버전
- 이미지 빌드 및 컨테이너 실행 명령
- 공통 볼륨, 포트와 환경 변수 이름
- 팀원이 동일한 환경을 재현하는 방법

실제 API 키는 `.env`에만 저장하고 Git에 올리지 않습니다. 저장소에는 변수 이름과 예시 형식만 있는 `.env.example`을 추가합니다.

`environments/`는 재사용할 공통 설정이고, `benchmarks/<project>/environment.md`는 특정 실험 당시 실제로 사용한 환경 기록입니다.

### `results/` — 여러 실험의 비교와 요약

개별 실험의 상세 로그가 아니라 여러 벤치마크를 함께 비교할 때 필요한 핵심 결과를 저장합니다.

```text
results/
├── README.md
├── summary.md
├── weekly/
│   └── week-03.md
└── tables/
    └── benchmark-summary.csv
```

다음 내용을 정리합니다.

- 프로젝트별 성공·부분 성공·실패 비교
- 주차별 진행 상황과 발표용 요약
- 여러 프로젝트에서 공통으로 발생한 오류와 제약사항
- 팀원별 실행 결과를 비교할 때의 환경 차이
- 이후 공통 서버에서 다시 검증할 항목

초기 단계에는 팀원별 하드웨어가 다르므로 실행 시간과 성능 수치는 참고값으로 취급하고, 반드시 실행 환경과 반복 횟수를 함께 표시합니다.

## 새 벤치마크 진행 순서

```text
1. 최신 main에서 개인 브랜치 생성
2. benchmarks/<project-name>/ 폴더 생성
3. templates/의 문서를 복사해 대상과 환경 기록
4. environments/의 공통 Docker 환경으로 실행
5. 명령, 결과, 오류와 해결 시도를 계속 기록
6. benchmarks/<project-name>/results.md에 개별 결과 작성
7. 비교할 결과가 쌓이면 results/summary.md 갱신
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
