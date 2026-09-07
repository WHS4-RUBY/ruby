# Stage 1 정상 웹 구현 완료 기록

확인일은 2026-08-30 KST다. 이 문서는 로컬 통합 환경에서 확인한 결과만 기록한다. 실제 서버 배포 완료나 취약점 부재의 수학적 증명을 뜻하지 않는다.

## 판정

Stage 1의 정상 업무 API와 로컬 통합 게이트 완료.

- 비회원, 고객, 판매자 직원, 고객지원 직원, 관리자 흐름 통과
- 역할별 접근 제어 통과
- PostgreSQL, Redis, S3 호환 객체 저장소, 비동기 worker 연결 통과
- 고정 seed와 전체 상태 해시를 이용한 반복 초기화 통과
- 의도적으로 활성화한 취약점 모듈 0개
- 판매자와 지원 담당자의 전용 브라우저 화면은 아직 없음. 해당 역할은 API 통합 검사로 검증

이 문서가 봉인된 뒤 Stage 2 평가기와 시험 격리 구조가 추가됐다. Stage 2의 현재 판정은 별도 문서에 기록하며 이 Stage 1 수치와 해시는 과거 기준선으로 보존한다. Stage 3 취약점 모듈은 아직 구현하지 않았다.

## 구현된 정상 업무

- 비회원: 상품 검색, 상품 상세 조회, 비회원 문의 작성
- 고객: 회원가입, 로그인, 로그아웃, 비밀번호 재설정, 주문, 결제, 미결제 주문 취소, 환불 요청, 문의와 첨부 파일
- 판매자 직원: 상품 생성, 수정, 삭제, 담당 상품 주문 조회, 배송과 환불 상태 처리
- 고객지원 직원: 고객 문의 답변과 종료, 비회원 문의 처리
- 관리자: 사용자 목록, 계정 활성 상태 변경, 역할 변경, 변경 대상 세션 무효화
- worker: Redis 작업 수신, S3 호환 저장소의 첨부 객체 확인, 첨부 상태 전환

## 상태 초기화

`POST /internal/reset`은 loopback에만 공개된 제어 API다. 올바른 제어 토큰이 있어야 실행된다.

- PostgreSQL 업무 데이터 재생성
- Redis 세션과 작업 대기열 삭제
- 객체 저장소의 시험 객체 삭제
- 고정 사용자 UUID, 비밀번호 salt, 생성 시각과 상품 데이터 재생성
- 단일 프로세스 잠금과 PostgreSQL advisory transaction lock으로 동시 초기화 직렬화

초기 상태 SHA256은 `1f2e722dc7b7cde2e1542f5a02a8091aafa0f4f21417b12c39bb34f483048195`다. 정상 업무 수행 후 값이 바뀌고 재설정 후 같은 값으로 복원됐다. 동시에 실행한 초기화 요청 2건도 모두 HTTP 204로 완료됐다.

## 런타임 구성

| 서비스 | 구현 | 로컬 이미지 SHA256 |
| --- | --- | --- |
| API | Python 3.13, FastAPI 0.141.1 | `99791a4ec71d9ea07fb2ff88b386fba5de9061bb3e953d9814690f0499ac274d` |
| worker | Python 3.13 | `a00ffbeca55d6d383d24e8abb9add4a9c97190737419173cb278e96987b17ba8` |
| web | React 19.2.8, Vite 8.2.2, Nginx | `66889ea09ece0963faa8d209e1e0d95e35818eacc213108b04dbdf865a506fe2` |
| PostgreSQL | Alpine 공식 PostgreSQL 17.11 패키지 | `5bfd92dac62759415b2e87b8d69d4a4aaeb373c26a2585cefdb67fa6cca8f22f` |
| Redis | Redis 8.10.1 Alpine | `4d4415527018bbb10d2d9e4b835903cc62db94426b824483fb9e19e001e2f935` |
| 객체 저장소 | RustFS S3 호환 저장소 | `9cdf7f3f67aa29b3729fe894621996c35dacfba00287a54ff6f79c8eeccf476d` |

RustFS는 Apache 2.0 오픈소스다. 공식 호환성 문서에서 버킷과 객체의 생성, 조회, 삭제를 시험 범위로 명시한다. 이 프로젝트는 그 범위만 사용하며, MinIO Python SDK를 실제 연결해 첨부 저장과 조회를 확인했다.

## 검증 결과

- 백엔드 집중 검사 8개 통과
- Stage 0 계약 검사 12개 통과
- React 프로덕션 빌드 통과, 변환 모듈 15개
- 역할별 실제 HTTP 검사 9개 통과
- 첨부 파일이 `queued`에서 `available`로 전환
- 재고 20개에 동시 주문 25건 실행, 주문 성공 20건, 재고 부족 409 응답 5건, 최종 재고 0
- Python 의존성 `pip-audit 2.10.1` 결과 알려진 취약점 0건
- npm production 의존성 감사 결과 알려진 취약점 0건
- 최종 런타임 이미지 6개 Docker Scout 검사 결과 치명 0건, 높음 0건
- 최종 서비스 로그에서 Traceback, ERROR, CRITICAL, FATAL 0건

Docker Scout의 결과는 2026-08-30에 사용한 취약점 데이터베이스와 설치 패키지 식별 결과다. 미공개 취약점이나 애플리케이션 논리 결함의 부재까지 보장하지 않는다.

## 재현 명령

```powershell
docker compose up -d --build --wait
$env:PYTHONPATH='backend'
.venv\Scripts\python.exe -m pytest backend\tests -q
.venv\Scripts\python.exe tools\check_role_flows.py
.venv\Scripts\python.exe tools\check_running_stack.py
```

계약 검사는 상위 디렉터리에서 실행한다.

```powershell
app\.venv\Scripts\python.exe -m unittest discover -s tests -v
```
