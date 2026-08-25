# 벤치마크: APIEcho

## 대상

- 논문 또는 프로젝트: APIEcho
- 원본 URL: <https://github.com/finall1008/apiecho>
- 논문: IEEE S&P 2026에 게재 예정인 APIEcho
- 논문 URL: 공식 저장소 README 기준 논문 링크 미공개
- 검증 커밋: `cb0990f4823a6ba6d927e3fe4a22ef9b00325b28`
- 라이선스: 공식 저장소에 별도 라이선스 파일이 없어 재배포 조건 확인 필요
- 확인 날짜: 2026년 8월 16일

## 검증 목표

공식 APIEcho 구현을 Docker 기반 FastAPI 애플리케이션에 연결해 다음 과정을 재현한다.

1. Sysdig로 대상 컨테이너의 시스템 이벤트를 수집한다.
2. `PythonAsyncioRequestPartitionHandler`가 이벤트를 HTTP 요청 단위로 분할하는지 확인한다.
3. 반복된 정상 요청이 동일한 API 범주로 분류되는지 확인한다.
4. 동일 API에 정상 요청과 다른 시스템 행위를 발생시키는 요청을 보낸다.
5. 공식 `DistanceDetector`가 이상 요청을 탐지하고 정상 요청은 정상으로 분류하는지 확인한다.

APIEcho 알고리즘은 재구현하지 않았으며 공식 구현의 partition, categorization, feature extraction, vectorization 및 `DistanceDetector`를 그대로 사용했다. 환경 호환성과 실행 중 확인된 upstream 오류만 `patches/`의 패치로 수정했다.

## 준비

```bash
git clone https://github.com/finall1008/apiecho.git upstream/apiecho
git -C upstream/apiecho checkout cb0990f4823a6ba6d927e3fe4a22ef9b00325b28

# patches/의 패치를 번호 순서대로 적용
for patch in patches/*.patch; do
  git -C upstream/apiecho apply "../../${patch}"
done

./scripts/setup.sh
./scripts/start-target.sh
```

필요한 도구는 Python 3.12, Poetry, Docker Engine, Docker Compose 및 Sysdig다. Native Ubuntu에서 host Sysdig를 사용할 때는 `sudo` 권한이 필요하다.

## 실행

```bash
./scripts/run-experiment.sh
```

자동 실행 스크립트는 정상 트래픽 50건과 이상 트래픽 1건을 생성하고, 이벤트 수집부터 결과 집계까지 수행한다. 정상 트래픽은 다음 두 endpoint에 각각 25회씩 순차 전송한다.

```text
GET /api/users/1
GET /api/products/1
```

이상 트래픽은 `GET /api/users/1?experiment=anomaly` 요청이다. Query string은 API 범주에서 제외되므로 정상 사용자 요청과 같은 `GET /api/users/1` 범주에서 비교된다. 이상 요청은 컨테이너 내부에서만 임시 파일 접근, `/etc/passwd` 읽기, 짧은 subprocess 실행 및 loopback 연결 시도를 추가로 수행한다.

## 결과

- 결과 상태: 성공
- 대상 FastAPI 컨테이너 실행 및 health check 성공
- 대상 container ID가 포함된 Sysdig 이벤트 수집 성공
- 요청 delimiter를 이용한 HTTP 요청 단위 partition 성공
- `GET /api/users/1`, `GET /api/products/1` 범주 처리 성공
- 탐지 임계값 `2.0`에서 이상 요청 점수 `2.92403829`, 판정 `True`
- 정상 요청 최대 점수 `0.15389676`, 정상 요청 오탐 `0건`
- 전체 처리 unit `52개`, 이상 unit `1개`, 탐지된 이상 unit `1개`

점수는 upstream `DistanceDetector._detect_calc()`와 동일하게 저장된 9차원 vector의 L2 norm으로 계산했다. 상세 결과와 해석은 [`results.md`](results.md)에 기록했다.

공식 구현의 핵심 파이프라인과 이상 탐지 동작은 재현했다. 다만 논문 원문의 전체 데이터셋, 평가 지표 및 실험 환경이 공개되지 않아 논문의 정량 결과와 직접 비교하지는 못했다.

## 오류와 제한사항

- WSL2 커널에는 Sysdig kernel module용 matching header가 없어 Docker Desktop Linux context에서 privileged `sysdig/sysdig:latest` modern eBPF helper를 사용했다.
- `CategorizerByApi`의 required field 선언과 실제 참조 필드가 달라 `fd.cip`를 `fd.rip`로 수정했다.
- Live run 중단 시 결과가 finalize되지 않는 경로를 수정했다.
- 평가 가능한 unit이 없을 때 division-by-zero가 발생하는 경로를 수정했다.
- Asyncio partitioner가 하나의 `current_unit_id`만 유지하므로 기준 실험은 단일 Uvicorn worker와 순차 요청으로 제한했다.
- 원본 Sysdig capture와 상세 로그는 용량 및 환경 정보 노출 가능성 때문에 이 저장소에 포함하지 않았다.
- Live Sysdig 로그에는 데이터셋용 `malicious` ground truth가 없어 upstream dump의 `Ground Truth`는 모두 `False`다. 실제 ground truth는 트래픽 manifest와 anomaly query로 관리했고, `Label`을 APIEcho의 예측값으로 사용했다.

## 다음 단계

- 여러 anomaly 유형을 반복 실행해 score 분포를 측정한다.
- 정상 요청 분포를 기반으로 threshold를 조정한다.
- 서로 다른 path ID 10개 이상으로 API template merge를 검증한다.
- 동시 asyncio 요청에서 partitioner의 한계를 측정한다.
- Native Ubuntu 공통 서버에서 host Sysdig만 사용하는 원래 topology로 재검증한다.
