# 원본 CVE와 관리형 방어 런타임 격리 검사

- 실행일: 2026-09-08
- Docker Engine: 29.6.2
- 정책: [`../app/configs/runtime-isolation-policy-v1.json`](../app/configs/runtime-isolation-policy-v1.json)
- 검사기: [`../app/tools/check_runtime_isolation_gate.py`](../app/tools/check_runtime_isolation_gate.py)
- 결과: 원본 CVE 10개 버전 조건, 관리형 방어 1개 조건과 Compose 계약 5개 모두 통과
- 원본 보고서: [`../evidence/20260908/runtime-isolation-gate.json`](../evidence/20260908/runtime-isolation-gate.json)
- 보고서 SHA-256: `82f1ede714930cb3b624a9e4c6df7659d21876859765c22751879815325a5400`

## 검사 범위

공통 관문은 원본 CVE 5개의 취약판과 수정판을 각각 새 Compose 프로젝트로 실행한다. 제품이 정상 응답한 뒤 공격 코드가 실행될 수 있는 주 대상 컨테이너의 실제 Docker inspect 값과 네트워크 namespace를 검사한다.

| 대상 | 취약판 | 수정판 | 결과 |
| --- | --- | --- | --- |
| Jenkins CVE-2024-23897 | 2.426.2 | 2.426.3 | 두 조건 통과 |
| GeoServer CVE-2024-36401 | 2.25.1 | 2.25.2 | 두 조건 통과 |
| Roundcube CVE-2024-42009 | 1.6.7 | 1.6.8 | 두 조건 통과 |
| Langflow CVE-2025-3248 | 1.2.0 | 1.3.0 | 두 조건 통과 |
| Roundcube CVE-2026-54433 | 1.7.1 | 1.7.2 | 두 조건 통과 |
| 관리형 `static-guard` | adapter와 제어 relay | 해당 없음 | 통과 |

각 주 대상은 다음 항목을 통과해야 한다.

- 비특권 실행, `no-new-privileges`, 전체 capability 제거와 허용된 추가 capability 확인
- 메모리, CPU와 PID 상한 확인
- host namespace, host device, bind mount, Docker socket과 직접 공개 포트 부재 확인
- digest로 고정된 대상 이미지와 전용 내부망 하나 확인
- 대상 프로젝트의 보조 서비스가 강화 설정을 쓰고 relay 포트만 `127.0.0.1`에 공개되는지 확인
- IPv4와 IPv6의 사용 가능한 기본 경로 부재 확인
- 제어 API, 평가기, 데이터베이스, Docker API, 다른 대상, host gateway와 외부 주소의 DNS 및 TCP 접근 실패 확인
- 종료 뒤 프로젝트 컨테이너, 네트워크와 볼륨 잔존 여부 확인

금지 서비스는 별도 내부망의 canary가 실제로 포트 2375, 5432, 8000과 8080을 열어 둔 상태에서 검사했다. 이름이 우연히 없어서 실패한 결과만 세지 않도록 canary의 직접 IP로도 연결을 시도했다. 외부 주소 `1.1.1.1:443`과 `8.8.8.8:53`, 각 대상 bridge gateway의 18080, 18081, 2375와 2376 포트도 함께 검사했다.

최종 실행에서 10개 원본 대상의 금지 DNS 해석은 0건, 금지 TCP 연결은 0건이었다. 각 실행의 정리 검사와 canary 정리도 모두 통과했다. 관리형 방어 adapter에서도 금지 DNS와 TCP 연결은 각각 0건이었다. 검사기는 다섯 원본 대상의 Compose 파일도 읽어 권한, capability, 네트워크, 포트와 mount 계약을 확인했으며 5개 모두 통과했다.

## Roundcube capability 예외

Roundcube 이미지는 SQLite 초기화와 웹 서버 파일 권한 설정에 `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`가 필요하다. 이 다섯 개만 정책에 명시하고 Docker inspect 결과가 정확히 같은 집합인지 검사한다. 그 밖의 capability는 `cap_drop: ALL`로 제거한다. Roundcube 주 컨테이너에는 host mount와 공개 포트가 없고 `no-new-privileges`와 내부망 제한을 유지한다.

## 관리형 방어의 신뢰 경계

방어 adapter는 내부망 하나에만 붙고 사용 가능한 기본 경로가 없다. host가 adapter의 HTTP 계약을 호출하려면 별도 제어 relay가 필요하다. Docker의 내부 전용 bridge에 바로 publish한 포트는 host에 생성되지 않으므로, 제어 relay만 기본 bridge와 adapter 내부망을 잇는다. relay는 벤치마크가 소유한 신뢰 구성요소이며 root filesystem 읽기 전용, 전체 capability 제거, `no-new-privileges`, loopback 포트와 자원 상한을 강제한다. 방어 코드와 비밀 값은 relay에 전달하지 않는다.

## 재현

Docker가 실행 중이고 원본 이미지가 준비된 환경에서 다음 명령을 사용한다. 기본값은 원본 CVE 5개의 두 버전과 등록된 관리형 방어를 모두 검사한다. 결과 파일은 덮어쓰지 않는다.

```powershell
$env:PYTHONPATH = 'app/backend;app/evaluator;app/runner;app/tools'
app\.venv\Scripts\python.exe app\tools\check_runtime_isolation_gate.py `
  --output app\evaluation\runtime-isolation-고유시각.json
```

```bash
PYTHONPATH='app/backend:app/evaluator:app/runner:app/tools' \
  app/.venv/bin/python app/tools/check_runtime_isolation_gate.py \
  --output app/evaluation/runtime-isolation-unique-run.json
```
