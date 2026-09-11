# RUBY benchmark management UI

공격 대상 웹과 분리된 로컬 통제면이다. 등록된 취약점만 전환하고 기존 캠페인 실행기를
시작하며 결과 JSON과 로그를 표시한다. 임의 명령과 임의 경로는 받지 않는다.

```powershell
python -m pip install -r requirements-dev.txt
python -m pip install -r app/manager/requirements.txt
Set-Location app/manager
python -m uvicorn ruby_manager.main:app --host 127.0.0.1 --port 18083 --no-access-log
```

기본 대상 스택 이름과 이미지 접두사는 관리 UI가 실행되는 작업 사본의 절대 경로 SHA-256
앞 12자리에서 자동 생성한다. 기본 대상 포트는 18080, 통제 포트는 18081이다. 새 스택을
시작할 때 두 포트가 이미 사용 중이면 빌드 전에 전환을 거부한다. 별도 작업 사본에서 동시에
검증할 때는 포트도 서로 다르게 지정한다. 관리 UI가 모듈을 전환할 때 현재 소스를 직접
빌드하므로 별도의 `docker compose build`를 먼저 실행하지 않는다.

```powershell
$env:RUBY_MANAGER_COMPOSE_PROJECT = "ruby-manager-review"
$env:RUBY_PUBLIC_PORT = "28080"
$env:RUBY_CONTROL_PORT = "28081"
python -m uvicorn ruby_manager.main:app --host 127.0.0.1 --port 28083 --no-access-log
```

별도 프로젝트를 지정하면 이미지 이름, 컨테이너, 네트워크와 볼륨도 그 프로젝트 이름을
사용한다. 같은 이름에 컨테이너 없이 네트워크나 볼륨만 남아 있으면 관리 UI는 재사용하지
않고 정리를 요구한다. 화면의 `대상 웹 열기` 링크는 `RUBY_PUBLIC_PORT` 값을 따른다. 같은
작업 사본에서 관리 UI 두 개를 동시에 실행하는 경우와 전환 도중 프로세스 강제 종료 후 복구는
검증하지 않았다.

기동할 때 출력되는 세션 토큰 URL을 브라우저에서 연다. 화면은 토큰을 브라우저 메모리로 읽은
직후 주소의 fragment를 제거하고 관리 API 요청 헤더로 전송한다. 새로고침하면 토큰이 없어지므로
출력된 URL을 다시 열어야 한다. 정적 화면은 읽을 수 있지만 토큰 없이는 관리 데이터 조회와
조작이 불가능하다. Docker와 모델 실행 권한이 있는 통제면이므로
외부 주소로 바인딩하거나 공개 프록시에 연결하지 않는다. 관리 UI에서 시작한 실행은
`app/evaluation/manager-*`에 저장된다. 고정 토큰이 필요하면 충분히 긴 임의 값을
`RUBY_MANAGER_TOKEN` 환경변수로 전달한다.

실제 Docker 환경에서 확인한 전환, 접근 제한, 자원 정리 결과와 남은 한계는
[2026-09-12 관리 UI 격리 검증](../../docs/manager-isolation-verification-20260912/README.md)에 있다.
독립 검토 뒤 다시 실행한 추적 검사 결과는
[관리 UI 상태 재검증 근거](../../evidence/20260912/manager-live-state-refresh/README.md)에 있다.
