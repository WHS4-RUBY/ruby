# tests — defense_proxy_v2 회귀·동작 테스트

프록시가 의도대로 동작하는지(그리고 고치다가 예전 동작을 깨지 않았는지) 확인하는 테스트다. 코드를 바꾼 뒤에는 이 폴더를 돌려라.

```bash
python tests/run_all.py            # 전부 (수 분 걸린다 — 지연 방어를 실제로 재는 테스트가 있다)
python tests/run_all.py ambig xff  # 이름에 'ambig' 또는 'xff' 가 들어간 것만
python tests/test_decoy_plan.py    # 하나만 직접
```

- 필요한 것은 `requirements.txt` 의 패키지(fastapi·uvicorn·httpx)뿐이다. 각 테스트는 스텁 백엔드(`stub_srv.py`)와 프록시를 **자기 프로세스로 띄우고**
  끝나면 내린다. 고정 포트를 쓰므로 **병렬로 돌리지 말 것**(`run_all.py` 는 순서대로 돌린다).
- 각 테스트는 독립 실행형 스크립트다: `PASS`/`FAIL` 줄을 출력하고, 하나라도 실패하면 종료코드 1.
- 지연을 재는 테스트(`test_delay_not_summed`, `test_range_and_postrce`, `test_decoy_plan`, `test_bundles_e2e`)는 기본 지연(요청당 0.5~1초가 흔한 PC)을
  뺀 **상대값**으로 비교한다. 그래도 PC 가 매우 느리거나 다른 작업으로 바쁘면 드물게 흔들릴 수 있으니, 실패하면 한 번 더 돌려 보고 같은 곳에서 계속 실패할 때만 고친다.

## 무엇을 확인하나

| 파일 | 확인하는 것 |
|---|---|
| `test_unit_maze_core.py` | 미로 단위 로직 — `synth_robots`(`Disallow: /` 안 만듦), HTML 주석 주입(charset 인지), 미로 패턴 생성 |
| `test_maze_safeguards.py` | 미로 안전장치 — 실제 경로 학습, SPA 폴백, 인증 요청, 403 처리, `X-Defense-Plan` maze, 서로 다른 경로 수로 세는 적응형 |
| `test_abort_and_head.py` | 지연 중 연결을 끊은 요청도 기록, HEAD 가 진짜 경로 학습을 오염시키지 않음 |
| `test_range_and_postrce.py` | `Range`/조건부 요청이 미로를 우회하지 못함, FAKE_SHELL 진입 후 지연이 에스컬레이션보다 약해지지 않음 |
| `test_delay_not_summed.py` | 에스컬레이션·미로·FAKE_SHELL·가짜 라우트 지연이 합산되지 않고 최댓값 하나만 걸림 |
| `test_ambig_routes.py` | AMBIG 차단 후 가짜 라우트도 403 |
| `test_traversal_probe.py` | `/icons/` 경로 탈출 시도 신호(응답은 안 바꿈) |
| `test_client_fallback.py` | `CLIENT_ID_FALLBACK=ip|global`, 헤더 우선 |
| `test_xff.py` | `X-Forwarded-For` 위조로 차단 우회(대조군 포함) — `UVICORN_PROXY_HEADERS=0` 이 막는지 |
| `test_preflight_maze.py`, `test_preflight_probe.py` | 시작 시 정합성 검사(미로 설정·실제 백엔드와의 충돌) |
| `test_migration_profile.py` | MIGRATION 서버별 값(`migration.*`) → 레시피·프로필 설정 도구·실제 프록시 |
| `test_decoy_plan.py` | 묶음 1(`decoy_maze`): 플랜이 있는 클라이언트에만 미로 + 적응형, sticky, 접촉은 켜진 뒤부터 |
| `test_recipe_per_client.py` | 클라이언트별 레시피(헤더·robots·병합·메모·로그인 미끼·`Server` 배너 일관성·충돌 규칙) |
| `test_bundles_e2e.py` | 묶음 3개(`decoy_maze`/`decoy_t21_shell`/`decoy_migration`)를 `X-Defense-Plan` 으로 호출 — 가짜 라우트·가짜 셸·격리·승급 |
| `test_dashboard_and_preset.py` | 대시보드 시작/중지·입력 검증, `nginx-fastapi` 프리셋 동작 |
| `test_golden.py` | 기본 설정의 동작 스냅샷(레시피·셸 출력·미로 응답·HTTP 응답)이 기준선과 같은가 |

## 골든 기준선(`golden_reference.json`)

`test_golden.py` 는 "지금 동작이 바뀌지 않았는가"를 보는 안전망이다. **동작을 의도적으로 바꿨을 때만** 기준선을 다시 만든다:

```bash
python tests/golden_snapshot.py tests/golden_reference.json
```

현재 기준선은 가짜 라우트를 훅으로 옮기고(클라이언트별 레시피) 이중 지연을 고친 뒤의 동작이다. 기본 설정(환경변수로 전역 레시피를 켜는 방식)의 응답은
그 이전 코드의 스냅샷과 바이트 단위로 같았다.

## 알려진 한계

- 테스트가 Windows 에서 개발·실행됐다. 경로·프로세스 종료는 `os.path`/`subprocess.terminate()` 로 쓰였지만 Linux/macOS 에서의 실행은 아직 확인하지 않았다.
- 에이전트(codex)를 쓰는 실험은 포함하지 않는다 — 여기는 프록시 동작만 본다.
- 정상 사용자 오탐·지연 비용은 측정하지 않는다.
