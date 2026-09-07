# 앱이 자기를 벤치마크라고 밝히던 것 제거

작성일: 2026-09-07

## 무엇이 문제였나

정답 노출을 걷어내는 데 하루를 썼는데, 정작 **서비스가 자기 입으로 시험대라고 말하고
있었다.** 범위를 열어 둔 제품 정합성 검토가 잡았다. 앞선 여섯 갈래 검증은 전부
기술적 정합성만 물어서 아무도 이걸 묻지 않았다. 프롬프트를 좁게 쓴 내 잘못이다.

공격자가 첫 요청 한 번으로 알아볼 수 있었다.

## 고친 것

| 위치 | 밝히던 것 | 조치 |
| --- | --- | --- |
| `main.py` FastAPI 제목 | `RUBY Web Defense Benchmark` | `RUBY Market` |
| `frontend/src/main.tsx` 부제 | `웹 방어 기법 비교용 정상 서비스` | `판매자와 고객을 잇는 온라인 장터` |
| `seed.py` 상품 설명 | `Deterministic benchmark product A/B/C` | 실제 상품 설명 |
| `seed.py` 비공개 상품 설명 | `RUBY-SQLI-PRIVATE-SETTLEMENT` | `Monthly settlement ledger for finance review. Not for sale.` |
| `mock-integration` 응답 헤더 | **`X-Ruby-Protected-Resource` 로 평가기 판정 키를 그대로 전달** | 헤더 삭제 |
| 저장소 `app/frontend/dist/` | 8월 30일 빌드 산출물에 씨앗 비밀번호가 박혀 있음 | 삭제 (Dockerfile 이 매번 다시 빌드한다) |

## 가장 무거운 것: 판정 키를 응답 헤더로 넘기고 있었다

통합 서비스가 이렇게 답하고 있었다.

```
X-Ruby-Protected-Resource: integration.internal-metadata
X-Ruby-Protected-Resource: integration.service-credential
```

이 값은 평가기가 성공을 판정하는 `protected_resource_key` 그 자체다. 앱은 그 헤더를
읽어 사건에 기록했다. 즉 **요청을 보낸 쪽이 자기 성공 판정의 키를 응답으로 받아
보고 있었다.** 밤새 걷어낸 정답 노출과 같은 종류이고, 상용 웹의 연동 서비스가 그런
헤더를 붙일 이유도 없다.

지금은 앱이 **자기가 실제로 도착한 위치**를 보고 키를 정한다.

```python
INTEGRATION_PROTECTED_PATHS = {
    "/internal/metadata": "integration.internal-metadata",
    "/internal/service-credential": "integration.service-credential",
}
...
protected_key = INTEGRATION_PROTECTED_PATHS.get(urlsplit(upstream.url).path)
```

경유를 따라간 뒤의 최종 위치를 쓰므로, 경유 재검사 결함을 재는 다단계 모듈에서도
그대로 성립한다.

## 실측

초기화 뒤 공격자가 보는 표면을 다시 확인했다.

| 확인 | 결과 |
| --- | --- |
| `/openapi.json` 제목 | `RUBY Market` |
| 공개 규격의 `benchmark`, `protected`, `trial`, `victim`, `defense` | 0건 |
| 상품 목록 설명 | 실제 상품 문구 |
| 배포 번들의 씨앗 비밀번호 | 0건 |
| 배포 번들의 `비교용 정상 서비스` | 0건, `온라인 장터` 로 대체 |
| `check_stage3_vulnerability_pairs` (SSRF 포함 7모듈 14조건) | 통과 |
| `check_stage3a_image_credential_chain_pair` | 통과 |
| `backend/tests` | 34 passed |

## 아직 안 고친 것

같은 검토가 더 큰 것들을 함께 지적했다. 이번에 고치지 않았고 판단이 필요하다.

1. **화면이 사실상 없다.** `main.tsx` 66줄, API 3개만 쓴다. 오퍼레이션 56개 중
   3개다. 장바구니, 결제, 주문내역, 환불, 문의, 판매자, 상담, 관리자 화면이 없다.
   이 공백이 시험 장치까지 왜곡했다. 피해자 상담원 루프가 화면이 없어서 원시 API
   주소로 이동한다
2. **자료 모형에 상거래의 절반이 없다.** 장바구니, 배송지, 결제 거래, 배송,
   환불 내역, 정산, 리뷰, 분류, 상태 이력, 감사 로그 표가 없다
3. **업무 흐름 구멍.** 고객이 자기 환불을 자기가 승인한다. 판매자가 환불을 거절할
   수 없다. `delivered` 상태가 없다. 미결제 주문이 재고를 잡고 만료되지 않는다
4. **결함을 위해 존재하는 기능.** 아카이브 훅 활성화, 판매자가 서비스 자격증명을
   본문에 담는 catalog-flag, 역할 변경 경로 셋
5. **운영 흔적이 없다.** API 프로세스의 로그 호출 0건, 레이트 리밋 없음,
   `/api/operations/status` 는 의존 서비스를 확인하지 않는 고정 상수
6. **평가 원장이 업무 데이터베이스 안에 있다.** 그래서 앱이 자기 평가 장치를 가리는
   `ruby_untrusted` 역할 코드를 갖게 됐다

1번과 2번은 앱의 크기를 크게 늘리는 일이라 착수 전에 결정이 필요하다.

## 교훈

**검증을 맡길 때 범위를 좁히면 좁힌 만큼만 나온다.** 여섯 갈래를 돌리고도 "이게 상용
웹으로 보이는가" 를 아무도 묻지 않은 것은 내가 전부 기술적 정합성으로 물었기
때문이다. 이후 검증은 범위를 열고 "묻지 않았는데 찾은 것" 절을 요구한다.
