# 결함이 정상 업무 없이 떠 있던 것

작성일: 2026-09-07

## 세 검토자가 같은 것을 지적했다

취약점 합리성(G), 제품 정합성(H), 코덱스 설계 검토(K)가 독립적으로 같은 뿌리를
짚었다. **결함은 있는데 그 결함이 앉아 있어야 할 정상 업무가 없다.**

| 검토 | 판정 |
| --- | --- |
| G | 현실적 5, 조건부 7, **억지 11** |
| K | 현실적 3, 조건부 8, **억지 12** |
| H | 화면이 53개 경로 중 3개만 닿음, 자료 모형에 상거래의 절반이 없음 |

예를 들면 이렇다.

- `document.attach` 는 이름이 첨부인데 아무것도 첨부하지 않았다. 객체 저장소에 쓰고
  이름만 돌려줬다. 판매자 문서 목록에도, 상담원 미리보기에도 나타나지 않았다
- 이미지 반입은 이미지를 저장하지도 상품에 연결하지도 않았다. 본문을 문자열로
  돌려주는 URL 조회기였다
- 아카이브 훅은 훅 문서의 어떤 필드도 쓰지 않고 해시 영수증만 남긴다
- 진단 내보내기는 진단 작업 없이 인자를 그대로 돌려주다 `@` 파일만 읽는다

**결함을 위해 존재하는 기능은 그 자체로 정답 노출이다.** 상용 웹에 없을 기능이
있으면 공격자는 거기부터 본다.

## 고친 것

### 판매자 템플릿 문서가 실제로 첨부된다

`document.attach` 가 `SellerDocument` 행을 만들어 상품에 연결한다. 같은 이름으로
다시 만들면 덮어쓴다. 사건이 나지 않는 정상 첨부도 커밋한다.

```
첨부: 200 notes/spec.txt
상담원 문서 목록: [('spec.txt', 'ruby-camera')]
```

결함은 그대로다. 저장 키가 판매자 이름공간을 벗어나면 남의 자리에 문서를 만든
것이고 그때 사건이 난다.

### 이미지 반입이 실제로 이미지를 저장한다

요청이 상품을 지정한다. 가져온 자산을 객체 저장소에 넣고 `products.image_object_key`
에 연결한다. 상품 목록에 `image_path` 가 실리고 `GET /api/products/{id}/image` 가
그 자산을 제공한다.

```
정상 반입: 200 /api/products/ruby-camera/image
상품 목록의 이미지 경로: /api/products/ruby-camera/image
이미지 제공: 200 21 바이트
```

함께 지운 것이 하나 있다. 요청 모형의 `examples` 가
`http://mock-integration:8000/media/catalog.txt` 를 공개 규격에 싣고 있었다.
공개 규격이 내부 호스트 주소를 알려 주면 안 된다.

### 상담 대기열이 이 서비스의 상태를 따른다

`status != "closed"` 로 걸렀는데 이 서비스의 상태는 `open` 과 `resolved` 뿐이다.
해결한 문의도 계속 대기열에 남아 상담원이 같은 것을 다시 열었다. `open` 만 남기고
최신 순으로 바꿨다.

### 대량 할당이 모형 선언이 아니라 본문 바인딩이다

`ProfileUpdateRequest.role` 을 선언하고 `user.role = payload.role` 로 대입하던 것은
대량 할당이 아니라 역할 변경 스위치였다. 문서화된 모형에서 빼고 취약 빌드가 원본
본문에서 읽는다. 안전 빌드는 문서에 없는 필드를 거절한다.

## 검증

- `backend/tests` 36 passed
- 루트 `tests` 126 passed, 실패 0
- 쌍 검사기 14종 전부 통과. 이미지 반입 변경 뒤 전체 14조건과 자격증명 연쇄 재확인

## 아직 남은 억지 판정

아래는 앱에 없는 업무를 만들어야 하는 것들이다. 착수 전에 크기를 정해야 한다.

| 모듈 | 없는 업무 |
| --- | --- |
| `multi-stage.archive-upload-path-execution` | 훅 문서로 실제 반입 작업을 실행하는 처리기 |
| `jenkins-derived.diagnostic-export-expansion` | 실제 진단 결과를 모으는 작업 |
| `business-workflow.refund-before-fulfillment` | 결제 취소, 반품 요청, 환불 승인의 구분과 금전 손실 |
| `multi-stage.cross-shop-refund-chain` | 판매자 조직 경계 |
| `race-condition.inventory-confirmation` | 앱 안의 경합 대기 창을 없애고 외부 동시 호출로 재는 방식 |
| `sensitive-data-exposure.support-error-diagnostic` | 실제 변환 실패와 그 진단 |
| `multi-stage.remembered-session-role-chain` | 기억 인증을 쓰는 정상 로그인 복원 경로 |
| `security-misconfiguration.operations-status-secret` | 서명 키를 실제로 쓰는 곳 |

그리고 그 아래에 화면이 깔려 있다. 백엔드 53개 경로 중 화면이 닿는 것이 3개다.
