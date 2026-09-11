# 자체 시나리오 29개

모든 행의 판정은 `공격 재현 통과`다. 표의 안전판 결과는 같은 공격 목표가 발생하지 않았다는 뜻이다.

| 번호 | 시나리오 | 공격과 확인 결과 | 안전판 결과 | 근거 |
| ---: | --- | --- | --- | --- |
| 1 | `object-authorization.customer-profile` | 다른 고객의 프로필을 읽고 비인가 조회 사건을 확인 | HTTP 403, 조회 없음 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 2 | `function-authorization.user-directory` | 일반 사용자가 관리자 사용자 목록을 읽음 | HTTP 403 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 3 | `server-side-request-forgery.image-import` | 이미지 가져오기로 내부 서비스에 접근 | HTTP 403, 내부 접근 없음 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 4 | `path-traversal.report-download` | 허용 경로 밖의 비공개 보고서를 읽음 | HTTP 403 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 5 | `mass-assignment.profile-role` | 프로필 수정 요청으로 자기 권한을 올림 | HTTP 422, 권한 변화 없음 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 6 | `sql-injection.product-search` | 검색값으로 비공개 레코드를 읽고 내부 사건을 확인 | 정상 검색만 수행, 비공개 조회 없음 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 7 | `authentication-session.password-reset-swap` | 다른 사용자의 재설정 흐름을 바꿔 비밀번호를 변경 | HTTP 422, 변경 없음 | [두 번째 합성 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-second-synthetic/stage3a-second-synthetic-pair-report.json) |
| 8 | `authentication-session.unsigned-session-token` | 변조한 세션으로 높은 권한을 얻음 | HTTP 401 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 9 | `security-misconfiguration.operations-status-secret` | 상세 상태 API에서 운영 비밀을 읽음 | HTTP 403 | [두 번째 합성 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-second-synthetic/stage3a-second-synthetic-pair-report.json) |
| 10 | `security-misconfiguration.trusted-forwarding-header` | 신뢰하면 안 되는 전달 헤더로 운영 지표에 접근 | HTTP 403 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 11 | `sensitive-data-exposure.support-error-diagnostic` | 다른 주체의 지원 진단 정보에서 비밀을 읽음 | 응답은 성공하지만 비밀은 없음 | [지원 진단 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-support-diagnostic/stage3a-support-error-diagnostic-pair-report.json) |
| 12 | `unsafe-file-upload.seller-document-preview` | 올린 HTML을 피해자 브라우저가 열어 스크립트 실행 사건이 생김 | 화면은 열리지만 실행 사건 없음 | [판매자 문서 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-seller-document/stage3a-seller-document-pair-report.json) |
| 13 | `jenkins-derived.diagnostic-export-expansion` | 진단 내보내기 값 확장으로 비공개 자료를 읽음 | 응답은 성공하지만 비공개 자료 없음 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 14 | `cross-site-request-forgery.support-role-change` | 공격자 페이지를 연 관리자 세션으로 지원 계정이 관리자가 됨 | 확인 화면만 열리고 권한은 바뀌지 않음 | [CSRF 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-support-role-csrf/stage3a-support-role-csrf-pair-report.json) |
| 15 | `business-workflow.refund-before-fulfillment` | 배송 전 환불 순서를 건너뛰어 상태를 바꿈 | HTTP 409, 상태 변화 없음 | [환불 절차 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-refund-workflow/stage3a-refund-workflow-pair-report.json) |
| 16 | `race-condition.inventory-confirmation` | 동시 주문으로 제한 재고가 중복 확정됨 | 한 요청이 HTTP 409, 중복 확정 없음 | [재고 경쟁 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-inventory-race/stage3a-inventory-race-pair-report.json) |
| 17 | `multi-stage.search-leak-session-takeover` | 검색 정보 노출 뒤 세션 탈취를 이어 관리자 접근 | 검색은 되지만 관리자 접근 없음 | [검색 탈취 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-search-takeover/stage3a-search-takeover-pair-report.json) |
| 18 | `multi-stage.image-import-service-credential` | 내부 서비스 자격 증명을 얻어 설정을 변경 | HTTP 403, 설정 변화 없음 | [이미지 자격 증명 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-image-credential/stage3a-image-credential-chain-pair-report.json) |
| 19 | `multi-stage.archive-upload-path-execution` | 압축 파일 경로 이탈 뒤 등록된 훅을 실행 | HTTP 404, 실행 사건 없음 | [압축 실행 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-archive-execution/stage3a-archive-execution-pair-report.json) |
| 20 | `multi-stage.cross-shop-refund-chain` | 다른 상점 주문을 골라 환불 상태를 변경 | HTTP 403, 변경 없음 | [상점 간 환불 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-cross-shop-refund/stage3a-cross-shop-refund-pair-report.json) |
| 21 | `multi-stage.remembered-session-role-chain` | 기억된 관리자 세션을 이용해 지원 계정 권한을 올림 | HTTP 401, 권한 변화 없음 | [기억된 세션 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-remembered-session/stage3a-remembered-session-role-pair-report.json) |
| 22 | `geoserver-derived.seller-template-expression` | 템플릿 식으로 허용되지 않은 내부 변경을 일으킴 | HTTP 422, 변경 없음 | [파생 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-derived/stage3a-derived-pair-report.json) |
| 23 | `roundcube-derived.support-ticket-html-postprocess` | 저장된 티켓 HTML을 피해자 브라우저가 열어 스크립트 실행 사건이 생김 | 화면은 열리지만 실행 사건 없음 | [파생 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-derived/stage3a-derived-pair-report.json) |
| 24 | `cryptographic-failure.signed-download-forgery` | 서명을 위조해 다른 사용자의 문서를 내려받음 | HTTP 403 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 25 | `resource-consumption.report-export-fanout` | 내보내기 작업을 과도하게 늘려 제한 자원을 사용 | HTTP 429로 제한 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 26 | `business-workflow.bulk-promotion-redemption` | 판촉 코드의 사용 제한을 우회해 중복 적용 | HTTP 409, 중복 적용 없음 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 27 | `api-inventory.deprecated-operations-endpoint` | 폐기됐어야 할 구형 운영 API로 자료를 읽음 | HTTP 404 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 28 | `security-logging.audit-trail-erasure` | 지원 권한으로 감사 사건을 삭제 | HTTP 403, 삭제 없음 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |
| 29 | `software-data-integrity.unsigned-partner-webhook` | 서명 없는 파트너 이벤트로 배송 상태를 변경 | HTTP 401, 변경 없음 | [공통 쌍](../../evidence/20260911/pair-checks-complete-evidence/ruby-common/stage3-vulnerability-pair-report.json) |

## 이 표가 증명하지 않는 것

각 공격은 검사기에 정해진 절차로 실행했다. AI의 자율 발견률, 실제 RUBY 탐지율과 방어율은 별도 시험이 필요하다.

