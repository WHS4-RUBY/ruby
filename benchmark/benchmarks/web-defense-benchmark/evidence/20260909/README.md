# 2026-09-09 완료 증거

이 디렉터리에는 KST 2026년 9월 9일에 끝난 공식 평가와 재검증의 공개 최소 결과만 둡니다.

| 파일 | 내용 | SHA-256 |
| --- | --- | --- |
| `qualification-sqli-codex-v10-official.json` | Codex v10 SQL 주입 무방어 시험 5회의 공식 실행 계획, 격리, 정상 흐름과 자격 미달 판정 | `ae92512a353ad70368a09dee07264ec65b837c99a9b4f7927cb6003cb5dbd45a` |
| `qualification-sqli-codex-v10-guided-v3-official.json` | 과업 지정 Codex v10 SQL 주입 무방어 자격 시험 5회의 5회 성공과 실행 무결성 | `8a517817c618312e1cc5208bbb29cf6cbc2c5220350c5619bd4a8bdc3e44a3d1` |
| `confirmatory-sqli-codex-v10-guided-v3-run-seal.json` | 99회 실행의 모델, 공격자, 범위, 예산, 이미지와 입력 해시 봉인 | `394143632ac89726021b566a7dcf8b3d7b69b3d32d9ddd02ad10290cab3a938d` |
| `confirmatory-sqli-codex-v10-guided-v3-schedule.json` | 조건 순서를 섞은 99개 사전 일정 | `41b80b47a9845c864cef897ee60d391108754eeb3cf79339589f4ebb8e42f4bc` |
| `confirmatory-sqli-codex-v10-guided-v3-campaign-summary.json` | 완료 99회, 미시작 0회와 최종 상태 합계 | `9f9683dd9d9ca36795afb68f99687a023de91cdc21de3548e5da52cfe8ae76bc` |
| `confirmatory-sqli-codex-v10-guided-v3-analysis.json` | 세 조건 각 33회의 성공률, 대응 효과, 신뢰구간과 검정 결과 | `9b282d3d47a6bf65ce7c2888950c689ae3530a04f0c7fa68c9f417b7ce8099a2` |
| `confirmatory-sqli-codex-v10-guided-v3-execution-integrity.json` | 99회 일정, 격리, 금지 도구, 정상 흐름과 자원 정리 검사 | `9c0a208d97d9d72f47e53943f9899e27c558221e4287600dc42f76e1643a3719` |
| `confirmatory-sqli-codex-v10-guided-v3-retry-audit.json` | 외부 서비스 필터로 무효가 된 한 시행과 동일 봉인 재시도의 연결 기록 | `462eca8c3a3c373d343220193265d6335043a89fffc91780a262d5a4106c9ff3` |
| `confirmatory-sqli-codex-v10-guided-v3-independent-review-inputs.json` | 구현 비참여자가 검토할 필수 입력과 SHA256 목록 | `9458d247dbcd8e0c2c9421cf48da83a18241197c69ad4cbdc80e65474cb38463` |
| `release-readiness.json` | 34개 대상 쌍, 격리, 방어 장착, 문서와 전체 회귀의 재검증 판정 | `6007631555dbc41662368c508351a80771425f61c56e0b7d57a6a66e896b44f5` |

원시 모델 대화, 인증 정보와 전체 상호작용 로그는 포함하지 않습니다. 과업 지정 결과는 `guided Codex gpt-5.6-sol medium, profile v10`, SQL 상품 검색 표적과 연결 계약 검증용 기준 모듈 조합에만 적용합니다. 실제 방어 제품이나 다른 취약점으로 확대하지 않으며 독립 검토자의 확인은 남아 있습니다.
