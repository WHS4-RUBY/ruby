# 평가 요구사항과 계약 추적표

이 표는 문서 요구사항이 설명에만 남지 않도록 기계 계약 또는 수동 검토 절차와 연결한다.

| 요구사항 | 계약과 검사 | 판정 방식 |
| --- | --- | --- |
| 공격자 공개 정보와 평가기 비밀 분리 | `public-brief`, `scenario`, `verifier`, `comparison-bundle` | 서로 다른 파일과 해시로 연결, 공격자 마운트 금지 |
| 공개 CVE와 블랙박스 조건 구분 | `public-brief.knowledge_condition`, `scenario.vulnerabilities.source_type` | `hidden-black-box`, `public-one-day`, `guided`와 출처를 독립 검사 |
| 다중 컨테이너 대상 봉인 | `deployment` | 구성요소 이미지, 설정, 네트워크, 볼륨, 초기 상태와 자원 제한 검사 |
| secure twin 비교 | `scenario`, `deployment`, `qualification-report`, `comparison-bundle` | 다른 배포 해시, 같은 구성요소와 공개 서비스, 기준 공격 실패 기록 |
| 실제 내부 사건으로 성공 판정 | `verifier`, `trial-result` | predicate, 주체, 객체, 사건 조건과 원장 해시 기록 |
| 미끼 성공과 실제 성공 분리 | `decoy-registry`, `verifier`, `trial-result` | 미끼 대상은 등록 ID만 허용, 실제 목표는 verifier만 판정 |
| 연결 유형과 기능 일치 | `defense-capability`, `attachment-lifecycle`, semantic validator | 관찰 전용 연결의 차단 주장과 잘못된 executor 거부 |
| 방어 모델 실제 ID 감사 | `defense-capability.model_use`, `trial-result.observed_model_ids` | 요청 ID, 관측 ID와 증거 해시 분리 기록 |
| 무방어와 방어 조건 동일성 | `experiment`, `comparison-bundle` | 공격자, 예산, 정상 트래픽, 대상, 격리와 측정값 비교 |
| 방어 오류와 예산 종료 분리 | `trial-result.status` | `invalid-defense-error`, `budget-exhausted`, 일반 실패 별도 기록 |
| 정상 사용자 오탐 | `experiment.normal_traffic`, `trial-result.metrics` | 동일 게이트웨이 일정과 정상 업무 완료 및 오탐 기록 |
| Automation Score와 Attack Score 독립 평가 | `telemetry-event` | 두 점수, 특징 증거 해시와 상호작용 ID를 같은 원장에 기록 |
| 12개 계열과 24개 시나리오 분포 | `portfolio`, portfolio validator | 단계 수, CVE, 브라우저, 다중 역할과 편중 상한 검사 |
| 반복 수와 기준선 자격 | `experiment.execution`, `qualification-report` | 검정력 해시, 최소 5회와 성공률 60% 기준을 결과와 분리 |
| 실제 파일 무결성 | `comparison-bundle`, `portfolio` | 상대 경로 제한과 파일 SHA256 재계산 |

기계적으로 판정할 수 없는 라이선스 해석, 논문과 원 구현의 의미적 동일성, 의도하지 않은 취약점 검토는 담당자가 근거 문서를 작성해야 한다. 해당 결과의 digest가 없는 상태에서는 `qualified`, `native` 또는 논문 직접 비교를 선언하지 않는다.
