# 보관 문서

프로젝트 종료 시점(`d54fe61`, 2026-10-12)에 **현재 상태를 설명하지 않게 된 문서**를 모아 둔
곳입니다. 지우지 않는 이유는 "왜 지금 구조가 이렇게 됐는지" 의 근거라서입니다.

**여기 있는 문서를 현재 동작의 근거로 쓰지 마세요.** 각 파일 맨 위에 보관 시점과 지금의 정본이
어디인지 적어 두었습니다. 본문에 나오는 파일 경로·테스트 수·"현재"·"다음 단계"는 모두 보관
이전 시점 기준이며, 보관하면서 본문을 고치지 않았습니다.

| 문서 | 무엇이었나 | 지금의 정본 |
| --- | --- | --- |
| [`refactor-inventory.md`](refactor-inventory.md) | `#47`~`#52` 리팩토링의 Phase 0/1 조사 보고서(`e8e0ab8` 기준) | [`../refactor-summary.md`](../refactor-summary.md) |
| [`path-alias-plan.md`](path-alias-plan.md) | 경로 별칭 v3 연구 설계. 계획한 30분 A/B 는 미실행 | [`../../defense/docs/path-alias-operations.md`](../../defense/docs/path-alias-operations.md) |
| [`path-alias-pr-review-ko.md`](path-alias-pr-review-ko.md) | 경로 별칭 v4 PR(`#47`) 검증 메모 | 같은 운영 가이드 + [`../refactor-summary.md`](../refactor-summary.md) 9절 |
| [`path-alias-slides.html`](path-alias-slides.html) | 경로 별칭 발표 슬라이드. 저장소에서 참조하는 곳이 없었다 | — |
| [`token-gate-history.md`](token-gate-history.md) | 토큰 단독 차단 게이트의 v2.1 설계서 + 로컬 Docker 검증 기록(두 파일을 합침) | [`../../defense/README.md`](../../defense/README.md) "토큰 관찰과 CRS 차단" |
| [`ruby-defense-grader-roadmap.md`](ruby-defense-grader-roadmap.md) | 그레이더 M0~M4 로드맵. M1 이후 미실행 | [`.../TEST_VALIDATION_STATUS.md`](../../benchmark/benchmarks/ruby-defense-grader/docs/TEST_VALIDATION_STATUS.md) |
| [`ruby-defense-grader-presentation-script.md`](ruby-defense-grader-presentation-script.md) | 그레이더 발표 대본(1회용) | [`.../METRIC_SPEC.md`](../../benchmark/benchmarks/ruby-defense-grader/docs/METRIC_SPEC.md) |
| [`ruby-defense-grader-pre-push-checklist.md`](ruby-defense-grader-pre-push-checklist.md) | 그레이더 개인 push 전 점검 루틴. CI 는 이 서브프로젝트를 실행하지 않는다 | — |

각 문서를 왜 보관했는지는 파일 머리의 보관 블록에 적어 두었습니다. 정리 작업 당시의 전수 조사
기록은 저장소 루트의 작업 문서 `documentation-cleanup-plan.md` ·
`documentation-cleanup-report.md` 에 있습니다(커밋 대상이 아닌 로컬 작업 문서입니다).
