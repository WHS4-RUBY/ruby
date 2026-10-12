# Benchmarks

프로젝트별 벤치마크 문서를 저장합니다. 지금 들어 있는 4건의 목록과 결과 요약은
[`benchmark/README.md`](../README.md#들어-있는-것) 의 "들어 있는 것" 표에 있습니다.

새 작업을 시작할 때 [`../templates/benchmark-report.md`](../templates/benchmark-report.md)와
[`../templates/environment-record.md`](../templates/environment-record.md)를 프로젝트 폴더로
복사해 사용하세요.

```text
benchmarks/<project-name>/
├── README.md
├── environment.md
└── results.md
```

원본 소스 전체를 이 저장소에 복사하기보다는 원본 URL과 검증한 commit 또는 tag를 기록하는 방식을 권장합니다.
각 파일에 무엇을 적는지는 [`benchmark/README.md`](../README.md#환경-기록과-결과-비교-규칙) 의
"환경 기록과 결과 비교 규칙" 절을 따릅니다.
