# 압축 파일 경로 이탈과 통제된 실행 쌍 검증

확인일은 2026-08-30 KST다.

## 흐름

1. 판매자 계정이 ZIP 파일을 업로드한다.
2. 정상 ZIP 파일은 secure와 vulnerable에서 모두 지정된 가져오기 디렉터리에 풀린다.
3. 공격 ZIP 파일은 `../runtime/catalog-hook.json` 경로를 사용한다.
4. secure는 가져오기 디렉터리를 벗어나는 항목을 422로 거부한다.
5. vulnerable은 웹 애플리케이션의 통제된 파일 루트 안에서 경로 이탈을 허용한다.
6. 별도 활성화 요청이 정확히 허용한 합성 훅만 읽고 고정된 실행 마커를 만든다. 운영체제 명령이나 외부 프로그램은 실행하지 않는다.
7. 비공개 평가기는 실행 마커와 내부 사건을 함께 확인한다.

## 결과

| 조건 | 정상 ZIP | 공격 ZIP | 활성화 | 마커 | 비공개 사건 |
| --- | ---: | ---: | ---: | --- | ---: |
| secure | 201 | 422 | 404 | 없음 | 0 |
| vulnerable | 201 | 201 | 200 | 생성 | 1 |

실행 종료 뒤 마커와 업로드 작업 디렉터리가 제거됐고 API는 secure 프로필로 복구됐다.

최종 보고서는 `app/evaluation/stage3a-archive-execution-pair-20260830-162307/stage3a-archive-execution-pair-report.json`이며 SHA256은 `4e41948b1994cccf0ac8f77c907c9562bf521c055fadfee436bf6561aaafc692`다.

첫 실제 실행은 컨테이너 비루트 사용자가 작업 디렉터리에 쓸 수 없어 실패했다. 실패 보고서는 `app/evaluation/stage3a-archive-execution-pair-20260830-162150/stage3a-archive-execution-pair-report.json`에 보존했다. Docker 이미지에서 해당 작업 디렉터리만 애플리케이션 사용자 소유로 고친 뒤 새 실행 ID로 통과했다.
