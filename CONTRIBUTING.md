# 기여 및 검토 규칙

## 기본 원칙

- `main` 브랜치에는 직접 push하지 않습니다.
- 작업마다 새 브랜치를 만들고 Pull Request로 제출합니다.
- 하나의 PR에는 가능한 한 하나의 컴포넌트 또는 하나의 목적만 담습니다.
- 관리자 또는 지정된 Code Owner가 검토한 뒤 병합합니다.

## 브랜치 이름

```text
benchmark/<project-name>
feature/<short-description>
experiment/<short-description>
docs/<topic>
fix/<short-description>
```

## 제출 전 확인

- [ ] 변경한 컴포넌트와 목적을 설명했다.
- [ ] 재현 가능한 실행 또는 검증 방법을 기록했다.
- [ ] 관련 테스트를 실행하고 결과를 기록했다.
- [ ] 다른 컴포넌트의 인터페이스에 미치는 영향을 확인했다.
- [ ] API 키, 토큰, `.env`, 실제 서버 정보와 개인정보를 포함하지 않았다.
- [ ] 외부 코드·데이터·모델의 출처와 라이선스를 표시했다.
- [ ] 대용량 바이너리나 원본 데이터셋을 불필요하게 추가하지 않았다.

## 저장소 규칙 (CI가 강제함)

아래 두 가지는 잊으면 CI가 실패합니다.

- **`shared/`가 편집 원본입니다.** 각 서비스 트리의 사본은 직접 고치지 않고
  `scripts/sync-shared.sh`로만 갱신합니다. 네 이미지의 빌드 컨텍스트가 모두 하위
  디렉터리라 Docker가 `COPY ../`를 금지하기 때문에 사본을 함께 커밋합니다.
  CI가 `scripts/sync-shared.sh --check`와 `defense/tests/test_shared_sources.py`로
  원본·사본 불일치를 막습니다.
- **오버레이 패키지 파일을 바꿨으면 같은 커밋에 매니페스트를 다시 넣습니다.**
  `defense/account-response-overlay/` 안의 파일(문서 포함)을 고친 뒤
  `cd defense/account-response-overlay && scripts/gen_manifest.sh`를 실행해
  `MANIFEST.sha256`을 갱신합니다. CI가 `scripts/gen_manifest.sh --check`로 검증하고,
  실패 시 고치는 명령을 출력합니다.

## PR 검토와 병합

- PR 작성자는 자신의 PR을 승인하지 않습니다.
- 새 커밋이 추가되면 변경된 내용을 다시 검토합니다.
- 리뷰 의견과 대화가 해결된 뒤 병합합니다.
- 기본 병합 방식은 `Squash and merge`를 사용합니다.
- 병합 후 작업 브랜치는 삭제합니다.

GitHub Ruleset이 적용되기 전까지도 위 절차를 팀 운영 규칙으로 준수합니다.
