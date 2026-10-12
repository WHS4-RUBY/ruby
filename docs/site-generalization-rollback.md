# 사이트 일반화 되돌리기

기준: `251ef4f`(#48) → `5355b4d`. 커밋 25개.

이 리팩토링은 Detection 의 비즈니스 로직 탐지 7개 모듈과 `deceptionEngine`, 그리고
Defense 의 `site_adapter` 분기를 **설정 선언**으로 옮긴 것이다. 되돌리는 방법이 세 층
있고, 아래로 갈수록 범위가 넓다.

---

## 1. 되돌리지 않고 끄기 (가장 빠름)

프로파일이 "무엇이 켜질지" 를 선언하므로, **프로파일을 고치는 것만으로** 개별 탐지를
끌 수 있다. 재배포도 코드 변경도 필요 없다 — 컨테이너만 다시 올리면 된다.

```bash
# 예: ruby-shop 대상에서 역할 게이트 판정만 끈다
#   detection/config/site-profiles/ruby-shop.json 에서 roleGated 블록을 지우고
#   _needsConfirmation 에 "roleGated" 를 더한다. 둘 다 해야 로드가 통과한다.
```

끈 사실은 조용히 묻히지 않는다 — 기동 로그, `GET /__detection/api/site-profile-status`,
관리 화면의 "실험 대상" 섹션이 모두 비활성을 보고한다. 끌 수 있는 기능 경로 18개 목록은
`defense/README.md` 의 "새 사이트 추가 > Detection 프로파일" 표에 있다.

**대상 전체를 Juice Shop 규칙으로 평가하려면** 환경변수 하나로 된다:

```bash
DETECTION_DEFAULT_SITE_PROFILE=juice-shop   # 프로파일 파일이 없는 모든 대상에 적용
```

반대로 프로파일 디렉터리 자체를 갈아끼우려면 `SITE_PROFILES_DIR` 를 쓴다.
모르는 프로파일 ID 를 주면 **기동이 실패한다**(조용히 무시하지 않는다).

---

## 2. 동작 변경 커밋만 되돌리기

커밋 25개 중 **동작이 바뀐 것은 다섯 개**다. 나머지는 선언 이동과 테스트 추가이므로
Juice Shop 결과가 동일하다. 하나씩 독립적으로 revert 할 수 있다.

```bash
git revert 5fe98ba   # 깨진 인증 쿠키의 500 수정
git revert e213522   # 가격 기준 캐시의 대상별 분리
git revert 4f75619   # 미끼 문서 링크가 프로파일 네임스페이스를 따름
git revert a045e4d   # 미로 배너 폴백을 프리셋에서 가져옴 (+ CHeaT 계약 테스트)
# 0c7ef4f 는 site_adapter 제거와 함께 engagement.family(ctx=None) 동작도 바꾼다 — 3번 참조
```

| 커밋 | 무엇이 바뀌었나 | 되돌리면 |
| --- | --- | --- |
| `5fe98ba` | `Cookie: token=%` 가 Express 500 을 내던 것을 고쳤다 | 외부에서 트리거 가능한 500 이 돌아온다 |
| `e213522` | 가격 캐시 키가 `<대상 ID>\|<productId>` 가 됐다 | 대상 전환 시 다른 사이트 가격을 기준값으로 쓰는 오염이 돌아온다. juice-shop 단독 트래픽은 어느 쪽이든 같다 |
| `4f75619` | 미끼 "Documents" 링크가 `profile.decoy_namespaces` 를 따른다 | 네임스페이스를 옮긴 사이트에서 링크가 미끼 밖(`/ftp`)을 가리킨다. 출하된 세 프로파일은 어느 쪽이든 같다 |
| `a045e4d` | `MAZE_VERSION` 폴백이 프리셋 배너가 됐다 | `SPOOF_SERVER=`(위조 끄기)일 때 미로가 다시 Apache 를 주장한다. apache-php 프리셋은 어느 쪽이든 같다 |
| `0c7ef4f` | `engagement.family(path, ctx=None)` 이 `None` 을 돌려준다 | ctx 없는 호출이 Juice Shop 로그인 루트를 가정하는 숨은 기본값이 돌아온다. 실제 호출부 네 곳은 모두 ctx 를 넘기므로 운영에는 영향이 없다 |

**ruby-shop 대상의 미끼 동작도 바뀌었다** — 이전에는 ruby-shop 에도 Angular 방언 위장
JS 가 나가고 423 미끼가 영구히 발동하지 않았다. 되돌리려면 코드가 아니라 프로파일을
고친다: `detection/config/site-profiles/ruby-shop.json` 의 `deception.frontendFlavor` 를
`angular-httpclient` 로, `deception.loginPath` 를 지우고 `_needsConfirmation` 에 더한다.

---

## 3. 모듈 단위로 되돌리기

모듈마다 **특성화 커밋 + 리팩토링 커밋 두 개**로 나뉘어 있다. 리팩토링만 되돌리면 그
모듈이 다시 모듈 상수를 읽고, 특성화 테스트는 남아 그 동작을 계속 고정한다.

| 모듈 | 특성화 | 리팩토링 |
| --- | --- | --- |
| `loginBruteForce` | `ee476e6` | `6578d69` |
| `passwordResetAbuse` | `d88a8a9` | `a90c0d5` |
| `priceTampering` | `4ad8f38` | `8d69259` |
| `priceIntegrity` | `2685254` | `17cc110` |
| `businessLogicSignatures` | `25be3fc` | `056cf91` |
| `identityMismatch` | `b59a901` | `3d0d3f5` |
| `roleGatedAccess` | `ee34a65` | `f055a31` |
| `deceptionEngine` | `ad15cbb` | `5e7993a` |
| 오버레이 `site_adapter` | `af75db2` | `0c7ef4f` |

**순서 제약 둘:**

1. `identityMismatch`(`3d0d3f5`)와 `roleGatedAccess`(`f055a31`)는 묶여 있다 —
   `roleGatedAccess` 가 `decodeClaimedIdentity`/`extractToken` 을 재export 해 쓰므로
   `f055a31` → `3d0d3f5` 순서로(역순) 되돌려야 한다.
2. 리팩토링 커밋을 되돌리면 해당 특성화 테스트가 프로파일 주입 헬퍼 때문에 깨진다.
   특성화도 함께 되돌리거나, 헬퍼만 손으로 떼야 한다.

인프라 커밋(`56b7f77`, `86395e6`)은 **마지막에** 되돌린다. 모듈이 하나라도 프로파일을
읽는 상태에서 로더를 없애면 기동이 실패한다.

---

## 4. 전체 되돌리기

가장 안전한 방법은 리팩토링 이전 이미지 태그로 재배포하는 것이다. `deploy.yml` 이 SHA
태그로 배포하므로 `251ef4f` 이전 태그를 쓰면 된다.

**데이터 마이그레이션은 없다.** 이 리팩토링은 저장소 스키마를 바꾸지 않았다 — 설정
선언만 옮겼으므로 볼륨을 그대로 두고 이미지만 되돌리면 된다(#47/#48 의 저장소 통합과
다른 점이다).

**새 환경변수 둘은 미설정이 기본이므로 되돌릴 필요가 없다:**
`DETECTION_DEFAULT_SITE_PROFILE`(비우면 `generic`), `SITE_PROFILES_DIR`(비우면 이미지 안
`detection/config/site-profiles`).

---

## 되돌린 뒤 확인

```bash
# 측정은 Docker 전용 — 명령은 docs/archive/refactor-inventory.md 의 "측정 방식" 절
docker build -t ruby-detection:check ./detection
docker run --rm ruby-detection:check npm test
docker run --rm -v "$PWD:/src" -w /src ruby-defense:check \
  python -m unittest discover -s defense/tests -p 'test_*.py'
scripts/sync-shared.sh --check
(cd defense/account-response-overlay && scripts/gen_manifest.sh --check)
```

되돌리기 기준 수치(`5355b4d` 시점): Detection `npm test` 413 + CRS 바이너리 12,
Defense `unittest` 270, CHeaT `run_all.py` 18/20(기존 불안정 2건), Overlay `pytest` 92 + 6,
Defense Node 12 + 6, `MANIFEST.sha256` 73/73.

오버레이 패키지 파일을 되돌리면 `scripts/gen_manifest.sh` 로 `MANIFEST.sha256` 을 같은
커밋에 넣어야 한다. 잊으면 CI 가 막고 고치는 명령을 출력한다.
