# site_analysis 감사 수정 보고

작성일: 2026-10-09. 수정과 파일 작성은 `defense/web-proxy-defense/site_analysis/` 안에서만 했다. 원본 웹 접속, 브라우저 실행과 실제 모델 호출은 하지 않았다. commit, push, stash도 하지 않았으며 다른 세션의 파일을 수정하지 않았다.

요청한 감사 결과 `audit-analysis-2.md`, 계획 `01-분석.md`와 기존 `ANALYSIS-REPORT.md`를 모두 읽고 반영했다. `anti-slop-code` 스킬을 적용했다. 아래 감사 위치는 감사 당시 줄 번호이고 현재 위치는 수정 후 줄 번호다.

## 적용한 결과와 남은 제한

요청별 모델 심사, URL 원문 등장 검사, 첫 거부의 탐색 종료, 묶음 전체의 형식 오류 폐기와 전체 가림 보류를 제거했다. 이동의 의미와 두 실행의 의미 일치 및 합친 답은 모델이 판단한다. 코드는 메서드 및 폼 제출과 외부 정찰 경계, 예산과 같은 실패 반복 상한, 전달 키와 숫자 계산을 담당한다.

기본값은 화면 60, 요청 시도 3000, 실행별 1800초다. 시도와 전송 수를 따로 남긴다. 표본과 모델 입력 창은 기본 600000자로 설정하며 토큰 수 추정이 아닌 기계적 문자 창이다. 본문과 소스의 뒤쪽 및 원바이트를 메모리에서 더 읽는 도구를 제공한다. 모든 분석과 교정 및 가림과 합치기 호출은 같은 달러 상한을 사용한다. 가림을 마친 칸과 숫자 계측을 단계별로 저장한다.

남긴 제한은 다음과 같다.

- POST 읽기 API와 로그인 제출도 보내지 않는다. 이번 사용자의 GET/HEAD 제한과 폼 제출 금지가 감사의 예외 허용 제안보다 우선한다. 요청 대상과 존재 및 차단 이유는 모델에게 알린다.
- 서비스워커 차단을 남긴다. 현재 요청 가로채기를 우회할 수 있으므로 GET/HEAD 경계를 보장하려면 필요하다. 서비스워커에 의존하는 웹은 관찰을 못 얻을 수 있다.
- WebSocket 송신은 모두 보류한다. 서버가 보내는 프레임을 받을 수 있지만 클라이언트 구독 메시지가 필요한 피드는 못 얻는다.
- HTTP 대체의 자동 리다이렉트 중단은 남긴다. 받은 헤더로 모델이 다음 화면을 고른다. 화면과 SPA 클릭은 HTTP 대체에서 못 얻는다.
- 쿠키 표준 파서는 HTTP 대체와 응답 헤더 메타데이터용으로 남겼다. 오류는 그 헤더만 격리하고 브라우저가 제공한 쿠키 이름과 속성을 별도로 읽는다. 쿠키 값은 복사하지 않는다.
- 공급자 사용량이 없는 호출은 금액을 확인할 수 없으므로 추가 호출을 멈춘다. Codex CLI 한 호출의 실제 금액이 남은 상한보다 커질 수 있으며 초과는 사용량 수신 뒤 발견한다. 원본에서 비용을 실측하지 않았다.
- 파일 저장 의존성 또는 잘못된 초기 설정은 전체 오류가 될 수 있다. 원시 진단에 값이 섞일 수 있어 터미널에는 코드 또는 오류 종류만 출력한다. 항목의 상세는 메모리에서 모델에게 돌려준다.

## 바꾼 파일과 현재 행

| 파일 | 현재 행과 변경 |
| --- | --- |
| `catalog.py` | 33, 42, 60, 74, 87: 추가 키와 확신 범위 강제 제거, 칸별 검증과 못 얻음 서술, 가림과 합치기 및 새 관찰 도구 형식 |
| `model.py` | 21, 41, 64, 73, 94, 114, 138: 정확한 자격 치환, 단가와 비용 상한, 부분 응답 및 형식 교정, 반복 실패, 모델 입력 창 |
| `record.py` | 27, 34, 41, 45, 66, 74, 84, 92: 실패 상세의 메모리 격리, 명시 출력 경로, 같은 실패 장부, 비유한 수 격리, 모델 의미 판단의 묶음 정책 적용 |
| `observer.py` | 18, 40, 86, 118, 130, 140, 155, 210, 235, 254, 292, 325, 367, 402, 446, 497, 548: 폼과 메서드 경계, 예산, 표본 재읽기, 항목 실패 격리, 요청 심사 제거, 쿠키 저장소, 수신 전용 WebSocket, 새 창과 실제 이동 URL, HTTP와 내려받기 |
| `prompts.py` | 4, 30 이후: 화면 선택 때 상태 변경 위험 판단, 요청 심사 지시 삭제, 칸별 가림과 의미 비교, 원답과 근거의 모델 판단 |
| `analyze.py` | 20, 41, 80, 95, 133, 204, 240, 302, 365, 392, 427, 462: CLI, 축별 교정과 가림, 실행 예외 격리, 단계별 저장, 의미 합치기와 오프라인 확인 |
| `SCHEMA.md` | 1 이후: 현재 동작의 규격 1.1로 갱신 |
| `ANALYSIS-REPORT.md` | 1: 최초 보고의 현재성 안내 추가, 본문은 이력 보존 |
| `FIX-REPORT.md` | 1 이후: 이번 처리와 확인 결과 |

`axes.json`, `AXES.md`, `__init__.py`는 변경하지 않았다. 별도 테스트 파일을 만들지 않았다. `py_compile`이 만드는 캐시는 패키지 내부의 `__pycache__/`다.

## 감사 189개 항목의 처리

| 감사 번호 | 감사 당시 위치 | 처리 | 이유와 현재 처리 | 현재 근거 |
| --- | --- | --- | --- | --- |
| 1 | site_analysis/catalog.py:5,44 | 남김 | 축 정본과 전달 형식의 필수 키 확인이다. 웹의 의미를 판별하지 않는다. 모델 출력 오류는 축별 교정으로 격리한다. | catalog.py:8,28,60 |
| 2 | site_analysis/catalog.py:9-10,12 | 남김 | 축 정본과 전달 형식의 필수 키 확인이다. 웹의 의미를 판별하지 않는다. 모델 출력 오류는 축별 교정으로 격리한다. | catalog.py:8,28,60 |
| 3 | site_analysis/catalog.py:13-14 | 남김 | 축 정본과 전달 형식의 필수 키 확인이다. 웹의 의미를 판별하지 않는다. 모델 출력 오류는 축별 교정으로 격리한다. | catalog.py:8,28,60 |
| 4 | site_analysis/catalog.py:15-16 | 남김 | 축 정본과 전달 형식의 필수 키 확인이다. 웹의 의미를 판별하지 않는다. 모델 출력 오류는 축별 교정으로 격리한다. | catalog.py:8,28,60 |
| 5 | site_analysis/catalog.py:17-24 | 남김 | 축 정본과 전달 형식의 필수 키 확인이다. 웹의 의미를 판별하지 않는다. 모델 출력 오류는 축별 교정으로 격리한다. | catalog.py:8,28,60 |
| 6 | site_analysis/catalog.py:28-30 | 남김 | 축 정본과 전달 형식의 필수 키 확인이다. 웹의 의미를 판별하지 않는다. 모델 출력 오류는 축별 교정으로 격리한다. | catalog.py:8,28,60 |
| 7 | site_analysis/catalog.py:33-35 | 고침 | 추가 키 거부와 공급자 strict 스키마를 제거했다. 필수 키만 읽고 추가 설명은 개별 가림 후 보존한다. | catalog.py:33,74; model.py:138 |
| 8 | site_analysis/catalog.py:42-45,50-53 | 고침 | 요청 심사 스키마와 로그인 도구를 없앴다. 칸별 가림, 표본 읽기와 새 창 선택 형식을 추가했다. | catalog.py:42; observer.py:325 |
| 9 | site_analysis/catalog.py:46,74-75 | 고침 | 확신의 0에서 1 범위를 제거했다. 모델의 척도와 추가 설명을 보존하며 JSON으로 기록할 수 있는지만 확인한다. | catalog.py:74 |
| 10 | site_analysis/catalog.py:47-49 | 고침 | 요청 심사 스키마와 로그인 도구를 없앴다. 칸별 가림, 표본 읽기와 새 창 선택 형식을 추가했다. | catalog.py:42; observer.py:325 |
| 11 | site_analysis/catalog.py:56-58,62-65 | 고침 | 묶음 전체 폐기를 없앴다. 정상 축을 보존하고 누락 또는 형식 오류 축만 이유와 원답을 모델에게 돌려 교정한다. | catalog.py:60,74; analyze.py:204 |
| 12 | site_analysis/catalog.py:67-69 | 고침 | 추가 키 거부와 공급자 strict 스키마를 제거했다. 필수 키만 읽고 추가 설명은 개별 가림 후 보존한다. | catalog.py:33,74; model.py:138 |
| 13 | site_analysis/catalog.py:68-69 | 고침 | 묶음 전체 폐기를 없앴다. 정상 축을 보존하고 누락 또는 형식 오류 축만 이유와 원답을 모델에게 돌려 교정한다. | catalog.py:60,74; analyze.py:204 |
| 14 | site_analysis/catalog.py:70-71 | 고침 | 묶음 전체 폐기를 없앴다. 정상 축을 보존하고 누락 또는 형식 오류 축만 이유와 원답을 모델에게 돌려 교정한다. | catalog.py:60,74; analyze.py:204 |
| 15 | site_analysis/catalog.py:72-73 | 고침 | 묶음 전체 폐기를 없앴다. 정상 축을 보존하고 누락 또는 형식 오류 축만 이유와 원답을 모델에게 돌려 교정한다. | catalog.py:60,74; analyze.py:204 |
| 16 | site_analysis/catalog.py:79-80 | 고침 | 계획의 못 봄 상태를 유지하면서 서술에 못 얻음과 이유를 쓴다. 얻지 못한 확신은 null이다. | catalog.py:87 |
| 17 | site_analysis/catalog.py:83-90 | 남김 | 축 정본에서 만든 문서와 기계적 Markdown 출력이다. 축 내용과 이름은 이번 지시가 승인한 구조를 유지한다. | catalog.py:91; AXES.md:1 |
| 18 | site_analysis/__init__.py:1 | 남김 | 패키지 설명뿐이며 기능을 제한하는 코드가 없다. | __init__.py:1 |
| 19 | site_analysis/model.py:20-31 | 고침 | 운영자가 제공한 자격의 정확 치환을 유지하고 객체 키에도 적용했다. 공개 교정본도 같은 값을 치환한다. | model.py:21; analyze.py:133 |
| 20 | site_analysis/model.py:35,43-46 | 고침 | 기본 호출별 180초와 실행 수 1/2 한정을 없앴다. 공유 시간 예산을 쓰며 운영자가 호출 시간과 양의 실행 수를 지정할 수 있다. | model.py:114; analyze.py:20,41 |
| 21 | site_analysis/model.py:54-56 | 남김 | Codex 실행 의존성 확인과 자체 도구 차단은 원본 쓰기 및 외부 정찰 경계다. 실제 모델 호출은 하지 않았다. | model.py:138 |
| 22 | site_analysis/model.py:61-66 | 남김 | Codex 실행 의존성 확인과 자체 도구 차단은 원본 쓰기 및 외부 정찰 경계다. 실제 모델 호출은 하지 않았다. | model.py:138 |
| 23 | site_analysis/model.py:69-75 | 고침 | 설명이나 코드 블록 속 JSON, 사용 가능한 부분 답을 보존한다. 형식 실패는 원시 응답과 이유를 메모리에서 교정 입력으로 돌린다. 공급자 실패 표식과 사용량, 비용은 별도로 기록한다. 사용량 미확인은 비용 경계에서 멈춘다. | model.py:73,114,138 |
| 24 | site_analysis/model.py:76-85 | 고침 | 설명이나 코드 블록 속 JSON, 사용 가능한 부분 답을 보존한다. 형식 실패는 원시 응답과 이유를 메모리에서 교정 입력으로 돌린다. 공급자 실패 표식과 사용량, 비용은 별도로 기록한다. 사용량 미확인은 비용 경계에서 멈춘다. | model.py:73,114,138 |
| 25 | site_analysis/model.py:86-98 | 고침 | 설명이나 코드 블록 속 JSON, 사용 가능한 부분 답을 보존한다. 형식 실패는 원시 응답과 이유를 메모리에서 교정 입력으로 돌린다. 공급자 실패 표식과 사용량, 비용은 별도로 기록한다. 사용량 미확인은 비용 경계에서 멈춘다. | model.py:73,114,138 |
| 26 | site_analysis/model.py:99-104 | 고침 | 설명이나 코드 블록 속 JSON, 사용 가능한 부분 답을 보존한다. 형식 실패는 원시 응답과 이유를 메모리에서 교정 입력으로 돌린다. 공급자 실패 표식과 사용량, 비용은 별도로 기록한다. 사용량 미확인은 비용 경계에서 멈춘다. | model.py:73,114,138 |
| 27 | site_analysis/model.py:106-114 | 고침 | 설명이나 코드 블록 속 JSON, 사용 가능한 부분 답을 보존한다. 형식 실패는 원시 응답과 이유를 메모리에서 교정 입력으로 돌린다. 공급자 실패 표식과 사용량, 비용은 별도로 기록한다. 사용량 미확인은 비용 경계에서 멈춘다. | model.py:73,114,138 |
| 28 | site_analysis/model.py:115-117 | 고침 | 설명이나 코드 블록 속 JSON, 사용 가능한 부분 답을 보존한다. 형식 실패는 원시 응답과 이유를 메모리에서 교정 입력으로 돌린다. 공급자 실패 표식과 사용량, 비용은 별도로 기록한다. 사용량 미확인은 비용 경계에서 멈춘다. | model.py:73,114,138 |
| 29 | site_analysis/model.py:76,81,84,119 | 남김 | 프로토콜 오류 수와 경과 시간의 숫자 계산 및 표시 정밀도다. | model.py:138 |
| 30 | site_analysis/prompts.py:4-26 | 고침 | GET 상태 변경 위험은 이동 선택 때 모델이 판단한다. URL의 원문 등장 요구와 로그인 예외를 없애고 사람 확인 후보를 거절한 뒤 대안을 고르게 했다. | prompts.py:4,39; observer.py:325 |
| 31 | site_analysis/prompts.py:29-32 | 남김 | 정본의 질문과 호출 묶음을 옮기는 구조다. 별도 웹 종류 분기가 없다. | prompts.py:30 |
| 32 | site_analysis/prompts.py:35-47 | 고침 | GET 상태 변경 위험은 이동 선택 때 모델이 판단한다. URL의 원문 등장 요구와 로그인 예외를 없애고 사람 확인 후보를 거절한 뒤 대안을 고르게 했다. | prompts.py:4,39; observer.py:325 |
| 33 | site_analysis/prompts.py:49-55 | 고침 | 요청별 모델 심사와 최근 두 표본 제한을 삭제했다. GET/HEAD 의존 요청은 그대로 보내며 POST 대상과 존재 및 차단 이유를 다음 모델 입력에 담는다. 메서드와 예산 및 외부 화면 경계만 코드로 지킨다. | observer.py:118,210; prompts.py:39 |
| 34 | site_analysis/prompts.py:57-64 | 고침 | 전체 안전 여부 하나로 모든 축을 비우는 경로를 없앴다. 칸별 교정본과 안전 여부를 받으며 실패한 가림 응답을 나누어 해당 칸만 비운다. 이미 공개한 칸은 보존한다. | analyze.py:133,240 |
| 35 | site_analysis/record.py:9-11 | 남김 | 저장소 기준 기본 비공개 작업 경로 계산이다. 명시 출력 경로를 이 위치로 강제하지 않는다. | record.py:9,41 |
| 36 | site_analysis/record.py:26-37 | 고침 | 항목별 못 얻음 처리를 유지하고 실제 오류 상세를 모델 입력의 메모리에 남긴다. 상세는 영구 기록과 터미널에 출력하지 않는다. | record.py:27,34,66; observer.py:176,191 |
| 37 | site_analysis/record.py:40-44 | 고침 | 저장소 .tmp 밖이라는 이유의 거부를 없앴다. --out의 명시 경로를 사용하며 비공개 위치 요구를 규격에 적었다. | record.py:41; SCHEMA.md:1 |
| 38 | site_analysis/record.py:47-52 | 고침 | 원자적 저장과 JSON 규격을 유지한다. 비유한 숫자는 그 칸만 못 얻음으로 바꾸어 다른 기록의 저장을 막지 않는다. | record.py:74,84 |
| 39 | site_analysis/record.py:58-62,76 | 고침 | 정확한 문자열 비교를 삭제했다. 두 실행의 의미 일치와 합친 답은 모델이 정한다. 받는 모델은 원답, 근거와 비교 및 합친 답을 함께 판단한다. 합친 답만 사용하라는 고정 문구를 없앴다. | record.py:92; analyze.py:302,462 |
| 40 | site_analysis/record.py:63-67 | 고침 | 묶음 이름의 union, consensus, retain 정책을 적용한다. 제거와 멈춤의 한 번 발견을 보존하고 의미 일치한 메움만 선택한다. 일치 수와 빠진 축 및 못 봄 수를 계산하며 원답도 남긴다. | record.py:92,125; analyze.py:462 |
| 41 | site_analysis/record.py:68-70 | 고침 | 정확한 문자열 비교를 삭제했다. 두 실행의 의미 일치와 합친 답은 모델이 정한다. 받는 모델은 원답, 근거와 비교 및 합친 답을 함께 판단한다. 합친 답만 사용하라는 고정 문구를 없앴다. | record.py:92; analyze.py:302,462 |
| 42 | site_analysis/record.py:71-79 | 고침 | 묶음 이름의 union, consensus, retain 정책을 적용한다. 제거와 멈춤의 한 번 발견을 보존하고 의미 일치한 메움만 선택한다. 일치 수와 빠진 축 및 못 봄 수를 계산하며 원답도 남긴다. | record.py:92,125; analyze.py:462 |
| 43 | site_analysis/record.py:82-89 | 고침 | 묶음 이름의 union, consensus, retain 정책을 적용한다. 제거와 멈춤의 한 번 발견을 보존하고 의미 일치한 메움만 선택한다. 일치 수와 빠진 축 및 못 봄 수를 계산하며 원답도 남긴다. | record.py:92,125; analyze.py:462 |
| 44 | site_analysis/observer.py:16-18,93-96 | 고침 | 쿠키 및 인증 값의 직접 비기록은 유지한다. 인증 도전 헤더 전체를 미리 지우지 않고 모델이 기술 형태를 해석하고 칸별로 가리게 했다. | observer.py:15,81; analyze.py:95,133 |
| 45 | site_analysis/observer.py:21-43 | 고침 | 로그인 제출 예외와 모든 읽기를 잠시 막는 폼 탐침을 삭제했다. 폼 메타데이터만 읽고 모든 네이티브 제출은 막는다. 이름 없는 필드도 보존한다. 실제 제출과 POST 로그인은 이번 사용자 금지선을 따른다. | observer.py:18,320,325 |
| 46 | site_analysis/observer.py:46-48 | 남김 | 원본과 외부 최상위 화면의 프로토콜, 호스트와 포트 경계 대조다. 이동 인자 오류는 모델에게 돌려주고 대안을 고른다. | observer.py:34,325 |
| 47 | site_analysis/observer.py:53-59 | 고침 | 기본 요청 3000, 화면 60, 초 1800으로 올리고 JSON 및 개별 CLI 인자로 바꾸게 했다. 표본과 맥락 창도 인자로 설정한다. | observer.py:40; analyze.py:20,41 |
| 48 | site_analysis/observer.py:64-90 | 고침 | 요청 시도 수와 전송 수를 분리했다. 숫자 상한과 소진 차원 비교는 유지한다. | observer.py:40,210 |
| 49 | site_analysis/observer.py:102-103,108-109 | 고침 | 쿠키 파서 실패는 그 헤더만 못 얻음으로 격리한다. 브라우저 쿠키 저장소의 이름과 속성도 값 없이 별도로 얻는다. HTTP 대체에는 네이티브 저장소가 없으므로 표준 파서와 칸별 실패를 남긴다. | observer.py:86,235,254 |
| 50 | site_analysis/observer.py:104-107 | 고침 | 쿠키 파서 실패는 그 헤더만 못 얻음으로 격리한다. 브라우저 쿠키 저장소의 이름과 속성도 값 없이 별도로 얻는다. HTTP 대체에는 네이티브 저장소가 없으므로 표준 파서와 칸별 실패를 남긴다. | observer.py:86,235,254 |
| 51 | site_analysis/observer.py:116-132,136-138 | 고침 | 관찰 권한은 실제 동작인 익명으로 기록한다. 자격 값의 비어 있음 의미 제한을 없앴고 자격 읽기 실패는 공개 관찰과 분리한다. HTTP와 브라우저 모두 폼 로그인 예외를 제공하지 않는다. | analyze.py:80,240,462; observer.py:118 |
| 52 | site_analysis/observer.py:148-159 | 고침 | 항목별 못 얻음 처리를 유지하고 실제 오류 상세를 모델 입력의 메모리에 남긴다. 상세는 영구 기록과 터미널에 출력하지 않는다. | record.py:27,34,66; observer.py:176,191 |
| 53 | site_analysis/observer.py:162-163 | 고침 | 요청별 모델 심사와 최근 두 표본 제한을 삭제했다. GET/HEAD 의존 요청은 그대로 보내며 POST 대상과 존재 및 차단 이유를 다음 모델 입력에 담는다. 메서드와 예산 및 외부 화면 경계만 코드로 지킨다. | observer.py:118,210; prompts.py:39 |
| 54 | site_analysis/observer.py:165-169 | 고침 | 요청별 모델 심사와 최근 두 표본 제한을 삭제했다. GET/HEAD 의존 요청은 그대로 보내며 POST 대상과 존재 및 차단 이유를 다음 모델 입력에 담는다. 메서드와 예산 및 외부 화면 경계만 코드로 지킨다. | observer.py:118,210; prompts.py:39 |
| 55 | site_analysis/observer.py:171-174 | 고침 | 요청별 모델 심사와 최근 두 표본 제한을 삭제했다. GET/HEAD 의존 요청은 그대로 보내며 POST 대상과 존재 및 차단 이유를 다음 모델 입력에 담는다. 메서드와 예산 및 외부 화면 경계만 코드로 지킨다. | observer.py:118,210; prompts.py:39 |
| 56 | site_analysis/observer.py:175-178,182-185 | 고침 | 요청별 모델 심사와 최근 두 표본 제한을 삭제했다. GET/HEAD 의존 요청은 그대로 보내며 POST 대상과 존재 및 차단 이유를 다음 모델 입력에 담는다. 메서드와 예산 및 외부 화면 경계만 코드로 지킨다. | observer.py:118,210; prompts.py:39 |
| 57 | site_analysis/observer.py:195-199 | 고침 | 로그인 제출 예외와 모든 읽기를 잠시 막는 폼 탐침을 삭제했다. 폼 메타데이터만 읽고 모든 네이티브 제출은 막는다. 이름 없는 필드도 보존한다. 실제 제출과 POST 로그인은 이번 사용자 금지선을 따른다. | observer.py:18,320,325 |
| 58 | site_analysis/observer.py:200-203 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 59 | site_analysis/observer.py:204-209 | 고침 | 로그인 제출 예외와 모든 읽기를 잠시 막는 폼 탐침을 삭제했다. 폼 메타데이터만 읽고 모든 네이티브 제출은 막는다. 이름 없는 필드도 보존한다. 실제 제출과 POST 로그인은 이번 사용자 금지선을 따른다. | observer.py:18,320,325 |
| 60 | site_analysis/observer.py:210-213 | 남김 | GET/HEAD 외 전송 금지는 이번 사용자 지시가 감사 제안보다 우선한다. POST 읽기 API를 보내는 예외는 만들지 않으며 요청 대상, 존재와 못 얻은 응답을 모델에게 알린다. | observer.py:210,446; prompts.py:4 |
| 61 | site_analysis/observer.py:214-217 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 62 | site_analysis/observer.py:218-222 | 고침 | 요청별 모델 심사와 최근 두 표본 제한을 삭제했다. GET/HEAD 의존 요청은 그대로 보내며 POST 대상과 존재 및 차단 이유를 다음 모델 입력에 담는다. 메서드와 예산 및 외부 화면 경계만 코드로 지킨다. | observer.py:118,210; prompts.py:39 |
| 63 | site_analysis/observer.py:224-228 | 고침 | 요청별 모델 심사와 최근 두 표본 제한을 삭제했다. GET/HEAD 의존 요청은 그대로 보내며 POST 대상과 존재 및 차단 이유를 다음 모델 입력에 담는다. 메서드와 예산 및 외부 화면 경계만 코드로 지킨다. | observer.py:118,210; prompts.py:39 |
| 64 | site_analysis/observer.py:236-244 | 고침 | 쿠키 파서 실패는 그 헤더만 못 얻음으로 격리한다. 브라우저 쿠키 저장소의 이름과 속성도 값 없이 별도로 얻는다. HTTP 대체에는 네이티브 저장소가 없으므로 표준 파서와 칸별 실패를 남긴다. | observer.py:86,235,254 |
| 65 | site_analysis/observer.py:245-246 | 고침 | 고정 5, 10, 15, 30초를 없앴다. 읽기, 화면과 이동은 공유 시간 예산의 남은 시간으로 제한한다. 항목 실패는 계속 격리한다. | observer.py:235,275,325,497 |
| 66 | site_analysis/observer.py:247-254 | 고침 | 전달 표본은 맥락 크기에 맞게 기계적으로 자르고 원본 크기와 단위를 알린다. 원바이트 및 소스는 메모리에 보존하며 모델이 read_sample로 뒤쪽과 인코딩을 선택한다. | observer.py:130,140,155; model.py:138 |
| 67 | site_analysis/observer.py:257-271 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 68 | site_analysis/observer.py:278 | 고침 | 고정 5, 10, 15, 30초를 없앴다. 읽기, 화면과 이동은 공유 시간 예산의 남은 시간으로 제한한다. 항목 실패는 계속 격리한다. | observer.py:235,275,325,497 |
| 69 | site_analysis/observer.py:280-285 | 고침 | 전달 표본은 맥락 크기에 맞게 기계적으로 자르고 원본 크기와 단위를 알린다. 원바이트 및 소스는 메모리에 보존하며 모델이 read_sample로 뒤쪽과 인코딩을 선택한다. | observer.py:130,140,155; model.py:138 |
| 70 | site_analysis/observer.py:288-303,336-338,367-369 | 고침 | 주소의 정확한 원문 등장 검사와 시작 fragment 거부를 삭제했다. 실제 브라우저 이동 URL과 해시를 그대로 관찰하고 공개할 때만 개별 가림을 적용한다. | analyze.py:41,95; observer.py:325,367 |
| 71 | site_analysis/observer.py:305-308,412-413 | 고침 | 브라우저가 만든 WebSocket 연결과 서버 수신을 관찰한다. 클라이언트 송신은 전달하지 않고 차단 수를 기록한다. 송신이 필요한 구독은 못 얻음으로 한계를 알린다. | observer.py:292 |
| 72 | site_analysis/observer.py:310-315 | 고침 | 로그인 제출 예외와 모든 읽기를 잠시 막는 폼 탐침을 삭제했다. 폼 메타데이터만 읽고 모든 네이티브 제출은 막는다. 이름 없는 필드도 보존한다. 실제 제출과 POST 로그인은 이번 사용자 금지선을 따른다. | observer.py:18,320,325 |
| 73 | site_analysis/observer.py:318-321 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 74 | site_analysis/observer.py:326-332 | 고침 | 거부나 행동 실패 한 번의 탐색 종료를 삭제했다. 도구와 인자 및 실패 이유를 다음 입력으로 돌리고 다른 후보를 계속 받는다. 모델의 더 볼 것 없음, 예산과 같은 실패 상한만 끝낸다. | observer.py:325,377,446 |
| 75 | site_analysis/observer.py:333,346,352,358 | 고침 | 고정 5, 10, 15, 30초를 없앴다. 읽기, 화면과 이동은 공유 시간 예산의 남은 시간으로 제한한다. 항목 실패는 계속 격리한다. | observer.py:235,275,325,497 |
| 76 | site_analysis/observer.py:334-354 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 77 | site_analysis/observer.py:340-345,349-351 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 78 | site_analysis/observer.py:355-361 | 고침 | 로그인 제출 예외와 모든 읽기를 잠시 막는 폼 탐침을 삭제했다. 폼 메타데이터만 읽고 모든 네이티브 제출은 막는다. 이름 없는 필드도 보존한다. 실제 제출과 POST 로그인은 이번 사용자 금지선을 따른다. | observer.py:18,320,325 |
| 79 | site_analysis/observer.py:362-366,374 | 고침 | 로그인 제출 예외와 모든 읽기를 잠시 막는 폼 탐침을 삭제했다. 폼 메타데이터만 읽고 모든 네이티브 제출은 막는다. 이름 없는 필드도 보존한다. 실제 제출과 POST 로그인은 이번 사용자 금지선을 따른다. | observer.py:18,320,325 |
| 80 | site_analysis/observer.py:371-373,375-378 | 고침 | 로그인 제출 예외와 모든 읽기를 잠시 막는 폼 탐침을 삭제했다. 폼 메타데이터만 읽고 모든 네이티브 제출은 막는다. 이름 없는 필드도 보존한다. 실제 제출과 POST 로그인은 이번 사용자 금지선을 따른다. | observer.py:18,320,325 |
| 81 | site_analysis/observer.py:380-389 | 고침 | 로그인 제출 예외와 모든 읽기를 잠시 막는 폼 탐침을 삭제했다. 폼 메타데이터만 읽고 모든 네이티브 제출은 막는다. 이름 없는 필드도 보존한다. 실제 제출과 POST 로그인은 이번 사용자 금지선을 따른다. | observer.py:18,320,325 |
| 82 | site_analysis/observer.py:390-391 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 83 | site_analysis/observer.py:397-403 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 84 | site_analysis/observer.py:408 | 부분 고침, 남김 | GET 내려받기를 복구했다. 서비스워커는 context.route를 우회할 수 있어 차단을 남겼다. 원본의 메서드 제한을 보장할 다른 경계를 이번 범위에서 구현하거나 검증하지 않았기 때문이다. | observer.py:402,548 |
| 85 | site_analysis/observer.py:411,417 | 고침 | 팝업 즉시 닫기를 없앴다. 새 창도 같은 요청 경계에서 관찰하며 모델이 select_page로 고른다. 응답은 문맥 전체에서 수집한다. | observer.py:367,402 |
| 86 | site_analysis/observer.py:418-424 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 87 | site_analysis/observer.py:425-430 | 고침 | 거부나 행동 실패 한 번의 탐색 종료를 삭제했다. 도구와 인자 및 실패 이유를 다음 입력으로 돌리고 다른 후보를 계속 받는다. 모델의 더 볼 것 없음, 예산과 같은 실패 상한만 끝낸다. | observer.py:325,377,446 |
| 88 | site_analysis/observer.py:431-435 | 고침 | 거부나 행동 실패 한 번의 탐색 종료를 삭제했다. 도구와 인자 및 실패 이유를 다음 입력으로 돌리고 다른 후보를 계속 받는다. 모델의 더 볼 것 없음, 예산과 같은 실패 상한만 끝낸다. | observer.py:325,377,446 |
| 89 | site_analysis/observer.py:440-444 | 고침 | 관찰 실행 예외를 실행별로 잡는다. 얻은 계측을 먼저 저장하고 묶음 분석을 계속한다. 브라우저 채널 실패는 같은 예산 안에서 HTTP 채널로 이어 가며 기존 응답을 보존한다. | observer.py:402; analyze.py:240,462 |
| 90 | site_analysis/observer.py:451-455 | 부분 고침, 남김 | 시스템 프록시 배제를 삭제했다. HTTP 자동 리다이렉트 중단은 남겼다. 받은 헤더를 모델에게 주어 다음 화면을 고르고 외부 화면 이동을 막기 위한 경계다. 브라우저의 원본 안 리다이렉트는 자원처럼 그대로 전송한다. | observer.py:446 |
| 91 | site_analysis/observer.py:456-457 | 고침 | 관찰 권한은 실제 동작인 익명으로 기록한다. 자격 값의 비어 있음 의미 제한을 없앴고 자격 읽기 실패는 공개 관찰과 분리한다. HTTP와 브라우저 모두 폼 로그인 예외를 제공하지 않는다. | analyze.py:80,240,462; observer.py:118 |
| 92 | site_analysis/observer.py:459-474 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 93 | site_analysis/observer.py:465,508 | 남김 | GET/HEAD 외 전송 금지는 이번 사용자 지시가 감사 제안보다 우선한다. POST 읽기 API를 보내는 예외는 만들지 않으며 요청 대상, 존재와 못 얻은 응답을 모델에게 알린다. | observer.py:210,446; prompts.py:4 |
| 94 | site_analysis/observer.py:478-484 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 95 | site_analysis/observer.py:485-492 | 고침 | 거부나 행동 실패 한 번의 탐색 종료를 삭제했다. 도구와 인자 및 실패 이유를 다음 입력으로 돌리고 다른 후보를 계속 받는다. 모델의 더 볼 것 없음, 예산과 같은 실패 상한만 끝낸다. | observer.py:325,377,446 |
| 96 | site_analysis/observer.py:494-496 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 97 | site_analysis/observer.py:498-501 | 고침 | 거부나 행동 실패 한 번의 탐색 종료를 삭제했다. 도구와 인자 및 실패 이유를 다음 입력으로 돌리고 다른 후보를 계속 받는다. 모델의 더 볼 것 없음, 예산과 같은 실패 상한만 끝낸다. | observer.py:325,377,446 |
| 98 | site_analysis/observer.py:508,511 | 고침 | 고정 5, 10, 15, 30초를 없앴다. 읽기, 화면과 이동은 공유 시간 예산의 남은 시간으로 제한한다. 항목 실패는 계속 격리한다. | observer.py:235,275,325,497 |
| 99 | site_analysis/observer.py:509-519 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 100 | site_analysis/observer.py:521-537 | 고침 | 전달 표본은 맥락 크기에 맞게 기계적으로 자르고 원본 크기와 단위를 알린다. 원바이트 및 소스는 메모리에 보존하며 모델이 read_sample로 뒤쪽과 인코딩을 선택한다. | observer.py:130,140,155; model.py:138 |
| 101 | site_analysis/observer.py:539-541 | 고침 | 내려받기를 일괄 취소하지 않는다. GET 파일은 임시 파일에서 메모리로 읽고 실패한 파일만 이유를 기록한다. 임시 저장은 브라우저 문맥 종료로 정리한다. | observer.py:548 |
| 102 | site_analysis/observer.py:543-564 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 103 | site_analysis/analyze.py:22-30 | 고침 | 기본 호출별 180초와 실행 수 1/2 한정을 없앴다. 공유 시간 예산을 쓰며 운영자가 호출 시간과 양의 실행 수를 지정할 수 있다. | model.py:114; analyze.py:20,41 |
| 104 | site_analysis/analyze.py:37-38 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 105 | site_analysis/analyze.py:37-38 | 고침 | 주소의 정확한 원문 등장 검사와 시작 fragment 거부를 삭제했다. 실제 브라우저 이동 URL과 해시를 그대로 관찰하고 공개할 때만 개별 가림을 적용한다. | analyze.py:41,95; observer.py:325,367 |
| 106 | site_analysis/analyze.py:39-45 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 107 | site_analysis/analyze.py:45-52 | 남김 또는 격리 보완 | 메서드, 외부 정찰과 숫자 예산 경계 및 전달 형식과 계측 구조다. 후보와 항목 실패는 이유를 남겨 다음 후보로 이어 간다. 실행할 수 없는 초기 설정은 오류다. | observer.py:210,325,402,446,497; analyze.py:41 |
| 108 | site_analysis/analyze.py:56-67 | 고침 | 추가 키 거부와 공급자 strict 스키마를 제거했다. 필수 키만 읽고 추가 설명은 개별 가림 후 보존한다. | catalog.py:33,74; model.py:138 |
| 109 | site_analysis/analyze.py:71-79 | 고침 | 관찰 권한은 실제 동작인 익명으로 기록한다. 자격 값의 비어 있음 의미 제한을 없앴고 자격 읽기 실패는 공개 관찰과 분리한다. HTTP와 브라우저 모두 폼 로그인 예외를 제공하지 않는다. | analyze.py:80,240,462; observer.py:118 |
| 110 | site_analysis/analyze.py:80-82 | 고침 | 관찰 권한은 실제 동작인 익명으로 기록한다. 자격 값의 비어 있음 의미 제한을 없앴고 자격 읽기 실패는 공개 관찰과 분리한다. HTTP와 브라우저 모두 폼 로그인 예외를 제공하지 않는다. | analyze.py:80,240,462; observer.py:118 |
| 111 | site_analysis/analyze.py:90-106 | 고침 | 개별 사실 문자열, 실제 URL, 쿠키 속성 이름과 값의 가림 후보를 만든다. 실패한 칸의 ID와 경로 및 이유를 남기고 모델 교정은 model_privacy 출처로 표시한다. 전체 판단 이력을 지우지 않는다. | analyze.py:95,120,133,240 |
| 112 | site_analysis/analyze.py:110-121 | 고침 | 개별 사실 문자열, 실제 URL, 쿠키 속성 이름과 값의 가림 후보를 만든다. 실패한 칸의 ID와 경로 및 이유를 남기고 모델 교정은 model_privacy 출처로 표시한다. 전체 판단 이력을 지우지 않는다. | analyze.py:95,120,133,240 |
| 113 | site_analysis/analyze.py:127-138 | 고침 | 묶음마다 attempts와 본문 및 base64를 일괄 제외하는 코드 경로를 삭제했다. 모든 관찰 표현과 요청 존재를 제공하며 더 읽을 표본은 모델이 고른다. | analyze.py:204; observer.py:118,155 |
| 114 | site_analysis/analyze.py:145 | 고침 | 관찰 실행 예외를 실행별로 잡는다. 얻은 계측을 먼저 저장하고 묶음 분석을 계속한다. 브라우저 채널 실패는 같은 예산 안에서 HTTP 채널로 이어 가며 기존 응답을 보존한다. | observer.py:402; analyze.py:240,462 |
| 115 | site_analysis/analyze.py:148-158 | 고침 | 묶음 전체 폐기를 없앴다. 정상 축을 보존하고 누락 또는 형식 오류 축만 이유와 원답을 모델에게 돌려 교정한다. | catalog.py:60,74; analyze.py:204 |
| 116 | site_analysis/analyze.py:167-173 | 고침 | 전체 안전 여부 하나로 모든 축을 비우는 경로를 없앴다. 칸별 교정본과 안전 여부를 받으며 실패한 가림 응답을 나누어 해당 칸만 비운다. 이미 공개한 칸은 보존한다. | analyze.py:133,240 |
| 117 | site_analysis/analyze.py:162,175-180,190 | 고침 | 전체 안전 여부 하나로 모든 축을 비우는 경로를 없앴다. 칸별 교정본과 안전 여부를 받으며 실패한 가림 응답을 나누어 해당 칸만 비운다. 이미 공개한 칸은 보존한다. | analyze.py:133,240 |
| 118 | site_analysis/analyze.py:181-193 | 고침 | 개별 사실 문자열, 실제 URL, 쿠키 속성 이름과 값의 가림 후보를 만든다. 실패한 칸의 ID와 경로 및 이유를 남기고 모델 교정은 model_privacy 출처로 표시한다. 전체 판단 이력을 지우지 않는다. | analyze.py:95,120,133,240 |
| 119 | site_analysis/analyze.py:196-214 | 고침 | dry-run은 의미 일치 모델 결정의 실행 규칙, 축별 오류 격리, 추가 키와 다른 확신 척도 허용, GET/HEAD와 POST 및 외부 화면 경계, 정상 반복과 같은 실패 상한을 오프라인에서 확인한다. | analyze.py:365,392,427 |
| 120 | site_analysis/analyze.py:217-241 | 고침 | dry-run은 의미 일치 모델 결정의 실행 규칙, 축별 오류 격리, 추가 키와 다른 확신 척도 허용, GET/HEAD와 POST 및 외부 화면 경계, 정상 반복과 같은 실패 상한을 오프라인에서 확인한다. | analyze.py:365,392,427 |
| 121 | site_analysis/analyze.py:248-274 | 고침 | 완료 실행만 기다리지 않고 가림 완료 칸과 숫자 계측을 단계별로 원자 저장한다. 상한과 부분 실패는 저장 후 종료 코드 2로 알린다. | analyze.py:240,462; record.py:84 |
| 122 | site_analysis/analyze.py:254 | 고침 | 정확한 문자열 비교를 삭제했다. 두 실행의 의미 일치와 합친 답은 모델이 정한다. 받는 모델은 원답, 근거와 비교 및 합친 답을 함께 판단한다. 합친 답만 사용하라는 고정 문구를 없앴다. | record.py:92; analyze.py:302,462 |
| 123 | site_analysis/analyze.py:266-267 | 고침, 복원 | --rates와 --max-cost-usd를 추가했다. decoy_build의 base/long 및 입력, 캐시 입력과 출력 단가 형식으로 모든 호출 비용을 계산하고 호출 전후 상한을 확인한다. 진행 중 한 호출의 초과는 사후 발견할 수 있다. | model.py:41,64,105,138; analyze.py:20,462 |
| 124 | site_analysis/analyze.py:276-277 | 고침 | 완료 실행만 기다리지 않고 가림 완료 칸과 숫자 계측을 단계별로 원자 저장한다. 상한과 부분 실패는 저장 후 종료 코드 2로 알린다. | analyze.py:240,462; record.py:84 |
| 125 | site_analysis/analyze.py:281-300,303-304 | 부분 고침, 남김 | 항목 상세는 메모리에서 모델에 전달한다. 터미널과 공개 기록에는 오류 코드 또는 종류만 출력한다. 원시 예외가 원본 값이나 자격을 포함할 수 있어 초기 설정 실패의 원문 출력은 남기지 않았다. | observer.py:176,186; analyze.py:531 |
| 126 | site_analysis/observer.py:425-436,site_analysis/analyze.py:151-158 | 고침, 복원 | --same-failure-limit 기본 8을 넣었다. 정규화한 도구와 인자 또는 같은 축에서 같은 오류만 세고 성공하면 해당 작업의 실패 수를 지운다. 서로 다른 실패나 성공 반복을 제한하지 않는다. | record.py:45; observer.py:176,377,391; model.py:114 |
| 127 | site_analysis/observer.py:171-174,326-329,425,481-484,site_analysis/axes.json:41 | 고침 | 사람 확인은 해당 후보를 통과하지 않고 대안을 고르게 했다. 모델이 더 볼 것이 없다고 stop을 정하면 탐색을 끝내며 stop 축의 한 번 발견은 합치기에서 보존한다. | prompts.py:4; observer.py:325; record.py:92 |
| 128 | decoy_build/models.py:16-19,170,174-182 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 129 | decoy_build/models.py:122 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 130 | decoy_build/models.py:125-150 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 131 | decoy_build/models.py:22-26,43-58,60-80,137-140,163-169 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 132 | decoy_build/models.py:38-39,48-51,156-157 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 133 | decoy_build/models.py:78,112-118 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 134 | decoy_build/transport.py:16-35,38-65 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 135 | decoy_build/transport.py:72-85 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 136 | decoy_build/transport.py:92,98-109 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 137 | decoy_build/transport.py:111-123 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 138 | decoy_build/transport.py:111-123 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 139 | decoy_build/transport.py:125-160,191-198 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 140 | decoy_build/transport.py:163-169 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 141 | decoy_build/transport.py:171-189 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 142 | decoy_build/transport.py:199-210 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 143 | decoy_build/build.py:18-21,44-49 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 144 | decoy_build/build.py:55-60,105-139 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 145 | decoy_build/build.py:140-149,158-175 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 146 | decoy_build/runner.py:15-58 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 147 | decoy_build/runner.py:60-100 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 148 | decoy_build/runner.py:107-132,174-183 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 149 | decoy_build/runner.py:127-185 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 150 | decoy_build/runner.py:134-161 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 151 | decoy_build/runner.py:187-196,460-461 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 152 | decoy_build/runner.py:211-234,249-257 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 153 | decoy_build/runner.py:258-286 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 154 | decoy_build/runner.py:289-305 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 155 | decoy_build/runner.py:306-378 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 156 | decoy_build/runner.py:380-421 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 157 | decoy_build/runner.py:437-449 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 158 | decoy_build/discriminate.py:24-35,101-110 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 159 | decoy_build/discriminate.py:23,34-35,86-87 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 160 | decoy_build/discriminate.py:47-74,88-99 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 161 | decoy_build/discriminate.py:85-93 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 162 | decoy_build/snapshot.py:24-31,87-90 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 163 | decoy_build/snapshot.py:34-55,103-121 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 164 | decoy_build/snapshot.py:58-101,124-184 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 165 | decoy_build/snapshot.py:214-286,288-361 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 166 | decoy_build/snapshot.py:293-298 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 167 | decoy_build/snapshot.py:379-437 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 168 | decoy_build/snapshot.py:445-466 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 169 | decoy_build/transport.py:111-123,decoy_build/snapshot.py:24-32,288-330 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 170 | register_generic_decoy.py:43-50,117-120,132-139,147-154,165-166,467-468 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 171 | register_generic_decoy.py:125-126,141-150,487-490 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 172 | register_generic_decoy.py:155-163,178-179,211-212 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 173 | register_generic_decoy.py:231-238 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 174 | register_generic_decoy.py:107-116,121-123,127-130,170-177,473-486,500-502 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 175 | register_generic_decoy.py:506-549 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 176 | register_generic_decoy.py:262-282,generic_decoy_adapter.py:146-165 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 177 | generic_decoy_adapter.py:116-127,177-191 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 178 | decoy_build/journal.py:24-48,168-182 | 남김, 범위 밖 | site_analysis 밖을 고치지 말라는 이번 지시를 따른다. decoy_build, 복사와 등록 및 어댑터 코드는 수정하지 않았다. 특히 register_generic_decoy.py는 다른 세션 소유다. 감사의 결함을 해결했다고 주장하지 않는다. | 수정 범위 밖 |
| 179 | site_analysis/axes.json:3-11,14-64 | 고침, 축 구조 남김 | 축 정본의 묶음 정책은 이번 사용자 지시가 명시한 결정으로 유지한다. 합의는 정확한 문자열 대신 모델의 의미 일치로 바꿨다. 실제 웹별 적용성은 측정하지 않았다. | axes.json:4; analyze.py:302; record.py:92 |
| 180 | site_analysis/AXES.md:1-57 | 남김 | 축 정본에서 만든 문서와 기계적 Markdown 출력이다. 축 내용과 이름은 이번 지시가 승인한 구조를 유지한다. | catalog.py:91; AXES.md:1 |
| 181 | site_analysis/SCHEMA.md:1-96 | 고침 | 현재 동작에 맞춰 규격 1.1로 다시 썼다. 전체 묶음 폐기, 전체 가림 보류와 문자열 합의 강제 설명을 제거했다. | SCHEMA.md:1 |
| 182 | site_analysis/ANALYSIS-REPORT.md:1-117 | 고침 | 최초 보고는 이력으로 보존하고 맨 앞에 현재 구현과 다른 부분 및 FIX 보고와 새 규격 안내를 추가했다. | ANALYSIS-REPORT.md:1 |
| 183 | site_analysis/SLIM-REPORT.md:없음,decoy_build/SLIM-REPORT.md:1-201,decoy_build/FIX-REPORT.md:1-96,decoy_build/FIX2-REPORT.md:1-57 | 남김 | 다른 모듈의 과거 보고는 수정 범위 밖이다. site_analysis의 현재 수정 증거는 이 보고와 현재 소스로 구분한다. | FIX-REPORT.md:1 |
| 184 | site_analysis/observer.py:193,253,275,533 | 남김 | 직전 원소와 참조 식별자를 만드는 인덱스 및 숫자 계산이다. | observer.py:140,275 |
| 185 | site_analysis/observer.py:189-190,162-174 | 고침 | 요청별 모델 심사와 최근 두 표본 제한을 삭제했다. GET/HEAD 의존 요청은 그대로 보내며 POST 대상과 존재 및 차단 이유를 다음 모델 입력에 담는다. 메서드와 예산 및 외부 화면 경계만 코드로 지킨다. | observer.py:118,210; prompts.py:39 |
| 186 | decoy_build/transport.py:184-189 | 남김, 범위 밖 | decoy_build의 전송, 작업자와 프롬프트 및 점검표는 이번 수정 범위 밖이다. 원본 쓰기와 개인정보 비기록 원칙은 site_analysis 자체에서 지킨다. | 수정 범위 밖 |
| 187 | decoy_build/worker.py:19-52,55-133 | 남김, 범위 밖 | decoy_build의 전송, 작업자와 프롬프트 및 점검표는 이번 수정 범위 밖이다. 원본 쓰기와 개인정보 비기록 원칙은 site_analysis 자체에서 지킨다. | 수정 범위 밖 |
| 188 | decoy_build/prompts.py:5-195,decoy_build/checklist.json:1-61 | 남김, 범위 밖 | decoy_build의 전송, 작업자와 프롬프트 및 점검표는 이번 수정 범위 밖이다. 원본 쓰기와 개인정보 비기록 원칙은 site_analysis 자체에서 지킨다. | 수정 범위 밖 |
| 189 | site_analysis/catalog.py:38-39,site_analysis/model.py:50-52,67-68,site_analysis/observer.py:134-146,189-194,235-239,323-325,site_analysis/analyze.py:161,166,site_analysis/record.py:22-23,80-84 | 고침 | 전달 키 구조는 유지하되 요청 심사 키를 삭제하고 칸별 가림, 의미 합치기, 원본 값 없는 실패 장부를 정의했다. 키 정의 자체로 웹 내용을 판단하지 않는다. | catalog.py:42; analyze.py:133,302; record.py:45 |

## 실행한 확인

작업 디렉터리는 저장소의 `defense/web-proxy-defense/`다. 마지막 소스 수정 후 아래 `py_compile`과 두 dry-run이 모두 종료 코드 0이었다. 단가를 생략한 dry-run과 `--max-cost-usd 25`로 상한을 덮어쓴 dry-run도 실행해 종료 코드 0을 확인했다. 실제 공급자 가격의 최신성을 검증한 것이 아니라 운영자 파일의 형식과 숫자를 확인한 것이다.

```powershell
python -B -m py_compile site_analysis/__init__.py site_analysis/catalog.py site_analysis/model.py site_analysis/prompts.py site_analysis/record.py site_analysis/observer.py site_analysis/analyze.py
python -B -m site_analysis.analyze --origin-url 'https://example.invalid/#/view' --out site_analysis/offline-analysis.json --rates ../../.tmp/installer-targets/wordpress/settings.json --max-cost-usd 25 --login-env SITE_ANALYSIS_DRY_RUN_UNSET --dry-run
python -B -m site_analysis.analyze --origin-url 'https://example.invalid/#/view' --out site_analysis/offline-analysis.json --runs 3 --max-pages 12 --max-requests 450 --max-seconds 120 --sample-chars 80000 --context-chars 120000 --same-failure-limit 3 --model-timeout 30 --rates ../../.tmp/installer-targets/wordpress/settings.json --dry-run
```

축 51개의 형식과 완전성, 모델의 의미 합의 결정에 따른 union/consensus/retain 적용, 형식 오류 축 하나의 격리와 추가 메타데이터 및 확신 65 허용, 같은 실패 상한과 성공 수 초기화, 요청별 모델 호출 없이 제3자 GET 및 HEAD 허용, POST 차단과 사유, 외부 최상위 이동 차단, 후보 거부가 stop으로 바뀌지 않음을 dry-run 내부에서 확인했다. 네트워크, 실제 모델과 파일 출력을 흉내 낸 분석 결과 파일은 만들지 않았다. dry-run이 출력한 `network_requests`, `model_calls`, `files_written`은 모두 0이며 지정 출력 파일이 없음을 확인했다. 자격 환경변수 값도 읽지 않았다.

## 실행하지 않은 것

원본 HTTP 및 브라우저 접속, 실제 모델 및 교정과 개인정보 가림 호출, 로그인, 폼 제출, WebSocket 연결, 내려받기, Playwright 실행, 의존성 설치, 별도 단위 검사와 pytest, Docker 조작, Git 변경과 외부 정찰은 실행하지 않았다. 실제 모델의 의미 일치 판단, 가림 정확성, 브라우저 및 Playwright 버전별 API 동작, 다섯 웹 적용성과 비용 실측은 미확인이다. 이를 완료한 검증으로 주장하지 않는다.

## 원본 WordPress에서 돌릴 명령 한 줄

이번에 로컬 `../../.tmp/installer-targets/wordpress/deployment.json`의 존재와 `public_origin` 키, `scope=installer-only`를 확인했다. 등록 코드의 설명은 이 대상을 미끼가 아닌 설치 분석용 시험 웹으로 명시한다. 이전 보고의 `decoy-generic/installer-targets/wordpress/deployment.json` 경로는 현재도 없으므로 그 경로를 재사용하지 않는다. 단가 파일에는 선택 모델 `gpt-6-sol`과 상한 25.00이 있었고 dry-run에서 읽혔다. 아래 명령은 등록된 시험 원본 WordPress를 대상으로 하며 실제로 실행하지 않았다. 현재 웹의 생존 여부와 주소 연결성은 접속하지 않아 미확인이다.

```powershell
python -B -m site_analysis.analyze --origin-url ((Get-Content -Encoding UTF8 -Raw '../../.tmp/installer-targets/wordpress/deployment.json' | ConvertFrom-Json).public_origin) --out ../../.tmp/site-analysis/wordpress-analysis.json --runs 2 --model gpt-6-sol --rates ../../.tmp/installer-targets/wordpress/settings.json --max-cost-usd 25 --same-failure-limit 8
```
