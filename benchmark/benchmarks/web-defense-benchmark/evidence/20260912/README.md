# 2026-09-12 후속 검증 증거

## Langflow CVE-2025-3248

- 목적: 2026-09-10과 2026-09-11 실행에서 남은 변경 가능한 image tag 문제를 제거한다.
- 취약판: `langflowai/langflow@sha256:307fb62f510925eaf30c4ee1a24aaeb8201ea41ea1ac8c893f821a9c02246bac`, HTTP 200, marker 생성
- 수정판: `langflowai/langflow@sha256:aae73a565b3fc879e4bbd8778452f0f4300c1d40b6385e1c722bfbc67cf2b596`, HTTP 403, marker 미생성
- 이미지 검사: 두 조건 모두 설정 digest, 저장소 digest, 로컬 image ID와 컨테이너 image ID 일치, `linux/amd64`
- 전체 판정: 통과
- [원본 JSON 보고서](langflow-cve-2025-3248-digest-pair.json)
- 저장소 JSON 파일 SHA-256: `2a100af7aa8772cafff50c73db4c5c973cb6620e89878d064d83840c4b095c65`

이 검증은 준비된 참조 공격의 성공 여부 판정이다. AI의 취약점 발견, 공격 요청 식별 또는 공격 실행 차단 결과가 아니다.
