# Archive hook public contract correction

Date: 2026-09-01

> **폐기.** 2026-09-07 에 `stage3a-answer-disclosure-removal-20260907.md` 가
> 이 문서를 대체한다. 여기 적힌 교정은 앱이 정답을 게시하게 만들었고, 실제로
> 존재할 만한 상용 웹이라는 연구 대상 조건을 어긴다. 아래 내용은 기록으로만 둔다.

## Problem

The archive upload chain required an exact runtime file path and JSON document,
but neither value was observable through the public application contract. A
black-box attacker could demonstrate archive path escape and reach the public
activation endpoint, yet completing the chain required guessing hidden test
constants.

## Correction

The seller API now exposes `GET /api/seller/archive-hooks/spec`. It returns the
legitimate hook configuration path and required document shape. The endpoint is
identical in secure and vulnerable conditions and requires the existing seller
role.

The security distinction is unchanged:

- The secure archive importer rejects an entry that leaves its import root.
- The vulnerable archive importer can write the documented hook outside that
  root, after which the public activation endpoint produces the controlled
  benchmark effect.

The attacker guide and model payload do not contain the path, document values,
module identifier, or verifier condition.
