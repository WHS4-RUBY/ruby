#!/usr/bin/env python3
"""설정 파일들을 로딩한 결과의 스냅샷을 만든다.

TOML 을 정리(중복 제거)할 때 "로딩 결과가 그대로인가"를 보는 회귀 안전망이다.
파일 수나 키 구성을 바꿔도 이 스냅샷이 같으면 동작은 같다.

의도적으로 바꿨다면 아래로 기준선을 다시 만든다:

    python tests/config_snapshot.py tests/config_reference.json
"""
import dataclasses
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from defense.config import load as load_decoy_config  # noqa: E402
from defense.overlay import load_overlay  # noqa: E402


def _plain(value):
    """경로는 파일 이름만 남긴다 — 절대 경로는 머신마다 다르다."""
    if dataclasses.is_dataclass(value):
        return {field.name: _plain(getattr(value, field.name))
                for field in dataclasses.fields(value)}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    if isinstance(value, str) and ('/' in value or '\\' in value) and value.endswith('.toml'):
        return os.path.basename(value)
    return value


def snapshot() -> dict:
    out = {}
    for path in sorted((ROOT / 'config').glob('overlay-*.toml')):
        settings = load_overlay(str(path))
        out[f'overlay:{path.name}'] = _plain(settings)
        out[f'decoy-for:{path.name}'] = _plain(load_decoy_config(settings.decoy_config))
    from defense.site_profile import load_site_profile
    for path in sorted((ROOT / 'config').glob('*.toml')):
        if path.name.startswith('overlay-'):
            continue                                  # 위에서 이미 담았다
        if path.name.startswith('site-'):
            out[f'site:{path.name}'] = _plain(load_site_profile(str(path)))
        else:
            out[f'decoy:{path.name}'] = _plain(load_decoy_config(str(path)))
    return out


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '-'
    body = json.dumps(snapshot(), indent=2, ensure_ascii=False, sort_keys=True) + '\n'
    if target == '-':
        sys.stdout.write(body)
    else:
        Path(target).write_text(body, encoding='utf-8')
        print(f'기준선을 다시 만들었다: {target}')
