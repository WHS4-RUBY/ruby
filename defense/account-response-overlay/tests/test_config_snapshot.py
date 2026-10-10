"""설정 파일을 정리한 뒤에도 로딩 결과가 기준선과 같은지.

TOML 의 중복을 지우거나 파일 수를 줄여도 이 스냅샷이 같으면 동작은 같다.
의도적으로 바꿨다면: python tests/config_snapshot.py tests/config_reference.json
"""
import json
from pathlib import Path

import pytest

from tests.config_snapshot import snapshot

REFERENCE = Path(__file__).resolve().parent / 'config_reference.json'


def test_every_config_loads_to_the_same_settings_as_the_reference():
    expected = json.loads(REFERENCE.read_text(encoding='utf-8'))
    actual = snapshot()
    assert set(expected) == set(actual), (
        '스냅샷 키 구성이 달라졌다. 파일을 지웠거나 추가했다면 기준선을 다시 만들 것. '
        f'사라진 것={sorted(set(expected) - set(actual))} '
        f'새로 생긴 것={sorted(set(actual) - set(expected))}')
    for key in sorted(expected):
        assert actual[key] == expected[key], f'{key} 의 로딩 결과가 기준선과 다르다'


def test_the_reference_covers_every_shipped_config():
    config_dir = Path(__file__).resolve().parents[1] / 'config'
    shipped = {path.name for path in config_dir.glob('*.toml')}
    covered = {key.split(':', 1)[1] for key in snapshot()}
    assert shipped == covered, f'스냅샷이 빠뜨린 설정={sorted(shipped - covered)}'


def test_the_secure_cookie_variant_comes_from_the_environment(monkeypatch):
    """decoy-server-v1/v2 와 overlay-server-v1/v2 는 이 값 하나 때문에 존재했다."""
    # load() 가 호출 시점에 환경을 읽으므로 모듈 reload 는 필요하지 않다 —
    # reload 하면 dataclass 타입이 새로 생겨 다른 테스트를 오염시킨다.
    from defense.config import load as load_decoy
    config_dir = Path(__file__).resolve().parents[1] / 'config'

    for name in ('decoy-v1.toml', 'decoy-v2.toml'):
        monkeypatch.delenv('OVERLAY_SECURE_COOKIE', raising=False)
        assert load_decoy(str(config_dir / name)).secure_cookie is False, name
        monkeypatch.setenv('OVERLAY_SECURE_COOKIE', 'true')
        assert load_decoy(str(config_dir / name)).secure_cookie is True, name
        monkeypatch.setenv('OVERLAY_SECURE_COOKIE', 'false')
        assert load_decoy(str(config_dir / name)).secure_cookie is False, name
    monkeypatch.setenv('OVERLAY_SECURE_COOKIE', 'maybe')
    with pytest.raises(ValueError):
        load_decoy(str(config_dir / 'decoy-v2.toml'))


def test_the_deleted_variants_are_gone_and_not_referenced():
    config_dir = Path(__file__).resolve().parents[1] / 'config'
    for name in ('default.toml', 'decoy-server-v1.toml', 'decoy-server-v2.toml',
                 'overlay-server-v1.toml', 'overlay-server-v2.toml'):
        assert not (config_dir / name).exists(), name
    root = Path(__file__).resolve().parents[1]
    for source in ('defense/cli.py', 'deploy/compose.yaml', 'deploy/live-lab.compose.yaml'):
        body = (root / source).read_text(encoding='utf-8')
        assert 'overlay-server-' not in body, source
        assert 'decoy-server-' not in body, source
        assert 'default.toml' not in body, source
