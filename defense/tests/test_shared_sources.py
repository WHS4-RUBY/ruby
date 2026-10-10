"""shared/ 의 편집 원본과 서비스 트리 사본이 같은지 검증한다.

루트 shared/ 는 네 이미지의 빌드 컨텍스트가 모두 하위 디렉터리라 Docker COPY 로
가져올 수 없다. 그래서 원본 하나와 사본들을 함께 커밋하고, 단일 출처는 파일 구조가
아니라 이 테스트가 보장한다. 사본 목록은 scripts/sync-shared.sh 한 곳에만 있고
여기서 그 목록을 읽어 쓴다 — 목록이 두 군데로 갈라지지 않게.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SYNC_SCRIPT = ROOT / 'scripts/sync-shared.sh'


def _pairs() -> tuple[tuple[str, str], ...]:
    body = SYNC_SCRIPT.read_text(encoding='utf-8')
    block = re.search(r'^PAIRS="\n(.*?)^"$', body, re.DOTALL | re.MULTILINE)
    assert block, 'scripts/sync-shared.sh 에서 PAIRS 목록을 찾지 못했다'
    found = []
    for line in block.group(1).splitlines():
        parts = line.split()
        if len(parts) == 2:
            found.append((parts[0], parts[1]))
    return tuple(found)


class SharedSourcesHaveNoDrift(unittest.TestCase):
    def test_the_sync_script_lists_pairs(self):
        pairs = _pairs()
        self.assertGreaterEqual(len(pairs), 2)
        for source, copy in pairs:
            with self.subTest(copy=copy):
                self.assertTrue(source.startswith('shared/'), source)
                self.assertFalse(copy.startswith('shared/'), copy)

    def test_every_copy_matches_its_original(self):
        for source, copy in _pairs():
            with self.subTest(copy=copy):
                original = ROOT / source
                self.assertTrue(original.exists(), f'{source} 원본이 없다')
                target = ROOT / copy
                self.assertTrue(target.exists(), f'{copy} 사본이 없다')
                self.assertEqual(original.read_bytes(), target.read_bytes(),
                                 'scripts/sync-shared.sh 로 사본을 다시 만들어야 한다')

    def test_each_copy_sits_inside_a_build_context_that_ships_it(self):
        # 사본이 이미지에 실제로 들어가는 위치인지. CHeaT 만 .dockerignore 가
        # allowlist 라 파일 이름이 명시돼 있어야 한다.
        cheat = ROOT / 'defense/CHeat-defense-proxy/defense_proxy_v2'
        for source, copy in _pairs():
            with self.subTest(copy=copy):
                if (ROOT / copy).is_relative_to(cheat):
                    name = Path(copy).name
                    self.assertIn(f'!{name}',
                                  (cheat / '.dockerignore').read_text(encoding='utf-8'))
                    self.assertIn(name, (cheat / 'Dockerfile').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
