"""두 Compose 가 같은 환경변수를 같은 값으로 다시 중복 선언하지 않는지.

docker-compose.yml 과 docker-compose.local.yml 은 Detection·Defense 환경변수를
74개씩 똑같이 들고 있었다. 공통분은 docker-compose.common.yml 의 base 서비스로
옮기고 extends 로 가져온다. 각 파일에 남은 항목은 배포별로 **다른** 값이어야 한다.

파서는 이 저장소의 Compose 파일 모양(2/4/6칸 들여쓰기, 리스트 또는 맵 형식)에
맞춘 최소 구현이다. defense 이미지에 YAML 의존성을 새로 넣지 않으려고 이렇게 했다.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / 'docker-compose.common.yml'
COMPOSES = (ROOT / 'docker-compose.yml', ROOT / 'docker-compose.local.yml')
SERVICES = ('detection', 'defense')


def _service_env(path: Path) -> dict[str, dict[str, str]]:
    """서비스 이름 -> {환경변수: 값}. environment 블록만 읽는다."""
    found: dict[str, dict[str, str]] = {}
    service = None
    in_env = False
    for line in path.read_text(encoding='utf-8').splitlines():
        header = re.match(r'^  ([a-z][a-z0-9-]*):\s*$', line)
        if header:
            service, in_env = header.group(1), False
            found.setdefault(service, {})
            continue
        if re.match(r'^    [a-z_]+:', line):
            in_env = bool(re.match(r'^    environment:\s*$', line))
            continue
        if not (in_env and service):
            continue
        item = re.match(r'^      - ([A-Z_][A-Z0-9_]*)=(.*)$', line) \
            or re.match(r'^      ([A-Z_][A-Z0-9_]*):\s?(.*)$', line)
        if item:
            found[service][item.group(1)] = item.group(2).strip().strip('"')
    return found


class ComposeFilesShareTheirCommonEnvironment(unittest.TestCase):
    def setUp(self):
        self.common = _service_env(COMMON)
        self.concrete = {path.name: _service_env(path) for path in COMPOSES}

    def test_the_common_file_defines_a_base_for_each_service(self):
        for service in SERVICES:
            with self.subTest(service=service):
                self.assertIn(f'{service}-base', self.common)
                self.assertTrue(self.common[f'{service}-base'])

    def test_the_common_file_is_not_runnable_on_its_own(self):
        body = COMMON.read_text(encoding='utf-8')
        self.assertNotIn('image:', body)
        self.assertNotIn('build:', body)

    def test_both_composes_extend_the_base(self):
        for path in COMPOSES:
            body = path.read_text(encoding='utf-8')
            for service in SERVICES:
                with self.subTest(compose=path.name, service=service):
                    self.assertIn(f'service: {service}-base', body)
            self.assertIn('file: docker-compose.common.yml', body)

    def test_no_variable_is_duplicated_with_the_same_value(self):
        for service in SERVICES:
            left = self.concrete['docker-compose.yml'].get(service, {})
            right = self.concrete['docker-compose.local.yml'].get(service, {})
            duplicated = {key for key in left if key in right and left[key] == right[key]}
            with self.subTest(service=service):
                self.assertEqual(set(), duplicated,
                                 'docker-compose.common.yml 로 옮겨야 하는 중복이다')

    def test_what_stays_inline_is_absent_from_the_base(self):
        # 같은 변수를 base 와 파일 양쪽에 두면 어느 값이 이기는지 읽는 사람이 알기 어렵다.
        # 배포별로 값이 다른 변수만 파일에 남기고, 그 변수는 base 에 두지 않는다.
        for service in SERVICES:
            base = set(self.common[f'{service}-base'])
            for name, parsed in self.concrete.items():
                with self.subTest(service=service, compose=name):
                    self.assertEqual(set(), base & set(parsed.get(service, {})))


if __name__ == '__main__':
    unittest.main()
