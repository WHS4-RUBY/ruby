"""The public-only switch must be applied before importing the ASGI app."""

import os
import subprocess
import sys
import unittest


class PublicEntrypointTests(unittest.TestCase):
    def test_proxy_docs_are_not_registered(self):
        result = subprocess.run(
            [sys.executable, "-c", (
                "from defense.app.main import app; "
                "assert app.openapi_url is None; "
                "assert not any(route.path in {'/docs', '/redoc'} for route in app.routes)"
            )],
            env={**os.environ, "DEFENSE_PUBLIC_TARGET_ONLY": "true"},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
