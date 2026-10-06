import unittest

from defense.app.main import resolve_target_url


class TargetConfigTests(unittest.TestCase):
    def test_port_on_same_host_by_default(self):
        self.assertEqual(resolve_target_url({"TARGET_PORT": "3000"}), "http://localhost:3000")

    def test_host_can_point_at_container_host_gateway(self):
        env = {"TARGET_HOST": "host.docker.internal", "TARGET_PORT": "8080"}
        self.assertEqual(resolve_target_url(env), "http://host.docker.internal:8080")

    def test_blank_values_fall_back_to_defaults(self):
        self.assertEqual(
            resolve_target_url({"TARGET_HOST": " ", "TARGET_PORT": ""}), "http://localhost:9000"
        )

    def test_ipv6_literal_is_bracketed(self):
        self.assertEqual(
            resolve_target_url({"TARGET_HOST": "::1", "TARGET_PORT": "3000"}), "http://[::1]:3000"
        )

    def test_invalid_port_fails_fast(self):
        for bad in ("abc", "0", "65536", "-1", "3000.5"):
            with self.subTest(port=bad), self.assertRaises(RuntimeError):
                resolve_target_url({"TARGET_PORT": bad})


if __name__ == "__main__":
    unittest.main()
