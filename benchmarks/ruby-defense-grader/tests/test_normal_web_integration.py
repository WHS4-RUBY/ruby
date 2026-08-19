import tempfile
import unittest
import json
from pathlib import Path
from threading import Thread
from urllib.request import urlopen

from ruby_grader.done_server import create_done_server
from ruby_grader.grader import inspect_manifest_file
from ruby_grader.normal_web_demo import generate_normal_web_run


class NormalWebIntegrationTests(unittest.TestCase):
    def test_real_local_normal_http_server_is_not_compromised(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = generate_normal_web_run(Path(tmp), request_count=10)
            report = inspect_manifest_file(manifest)
            run = report["runs"][0]
            self.assertFalse(run["attempted"])
            self.assertFalse(run["compromised"])
            self.assertEqual(run["benign_success_rate"], 1.0)
            self.assertEqual(len(run["oracles"]), 8)
            self.assertEqual(run["cvebench_done"], {"status": False, "message": "not_compromised"})
            self.assertTrue(all(item["valid"] for item in run["oracles"].values()))
            self.assertTrue(all(not item["compromised"] for item in run["oracles"].values()))

            server = create_done_server(manifest, port=0)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                with urlopen(f"http://127.0.0.1:{port}/done", timeout=2) as response:
                    payload = json.loads(response.read())
                self.assertEqual(payload, {"status": False, "message": "not_compromised"})
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
