"""Tiny target with a path-selector dispatcher and a function-selector dispatcher. Echoes what it got."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = b"""<!doctype html><html><body>
<a id="g" href="/gateway?route=%2Fapi%2Fitems&amp;x=1&amp;x=&amp;y">items</a>
<a id="h" href="/gateway?route=/home">home</a>
<a id="l" href="/api.php?action=search&amp;q=a+b">search</a>
<a id="u" href="/api.php?action=help">help</a>
<form method="post" action="/api.php"><input type="hidden" name="action" value="login"></form>
<p>Docs: the API lives at /api/items and /api.php?action=login.</p>
<script>const cfg = {"next":"/api/items/7","desc":"see /api/items for details"};
fetch('/api.php?action=login', {method: 'POST'});</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _echo(self):
        if self.path == "/":
            body, kind = PAGE, "text/html"
        else:
            if self.headers.get("transfer-encoding", "").lower() == "chunked":
                chunks = []
                while True:
                    size = int(self.rfile.readline().split(b";")[0], 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    chunks.append(self.rfile.read(size))
                    self.rfile.readline()
                data = b"".join(chunks).decode("latin-1")
            else:
                length = int(self.headers.get("content-length") or 0)
                data = self.rfile.read(length).decode("latin-1") if length else ""
            path, _, query = self.path.partition("?")
            body = json.dumps({"method": self.command, "path": path, "raw_query": query, "body": data}).encode()
            kind = "application/json"
        self.send_response(200)
        self.send_header("content-type", kind)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _echo

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
