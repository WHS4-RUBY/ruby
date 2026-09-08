from __future__ import annotations

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_BODY = 2 * 1024 * 1024


class RelayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _relay(self) -> None:
        length_text = self.headers.get("Content-Length", "0")
        if not length_text.isdigit() or int(length_text) > MAX_BODY:
            self.send_error(413)
            return
        length = int(length_text)
        body = self.rfile.read(length) if length else None
        connection = http.client.HTTPConnection("defense-adapter", 8081, timeout=10)
        try:
            connection.request(
                self.command,
                self.path,
                body=body,
                headers={
                    name: value
                    for name, value in self.headers.items()
                    if name.lower()
                    not in {"connection", "host", "content-length", "transfer-encoding"}
                },
            )
            response = connection.getresponse()
            payload = response.read(MAX_BODY + 1)
            if len(payload) > MAX_BODY:
                self.send_error(502)
                return
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in {"connection", "content-length", "transfer-encoding"}:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except Exception:
            self.send_error(502)
        finally:
            connection.close()

    do_GET = _relay
    do_POST = _relay

    def log_message(self, format, *args):
        return


server = ThreadingHTTPServer(("0.0.0.0", 8080), RelayHandler)
server.serve_forever()
