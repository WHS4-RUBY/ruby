"""테스트용 백엔드 — python stub_srv.py <port> <mode: 404|spa> [robots: none|real|html]

  /                 index.html (셸)
  /robots.txt       none → 404, real → "User-agent: *\nDisallow: /secret-real/", html → (SPA 모드에선 셸)
  /admin            200 "REAL ADMIN" (진짜 경로, 비-셸)
  /config           Authorization 헤더 있으면 200 "REAL CONFIG", 없으면 403
  /real-spa-route   spa 모드에선 셸(폴백), 404 모드에선 404
  /euckr            EUC-KR 한글 페이지(Content-Type charset=euc-kr)
  그 외             404 모드 → 404, spa 모드 → 셸(200)
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT, MODE = int(sys.argv[1]), sys.argv[2]
ROBOTS = sys.argv[3] if len(sys.argv) > 3 else "none"
SHELL = b"<html><head><title>x</title></head><body>hi</body></html>"
EUCKR = "<html><head><title>한글</title></head><body>안녕하세요</body></html>".encode("euc-kr")


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            return self._send(200, SHELL)
        if p == "/robots.txt":
            if ROBOTS == "real":
                return self._send(200, b"User-agent: *\nDisallow: /secret-real/\n", "text/plain")
            if ROBOTS == "html" and MODE == "spa":
                return self._send(200, SHELL)
            return self._send(404, b"not found", "text/plain")
        if p == "/admin":
            return self._send(200, b"<html><body>REAL ADMIN</body></html>")
        if p == "/config":
            if self.headers.get("Authorization"):
                return self._send(200, b'{"real":"config"}', "application/json")
            return self._send(403, b"forbidden", "text/plain")
        if p == "/euckr":
            return self._send(200, EUCKR, "text/html; charset=euc-kr")
        if MODE == "spa":
            return self._send(200, SHELL)
        return self._send(404, b"not found", "text/plain")

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
