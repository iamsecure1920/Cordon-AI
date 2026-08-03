"""A deliberately vulnerable loopback app, for proving the exploit probes parse a real hit.

the validation target is a Next.js site behind Vercel and Cloudflare. Pointing cmdi_probe at
it proves the wrapper builds an argv the binary accepts and that a *negative*
result is reported honestly — it cannot prove the wrapper parses a finding,
because there is no finding to parse. That path has never been exercised, and an
unexercised parse path is the same defect as an unexercised tool: it reports
nothing and nothing distinguishes that from clean.

Binds 127.0.0.1 only. Never expose this.

  GET /ssti?q=       renders q as a Jinja2 template
  GET /cmd?cmd=      concatenates cmd into a shell string
  GET /fetch?url=    fetches url server-side and returns the body
"""
from __future__ import annotations

import subprocess
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from jinja2 import Template

PORT = 8899


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, body: str, code: int = 200) -> None:
        raw = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        path = parts.path

        if path == "/":
            self._send(
                "<h1>EasyHunt validation lab</h1>"
                "<ul><li><a href='/ssti?q=hello'>/ssti</a></li>"
                "<li><a href='/cmd?cmd=date'>/cmd</a></li>"
                "<li><a href='/fetch?url=http://127.0.0.1:8899/'>/fetch</a></li></ul>"
            )
        elif path == "/ssti":
            value = (query.get("q") or ["hello"])[0]
            try:
                rendered = Template("<p>Hello " + value + "</p>").render()
            except Exception as exc:  # noqa: BLE001
                rendered = f"<p>template error: {exc}</p>"
            self._send(rendered)
        elif path == "/cmd":
            value = (query.get("cmd") or ["date"])[0]
            try:
                out = subprocess.run(  # noqa: S602 - the entire point
                    "echo " + value, shell=True, capture_output=True, timeout=10, text=True
                )
                body = f"<pre>{out.stdout}{out.stderr}</pre>"
            except Exception as exc:  # noqa: BLE001
                body = f"<pre>{exc}</pre>"
            self._send(body)
        elif path == "/fetch":
            value = (query.get("url") or [""])[0]
            if not value:
                self._send("<p>need ?url=</p>", 400)
                return
            try:
                with urllib.request.urlopen(value, timeout=5) as resp:  # noqa: S310
                    body = resp.read(4096).decode("utf-8", "replace")
                self._send(f"<pre>{body}</pre>")
            except Exception as exc:  # noqa: BLE001
                self._send(f"<pre>fetch failed: {exc}</pre>", 502)
        else:
            self._send("<h1>404</h1>", 404)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._send("<p>ok</p>")

    def log_message(self, fmt: str, *args: object) -> None:
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"lab on http://127.0.0.1:{PORT}/", flush=True)
    server.serve_forever()
