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

Binds 127.0.0.1 *and* the Docker bridge gateway (172.17.0.1 by default). Tools
that run in the sandbox get `--network bridge`, where 127.0.0.1 is the container
itself — a lab reachable only on host loopback would be invisible to exactly the
tools most worth testing, and each would report a clean scan of nothing. Both
addresses are host-local; neither is reachable from outside this machine.
"""
from __future__ import annotations

import subprocess
import threading
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
                "<h1>Cordon validation lab</h1>"
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


def _bridge_gateway() -> str | None:
    """The docker0 address, or None when there is no bridge to bind to."""
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "docker0"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:  # noqa: BLE001
        return None
    for token in out.split():
        if "/" in token and token.count(".") == 3:
            return token.split("/")[0]
    return None


if __name__ == "__main__":
    addresses = ["127.0.0.1"]
    gateway = _bridge_gateway()
    if gateway and gateway not in addresses:
        addresses.append(gateway)

    servers = []
    for address in addresses:
        try:
            servers.append(ThreadingHTTPServer((address, PORT), Handler))
            print(f"lab on http://{address}:{PORT}/", flush=True)
        except OSError as exc:
            print(f"could not bind {address}:{PORT} - {exc}", flush=True)
    if not servers:
        raise SystemExit(1)

    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()
