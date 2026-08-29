from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ravage.probe_suite import available_probes

XXE_SECRET = "FLAG{xxe_boundary_file_read}"


class _XxeSoapHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        self._send(
            200,
            '<form action="/soap" method="post">'
            '<textarea name="xml"></textarea><button type="submit">Import</button></form>',
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        if "<!ENTITY" in body and "file:///flag" in body:
            self._send(200, f"<response>{XXE_SECRET}</response>")
            return
        if "<!ENTITY" in body and "file:///etc/passwd" in body:
            self._send(200, "root:x:0:0:root:/root:/bin/bash")
            return
        self._send(200, "<response>ok</response>")

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def xxe_soap_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _XxeSoapHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_xxe_boundary_is_an_available_probe() -> None:
    assert "xxe_boundary" in {item["name"] for item in available_probes()}
