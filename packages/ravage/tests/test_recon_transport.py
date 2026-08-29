from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from ravage.web_core.recon import run_recon


def test_recon_counts_redirect_hops_and_fetches_bounded_external_javascript() -> None:
    requested: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requested.append(self.path)
            if self.path == "/":
                self.send_response(302)
                self.send_header("Location", "/home")
                self.end_headers()
                return
            if self.path == "/home":
                self._write(
                    b"<html><a href='/next'>next</a>"
                    b"<script src='/app.js'></script></html>",
                    content_type="text/html; charset=utf-8",
                )
                return
            if self.path == "/app.js":
                self._write(
                    b"fetch('/api/jobs', {method: 'POST', "
                    b"body: JSON.stringify({job_id: 1})});",
                    content_type="application/javascript",
                )
                return
            if self.path == "/next":
                self._write(b"<html>done</html>", content_type="text/html")
                return
            self.send_error(404)

        def _write(self, body: bytes, *, content_type: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_recon(
            f"http://127.0.0.1:{server.server_port}/",
            max_pages=2,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.http_request_count == 4
    assert requested == ["/", "/home", "/app.js", "/next"]
    assert result.pages[0].final_url.endswith("/home")
    assert result.pages[0].request_templates == [
        {
            "source": "javascript_external",
            "method": "POST",
            "url": "/api/jobs",
            "fields": {"job_id": "1"},
            "script_url": f"http://127.0.0.1:{server.server_port}/app.js",
            "transport": "fetch",
        }
    ]
