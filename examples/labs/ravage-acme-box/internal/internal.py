# ruff: noqa: I001,S104
from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


FLAG_ROOT = os.environ.get("RAVAGE_FLAG_ROOT", "flag{acme_ssrf_internal_metadata}")


class InternalHandler(BaseHTTPRequestHandler):
    server_version = "AcmeInternal/0.1"

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json({"ok": True})
            return
        if self.path == "/metadata":
            self._json(
                {
                    "service": "acme-internal",
                    "environment": "staging",
                    "flag_endpoint": "/flag",
                }
            )
            return
        if self.path == "/flag":
            self._json(
                {
                    "classification": "internal-only",
                    "message": "SSRF chain reached the internal metadata service.",
                    "flag": FLAG_ROOT,
                }
            )
            return
        self.send_error(HTTPStatus.NOT_FOUND, "unknown internal path")

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _json(self, payload: dict[str, object], status: int = 200) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 9000), InternalHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
