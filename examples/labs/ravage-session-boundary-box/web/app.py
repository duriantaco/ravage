# ruff: noqa: I001,PLR0911,S104,S324
from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import secrets
import urllib.parse
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


PORT = int(os.environ.get("BOUNDARY_PORT", "8000"))
FLAG_CSRF = os.environ.get("BOUNDARY_FLAG_CSRF", "flag{boundary_csrf_omission}")
FLAG_CORS = os.environ.get("BOUNDARY_FLAG_CORS", "flag{boundary_cors_profile}")
FLAG_STORAGE = os.environ.get("BOUNDARY_FLAG_STORAGE", "flag{boundary_storage_secret}")
COOKIE_NAME = "boundary_session"
CSRF_BY_SESSION: dict[str, str] = {}


class BoundaryHandler(BaseHTTPRequestHandler):
    def version_string(self) -> str:
        return "BoundaryLab/1.0"

    def do_OPTIONS(self) -> None:
        if self.path.startswith("/api/"):
            self.send_response(HTTPStatus.NO_CONTENT)
            self._cors_headers()
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Ravage-Probe")
            self.end_headers()
            return
        self.send_error(HTTPStatus.NOT_FOUND, "unknown path")

    def do_GET(self) -> None:
        if self.headers.get("Upgrade", "").lower() == "websocket" and self.path.startswith("/ws"):
            self._websocket_upgrade()
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            self._json({"ok": True})
            return
        if parsed.path == "/":
            self._html(_home())
            return
        if parsed.path == "/transfer":
            session_id = self._session_id()
            token = secrets.token_hex(12)
            CSRF_BY_SESSION[session_id] = token
            self._html(_transfer_form(token), cookie=session_id)
            return
        if parsed.path == "/console":
            self._html("<h1>Operator Console</h1><p>Frame policy intentionally absent.</p>")
            return
        if parsed.path == "/storage":
            self._html(_storage_page())
            return
        if parsed.path == "/api/profile":
            payload = {"user": "analyst", "role": "operator"}
            if self.headers.get("Origin"):
                payload["cors_flag"] = FLAG_CORS
            self._json(payload, cors=True)
            return
        if parsed.path == "/logout":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"{COOKIE_NAME}=deleted; Max-Age=0; Path=/")
            self.end_headers()
            return
        self.send_error(HTTPStatus.NOT_FOUND, "unknown path")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/transfer":
            self.send_error(HTTPStatus.NOT_FOUND, "unknown path")
            return
        fields = urllib.parse.parse_qs(self.rfile.read(_content_length(self)).decode())
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        session_id = cookie.get(COOKIE_NAME).value if cookie.get(COOKIE_NAME) else ""
        expected = CSRF_BY_SESSION.get(session_id, "")
        supplied = fields.get("csrf_token", [""])[0]
        if not supplied:
            self._html(f"<h1>Transfer queued</h1><p>{html.escape(FLAG_CSRF)}</p>")
            return
        if supplied == expected:
            self._html("<h1>Transfer queued</h1><p>Saved with token.</p>")
            return
        self._html("<h1>Invalid CSRF token</h1>", status=HTTPStatus.FORBIDDEN)

    def _session_id(self) -> str:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get(COOKIE_NAME)
        if morsel and morsel.value:
            return morsel.value
        return secrets.token_hex(10)

    def _cors_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")

    def _websocket_upgrade(self) -> None:
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        self.send_response(HTTPStatus.SWITCHING_PROTOCOLS)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

    def _json(self, payload: dict[str, object], *, cors: bool = False) -> None:
        body = json.dumps(payload).encode()
        self.send_response(HTTPStatus.OK)
        if cors:
            self._cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: str, *, status: HTTPStatus = HTTPStatus.OK, cookie: str = "") -> None:
        data = (
            "<!doctype html><html><head><title>Session Boundary Lab</title></head>"
            f"<body>{body}</body></html>"
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if cookie:
            self.send_header("Set-Cookie", f"{COOKIE_NAME}={cookie}; Path=/")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _home() -> str:
    return """
<h1>Session Boundary Lab</h1>
<nav>
  <a href="/transfer">Transfer</a>
  <a href="/console">Console</a>
  <a href="/storage">Storage</a>
  <a href="/api/profile">Profile API</a>
</nav>
<script>
const socketPath = "ws://" + location.host + "/ws";
</script>
"""


def _transfer_form(token: str) -> str:
    return f"""
<h1>Transfer Credits</h1>
<form method="post" action="/transfer">
  <input type="hidden" name="csrf_token" value="{html.escape(token)}">
  <input name="amount" value="25">
  <input name="recipient" value="research">
  <button type="submit">Save transfer</button>
</form>
<a href="/logout">Logout</a>
"""


def _storage_page() -> str:
    return f"""
<h1>Browser Storage</h1>
<script>
sessionStorage.setItem("supportDebugToken", "{FLAG_STORAGE}");
</script>
"""


def _content_length(handler: BaseHTTPRequestHandler) -> int:
    try:
        return int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        return 0


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), BoundaryHandler).serve_forever()
