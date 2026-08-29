from __future__ import annotations

# ruff: noqa: ARG002,E501,I001,PLR0911,RUF012,S324

import base64
import hashlib
import json
import secrets
import threading
import urllib.parse
from collections.abc import Iterator, Mapping
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import pytest

from ravage.agent_core.action_executor import execute_action
from ravage.agent_core.agent_state import AgentState
from ravage.run_data.audit import AuditStore
from ravage.web_core.http_probe import ProbeSession
from ravage.probes.web_boundaries import probe_browser_boundary, probe_csrf_session
from ravage.runtime import ToolRuntime
from ravage.run_data.workspace import AgentWorkspace


@pytest.fixture
def boundary_server() -> Iterator[str]:
    _BoundaryHandler.csrf_by_session = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BoundaryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_csrf_session_probe_extracts_omission_flag(boundary_server: str) -> None:
    result = probe_csrf_session(ProbeSession(boundary_server, timeout_seconds=5), AgentState())
    types = {finding.get("type") for finding in result.findings}

    assert result.ok
    assert "csrf_omission_extracted_proof" in types
    assert "session_cookie_attribute_signal" in types
    assert "flag{csrf_omission_takeover}" in json.dumps(result.findings)


def test_browser_boundary_probe_covers_cors_storage_clickjacking_and_websocket(boundary_server: str) -> None:
    result = probe_browser_boundary(ProbeSession(boundary_server, timeout_seconds=5), AgentState())
    types = {finding.get("type") for finding in result.findings}

    assert result.ok
    assert "cors_extracted_proof" in types
    assert "browser_storage_secret_exposure" in types
    assert "clickjacking_frame_policy_missing" in types
    assert "websocket_cross_origin_handshake_signal" in types
    assert "flag{cors_boundary_read}" in json.dumps(result.findings)
    assert "flag{storage_boundary_secret}" in json.dumps(result.findings)


def test_run_probe_csrf_session_captures_flag(boundary_server: str, tmp_path) -> None:  # noqa: ANN001
    state = AgentState()
    audit = AuditStore(tmp_path / "audit.db")
    workspace = AgentWorkspace.open(tmp_path / "workspace")
    try:
        outcome = execute_action(
            {
                "action": "run_probe",
                "task_id": "stateful-session",
                "probe": "csrf_session",
                "timeout_seconds": 5,
            },
            target_url=boundary_server,
            runtime=ToolRuntime(),
            state=state,
            workspace=workspace,
            audit=audit,
            engagement_id=uuid4(),
            repeat_count=1,
            max_observation_chars=4000,
            max_transcript_chars=12000,
            proof_recognition_enabled=True,
        )
    finally:
        audit.close()

    assert outcome.stop
    assert outcome.flag == "flag{csrf_omission_takeover}"
    assert state.flags == ["flag{csrf_omission_takeover}"]


class _BoundaryHandler(BaseHTTPRequestHandler):
    csrf_by_session: dict[str, str] = {}

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_OPTIONS(self) -> None:
        if self.path.startswith("/api/"):
            self.send_response(HTTPStatus.NO_CONTENT)
            self._cors_headers()
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Ravage-Probe")
            self.end_headers()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_GET(self) -> None:
        if self.headers.get("Upgrade", "").lower() == "websocket" and self.path.startswith("/ws"):
            self._websocket_upgrade()
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self._html(
                """
<h1>Boundary App</h1>
<a href="/transfer">Transfer</a>
<a href="/console">Console</a>
<a href="/storage">Storage</a>
<script>const wsUrl = "ws://" + location.host + "/ws";</script>
"""
            )
            return
        if parsed.path == "/transfer":
            session_id = secrets.token_hex(8)
            token = secrets.token_hex(8)
            self.csrf_by_session[session_id] = token
            self._html(
                f"""
<h1>Transfer</h1>
<form method="post" action="/transfer">
  <input type="hidden" name="csrf_token" value="{token}">
  <input name="amount" value="10">
  <input name="recipient" value="research">
  <button type="submit">Save</button>
</form>
<a href="/logout">Logout</a>
""",
                cookie=session_id,
            )
            return
        if parsed.path == "/console":
            self._html("<h1>Admin Console</h1><p>missing frame policy</p>")
            return
        if parsed.path == "/storage":
            self._html(
                '<h1>Storage</h1><script>sessionStorage.setItem("supportToken", "flag{storage_boundary_secret}");</script>'
            )
            return
        if parsed.path == "/api/profile":
            payload: dict[str, object] = {"user": "analyst"}
            if self.headers.get("Origin"):
                payload["flag"] = "flag{cors_boundary_read}"
            self._json(payload, cors=True)
            return
        if parsed.path == "/logout":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "boundary_session=deleted; Max-Age=0; Path=/")
            self.end_headers()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path != "/transfer":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        fields = urllib.parse.parse_qs(self.rfile.read(_content_length(self)).decode())
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        session_morsel = cookie.get("boundary_session")
        session_id = ""
        if session_morsel is not None:
            session_id = session_morsel.value
        expected = self.csrf_by_session.get(session_id, "")
        token = fields.get("csrf_token", [""])[0]
        if not token:
            self._html("<h1>Transfer saved</h1><p>flag{csrf_omission_takeover}</p>")
            return
        if token == expected:
            self._html("<h1>Transfer saved</h1><p>saved with token</p>")
            return
        self._html("<h1>Invalid CSRF token</h1>", status=HTTPStatus.FORBIDDEN)

    def _cors_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")

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

    def _json(self, payload: Mapping[str, object], *, cors: bool = False) -> None:
        body = json.dumps(payload).encode()
        self.send_response(HTTPStatus.OK)
        if cors:
            self._cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(
        self,
        body: str,
        *,
        status: HTTPStatus = HTTPStatus.OK,
        cookie: str = "",
    ) -> None:
        data = f"<!doctype html><html><body>{body}</body></html>".encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if cookie:
            self.send_header("Set-Cookie", f"boundary_session={cookie}; Path=/")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _content_length(handler: BaseHTTPRequestHandler) -> int:
    try:
        return int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        return 0
