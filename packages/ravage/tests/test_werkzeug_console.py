from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from urllib.parse import parse_qs, urlsplit

import pytest

from ravage.agent_core.agent_state import AgentState
from ravage.probes.werkzeug_console import compute_werkzeug_pin, probe_werkzeug_console
from ravage.web_core.http_probe import ProbeSession

SECRET = "FLAG{w3rkz3ug_c0nsole_rce}"
_DEBUGGER_SECRET = "testsecret123"
_TOKEN_RE = re.compile(r"RAVAGE_WZ_[0-9a-f]+")

_DEBUGGER_PAGE = (
    "<html><head><title>Error</title></head><body>"
    "<h1>Werkzeug Debugger</h1>"
    "<div class=\"traceback\">Traceback (most recent call last):</div>"
    "<script>var CONSOLE_MODE = true, EVALEX = true, EVALEX_TRUSTED = false, "
    f'SECRET = "{_DEBUGGER_SECRET}";</script>'
    "<div class=\"console\" data-frm=\"140234567\">?frm=140234567</div>"
    "</body></html>"
)


class _UnlockedConsoleHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        params = parse_qs(parts.query)
        if "__debugger__" not in params:
            self._send(_DEBUGGER_PAGE)
            return
        if params.get("s", [""])[0] != _DEBUGGER_SECRET:
            self._send("Forbidden")
            return
        cmd = params.get("cmd", [""])[0]
        if "cat " in cmd or "environ" in cmd:  # simulated RCE output
            self._send(f"<span class=object>{SECRET}</span>")
            return
        token = _TOKEN_RE.search(cmd)
        self._send(f"<span>{token.group(0) if token else 'None'}</span>")

    def _send(self, body: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


class _LockedConsoleHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        params = parse_qs(parts.query)
        if "__debugger__" not in params:
            self._send(_DEBUGGER_PAGE)
            return
        # PIN-protected: eval never returns output until pinauth succeeds (it never does here).
        self._send('{"auth": false, "exhausted": false}')

    def _send(self, body: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    return server, thread, f"http://127.0.0.1:{port}/"


@pytest.fixture()
def unlocked_console():
    server, thread, url = _serve(_UnlockedConsoleHandler)
    try:
        yield url
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.fixture()
def locked_console():
    server, thread, url = _serve(_LockedConsoleHandler)
    try:
        yield url
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _types(result) -> set[str]:
    return {str(f.get("type")) for f in result.findings}


def test_unlocked_console_evals_to_proof(unlocked_console: str) -> None:
    session = ProbeSession(unlocked_console, timeout_seconds=5)
    result = probe_werkzeug_console(session, AgentState())

    types = _types(result)
    assert "werkzeug_console_exposed" in types
    assert "werkzeug_console_unlocked" in types
    assert "werkzeug_console_extracted_proof" in types
    proofs = [f["proof"] for f in result.findings if f.get("type") == "werkzeug_console_extracted_proof"]
    assert SECRET in proofs


def test_locked_console_is_reported_and_abandoned(locked_console: str) -> None:
    session = ProbeSession(locked_console, timeout_seconds=5)
    result = probe_werkzeug_console(session, AgentState())

    types = _types(result)
    assert "werkzeug_console_exposed" in types
    assert "werkzeug_console_locked" in types
    assert "werkzeug_console_extracted_proof" not in types


def test_no_console_returns_not_ok() -> None:
    class _Plain:
        target_url = "http://127.0.0.1/"

        def absolute(self, path: str) -> str:
            from urllib.parse import urljoin

            return urljoin(self.target_url, path)

        def get(self, url: str, **_: object):
            from ravage.web_core.http_probe import ProbeResponse

            return ProbeResponse(method="GET", url=url, status=404, final_url=url, elapsed_ms=1, headers={}, body="not found")

    session = cast(ProbeSession, _Plain())
    result = probe_werkzeug_console(session, AgentState())
    assert result.ok is False


def test_compute_werkzeug_pin_is_nine_digits_and_deterministic() -> None:
    bits = {
        "username": "root",
        "modname": "flask.app",
        "appname": "Flask",
        "modfile": "/usr/local/lib/python3.11/site-packages/flask/app.py",
        "mac_decimal": "2485377892893",
        "machine_id": "3e1b9f8a7c6d5e4f3a2b1c0d9e8f7a6b",
    }
    pin = compute_werkzeug_pin(**bits)
    assert pin.isdigit() and len(pin) == 9
    assert compute_werkzeug_pin(**bits) == pin  # deterministic
