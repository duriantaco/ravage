from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest

from ravage.agent_core.agent_state import AgentState
from ravage.probes.specialists import (
    _looks_storable_target,
    _stored_eval_signal,
    _try_stored_ssti,
)
from ravage.web_core.http_probe import ProbeSession

SECRET = "FLAG{st0red_ssti_pwn}"
_FINGERPRINT_EVAL = {
    "{{7*7}}": "49",
    "{{7*'7'}}": "7777777",
    "{{'ravage'|upper}}": "RAVAGE",
    "{{'ravage'.upper()}}": "RAVAGE",
}
_RCE_MARKERS = ("popen", "globals", "__class__", "config", "subprocess", "cycler", "lipsum", "mro", "import", "__")


def _render(stored: str) -> str:
    if not stored:
        return "<div class=comment></div>"
    out = stored
    for pattern, value in _FINGERPRINT_EVAL.items():
        out = out.replace(pattern, value)
    if any(marker in stored for marker in _RCE_MARKERS):  # simulated template RCE
        out = SECRET
    return f"<div class=comment>{out}</div>"


class _StoredSstiHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        comment = parse_qs(body).get("comment", [""])[0]
        self.server.last_comment = comment  # type: ignore[attr-defined]
        self._send("saved")

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/comments"):
            self._send(_render(getattr(self.server, "last_comment", "")))
        else:
            self._send("<h1>home</h1>")

    def _send(self, body: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def stored_ssti_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StoredSstiHandler)
    server.last_comment = ""  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_stored_eval_signal_logic() -> None:
    assert _stored_eval_signal("result is 49 here", "no value", ["49"], "{{7*7}}")
    assert not _stored_eval_signal("{{7*7}}", "", ["49"], "{{7*7}}")  # payload reflected unrendered
    assert not _stored_eval_signal("49", "49", ["49"], "{{7*7}}")  # value already present in baseline


def test_looks_storable_target() -> None:
    assert _looks_storable_target({"kind": "form", "input": "x"})
    assert _looks_storable_target({"kind": "query_param", "input": "comment"})
    assert not _looks_storable_target({"kind": "query_param", "input": "q"})


def test_stored_deferred_ssti_extracts_proof(stored_ssti_server: str) -> None:
    session = ProbeSession(stored_ssti_server, timeout_seconds=5)
    state = AgentState()
    state.signals["endpoints"] = [stored_ssti_server + "comments"]
    target = {
        "kind": "form",
        "url": stored_ssti_server + "comment",
        "input": "comment",
        "form": {
            "action": stored_ssti_server + "comment",
            "method": "post",
            "inputs": [{"name": "comment", "type": "text"}],
        },
    }

    finding, _requests, _budget = _try_stored_ssti(session, state, [target], budget=28)

    assert finding is not None
    assert finding["type"] == "ssti_extracted_proof"
    assert finding["channel"] == "stored_deferred"
    assert SECRET in finding["proofs"]
