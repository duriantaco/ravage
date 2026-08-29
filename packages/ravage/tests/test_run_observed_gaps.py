from __future__ import annotations

import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING

import pytest
from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.auth_session import probe_auth_session
from ravage.probe_suite import _canonical_host_default_headers
from ravage.web_core.http_probe import ProbeSession

if TYPE_CHECKING:
    from collections.abc import Generator

FLAG = "FLAG{run_observed_gap}"


class _HostSensitiveHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:
        if self.headers.get("Host", "").split(":")[0] == "localhost":
            self._send(HTTPStatus.OK, f"<h1>home {FLAG}</h1>")
        else:
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "http://localhost/")
            self.end_headers()

    def _send(self, status: HTTPStatus, body: str) -> None:
        self.send_response(status)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture
def host_sensitive_server() -> Generator[str, None, None]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HostSensitiveHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_canonical_host_default_headers_derived_from_state() -> None:
    state = AgentState()
    assert _canonical_host_default_headers(state) is None
    state.signals["canonical_hosts"] = ["localhost"]
    assert _canonical_host_default_headers(state) == {"Host": "localhost"}
    state.signals["canonical_hosts"] = ["evil.example.com"]  # non-local rejected
    assert _canonical_host_default_headers(state) is None


def test_probe_session_replays_canonical_host(host_sensitive_server: str) -> None:
    plain = ProbeSession(host_sensitive_server, timeout_seconds=5)
    assert plain.get(host_sensitive_server).status == HTTPStatus.FOUND

    canonical = ProbeSession(
        host_sensitive_server,
        timeout_seconds=5,
        default_headers={"Host": "localhost"},
    )
    served = canonical.get(host_sensitive_server)
    assert served.status == HTTPStatus.OK
    assert FLAG in served.body


def test_forked_session_inherits_canonical_host(host_sensitive_server: str) -> None:
    canonical = ProbeSession(
        host_sensitive_server,
        timeout_seconds=5,
        default_headers={"Host": "localhost"},
    )
    forked = canonical.fork()
    assert forked.default_headers == {"Host": "localhost"}
    assert FLAG in forked.get(host_sensitive_server).body


def test_absolute_canonical_host_link_is_rewritten_to_target(host_sensitive_server: str) -> None:
    canonical = ProbeSession(
        host_sensitive_server,
        timeout_seconds=5,
        default_headers={"Host": "localhost"},
    )
    response = canonical.get("http://localhost/")
    assert response.status == HTTPStatus.OK
    assert FLAG in response.body


class _PremiumRegisterHandler(BaseHTTPRequestHandler):

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:
        self._send(
            '<html><body><form action="/register" method="post">'
            '<input name="username" type="text"><input name="password" type="password">'
            "<button>Register</button></form></body></html>"
        )

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        self.rfile.read(length)
        if self.path.startswith("/verify"):
            self._send("<h1>account verified</h1>")
            return
        # Registration response carries the premium proof AND a second-step form.
        self._send(
            f"<h1>premium account created {FLAG}</h1>"
            '<form action="/verify" method="post"><input name="password" type="password"></form>'
        )

    def _send(self, body: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture
def premium_register_server() -> Generator[str, None, None]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PremiumRegisterHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_auth_scans_submit_response_for_proof(premium_register_server: str) -> None:
    session = ProbeSession(premium_register_server, timeout_seconds=5)
    result = probe_auth_session(session, AgentState())

    proofs = [
        finding["proof"]
        for finding in result.findings
        if finding.get("type") == "auth_extracted_proof"
    ]
    assert FLAG in proofs


class _WizardHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:
        self._send(
            '<form action="/accounts/register/step1/" method="post">'
            '<input name="name" type="text"><input name="password" type="password">'
            "<button>Next</button></form>"
        )

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        if self.path.startswith("/accounts/register/step1"):
            self._send(
                '<form action="/accounts/register/step2/" method="post">'
                '<input name="email"><button>Next</button></form>'
            )
        elif self.path.startswith("/accounts/register/step2"):
            self._send(
                '<form action="/accounts/register/step3/" method="post">'
                '<input type="checkbox" name="is_premium"><button>Finish</button></form>'
            )
        elif self.path.startswith("/accounts/register/step3"):
            body = (
                f"<h1>premium account created {FLAG}</h1>"
                if "is_premium" in body
                else "<h1>basic account</h1>"
            )
            self._send(body)
        else:
            self._send("<h1>home</h1>")

    def _send(self, body: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture
def wizard_server() -> Generator[str, None, None]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WizardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_auth_probe_owns_multistep_wizard_with_premium_escalation(wizard_server: str) -> None:
    session = ProbeSession(wizard_server, timeout_seconds=5)
    result = probe_auth_session(session, AgentState())

    proofs = [f["proof"] for f in result.findings if f.get("type") == "auth_extracted_proof"]
    assert FLAG in proofs
