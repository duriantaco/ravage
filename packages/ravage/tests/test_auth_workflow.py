from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from urllib.parse import parse_qs

import pytest

from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.auth_credentials import (
    _common_credential_identities,
    _credential_pairs_from_text,
    _default_credential_identities,
    _default_credential_identities_for_state,
    _state_seed_credential_pairs,
)
from ravage.deterministic_agents.auth_discovery import (
    _auth_forms,
    _form_looks_auth_related,
    _form_looks_login_related,
)
from ravage.deterministic_agents.auth_forms import (
    _script_adjusted_password_form,
    _script_identity_headers,
    _script_literal_data_fields,
)
from ravage.deterministic_agents.auth_identity import (
    _identity,
    _identity_fields,
)
from ravage.deterministic_agents.auth_session import (
    probe_auth_session,
    probe_default_credentials,
)
from ravage.deterministic_agents.auth_session_support import (
    access_score,
    cookie_is_privilege_like,
    privilege_cookie_variants,
    rebuild_cookie_header,
    set_cookie_pairs,
)
from ravage.probe_suite import run_builtin_probe
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

SECRET = "FLAG{c00kie_r0le_pwn}"


def test_auth_forms_skip_off_origin_signal_forms() -> None:
    state = AgentState()
    state.surface["origin"] = "http://127.0.0.1:8000"
    state.surface["target_url"] = "http://127.0.0.1:8000/"
    state.signals["forms"] = [
        json.dumps(
            {
                "action": "https://forms.example.test/login",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"},
                ],
            },
            sort_keys=True,
        ),
        json.dumps(
            {
                "action": "http://127.0.0.1:8000/login",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"},
                ],
            },
            sort_keys=True,
        ),
    ]

    forms = _auth_forms(state)

    assert [form["action"] for form in forms] == ["http://127.0.0.1:8000/login"]


def test_default_credential_spray_covers_common_pairs() -> None:
    pairs = {(i["username"], i["password"]) for i in _common_credential_identities()}
    assert ("admin", "admin") in pairs
    assert ("admin", "password") in pairs
    assert ("root", "root") in pairs
    assert len(pairs) >= 8


def test_credential_pair_extraction_keeps_hint_before_todo_comment() -> None:
    body = (
        '<body><!-- test1:test1 TODO: remove before deploy --><form action="/login"></form></body>'
    )

    assert ("test1", "test1") in _credential_pairs_from_text(body)


def test_default_credential_probe_uses_bounded_generic_defaults() -> None:
    pairs = {(i["username"], i["password"]) for i in _default_credential_identities()}
    assert ("admin", "adminpass") in pairs
    assert ("admin", "admin@123") in pairs
    assert ("webadmin", "webadmin") in pairs
    assert ("postgres", "postgres") in pairs
    assert ("john", "password123") in pairs
    assert ("admin", "wordpress") in pairs


def test_default_credential_state_order_prioritizes_common_self_pairs() -> None:
    class _NoopCredentialDiscoverySession:
        target_url = "http://127.0.0.1"

        def absolute(self, path: str) -> str:
            return path if path.startswith("http") else f"{self.target_url}{path}"

        def in_scope(self, url: str) -> bool:
            return url.startswith(self.target_url)

        def get(self, url: str):
            return type(
                "Response",
                (),
                {
                    "status": 404,
                    "body": "",
                    "url": url,
                    "summary": lambda self, body_chars=0: {
                        "status": self.status,
                        "body_len": 0,
                        "url": self.url,
                    },
                },
            )()

    state = AgentState()
    state.surface = {
        "pages": [
            {
                "url": "http://127.0.0.1/login",
                "body": "login page with https://cdn.jsdelivr.net/npm/bootstrap assets",
            }
        ]
    }

    identities = _default_credential_identities_for_state(
        _NoopCredentialDiscoverySession(),  # type: ignore[arg-type]
        state,
        [],
        auth_forms=[],
    )
    pairs = [(identity["username"], identity["password"]) for identity in identities[:5]]

    assert ("user", "user") in pairs
    assert ("demo", "demo") in pairs
    assert not any(username == "cdn.jsdelivr.net" for username, _ in pairs)


def test_authorized_seed_credentials_are_extracted_from_state_without_proofs() -> None:
    state = AgentState()
    state.surface["authorized_seed_credentials"] = [
        {"username": "analyst", "password": "analyst123", "source": "OPERATOR_NOTES.md"},
        {"username": "flag{not_a_user}", "password": "anything"},
        {"username": "admin", "password": "flag{not_a_password}"},
    ]

    assert _state_seed_credential_pairs(state) == [("analyst", "analyst123")]


def test_openapi_username_query_form_is_not_login_surface() -> None:
    form = {
        "action": "http://127.0.0.1/?username=ravage",
        "method": "GET",
        "categories": ["api", "openapi"],
        "inputs": [{"name": "username", "type": "string"}],
    }

    assert _form_looks_auth_related(form) is False
    assert _form_looks_login_related(form) is False


class _ProfilePrivilegeSession:
    def __init__(self, backend: dict[str, bool] | None = None) -> None:
        self.target_url = "http://127.0.0.1"
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = 5
        self.cookies = []
        self._backend = backend if backend is not None else {"premium": False}

    @property
    def premium(self) -> bool:
        return self._backend["premium"]

    @premium.setter
    def premium(self, value: bool) -> None:
        self._backend["premium"] = value

    def fork(self, *, timeout_seconds: int | None = None) -> "_ProfilePrivilegeSession":
        forked = _ProfilePrivilegeSession(self._backend)
        forked.timeout_seconds = timeout_seconds or self.timeout_seconds
        return forked

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        path = self._path(url)
        if path == "/":
            body = (
                '<form method="post" action="/token">'
                '<input name="username"><input name="password" type="password">'
                "</form>"
            )
            return self._response("GET", url, body)
        if path == "/company/1/jobs":
            body = '<a href="/edit_profile/1">profile</a><div>demo public job</div>'
            if self.premium:
                body += "<div>flag{authenticated_privilege_profile}</div>"
            return self._response("GET", url, body)
        if path == "/edit_profile/1":
            body = (
                '<form method="post" action="/edit_profile/1">'
                '<input name="name" value="demo">'
                '<select name="level" disabled><option value="0" selected>Standard</option>'
                '<option value="1">Premium</option></select>'
                "</form>"
            )
            return self._response("GET", url, body)
        return self._response("GET", url, "not found", status=404)

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        path = self._path(url)
        if (
            path == "/token"
            and fields.get("username") == "demo"
            and fields.get("password") == "demo"
        ):
            self.cookies = [type("Cookie", (), {"name": "access_token", "value": "Bearer demo"})()]
            body = '<a href="/edit_profile/1">profile</a><div>demo public job</div>'
            return self._response("POST", url, body, final_url=self.absolute("/company/1/jobs"))
        if path == "/edit_profile/1" and fields.get("level") in {"1", "true", "premium", "9"}:
            self.premium = True
            return self._response("POST", url, "<div>Profile updated successfully</div>")
        return self._response("POST", url, "bad request", status=400)

    def _path(self, url: str) -> str:
        return url.removeprefix(self.origin) or "/"

    def _response(
        self,
        method: str,
        url: str,
        body: str,
        *,
        status: int = 200,
        final_url: str | None = None,
    ) -> ProbeResponse:
        return ProbeResponse(
            method=method,
            url=self.absolute(url),
            status=status,
            final_url=final_url or self.absolute(url),
            elapsed_ms=1,
            body=body,
        )


def test_default_credentials_mutates_authenticated_privilege_profile_form() -> None:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1",
        "origin": "http://127.0.0.1",
        "forms": [
            {
                "method": "POST",
                "action": "http://127.0.0.1/token",
                "inputs": [
                    {"name": "username", "type": "text", "value": ""},
                    {"name": "password", "type": "password", "value": ""},
                ],
                "categories": ["auth"],
            }
        ],
        "endpoints": [{"url": "http://127.0.0.1/company/1/jobs"}],
    }

    session = cast(ProbeSession, _ProfilePrivilegeSession())
    result = probe_default_credentials(session, state)

    assert result.ok is True
    assert any(
        "flag{authenticated_privilege_profile}" in str(finding.get("proofs"))
        for finding in result.findings
    )
    assert any(
        request.get("probe_kind") == "authenticated_privilege_form_submit"
        for request in result.requests
    )


def test_privilege_cookie_variants_map_low_to_high() -> None:
    assert "admin" in privilege_cookie_variants("user")
    assert privilege_cookie_variants("0") == ["1"]
    assert privilege_cookie_variants("false") == ["true"]
    assert privilege_cookie_variants("a1b2c3") == ["admin", "true", "1"]


def test_cookie_is_privilege_like() -> None:
    assert cookie_is_privilege_like("role", "user")
    assert cookie_is_privilege_like("is_admin", "0")
    assert cookie_is_privilege_like("session", "user")  # value is privilege-like
    assert not cookie_is_privilege_like("PHPSESSID", "9f8a7b6c5d4e")


def test_rebuild_cookie_header_only_changes_target() -> None:
    cookies = {"session": "abc", "role": "user"}
    assert rebuild_cookie_header(cookies, "role", "admin") == "session=abc; role=admin"


def test_set_cookie_pairs_skips_attributes() -> None:
    pairs = set_cookie_pairs("role=user; Path=/; HttpOnly")
    assert pairs == [("role", "user")]


def test_script_literal_data_fields_preserve_ajax_submit_marker() -> None:
    body = (
        "$.ajax({method: 'POST', data: {username: username, password: password, submit: 'submit'}})"
    )
    assert _script_literal_data_fields(body) == {"submit": "submit"}


def test_script_adjusted_password_form_uses_same_origin_ajax_target() -> None:
    body = """
    <script>
    $.ajax({
      url: 'index.php',
      method: 'POST',
      data: {username: username, password: password, submit: 'submit'}
    })
    </script>
    """
    form = {
        "action": "http://example.test/",
        "method": "GET",
        "inputs": [
            {"name": "username", "type": "text"},
            {"name": "password", "type": "password"},
        ],
    }
    response = ProbeResponse(
        method="GET",
        url="http://example.test/",
        status=200,
        final_url="http://example.test/",
        elapsed_ms=1,
        headers={},
        body=body,
    )

    adjusted = _script_adjusted_password_form(form, response, _script_identity_headers(body))
    fields = _identity_fields(adjusted, _identity("ajax"))

    assert adjusted["method"] == "POST"
    assert adjusted["action"] == "http://example.test/index.php"
    assert adjusted["script_headers"] == {"X-Requested-With": "XMLHttpRequest"}
    assert fields["submit"] == "submit"


def test_identity_fields_fit_password_minlength() -> None:
    form = {
        "action": "http://example.test/register",
        "method": "POST",
        "inputs": [
            {"name": "username", "type": "text"},
            {"name": "password", "type": "password", "minlength": "24"},
        ],
    }

    fields = _identity_fields(form, _identity("longpass"))

    assert fields["username"].startswith("ravage_longpass_")
    assert len(fields["password"]) >= 24


def test_identity_fields_use_generated_identity_for_registration_name() -> None:
    form = {
        "action": "http://example.test/register",
        "method": "POST",
        "inputs": [
            {"name": "name", "type": "text", "maxlength": "40"},
            {"name": "password", "type": "password", "minlength": "10"},
        ],
    }
    identity = _identity("named")

    fields = _identity_fields(form, identity)

    assert fields["name"] == identity["username"]
    assert fields["name"] != "ravage"


def test_access_score_rewards_access_and_punishes_denial() -> None:
    allowed = ProbeResponse(
        method="GET",
        url="u",
        status=200,
        final_url="u",
        elapsed_ms=1,
        headers={},
        body="admin dashboard",
    )
    denied = ProbeResponse(
        method="GET", url="u", status=403, final_url="u", elapsed_ms=1, headers={}, body="forbidden"
    )
    assert access_score(allowed) > access_score(denied)


# --- real end-to-end cookie-tampering test ------------------------------------


class _RoleCookieHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002 - silence test server
        return

    def do_GET(self) -> None:  # noqa: N802
        cookie = self.headers.get("Cookie", "")
        role = ""
        for pair in cookie.split(";"):
            if "=" in pair and pair.strip().startswith("role="):
                role = pair.strip().split("=", 1)[1]
        if self.path.startswith("/admin"):
            if role == "admin":
                self._send(200, f"<h1>admin panel {SECRET}</h1>")
            else:
                self._send(403, "forbidden")
            return
        # baseline pages issue a low-privilege role cookie
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "role=user; Path=/")
        self.end_headers()
        self.wfile.write(b"<h1>welcome guest</h1>")

    def _send(self, status: int, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture()
def role_cookie_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RoleCookieHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_cookie_role_tampering_reaches_admin_proof(role_cookie_server: str) -> None:
    session = ProbeSession(role_cookie_server, timeout_seconds=5)
    result = probe_auth_session(session, AgentState())

    types = {str(f.get("type")) for f in result.findings}
    assert "auth_extracted_proof" in types
    proofs = [f["proof"] for f in result.findings if f.get("type") == "auth_extracted_proof"]
    assert SECRET in proofs


class _SerializedProfileCookieHandler(BaseHTTPRequestHandler):
    cookie_value = base64.b64encode(
        b'O:11:"UserProfile":2:{s:6:"userid";i:2;s:8:"username";s:5:"alice";}'
    ).decode("ascii")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        self._send(
            200,
            '<form action="/login" method="post">'
            '<input name="username" type="text"><input name="password" type="password">'
            '<button type="submit">Login</button></form>',
        )

    def do_POST(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", f"data={self.cookie_value}; Path=/")
        self.end_headers()
        self.wfile.write(b"<h1>Welcome alice</h1><a href='/logout'>Logout</a>")

    def _send(self, status: int, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class _DefaultCredentialLoginHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/admin"):
            if "sid=admin" in self.headers.get("Cookie", ""):
                self._send(200, f"<h1>admin dashboard {SECRET}</h1>")
            else:
                self._send(403, "forbidden")
            return
        self._send(
            200,
            '<form action="/login" method="post">'
            '<input name="username" type="text"><input name="password" type="password">'
            '<button type="submit">Login</button></form>',
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        params = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if params.get("username") == ["admin"] and params.get("password") == ["password123"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sid=admin; Path=/")
            self.end_headers()
            self.wfile.write(b"<h1>welcome admin</h1><a href='/logout'>Logout</a>")
            return
        self._send(401, "invalid credentials")

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def default_credential_login_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DefaultCredentialLoginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class _LoginFailureWithPublicNavHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        self._send(
            200,
            '<nav><a href="/dashboard">Dashboard</a><a href="/admin">Admin</a>'
            '<a href="/invoices">Invoices</a></nav>'
            '<form action="/login" method="post">'
            '<input name="username" type="text"><input name="password" type="password">'
            '<button type="submit">Login</button></form>',
        )

    def do_POST(self) -> None:  # noqa: N802
        self._send(
            401,
            '<nav><a href="/dashboard">Dashboard</a><a href="/admin">Admin</a>'
            '<a href="/invoices">Invoices</a></nav>'
            "Invalid username or password.",
        )

    def _send(self, status: int, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture()
def login_failure_with_public_nav_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LoginFailureWithPublicNavHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_default_credentials_does_not_confirm_public_nav_after_failed_login(
    login_failure_with_public_nav_server: str,
) -> None:
    state = AgentState()
    state.surface["forms"] = [
        {
            "action": login_failure_with_public_nav_server + "login",
            "method": "POST",
            "inputs": [
                {"name": "username", "type": "text", "value": ""},
                {"name": "password", "type": "password", "value": ""},
            ],
            "categories": ["auth"],
        }
    ]

    result = probe_default_credentials(
        ProbeSession(login_failure_with_public_nav_server, timeout_seconds=5), state
    )

    assert not any(
        finding.get("type") == "default_credentials_valid" for finding in result.findings
    )
    assert not any(
        finding.get("type") == "auth_session_followup_signal" for finding in result.findings
    )


class _RegisterAndDefaultAdminLoginHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/profile"):
            if "sid=admin" in self.headers.get("Cookie", ""):
                self._send(200, f"<h1>admin profile {SECRET}</h1>")
                return
            self._send(200, "<h1>user profile</h1>")
            return
        self._send(
            200,
            '<form action="/register" method="post">'
            '<input name="username" type="text"><input name="password" type="password">'
            '<button type="submit">Register</button></form>'
            '<form action="/login" method="post">'
            '<input name="username" type="text"><input name="password" type="password">'
            '<button type="submit">Login</button></form>',
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        params = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if self.path == "/register":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sid=user; Path=/")
            self.end_headers()
            self.wfile.write(b"<h1>welcome new user</h1><a href='/profile'>Profile</a>")
            return
        if (
            self.path == "/login"
            and params.get("username") == ["admin"]
            and params.get("password") == ["adminpass"]
        ):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sid=admin; Path=/")
            self.end_headers()
            self.wfile.write(
                f"<h1>welcome admin {SECRET}</h1><a href='/profile'>Profile</a>".encode("utf-8")
            )
            return
        self._send(401, "invalid credentials")

    def _send(self, status: int, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture()
def register_and_default_admin_login_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RegisterAndDefaultAdminLoginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_default_credentials_skips_registration_before_admin_login(
    register_and_default_admin_login_server: str,
) -> None:
    base = register_and_default_admin_login_server.rstrip("/")
    state = AgentState()
    state.surface = {
        "target_url": register_and_default_admin_login_server,
        "origin": base,
        "forms": [
            {
                "action": base + "/register",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text", "value": ""},
                    {"name": "password", "type": "password", "value": ""},
                ],
                "categories": ["auth"],
            },
            {
                "action": base + "/login",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text", "value": ""},
                    {"name": "password", "type": "password", "value": ""},
                ],
                "categories": ["auth"],
            },
        ],
    }

    result = probe_default_credentials(
        ProbeSession(register_and_default_admin_login_server, timeout_seconds=5),
        state,
    )

    assert result.ok
    assert any(finding.get("username") == "admin" for finding in result.findings)
    assert any(SECRET in str(finding.get("proofs")) for finding in result.findings)
    assert not any(
        request.get("probe_kind") == "auth_form_submit"
        and _request_form_action(request).endswith("/register")
        for request in result.requests
    )


class _TrustedProxyLoginHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        self._send(
            200,
            '<form action="/login" method="post">'
            '<input name="username" type="text"><input name="password" type="password">'
            '<button name="submit">Login</button></form>',
        )

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/login" and self.headers.get("X-Forwarded-For") == "127.0.0.1":
            self._send(200, f"<h1>local admin {SECRET}</h1>")
            return
        self._send(403, "forbidden")

    def _send(self, status: int, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture()
def trusted_proxy_login_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TrustedProxyLoginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class _WordPressLoginDefaultCredentialHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/wp-admin/"):
            if "wordpress_logged_in=admin" in self.headers.get("Cookie", ""):
                self._send(200, f"<h1>Dashboard {SECRET}</h1>")
            else:
                self.send_response(302)
                self.send_header("Location", "/wp-login.php?redirect_to=/wp-admin/&reauth=1")
                self.end_headers()
            return
        if self.path.startswith("/wp-login.php"):
            self._send(
                200,
                '<form name="loginform" id="loginform" action="/wp-login.php" method="post">'
                '<input type="text" name="log" id="user_login" value="">'
                '<input type="password" name="pwd" id="user_pass" value="">'
                '<input type="hidden" name="redirect_to" value="/wp-admin/">'
                '<input type="hidden" name="testcookie" value="1">'
                '<input type="submit" name="wp-submit" value="Log In">'
                "</form>",
            )
            return
        self._send(200, "<a href='/wp-login.php'>Log in</a>")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        params = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if params.get("log") == ["admin"] and params.get("pwd") == ["password123"]:
            self.send_response(302)
            self.send_header("Location", "/wp-admin/")
            self.send_header("Set-Cookie", "wordpress_logged_in=admin; Path=/")
            self.end_headers()
            return
        self._send(200, "<form><input name='log'><input type='password' name='pwd'></form>")

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def wordpress_default_credential_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WordPressLoginDefaultCredentialHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class _PublicLoginIgnoresBasicHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        self._send(
            200,
            '<form action="/login" method="post">'
            '<input name="username" type="text"><input name="password" type="password">'
            '<button type="submit">Login</button></form>',
        )

    def do_POST(self) -> None:  # noqa: N802
        self._send(200, '{"response":"username"}')

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def public_login_ignores_basic_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PublicLoginIgnoresBasicHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_default_credentials_does_not_treat_public_page_as_basic_auth(
    public_login_ignores_basic_server: str,
) -> None:
    result = probe_default_credentials(
        ProbeSession(public_login_ignores_basic_server, timeout_seconds=5), AgentState()
    )

    assert not any(
        finding.get("type") == "default_credentials_valid" and finding.get("scheme") == "basic"
        for finding in result.findings
    )


class _BasicAuthMethodBypassHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        self._challenge()

    def do_POST(self) -> None:  # noqa: N802
        self._challenge()

    def do_PUT(self) -> None:  # noqa: N802
        if self.path != "/index.php":
            self._challenge()
            return
        self._send(200, f"<h1>method bypass {SECRET}</h1>")

    def _challenge(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="admin"')
        self.end_headers()

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def basic_auth_method_bypass_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BasicAuthMethodBypassHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_default_credentials_tries_basic_auth_method_bypass(
    basic_auth_method_bypass_server: str,
) -> None:
    result = probe_default_credentials(
        ProbeSession(basic_auth_method_bypass_server, timeout_seconds=5), AgentState()
    )

    proofs = [
        finding.get("proof")
        for finding in result.findings
        if finding.get("type") == "auth_extracted_proof"
    ]
    assert SECRET in proofs
    assert any(
        request.get("probe_kind") == "basic_auth_method_bypass"
        and request.get("method") == "PUT"
        and str(request.get("url", "")).endswith("/index.php")
        for request in result.requests
    )


class _BasicAuthChallengeHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        auth = self.headers.get("Authorization", "")
        expected = "Basic " + base64.b64encode(b"admin:admin").decode("ascii")
        if auth == expected:
            self._send(200, f"<h1>welcome admin {SECRET}</h1>")
            return
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="admin"')
        self.end_headers()

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def basic_auth_challenge_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BasicAuthChallengeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class _RegisterEscalationHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        self._send(
            200,
            '<html><body><form action="/register" method="post">'
            '<input name="username" type="text"><input name="password" type="password">'
            '<button type="submit">Register</button></form></body></html>',
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        # Mass-assignment: the server trusts a client-supplied role field.
        if "role=admin" in body:
            self._send(200, f"<h1>admin account created {SECRET}</h1>")
        else:
            self._send(200, "<h1>welcome new user</h1>")

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def register_escalation_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RegisterEscalationHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_mass_assignment_role_field_extracts_proof(register_escalation_server: str) -> None:
    session = ProbeSession(register_escalation_server, timeout_seconds=5)
    result = probe_auth_session(session, AgentState())

    proofs = [f["proof"] for f in result.findings if f.get("type") == "auth_extracted_proof"]
    assert SECRET in proofs


class _DeferredFlowHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        self._send(
            200,
            '<form id="register" action="/register-step1" method="post">'
            '<input name="name" type="text"><button type="submit">Register</button></form>',
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        params = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if self.path == "/register-step1":
            name = params.get("name", [""])[0]
            self._send(
                200,
                '<form action="/register-step2" method="post">'
                f'<input type="hidden" name="name" value="{name}">'
                '<input name="email" type="email"><button type="submit">Next</button></form>',
            )
            return
        if self.path == "/register-step2" and params.get("name", [""])[0] == "{{7*7}}":
            self._send(200, f"<h1>registration complete {SECRET}</h1>")
            return
        self._send(200, "<h1>registration complete</h1>")

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def deferred_flow_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DeferredFlowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_deferred_multi_step_form_flow_extracts_proof(deferred_flow_server: str) -> None:
    session = ProbeSession(deferred_flow_server, timeout_seconds=5)
    result = probe_auth_session(session, AgentState())

    proofs = [f["proof"] for f in result.findings if f.get("type") == "auth_extracted_proof"]
    assert SECRET in proofs


class _DeferredTemplateContextHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        self._send(
            200,
            '<form id="register" action="/step1" method="post">'
            '<input name="name" type="text"><button type="submit">Register</button></form>',
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        params = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if self.path == "/step1":
            name = params.get("name", [""])[0]
            self._send(
                200,
                '<form action="/step2" method="post">'
                f'<input type="hidden" name="name" value="{name}">'
                '<input name="email" type="email"><button type="submit">Next</button></form>',
            )
            return
        if self.path == "/step2" and params.get("name", [""])[0] in {"{{ flag }}", "{{flag}}"}:
            self._send(200, f"<script>alert('{SECRET}')</script>")
            return
        self._send(200, "<h1>registration complete</h1>")

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def deferred_template_context_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DeferredTemplateContextHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_deferred_form_flow_extracts_template_context_proof(
    deferred_template_context_server: str,
) -> None:
    result = probe_auth_session(
        ProbeSession(deferred_template_context_server, timeout_seconds=5), AgentState()
    )

    proofs = [f["proof"] for f in result.findings if f.get("type") == "auth_extracted_proof"]
    assert SECRET in proofs


class _RedirectedDeferredTemplateHandler(BaseHTTPRequestHandler):
    stored_names: dict[str, str] = {}

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/step2"):
            self._send(
                200,
                '<form action="/step2" method="post">'
                '<input name="email" type="email"><button type="submit">Next</button></form>',
            )
            return
        if self.path.startswith("/step3"):
            name = self.stored_names.get(self._session_id(), "")
            rendered = SECRET if name in {"{{ flag }}", "{{flag}}"} else name
            self._send(200, f'<script>alert("Hello {rendered}")</script>')
            return
        self._send(
            200,
            '<form action="/step1" method="post">'
            '<input name="name" type="text" maxlength="100">'
            '<input name="password" type="password" minlength="10">'
            '<button type="submit">Next</button></form>',
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        params = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if self.path == "/step1":
            sid = base64.b16encode(threading.current_thread().name.encode("utf-8"))[:12].decode(
                "ascii"
            )
            self.stored_names[sid] = params.get("name", [""])[0]
            self.send_response(302)
            self.send_header("Location", "/step2")
            self.send_header("Set-Cookie", f"sid={sid}; Path=/")
            self.end_headers()
            return
        if self.path == "/step2":
            self.send_response(302)
            self.send_header("Location", "/step3")
            self.end_headers()
            return
        self._send(400, "invalid")

    def _session_id(self) -> str:
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("sid="):
                return part.split("=", 1)[1]
        return ""

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def redirected_deferred_template_server():
    _RedirectedDeferredTemplateHandler.stored_names = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectedDeferredTemplateHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_deferred_form_flow_extracts_template_context_proof_after_redirect(
    redirected_deferred_template_server: str,
) -> None:
    state = AgentState()
    state.surface["forms"] = [
        {
            "action": redirected_deferred_template_server + "step1",
            "method": "POST",
            "inputs": [
                {"name": "name", "type": "text", "maxlength": "100"},
                {"name": "password", "type": "password", "minlength": "10"},
            ],
            "categories": ["auth"],
        }
    ]

    result = probe_auth_session(
        ProbeSession(redirected_deferred_template_server, timeout_seconds=5), state
    )

    proofs = [f["proof"] for f in result.findings if f.get("type") == "auth_extracted_proof"]
    assert SECRET in proofs
    assert any(
        request.get("probe_kind") == "deferred_form_flow_page"
        and str(request.get("location")).endswith("/step3")
        for request in result.requests
    )


def test_ssti_fingerprint_reuses_deferred_registration_workflow_after_redirect(
    redirected_deferred_template_server: str,
) -> None:
    state = AgentState()
    state.surface["forms"] = [
        {
            "action": redirected_deferred_template_server + "step1",
            "method": "POST",
            "inputs": [
                {"name": "name", "type": "text", "maxlength": "100"},
                {"name": "password", "type": "password", "minlength": "10"},
            ],
            "categories": ["auth", "registration"],
        }
    ]
    state.signals["markers"] = ["django template"]

    result = run_builtin_probe(
        "ssti_fingerprint",
        target_url=redirected_deferred_template_server,
        state=state,
        timeout_seconds=5,
    )

    assert result.ok
    assert result.findings[0]["type"] == "ssti_extracted_proof"
    proofs = result.findings[0]["proofs"]
    assert isinstance(proofs, list)
    assert SECRET in proofs
    assert any(
        request.get("probe_kind") == "ssti_deferred_form_flow_page"
        and str(request.get("location")).endswith("/step3")
        for request in result.requests
    )


def _request_form_action(request: dict[str, object]) -> str:
    form = request.get("form")
    if not isinstance(form, dict):
        return ""
    return str(form.get("action") or "")


class _MultiStepRegistrationHandler(BaseHTTPRequestHandler):
    token = "multi-step-token"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/step2"):
            self._send(
                200,
                '<form action="/step2" method="post">'
                f'<input type="hidden" name="csrfmiddlewaretoken" value="{self.token}">'
                '<input type="email" name="email" required>'
                '<button type="submit">Next</button></form>',
            )
            return
        if self.path.startswith("/step3"):
            self._send(
                200,
                '<form action="/step3" method="post">'
                f'<input type="hidden" name="csrfmiddlewaretoken" value="{self.token}">'
                '<input type="checkbox" name="is_premium">'
                '<button type="submit">Complete</button></form>',
            )
            return
        self._send(
            200,
            '<form action="/step1" method="post">'
            f'<input type="hidden" name="csrfmiddlewaretoken" value="{self.token}">'
            '<input type="text" name="name" maxlength="100">'
            '<input type="password" name="password" minlength="10">'
            '<button type="submit">Next</button></form>',
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        params = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if params.get("csrfmiddlewaretoken", [""])[0] != self.token:
            self._send(403, "forbidden")
            return
        if self.path == "/step1" and params.get("name") and params.get("password"):
            self._redirect("/step2")
            return
        if self.path == "/step2" and params.get("email", [""])[0].endswith("@example.test"):
            self._redirect("/step3")
            return
        if self.path == "/step3" and params.get("is_premium"):
            self._send(200, f"<h1>registration complete {SECRET}</h1>")
            return
        self._send(400, "invalid")

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def multi_step_registration_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MultiStepRegistrationHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class _WorkflowProgressHandler(BaseHTTPRequestHandler):
    token = "progress-token"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/next"):
            self._send(200, "<h1>Step 2</h1><form method='post'><input name='bio'></form>")
            return
        self._send(
            200,
            (
                '<form action="/register" method="post">'
                f'<input type="hidden" name="csrfmiddlewaretoken" value="{self.token}">'
                '<input name="name" type="text" maxlength="100">'
                '<input name="password" type="password" minlength="10">'
                '<button type="submit">Next</button></form>'
            ),
            headers={"Set-Cookie": f"csrftoken={self.token}; Path=/"},
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        if f"csrfmiddlewaretoken={self.token}" in body and "password=" in body:
            self.send_response(302)
            self.send_header("Location", "/next")
            self.end_headers()
            return
        self._send(200, "<h1>Step 1</h1>")

    def _send(self, status: int, body: str, *, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@pytest.fixture()
def workflow_progress_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WorkflowProgressHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
