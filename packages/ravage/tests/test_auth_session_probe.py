from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlsplit

from ravage import probe_suite
from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents import auth_session
from ravage.probe_suite import run_builtin_probe
from ravage.web_core.http_probe import ProbeResponse

_AUTH_PROOF = "flag{auth_session_token_replay_92d1c0}"
_OBJECT_IDOR_PROOF = "flag{auth_session_client_side_object_idor}"
_NUMERIC_PATH_IDOR_PROOF = "flag{auth_session_numeric_path_idor}"
_HEADER_IDOR_PROOF = "flag{auth_session_identity_header_idor}"


class _TokenAuthSession:
    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        self.target_url = target_url
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = timeout_seconds
        self.cookies: list[_Cookie] = []

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        return self.request("GET", url, headers=headers)

    def post_form(self, url: str, fields: dict[str, str], *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return self.request("POST", url, data=urlencode(fields).encode("utf-8"))

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        if method == "GET" and path == "/token":
            return ProbeResponse(method=method, url=absolute, status=405, final_url=absolute, elapsed_ms=3, body="")
        if method == "POST" and path == "/token":
            fields = {key: values[-1] for key, values in parse_qs((data or b"").decode()).items()}
            if fields.get("username") == "demo" and fields.get("password") == "demo":
                body = '<html>account <input type="hidden" name="access_token" value="demo-token-12345"></html>'
                return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=4, body=body)
            return ProbeResponse(method=method, url=absolute, status=401, final_url=absolute, elapsed_ms=4, body="invalid")
        if method == "GET" and path == "/json":
            auth = (headers or {}).get("Authorization", "")
            body = _AUTH_PROOF if auth == "Bearer demo-token-12345" else '{"detail":"Unauthorized"}'
            status = 200 if auth == "Bearer demo-token-12345" else 401
            return ProbeResponse(method=method, url=absolute, status=status, final_url=absolute, elapsed_ms=3, body=body)
        return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body="<html>Login</html>")


class _Cookie:
    def __init__(self, name: str, value: str) -> None:
        self.name = name
        self.value = value

class _ProfileUploadAuthSession:
    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        self.target_url = target_url
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = timeout_seconds
        self.cookies: list[_Cookie] = []

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        if path == "/profile" and self._authenticated():
            body = (
                "<html><h1>Profile</h1><a href='/logout'>logout</a>"
                "<form method='post' action='/profile' enctype='multipart/form-data'>"
                "<input type='file' name='loan_file'>"
                "<input type='hidden' name='csrf' value='csrf123'>"
                "</form></html>"
            )
            return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=3, body="<html>Login</html>")

    def post_form(self, url: str, fields: dict[str, str], *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        if urlsplit(absolute).path == "/login" and fields.get("username") == "test" and fields.get("password") == "test":
            self.cookies = [_Cookie("session", "valid")]
            return ProbeResponse(
                method="POST",
                url=absolute,
                status=302,
                final_url=self.absolute("/profile"),
                elapsed_ms=4,
                headers={"set-cookie": "session=valid; HttpOnly"},
                body="",
            )
        return ProbeResponse(method="POST", url=absolute, status=401, final_url=absolute, elapsed_ms=4, body="invalid")

    def _authenticated(self) -> bool:
        return any(cookie.name == "session" and cookie.value == "valid" for cookie in self.cookies)


class _TwoStepClientSideIdorSession:
    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        self.target_url = target_url
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = timeout_seconds
        self.cookies: list[_Cookie] = []
        self.archived_flag_order = False

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        return self.request("GET", url, headers=headers)

    def post_form(self, url: str, fields: dict[str, str], *, headers: dict[str, str] | None = None) -> ProbeResponse:
        return self.request("POST", url, data=urlencode(fields).encode("utf-8"), headers=headers)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        fields = {key: values[-1] for key, values in parse_qs((data or b"").decode()).items()}
        if method == "GET" and path == "/":
            body = '<form method="post"><input name="username"></form>'
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        if method == "POST" and path == "/" and fields.get("username") == "test":
            return ProbeResponse(
                method=method,
                url=absolute,
                status=302,
                final_url=absolute,
                elapsed_ms=4,
                headers={"location": "/password/test"},
                body="",
            )
        if method == "GET" and path == "/password/test":
            body = (
                '<form method="post">'
                '<input name="username" value="test" hidden>'
                '<input name="user_id" value="10032" hidden>'
                '<input type="password" name="password">'
                "</form>"
            )
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        if (
            method == "POST"
            and path == "/password/test"
            and fields.get("password") == "test"
            and fields.get("user_id") == "10032"
        ):
            self.cookies = [_Cookie("session", "valid")]
            return ProbeResponse(
                method=method,
                url=absolute,
                status=302,
                final_url=absolute,
                elapsed_ms=4,
                headers={"location": "/dashboard", "set-cookie": "session=valid; HttpOnly"},
                body="",
            )
        if method == "GET" and path == "/dashboard" and self._authenticated():
            body = '<h1>Dashboard</h1><a href="/orders">Orders</a>'
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        if method == "GET" and path == "/orders" and self._authenticated():
            body = (
                "<script>"
                "$.ajax({url: '/order/' + orderId + '/receipt', method: 'GET'});"
                "$.ajax({url: '/order/' + orderId + '/archive', method: 'GET'});"
                "</script>"
            )
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        if method == "GET" and path == "/orders_archive" and self._authenticated():
            body = (
                '<a href="#" class="receipt-link" data-order-id="300123">Receipt</a>'
                '<a href="#" class="receipt-link" data-order-id="300214">Receipt</a>'
                '<a href="#" class="receipt-link" data-order-id="300327">Receipt</a>'
            )
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        if method == "GET" and path == "/order/300198/archive" and self._authenticated():
            self.archived_flag_order = True
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body="archived")
        if method == "GET" and path == "/order/300198/receipt" and self._authenticated() and self.archived_flag_order:
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=_OBJECT_IDOR_PROOF)
        if method == "GET" and path.startswith("/order/") and self._authenticated():
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body="own receipt")
        return ProbeResponse(method=method, url=absolute, status=404, final_url=absolute, elapsed_ms=3, body="missing")

    def _authenticated(self) -> bool:
        return any(cookie.name == "session" and cookie.value == "valid" for cookie in self.cookies)


class _TwoStepHeaderIdentitySession:
    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        self.target_url = target_url
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = timeout_seconds
        self.cookies: list[_Cookie] = []

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        return self.request("GET", url, headers=headers)

    def post_form(self, url: str, fields: dict[str, str], *, headers: dict[str, str] | None = None) -> ProbeResponse:
        return self.request("POST", url, data=urlencode(fields).encode("utf-8"), headers=headers)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        request_headers = headers or {}
        fields = {key: values[-1] for key, values in parse_qs((data or b"").decode()).items()}
        if method == "GET" and path == "/":
            body = '<form method="post"><input name="username"></form>'
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        if method == "POST" and path == "/" and fields.get("username") == "test":
            body = (
                '<form><input name="username" value="test" hidden>'
                '<input name="user_id" value="10032" hidden>'
                '<input type="password" name="password"></form>'
                "<script>fetch('#', {method:'POST', headers:{'X-UserId':'10032'}});</script>"
            )
            return ProbeResponse(
                method=method,
                url=absolute,
                status=200,
                final_url=self.absolute("/password/test"),
                elapsed_ms=3,
                body=body,
            )
        if (
            method == "POST"
            and path == "/password/test"
            and fields.get("password") == "test"
            and fields.get("user_id") == "10032"
            and request_headers.get("X-UserId") == "10032"
        ):
            self.cookies = [_Cookie("session", "customer")]
            body = '<h1>Dashboard</h1><input type="hidden" name="user_id" value="10032">'
            return ProbeResponse(method=method, url=absolute, status=200, final_url=self.absolute("/dashboard"), elapsed_ms=4, body=body)
        if method == "GET" and path == "/dashboard" and request_headers.get("X-UserId") == "10052":
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=_HEADER_IDOR_PROOF)
        if method == "GET" and path == "/dashboard" and self._authenticated():
            body = '<h1>Dashboard</h1><input type="hidden" name="user_id" value="10032">'
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        return ProbeResponse(method=method, url=absolute, status=404, final_url=absolute, elapsed_ms=3, body="missing")

    def _authenticated(self) -> bool:
        return any(cookie.name == "session" and cookie.value == "customer" for cookie in self.cookies)


class _NumericPathIdorAfterLoginSession:
    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        self.target_url = target_url
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = timeout_seconds
        self.cookies: list[_Cookie] = []

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        return self.request("GET", url, headers=headers)

    def post_form(self, url: str, fields: dict[str, str], *, headers: dict[str, str] | None = None) -> ProbeResponse:
        return self.request("POST", url, data=urlencode(fields).encode("utf-8"), headers=headers)

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        fields = {key: values[-1] for key, values in parse_qs((data or b"").decode()).items()}
        if method == "GET" and path == "/":
            body = (
                '<form method="post" action="/token">'
                '<input name="username">'
                '<input type="password" name="password">'
                '<button name="submit" value="submit">login</button>'
                "</form>"
            )
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        if method == "POST" and path == "/token" and fields.get("username") == "demo" and fields.get("password") == "demo":
            self.cookies = [_Cookie("access_token", "demo")]
            return ProbeResponse(
                method=method,
                url=absolute,
                status=303,
                final_url=self.absolute("/company/1/jobs"),
                elapsed_ms=4,
                headers={"location": "/company/1/jobs", "set-cookie": "access_token=demo; HttpOnly"},
                body="",
            )
        if method == "GET" and path == "/company/1/jobs" and self._authenticated():
            body = "<h2>Jobs for Company 1</h2><p>demo Job 1</p>"
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        if method == "GET" and path == "/company/2/jobs" and self._authenticated():
            body = f"<h2>Jobs for Company 2</h2><p>{_NUMERIC_PATH_IDOR_PROOF}</p>"
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        return ProbeResponse(method=method, url=absolute, status=404, final_url=absolute, elapsed_ms=3, body="missing")

    def _authenticated(self) -> bool:
        return any(cookie.name == "access_token" and cookie.value == "demo" for cookie in self.cookies)


def _state_with_token_form() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "forms": [
            {
                "id": "token",
                "action": "http://127.0.0.1/token",
                "method": "POST",
                "categories": ["auth"],
                "inputs": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}],
            }
        ],
        "endpoints": [{"url": "http://127.0.0.1/json", "hints": ["api"]}],
        "parameters": [],
    }
    return state


def _state_with_profile_login_form() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "forms": [
            {
                "id": "login",
                "action": "http://127.0.0.1/login",
                "method": "POST",
                "categories": ["auth"],
                "inputs": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}],
            }
        ],
        "endpoints": [{"url": "http://127.0.0.1/profile", "hints": ["profile"]}],
        "parameters": [],
    }
    return state


def _empty_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "endpoints": [],
        "forms": [],
        "parameters": [],
    }
    return state


def test_stateful_session_surfaces_authenticated_followup_forms(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _ProfileUploadAuthSession)
    monkeypatch.setattr(auth_session, "ProbeSession", _ProfileUploadAuthSession)

    result = run_builtin_probe("stateful_session", target_url="http://127.0.0.1/", state=_state_with_profile_login_form())

    signals = [finding for finding in result.findings if finding.get("type") == "auth_session_followup_signal"]
    assert signals
    forms = signals[0]["forms"]
    assert isinstance(forms, list)
    assert forms
    form = forms[0]
    assert form["action"] == "http://127.0.0.1/profile"
    assert form["method"] == "POST"
    assert {"authenticated", "upload", "file", "profile"}.issubset(set(form["categories"]))
    assert form["auth_headers"] == {"Cookie": "session=valid"}
    assert any(input_field["name"] == "loan_file" and input_field["type"] == "file" for input_field in form["inputs"])
