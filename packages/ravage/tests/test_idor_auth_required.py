from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

from ravage import probe_suite
from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite import run_builtin_probe
from ravage.web_core.http_probe import ProbeResponse

if TYPE_CHECKING:
    from ravage.probe_suite_parts.result import ProbeRunResult

_FLAG = "flag{idor_neighbour_object_5b9f}"
_COOKIE_IDENTITY_FLAG = "flag{idor_cookie_identity_bearer_base64}"
_PRIVILEGE_FIELD_FLAG = "flag{idor_privilege_field_auth_replay}"
_AUTH_NUMERIC_PATH_FLAG = "flag{idor_authenticated_numeric_path}"
_AUTH_QUERY_PARAM_FLAG = "flag{idor_authenticated_query_parameter}"
_PASSWORD_CHANGE_FLAG = "flag{idor_password_change_admin_takeover}"
_FIRST_USER_OBJECTID_FLAG = "flag{idor_first_user_objectid_counter}"


class _BaseFakeSession:
    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        self.target_url = target_url
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = timeout_seconds

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        return self.request("GET", url)

    def post_form(self, url: str, fields: dict[str, str], *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers, fields
        return self.request("POST", url)

    def request(self, method: str, url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None) -> ProbeResponse:
        del data, headers
        fields = {key: values[-1] for key, values in parse_qs(urlsplit(url).query).items()}
        return self._response(method, url, fields)

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        raise NotImplementedError


class _FirstUserObjectIdSession(_BaseFakeSession):
    first_timestamp = 1_700_000_000
    middle = "abcdef1234"
    first_id = f"{first_timestamp:08x}{middle}000001"
    new_id = f"{first_timestamp + 30:08x}{middle}000006"

    def post_form(self, url: str, fields: dict[str, str], *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del fields, headers
        if urlsplit(url).path == "/register":
            return ProbeResponse(
                method="POST",
                url=url,
                status=200,
                final_url=url,
                elapsed_ms=5,
                body=json.dumps(
                    {
                        "userId": self.new_id,
                        "message": "User created successfully.",
                        "maybehint": "You are 5 from your target user",
                    }
                ),
            )
        return ProbeResponse(method="POST", url=url, status=404, final_url=url, elapsed_ms=5, body="missing")

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        del fields
        path = urlsplit(url).path
        if path in {"", "/", "/info", "/register", "/login"}:
            body = (
                "<h1>GetTheFirst</h1>"
                f"<p>1st user to register here was at Unix timestamp: {self.first_timestamp}</p>"
                '<a href="/register">Register</a><a href="/login">Login</a><a href="/starttime">StartTime</a>'
            )
            return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=body)
        if path == "/starttime":
            return ProbeResponse(
                method=method,
                url=url,
                status=200,
                final_url=url,
                elapsed_ms=5,
                body=str(self.first_timestamp),
            )
        if path == f"/profile/{self.first_id}":
            return ProbeResponse(
                method=method,
                url=url,
                status=200,
                final_url=url,
                elapsed_ms=5,
                body=f"<h1>Welcome, user0</h1><p>{_FIRST_USER_OBJECTID_FLAG}</p>",
            )
        if path.startswith("/profile/"):
            return ProbeResponse(
                method=method,
                url=url,
                status=200,
                final_url=url,
                elapsed_ms=5,
                body="<h1>Welcome, current user</h1>-",
            )
        return ProbeResponse(method=method, url=url, status=404, final_url=url, elapsed_ms=5, body="missing")


def test_idor_boundary_derives_first_user_mongo_objectid(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _FirstUserObjectIdSession)
    state = AgentState()
    state.surface["visible_description"] = (
        "Users can register, log in, and view profiles. The objective is to view "
        "the first user, and the system provides the start timestamp when that user was created."
    )
    state.signals = {
        "endpoints": ["http://127.0.0.1/register", "http://127.0.0.1/profile"],
        "forms": [
            json.dumps(
                {
                    "action": "http://127.0.0.1/register",
                    "method": "POST",
                    "inputs": [{"name": "username"}, {"name": "password", "type": "password"}],
                }
            )
        ],
    }

    result = run_builtin_probe("idor_boundary", target_url="http://127.0.0.1/", state=state)

    assert result.ok
    assert any(
        _FIRST_USER_OBJECTID_FLAG in _finding_proofs(finding)
        for finding in result.findings
    )


class _AuthWalledSession(_BaseFakeSession):
    """Every ID-bearing object requires a login the probe does not hold."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        body = "<h1>401 Unauthorized</h1> login required"
        return ProbeResponse(method=method, url=url, status=401, final_url=url, elapsed_ms=5, body=body)


class _OpenNeighbourSession(_BaseFakeSession):
    """No auth wall; a neighbouring id leaks the flag."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        ident = fields.get("id", "")
        if ident == "9":
            body = f"<div>order 9 of victim — {_FLAG}</div>"
        else:
            body = "<div>order 10 of current user</div>"
        return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=body)


def _state_with_id_param() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/order",
        "origin": "http://127.0.0.1",
        "parameters": [
            {
                "name": "id",
                "locations": ["http://127.0.0.1/order?id=10"],
                "value": "10",
                "hints": ["object_id"],
                "priority": 80,
            }
        ],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/order?id=10", "hints": ["object"]}],
    }
    return state


def _findings_types(result: ProbeRunResult) -> set[str]:
    return {str(f.get("type")) for f in result.findings}


def _finding_proofs(finding: dict[str, object]) -> list[str]:
    proofs = finding.get("proofs")
    if not isinstance(proofs, list):
        return []
    return [str(proof) for proof in proofs]


def _finding_with_proof(result: ProbeRunResult, proof: str) -> dict[str, object]:
    for finding in result.findings:
        if proof in _finding_proofs(finding):
            return finding
    message = f"finding proof not found: {proof}"
    raise AssertionError(message)


def _replay(finding: dict[str, object]) -> dict[str, object]:
    replay = finding.get("replay")
    assert isinstance(replay, dict)
    return {str(key): value for key, value in replay.items()}


def _replay_headers(finding: dict[str, object]) -> dict[str, object]:
    headers = _replay(finding).get("headers")
    assert isinstance(headers, dict)
    return {str(key): value for key, value in headers.items()}


def _request_target(request: dict[str, object]) -> dict[str, object]:
    target = request.get("target")
    assert isinstance(target, dict)
    return {str(key): value for key, value in target.items()}


def test_auth_walled_idor_emits_authentication_guidance(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _AuthWalledSession)

    result = run_builtin_probe("idor_boundary", target_url="http://127.0.0.1/order", state=_state_with_id_param())

    assert "idor_requires_authentication" in _findings_types(result)
    guidance = next(f for f in result.findings if f["type"] == "idor_requires_authentication")
    auth_blocked_targets = guidance.get("auth_blocked_targets")
    assert isinstance(auth_blocked_targets, list)
    assert auth_blocked_targets
    next_step = str(guidance.get("next") or "")
    assert "stateful_session" in next_step or "log in" in next_step


def test_open_idor_does_not_emit_auth_guidance(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _OpenNeighbourSession)

    result = run_builtin_probe("idor_boundary", target_url="http://127.0.0.1/order", state=_state_with_id_param())

    types = _findings_types(result)
    assert "idor_requires_authentication" not in types
    assert any(_FLAG in _finding_proofs(f) for f in result.findings)


class _PathIdorSession(_BaseFakeSession):
    """Path-based IDOR: /order/<id>/receipt leaks a neighbouring order."""

    def _response(self, method: str, url: str, fields: dict[str, str]) -> ProbeResponse:
        del fields
        path = urlsplit(url).path
        if path == "/order/9/receipt":
            body = f"<div>receipt for victim order 9 — {_FLAG}</div>"
        else:
            body = "<div>receipt for order 10 (current user)</div>"
        return ProbeResponse(method=method, url=url, status=200, final_url=url, elapsed_ms=5, body=body)


def _state_with_path_id() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/order/10/receipt",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/order/10/receipt", "hints": ["receipt"]}],
    }
    return state


def test_path_based_idor_enumerates_numeric_path_segment(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _PathIdorSession)

    result = run_builtin_probe(
        "idor_boundary", target_url="http://127.0.0.1/order/10/receipt", state=_state_with_path_id()
    )

    assert any(_FLAG in _finding_proofs(f) for f in result.findings)
    # The winning request must rewrite the numeric path segment, not a query string.
    assert any("/order/9/receipt" in str(r.get("url", "")) for r in result.requests)
    assert not any("?" in str(r.get("url", "")) and "id=" in str(r.get("url", "")) for r in result.findings)


class _HeaderIdorSession(_BaseFakeSession):
    """Identity-header IDOR: an X-User-Id header overrides the absent session."""

    _identity = {h.lower() for h in (
        "X-User-Id", "X-UserId", "X-User", "X-Account-Id", "X-Customer-Id",
        "X-Id", "X-Auth-User", "X-Authenticated-User", "X-Remote-User",
        "X-Forwarded-User", "User-Id", "X-Userid",
    )}

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        ident = None
        for name, value in (headers or {}).items():
            if name.lower() in self._identity:
                ident = value
                break
        if ident is None:
            body = "<div>please log in to view your dashboard</div>"
        elif ident == "3":
            body = f"<div>dashboard for user 3 (admin) — {_FLAG}</div>"
        else:
            body = f"<div>dashboard for user {ident} with orders and account email</div>"
        return ProbeResponse(method="GET", url=url, status=200, final_url=url, elapsed_ms=5, body=body)

    def request(self, method: str, url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None) -> ProbeResponse:
        del data
        return self.get(url, headers=headers)


def _state_with_dashboard() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/dashboard",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/dashboard", "hints": ["dashboard"]}],
    }
    return state


def test_identity_header_idor_swaps_user_via_request_header(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _HeaderIdorSession)

    result = run_builtin_probe("idor_boundary", target_url="http://127.0.0.1/dashboard", state=_state_with_dashboard())

    assert any(_FLAG in _finding_proofs(f) for f in result.findings)
    assert any(str(f.get("type", "")).startswith("idor_identity_header") for f in result.findings)
    winner = _finding_with_proof(result, _FLAG)
    assert _replay_headers(winner)


class _CookieIdentityIdorSession(_BaseFakeSession):
    """Cookie identity IDOR: access_token="Bearer MQ==" means company 1."""

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        cookie = (headers or {}).get("Cookie", "")
        if path == "/openapi.json":
            body = json.dumps(
                {
                    "paths": {
                        "/company/{company_id}/jobs": {"get": {}},
                        "/edit_profile/{company_id}": {"get": {}},
                    }
                }
            )
            return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=5, body=body)
        if path == "/company/1/jobs" and 'access_token="Bearer MQ=="' in cookie:
            return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=5, body="jobs for company 1")
        if path == "/edit_profile/1" and 'access_token="Bearer MQ=="' in cookie:
            return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=5, body="edit company 1")
        if path == "/company/2/jobs" and 'access_token="Bearer Mg=="' in cookie:
            body = f"jobs for company 2 {_COOKIE_IDENTITY_FLAG}"
            return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=5, body=body)
        if path == "/edit_profile/2" and 'access_token="Bearer Mg=="' in cookie:
            return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=5, body="edit company 2")
        return ProbeResponse(method="GET", url=absolute, status=401, final_url=absolute, elapsed_ms=5, body="Unauthorized")

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, method
        return self.get(url, headers=headers)


def _state_with_bearer_base64_cookie() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/company/1/jobs",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [
            {"url": "http://127.0.0.1/company/1/jobs", "hints": ["authenticated", "company"]},
            {"url": "http://127.0.0.1/edit_profile/1", "hints": ["authenticated", "profile"]},
        ],
    }
    state.signals = {
        "cookies": ['access_token="Bearer MQ=="'],
        "endpoints": [
            "http://127.0.0.1/company/1/jobs",
            "http://127.0.0.1/edit_profile/1",
        ],
    }
    return state


def test_idor_boundary_mutates_bearer_base64_identity_cookie(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _CookieIdentityIdorSession)

    result = run_builtin_probe(
        "idor_boundary",
        target_url="http://127.0.0.1/company/1/jobs",
        state=_state_with_bearer_base64_cookie(),
    )

    assert any(_COOKIE_IDENTITY_FLAG in _finding_proofs(f) for f in result.findings)
    winner = _finding_with_proof(result, _COOKIE_IDENTITY_FLAG)
    assert winner["type"] == "idor_cookie_identity_exposed_secret"
    assert winner["cookie"] == "access_token"
    assert winner["original_identity"] == "1"
    assert winner["candidate_identity"] == "2"
    assert _replay(winner)["url"] == "http://127.0.0.1/company/2/jobs"
    assert _replay_headers(winner)["Cookie"] == 'access_token="Bearer Mg=="'


class _AuthenticatedPrivilegeFieldSession(_BaseFakeSession):

    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        super().__init__(target_url, timeout_seconds=timeout_seconds)
        self.is_admin = False

    @staticmethod
    def _authenticated(headers: dict[str, str] | None) -> bool:
        return "access_token=demo-token" in str((headers or {}).get("Cookie") or "")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        if not self._authenticated(headers):
            return ProbeResponse(
                method="GET",
                url=absolute,
                status=401,
                final_url=absolute,
                elapsed_ms=5,
                body='{"detail":"Not authenticated"}',
            )
        if path == "/company/1/jobs" and self.is_admin:
            return ProbeResponse(
                method="GET",
                url=absolute,
                status=200,
                final_url=absolute,
                elapsed_ms=5,
                body=f"admin job queue {_PRIVILEGE_FIELD_FLAG}",
            )
        if path == "/edit_profile/1":
            return ProbeResponse(
                method="GET",
                url=absolute,
                status=200,
                final_url=absolute,
                elapsed_ms=5,
                body="edit company profile",
            )
        return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=5, body="jobs")

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        absolute = self.absolute(url)
        if not self._authenticated(headers):
            return ProbeResponse(
                method="POST",
                url=absolute,
                status=401,
                final_url=absolute,
                elapsed_ms=5,
                body='{"detail":"Not authenticated"}',
            )
        if fields.get("is_admin") in {"1", "true", "True", "on"}:
            self.is_admin = True
        return ProbeResponse(
            method="POST",
            url=absolute,
            status=200,
            final_url=absolute,
            elapsed_ms=5,
            body="Profile updated successfully",
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data
        return self.get(url, headers=headers) if method.upper() == "GET" else self.post_form(url, {}, headers=headers)


def _state_with_authenticated_privilege_form() -> AgentState:
    state = AgentState()
    auth_headers = {"Cookie": "access_token=demo-token"}
    state.surface = {
        "target_url": "http://127.0.0.1/company/1/jobs",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [
            {"url": "http://127.0.0.1/company/1/jobs", "hints": ["authenticated", "company"]},
            {"url": "http://127.0.0.1/edit_profile/1", "hints": ["authenticated", "profile"]},
        ],
    }
    state.signals = {
        "forms": [
            json.dumps(
                {
                    "action": "http://127.0.0.1/edit_profile/1",
                    "auth_headers": auth_headers,
                    "categories": ["authenticated", "profile"],
                    "id": "auth-followup-form-0",
                    "inputs": [
                        {"disabled": False, "name": "name", "required": True, "type": "text", "value": "demo"},
                        {"disabled": True, "name": "is_admin", "required": False, "type": "select", "value": ""},
                    ],
                    "method": "POST",
                },
                sort_keys=True,
            )
        ],
        "auth_headers": ["Cookie: access_token=demo-token"],
        "endpoints": [
            "http://127.0.0.1/company/1/jobs",
            "http://127.0.0.1/edit_profile/1",
        ],
    }
    return state


def test_privilege_field_idor_preserves_authenticated_replay_headers(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _AuthenticatedPrivilegeFieldSession)

    result = run_builtin_probe(
        "idor_boundary",
        target_url="http://127.0.0.1/company/1/jobs",
        state=_state_with_authenticated_privilege_form(),
    )

    assert any(_PRIVILEGE_FIELD_FLAG in _finding_proofs(f) for f in result.findings)
    winner = _finding_with_proof(result, _PRIVILEGE_FIELD_FLAG)
    assert winner["type"] == "vertical_idor_privilege_field"
    assert _replay_headers(winner)["Cookie"] == "access_token=demo-token"
    assert any(
        request.get("probe_kind") == "privilege_escalation_submit" and request.get("authenticated") is True
        for request in result.requests
    )


class _AuthenticatedNumericPathIdorSession(_BaseFakeSession):
    """Path IDOR: /company/<id>/jobs requires preserving the auth cookie."""

    @staticmethod
    def _authenticated(headers: dict[str, str] | None) -> bool:
        return "session=valid" in str((headers or {}).get("Cookie") or "")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        if not self._authenticated(headers):
            return ProbeResponse(method="GET", url=absolute, status=401, final_url=absolute, elapsed_ms=5, body="login required")
        if path == "/company/2/jobs":
            return ProbeResponse(
                method="GET",
                url=absolute,
                status=200,
                final_url=absolute,
                elapsed_ms=5,
                body=f"jobs for company 2 {_AUTH_NUMERIC_PATH_FLAG}",
            )
        if path == "/company/1/jobs":
            return ProbeResponse(
                method="GET",
                url=absolute,
                status=200,
                final_url=absolute,
                elapsed_ms=5,
                body="jobs for company 1",
            )
        return ProbeResponse(method="GET", url=absolute, status=404, final_url=absolute, elapsed_ms=5, body="missing")

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data
        return self.get(url, headers=headers) if method.upper() == "GET" else self.post_form(url, {}, headers=headers)


def _state_with_authenticated_company_jobs_path() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/company/1/jobs",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [{"url": "http://127.0.0.1/company/1/jobs", "hints": ["authenticated", "company"]}],
    }
    state.signals = {
        "auth_headers": ["Cookie: session=valid"],
        "cookies": ["session=valid"],
        "endpoints": ["http://127.0.0.1/company/1/jobs"],
    }
    return state


def test_idor_boundary_preserves_auth_headers_for_numeric_path_targets(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _AuthenticatedNumericPathIdorSession)

    result = run_builtin_probe(
        "idor_boundary",
        target_url="http://127.0.0.1/company/1/jobs",
        state=_state_with_authenticated_company_jobs_path(),
    )

    assert any(_AUTH_NUMERIC_PATH_FLAG in _finding_proofs(f) for f in result.findings)
    winner = _finding_with_proof(result, _AUTH_NUMERIC_PATH_FLAG)
    assert _replay(winner)["url"] == "http://127.0.0.1/company/2/jobs"
    assert _replay_headers(winner)["Cookie"] == "session=valid"
    assert any(
        request.get("probe_kind") == "idor_candidate"
        and request.get("candidate_id") == "2"
        and _request_target(request).get("authenticated") is True
        for request in result.requests
    )


class _AuthenticatedQueryParamIdorSession(_BaseFakeSession):
    """An authenticated object API exposes adjacent IDs in a query parameter."""

    @staticmethod
    def _authenticated(headers: dict[str, str] | None) -> bool:
        return "session=valid" in str((headers or {}).get("Cookie") or "")

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        absolute = self.absolute(url)
        parts = urlsplit(absolute)
        if not self._authenticated(headers):
            return ProbeResponse(
                method="GET",
                url=absolute,
                status=401,
                final_url=absolute,
                elapsed_ms=5,
                body="authentication required",
            )
        if parts.path != "/api/invoices":
            return ProbeResponse(
                method="GET",
                url=absolute,
                status=404,
                final_url=absolute,
                elapsed_ms=5,
                body="missing",
            )
        invoice_id = parse_qs(parts.query).get("id", [""])[-1]
        if invoice_id == "9002":
            body = json.dumps(
                {
                    "id": 9002,
                    "owner_id": 2,
                    "notes": _AUTH_QUERY_PARAM_FLAG,
                }
            )
        else:
            body = json.dumps({"id": 9001, "owner_id": 1, "title": "current invoice"})
        return ProbeResponse(
            method="GET",
            url=absolute,
            status=200,
            final_url=absolute,
            elapsed_ms=5,
            body=body,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data
        return self.get(url, headers=headers)


def test_idor_boundary_mutates_authenticated_query_id_in_place(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _AuthenticatedQueryParamIdorSession)
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/api/invoices?id=9001",
        "origin": "http://127.0.0.1",
        "parameters": [],
        "forms": [],
        "endpoints": [
            {
                "url": "http://127.0.0.1/api/invoices?id=9001",
                "hints": ["authenticated", "invoice"],
            }
        ],
    }
    state.signals = {
        "auth_headers": ["Cookie: session=valid"],
        "cookies": ["session=valid"],
        "endpoints": ["http://127.0.0.1/api/invoices?id=9001"],
    }

    result = run_builtin_probe(
        "idor_boundary",
        target_url="http://127.0.0.1/api/invoices?id=9001",
        state=state,
    )

    assert any(_AUTH_QUERY_PARAM_FLAG in _finding_proofs(f) for f in result.findings)
    winner = _finding_with_proof(result, _AUTH_QUERY_PARAM_FLAG)
    assert _replay(winner)["url"] == "http://127.0.0.1/api/invoices?id=9002"
    assert _replay_headers(winner)["Cookie"] == "session=valid"
    assert any(
        request.get("probe_kind") == "idor_authenticated_object_followup"
        and request.get("url") == "http://127.0.0.1/api/invoices?id=9002"
        for request in result.requests
    )


class _PasswordChangeBackend:
    def __init__(self) -> None:
        self.next_id = 20
        self.users: dict[int, dict[str, str]] = {
            7: {
                "username": "admin",
                "email": "admin@example.test",
                "password": "AdminOld123!",
                "role": "ADMIN",
            }
        }


class _PasswordChangeIdorSession(_BaseFakeSession):
    """Password-change IDOR: userId in AJAX POST decides whose password changes."""

    def __init__(
        self,
        target_url: str,
        *,
        timeout_seconds: int = 10,
        backend: _PasswordChangeBackend | None = None,
    ) -> None:
        super().__init__(target_url, timeout_seconds=timeout_seconds)
        self.backend = backend or _PasswordChangeBackend()
        self.user_id: int | None = None

    def fork(self, *, timeout_seconds: int | None = None) -> "_PasswordChangeIdorSession":
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        return _PasswordChangeIdorSession(
            self.target_url,
            timeout_seconds=timeout,
            backend=self.backend,
        )

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        if path not in {"/profile.php", "/profile", "/dashboard.php", "/dashboard"}:
            return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=5, body="ok")
        if self.user_id is None:
            return ProbeResponse(
                method="GET",
                url=absolute,
                status=401,
                final_url=absolute,
                elapsed_ms=5,
                body="login required",
            )
        user = self.backend.users[self.user_id]
        if user["role"] == "ADMIN":
            body = f"<h1>Admin profile</h1><p>{_PASSWORD_CHANGE_FLAG}</p>"
        else:
            body = (
                "<script>\n"
                "$.ajax({\n"
                "  url: 'api/change_password.php',\n"
                "  method: 'POST',\n"
                "  data: {\n"
                "    oldPassword: $('#oldPassword').val(),\n"
                "    newPassword: $('#newPassword').val(),\n"
                "    confirmPassword: $('#confirmPassword').val(),\n"
                f"    userId: {self.user_id}\n"
                "  }\n"
                "});\n"
                "</script>"
            )
        return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=5, body=body)

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        if path.endswith("/register.php") or path.endswith("/register"):
            return self._register(absolute, fields)
        if path.endswith("/login.php") or path.endswith("/login"):
            return self._login(absolute, fields)
        if "password" in path:
            return self._change_password(absolute, fields)
        return ProbeResponse(method="POST", url=absolute, status=404, final_url=absolute, elapsed_ms=5, body="missing")

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data
        if method.upper() == "GET":
            return self.get(url, headers=headers)
        return self.post_form(url, {}, headers=headers)

    def _register(self, url: str, fields: dict[str, str]) -> ProbeResponse:
        user_id = self.backend.next_id
        self.backend.next_id += 1
        username = fields.get("username") or fields.get("user") or f"user{user_id}"
        self.backend.users[user_id] = {
            "username": username,
            "email": fields.get("email") or f"{username}@example.test",
            "password": fields.get("password") or "",
            "role": "USER",
        }
        return self._json_response("POST", url, {"success": True, "id": user_id})

    def _login(self, url: str, fields: dict[str, str]) -> ProbeResponse:
        username = fields.get("username") or fields.get("user") or fields.get("email") or ""
        password = fields.get("password") or ""
        for user_id, user in self.backend.users.items():
            if username not in {user["username"], user["email"]}:
                continue
            if password != user["password"]:
                continue
            self.user_id = user_id
            return self._json_response("POST", url, {"success": True})
        return self._json_response("POST", url, {"success": False, "message": "Invalid username or password"})

    def _change_password(self, url: str, fields: dict[str, str]) -> ProbeResponse:
        if self.user_id is None:
            return self._json_response("POST", url, {"success": False, "message": "User not authenticated"}, status=401)
        current = self.backend.users[self.user_id]
        old_password = fields.get("oldPassword") or fields.get("old_password") or ""
        if old_password != current["password"]:
            return self._json_response("POST", url, {"success": False, "message": "Old password is incorrect"})
        target_id = int(fields.get("userId") or fields.get("user_id") or fields.get("id") or self.user_id)
        target = self.backend.users.get(target_id)
        if target is None:
            return self._json_response("POST", url, {"success": False, "message": "No such user"})
        target["password"] = fields.get("newPassword") or fields.get("new_password") or fields.get("password") or ""
        return self._json_response("POST", url, {"success": True, "message": "Password changed successfully"})

    @staticmethod
    def _json_response(
        method: str,
        url: str,
        payload: dict[str, object],
        *,
        status: int = 200,
    ) -> ProbeResponse:
        return ProbeResponse(
            method=method,
            url=url,
            status=status,
            final_url=url,
            elapsed_ms=5,
            body=json.dumps(payload),
        )


class _AccountIdPasswordChangeIdorSession(_PasswordChangeIdorSession):
    """Same flaw, but the frontend template names the target field accountId."""

    def fork(self, *, timeout_seconds: int | None = None) -> "_AccountIdPasswordChangeIdorSession":
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        return _AccountIdPasswordChangeIdorSession(
            self.target_url,
            timeout_seconds=timeout,
            backend=self.backend,
        )

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del headers
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        if path not in {"/profile.php", "/profile", "/dashboard.php", "/dashboard"}:
            return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=5, body="ok")
        if self.user_id is None:
            return ProbeResponse(
                method="GET",
                url=absolute,
                status=401,
                final_url=absolute,
                elapsed_ms=5,
                body="login required",
            )
        user = self.backend.users[self.user_id]
        if user["role"] == "ADMIN":
            body = f"<h1>Admin profile</h1><p>{_PASSWORD_CHANGE_FLAG}</p>"
        else:
            body = (
                "<script>\n"
                "$.ajax({\n"
                "  url: 'api/account_password.php',\n"
                "  method: 'POST',\n"
                "  data: {\n"
                "    currentPassword: $('#currentPassword').val(),\n"
                "    replacementPassword: $('#replacementPassword').val(),\n"
                f"    accountId: {self.user_id}\n"
                "  }\n"
                "});\n"
                "</script>"
            )
        return ProbeResponse(method="GET", url=absolute, status=200, final_url=absolute, elapsed_ms=5, body=body)

    def _change_password(self, url: str, fields: dict[str, str]) -> ProbeResponse:
        if self.user_id is None:
            return self._json_response("POST", url, {"success": False, "message": "User not authenticated"}, status=401)
        current = self.backend.users[self.user_id]
        old_password = fields.get("currentPassword") or ""
        if old_password != current["password"]:
            return self._json_response("POST", url, {"success": False, "message": "Old password is incorrect"})
        raw_target_id = fields.get("accountId") or str(self.user_id)
        target = self.backend.users.get(int(raw_target_id))
        if target is None:
            return self._json_response("POST", url, {"success": False, "message": "No such user"})
        target["password"] = fields.get("replacementPassword") or ""
        return self._json_response("POST", url, {"success": True, "message": "Password changed successfully"})


def _state_with_password_change_idor() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/profile.php",
        "origin": "http://127.0.0.1",
        "visible_description": "IDOR allows a low-privilege user to change another user's password.",
        "parameters": [],
        "forms": [],
        "endpoints": [
            {"url": "http://127.0.0.1/api/register.php", "hints": ["auth"]},
            {"url": "http://127.0.0.1/api/login.php", "hints": ["auth"]},
            {"url": "http://127.0.0.1/profile.php", "hints": ["profile"]},
            {"url": "http://127.0.0.1/api/change_password.php", "hints": ["password"]},
        ],
    }
    state.signals = {
        "endpoints": [
            "http://127.0.0.1/api/register.php",
            "http://127.0.0.1/api/login.php",
            "http://127.0.0.1/profile.php",
            "http://127.0.0.1/api/change_password.php",
        ],
        "parameters": ["userId", "oldPassword", "newPassword", "confirmPassword"],
        "markers": ["idor", "password"],
    }
    state.facts = [
        "Description suggests an IDOR where a low-privilege user can change another user's password."
    ]
    return state


def test_idor_boundary_exploits_password_change_userid_override(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _PasswordChangeIdorSession)

    result = run_builtin_probe(
        "idor_boundary",
        target_url="http://127.0.0.1/profile.php",
        state=_state_with_password_change_idor(),
    )

    assert any(_PASSWORD_CHANGE_FLAG in _finding_proofs(f) for f in result.findings)
    winner = _finding_with_proof(result, _PASSWORD_CHANGE_FLAG)
    assert winner["type"] == "idor_password_change_exposed_secret"
    assert winner["changed_user_id"] == "7"
    assert any(
        request.get("probe_kind") == "idor_password_change_candidate"
        and request.get("candidate_user_id") == "7"
        for request in result.requests
    )


def test_idor_boundary_uses_frontend_password_change_field_names(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _AccountIdPasswordChangeIdorSession)

    result = run_builtin_probe(
        "idor_boundary",
        target_url="http://127.0.0.1/profile.php",
        state=_state_with_password_change_idor(),
    )

    assert any(_PASSWORD_CHANGE_FLAG in _finding_proofs(f) for f in result.findings)
    winner = _finding_with_proof(result, _PASSWORD_CHANGE_FLAG)
    replay = winner.get("replay")
    assert isinstance(replay, dict)
    form = replay.get("form")
    assert isinstance(form, dict)
    assert replay.get("payload_field") == "accountId"
    assert form.get("accountId") == "7"
