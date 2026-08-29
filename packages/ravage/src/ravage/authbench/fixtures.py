from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import parse_qsl

from .contracts import (
    AuthBenchCaseSpec,
    AuthBenchIdentity,
    AuthBenchManifest,
)

FORM_COOKIE_CASE = "form_cookie_login"
ROTATING_CSRF_CASE = "rotating_csrf"
BEARER_REFRESH_CASE = "bearer_refresh"
FORCED_EXPIRY_CASE = "forced_expiry"
TWO_IDENTITY_CASE = "two_identity_isolation"
FALSE_AUTH_CASE = "negative_false_auth"
UNSAFE_POST_CASE = "unsafe_post_no_replay"


@dataclass(frozen=True, slots=True)
class AuthBenchResponse:
    status: int
    body: str = ""
    headers: tuple[tuple[str, str], ...] = ()

    def header(self, name: str) -> str | None:
        wanted = name.casefold()
        for header_name, value in self.headers:
            if header_name.casefold() == wanted:
                return value
        return None

    def json(self) -> dict[str, object]:
        value = json.loads(self.body)
        if not isinstance(value, dict):
            raise ValueError("response body is not a JSON object")
        return value


class AuthBenchClient:
    """Cookie-aware, ``ProbeSession``-shaped client for the local fixture.

    ``SessionManager`` deliberately accepts this client through structural
    compatibility in AuthBench.  That keeps the benchmark deterministic and
    network-free while exercising Ravage's production lifecycle code.
    """

    def __init__(self, fixture: _AuthBenchFixture, label: str) -> None:
        if not label.strip():
            raise ValueError("client label must not be empty")
        self._fixture = fixture
        self.label = label
        self.default_headers: dict[str, str] = {}
        self.cookies: dict[str, str] = {}
        self._fork_count = 0

    def fork(self, *, timeout_seconds: int | None = None) -> AuthBenchClient:
        del timeout_seconds
        self._fork_count += 1
        child = AuthBenchClient(
            self._fixture,
            f"{self.label}/identity-{self._fork_count}",
        )
        child.default_headers.update(self.default_headers)
        return child

    def get(
        self,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> AuthBenchResponse:
        return self.request("GET", path, headers=headers)

    def post_form(
        self,
        path: str,
        form: Mapping[str, str],
        *,
        headers: Mapping[str, str] | None = None,
    ) -> AuthBenchResponse:
        return self.request("POST", path, form=form, headers=headers)

    def request(
        self,
        method: str,
        path: str,
        *,
        form: Mapping[str, str] | None = None,
        data: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> AuthBenchResponse:
        del timeout_seconds
        if not path.startswith("/"):
            raise ValueError("fixture requests require an absolute path")
        if form is not None and data is not None:
            raise ValueError("fixture request accepts either form or data, not both")
        request_headers = dict(self.default_headers)
        request_headers.update(headers or {})
        request_form = dict(form or {})
        if data is not None:
            request_form = dict(parse_qsl(data.decode("utf-8"), keep_blank_values=True))
        if self.cookies and not _has_header(request_headers, "cookie"):
            request_headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in sorted(self.cookies.items())
            )
        response = self._fixture.handle(
            _FixtureRequest(
                method=method.upper(),
                path=path,
                form=request_form,
                headers=request_headers,
                client_label=self.label,
            )
        )
        set_cookie = response.header("set-cookie")
        if set_cookie is not None:
            pair = set_cookie.split(";", 1)[0]
            if "=" in pair:
                name, value = pair.split("=", 1)
                if value:
                    self.cookies[name.strip()] = value.strip()
                else:
                    self.cookies.pop(name.strip(), None)
        return response

    def cookie(self, name: str) -> str | None:
        return self.cookies.get(name)


@dataclass(frozen=True, slots=True)
class AuthBenchCaseContext:
    spec: AuthBenchCaseSpec
    _client_factory: Callable[[str], AuthBenchClient]

    def new_client(self, label: str = "default") -> AuthBenchClient:
        return self._client_factory(label)


@dataclass(frozen=True, slots=True)
class _TruthEvent:
    kind: str
    client_label: str
    identity: str | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class _FixtureRequest:
    method: str
    path: str
    form: Mapping[str, str]
    headers: Mapping[str, str]
    client_label: str


def default_manifest() -> AuthBenchManifest:
    alice = AuthBenchIdentity("alice", "alice@example.test", "correct-horse")
    bob = AuthBenchIdentity("bob", "bob@example.test", "battery-staple")
    cases = (
        AuthBenchCaseSpec(
            case_id=FORM_COOKIE_CASE,
            title="Form login establishes a cookie session",
            entrypoint="/form/login",
            objective="Authenticate Alice and prove the cookie reaches a protected resource.",
            identities=(alice,),
        ),
        AuthBenchCaseSpec(
            case_id=ROTATING_CSRF_CASE,
            title="Rotating CSRF login and mutation",
            entrypoint="/csrf/login",
            objective="Use the current login token and the rotated post-login token.",
            identities=(alice,),
        ),
        AuthBenchCaseSpec(
            case_id=BEARER_REFRESH_CASE,
            title="Bearer access and refresh rotation",
            entrypoint="/bearer/login",
            objective="Recover from access-token expiry with the refresh token.",
            identities=(alice,),
        ),
        AuthBenchCaseSpec(
            case_id=FORCED_EXPIRY_CASE,
            title="Forced cookie-session expiry",
            entrypoint="/expiry/login",
            objective="Detect expiry, sign in again, and restore protected access.",
            identities=(alice,),
        ),
        AuthBenchCaseSpec(
            case_id=TWO_IDENTITY_CASE,
            title="Two independent identities",
            entrypoint="/multi/login",
            objective="Keep Alice and Bob isolated and reject cross-account access.",
            identities=(alice, bob),
        ),
        AuthBenchCaseSpec(
            case_id=FALSE_AUTH_CASE,
            title="False-authentication negative control",
            entrypoint="/negative/login",
            objective="Reject a deceptive login response that never creates a session.",
            identities=(alice,),
        ),
        AuthBenchCaseSpec(
            case_id=UNSAFE_POST_CASE,
            title="Unsafe POST is not replayed after ambiguous expiry",
            entrypoint="/unsafe/login",
            objective="Do not replay a charge that committed before returning 401.",
            identities=(alice,),
        ),
    )
    return AuthBenchManifest(benchmark_id="ravage-authbench-core", revision=1, cases=cases)


class _AuthBenchFixture:
    def __init__(self, spec: AuthBenchCaseSpec) -> None:
        self.spec = spec
        self._events: list[_TruthEvent] = []
        self._counter = 0
        self._sessions: dict[str, str] = {}
        self._expired_sessions: set[str] = set()
        self._csrf_tokens: dict[tuple[str, str], str] = {}
        self._access_tokens: dict[str, tuple[str, int, int]] = {}
        self._refresh_tokens: dict[str, tuple[str, int]] = {}

    def context(self) -> AuthBenchCaseContext:
        return AuthBenchCaseContext(spec=self.spec, _client_factory=self.client)

    def client(self, label: str) -> AuthBenchClient:
        return AuthBenchClient(self, label)

    def truth_events(self) -> tuple[_TruthEvent, ...]:
        return tuple(self._events)

    def handle(self, request: _FixtureRequest) -> AuthBenchResponse:
        handlers = {
            FORM_COOKIE_CASE: self._handle_form_cookie,
            ROTATING_CSRF_CASE: self._handle_rotating_csrf,
            BEARER_REFRESH_CASE: self._handle_bearer_refresh,
            FORCED_EXPIRY_CASE: self._handle_forced_expiry,
            TWO_IDENTITY_CASE: self._handle_two_identity,
            FALSE_AUTH_CASE: self._handle_false_auth,
            UNSAFE_POST_CASE: self._handle_unsafe_post,
        }
        handler = handlers.get(self.spec.case_id)
        if handler is None:
            raise ValueError(f"unsupported AuthBench case: {self.spec.case_id}")
        return handler(request)

    def _handle_form_cookie(self, request: _FixtureRequest) -> AuthBenchResponse:
        if request.method == "GET" and request.path == "/form/login":
            return _html(200, _login_form("/form/login"))
        if request.method == "POST" and request.path == "/form/login":
            identity = self._credential_identity(request)
            if identity is None:
                self._event("login_rejected", request)
                return _html(401, "invalid credentials")
            return self._session_login(request, identity, location="/form/profile")
        if request.method == "GET" and request.path == "/form/profile":
            identity = self._session_identity(request)
            if identity is None:
                self._event("protected_denied", request)
                return _json(401, {"error": "authentication_required"})
            self._event("protected_access", request, identity)
            return _json(200, {"identity": identity})
        return _not_found()

    def _handle_rotating_csrf(self, request: _FixtureRequest) -> AuthBenchResponse:
        if request.method == "GET" and request.path == "/csrf/login":
            token = self._issue_csrf(request, "login")
            return _html(200, _login_form("/csrf/login", csrf_token=token))
        if request.method == "POST" and request.path == "/csrf/login":
            if not self._consume_csrf(request, "login"):
                return _json(403, {"error": "invalid_csrf"})
            identity = self._credential_identity(request)
            if identity is None:
                self._event("login_rejected", request)
                return _json(401, {"error": "invalid_credentials"})
            session = self._new_session(request, identity)
            action_token = self._issue_csrf(request, "action")
            return _json(
                200,
                {"authenticated": True, "csrf_token": action_token},
                set_cookie=_session_cookie(session),
            )
        if request.method == "POST" and request.path == "/csrf/email":
            identity = self._session_identity(request)
            if identity is None:
                self._event("protected_denied", request)
                return _json(401, {"error": "authentication_required"})
            if not self._consume_csrf(request, "action"):
                return _json(403, {"error": "invalid_csrf"})
            self._event("csrf_mutation", request, identity, request.form.get("email", ""))
            next_token = self._issue_csrf(request, "action")
            return _json(200, {"updated": True, "csrf_token": next_token})
        return _not_found()

    def _handle_bearer_refresh(self, request: _FixtureRequest) -> AuthBenchResponse:
        if request.method == "POST" and request.path == "/bearer/login":
            identity = self._credential_identity(request)
            if identity is None:
                self._event("login_rejected", request)
                return _json(401, {"error": "invalid_credentials"})
            access, refresh = self._new_bearer_tokens(identity, generation=1)
            self._event("bearer_login", request, identity)
            return _json(200, {"access_token": access, "refresh_token": refresh})
        if request.method == "GET" and request.path == "/bearer/resource":
            token = _bearer_token(request.headers)
            token_state = self._access_tokens.get(token or "")
            if token_state is None:
                self._event("bearer_denied", request)
                return _json(401, {"error": "invalid_token"})
            identity, remaining_uses, generation = token_state
            if remaining_uses < 1:
                self._event("bearer_expired", request, identity)
                return _json(401, {"error": "token_expired"})
            self._access_tokens[token or ""] = (identity, remaining_uses - 1, generation)
            self._event("bearer_resource", request, identity, str(generation))
            return _json(200, {"identity": identity, "generation": generation})
        if request.method == "POST" and request.path == "/bearer/refresh":
            refresh = request.form.get("refresh_token", "")
            refresh_state = self._refresh_tokens.pop(refresh, None)
            if refresh_state is None:
                self._event("refresh_rejected", request)
                return _json(401, {"error": "invalid_refresh_token"})
            identity, generation = refresh_state
            access, rotated_refresh = self._new_bearer_tokens(identity, generation=generation + 1)
            self._event("bearer_refresh", request, identity, str(generation + 1))
            return _json(200, {"access_token": access, "refresh_token": rotated_refresh})
        return _not_found()

    def _handle_forced_expiry(self, request: _FixtureRequest) -> AuthBenchResponse:
        if request.method == "GET" and request.path == "/expiry/login":
            return _html(200, _login_form("/expiry/login"))
        if request.method == "POST" and request.path == "/expiry/login":
            identity = self._credential_identity(request)
            if identity is None:
                self._event("login_rejected", request)
                return _json(401, {"error": "invalid_credentials"})
            return self._session_login(request, identity, location="/expiry/resource")
        if request.method == "GET" and request.path == "/expiry/resource":
            session = _cookie(request.headers, "authbench_session")
            identity = self._session_identity(request)
            if identity is None:
                if session in self._expired_sessions:
                    self._event("forced_expiry_seen", request)
                else:
                    self._event("protected_denied", request)
                return _json(401, {"error": "session_expired"})
            self._event("expiry_resource", request, identity)
            if session is not None:
                self._expired_sessions.add(session)
            return _json(200, {"identity": identity})
        return _not_found()

    def _handle_two_identity(self, request: _FixtureRequest) -> AuthBenchResponse:
        if request.method == "GET" and request.path == "/multi/login":
            return _html(200, _login_form("/multi/login"))
        if request.method == "POST" and request.path == "/multi/login":
            identity = self._credential_identity(request)
            if identity is None:
                self._event("login_rejected", request)
                return _json(401, {"error": "invalid_credentials"})
            return self._session_login(request, identity, location="/multi/me")
        if request.method == "GET" and request.path == "/multi/me":
            identity = self._session_identity(request)
            if identity is None:
                self._event("protected_denied", request)
                return _json(401, {"error": "authentication_required"})
            self._event("multi_me", request, identity)
            return _json(200, {"identity": identity})
        if request.method == "GET" and request.path.startswith("/multi/user/"):
            identity = self._session_identity(request)
            requested_identity = request.path.removeprefix("/multi/user/")
            if identity is None:
                self._event("protected_denied", request)
                return _json(401, {"error": "authentication_required"})
            if requested_identity != identity:
                self._event("cross_identity_denied", request, identity, requested_identity)
                return _json(403, {"error": "forbidden"})
            self._event("own_identity_access", request, identity)
            return _json(200, {"identity": identity})
        return _not_found()

    def _handle_false_auth(self, request: _FixtureRequest) -> AuthBenchResponse:
        if request.method == "GET" and request.path == "/negative/login":
            return _html(200, _login_form("/negative/login"))
        if request.method == "POST" and request.path == "/negative/login":
            self._event("deceptive_login", request)
            return _html(200, "<h1>Welcome back</h1><p>Authentication queued.</p>")
        if request.method == "GET" and request.path == "/negative/profile":
            self._event("negative_protected_denied", request)
            return _json(401, {"error": "authentication_required"})
        return _not_found()

    def _handle_unsafe_post(self, request: _FixtureRequest) -> AuthBenchResponse:
        if request.method == "GET" and request.path == "/unsafe/login":
            return _html(200, _login_form("/unsafe/login"))
        if request.method == "POST" and request.path == "/unsafe/login":
            identity = self._credential_identity(request)
            if identity is None:
                self._event("login_rejected", request)
                return _json(401, {"error": "invalid_credentials"})
            return self._session_login(request, identity, location="/unsafe/charge")
        if request.method == "POST" and request.path == "/unsafe/charge":
            self._event("unsafe_post_attempt", request)
            identity = self._session_identity(request)
            if identity is None:
                return _json(401, {"error": "session_expired"})
            self._event("unsafe_post_committed", request, identity, request.form.get("amount", ""))
            session = _cookie(request.headers, "authbench_session")
            if session is not None:
                self._expired_sessions.add(session)
            return _json(401, {"error": "session_expired_after_commit"})
        return _not_found()

    def _credential_identity(self, request: _FixtureRequest) -> str | None:
        username = request.form.get("username")
        password = request.form.get("password")
        for identity in self.spec.identities:
            if identity.username == username and identity.password == password:
                return identity.identity_id
        return None

    def _session_login(
        self,
        request: _FixtureRequest,
        identity: str,
        *,
        location: str,
    ) -> AuthBenchResponse:
        session = self._new_session(request, identity)
        return AuthBenchResponse(
            status=303,
            headers=(
                ("Location", location),
                ("Set-Cookie", _session_cookie(session)),
            ),
        )

    def _new_session(self, request: _FixtureRequest, identity: str) -> str:
        session = self._token("session")
        self._sessions[session] = identity
        self._event("session_login", request, identity)
        return session

    def _session_identity(self, request: _FixtureRequest) -> str | None:
        session = _cookie(request.headers, "authbench_session")
        if session is None or session in self._expired_sessions:
            return None
        return self._sessions.get(session)

    def _issue_csrf(self, request: _FixtureRequest, purpose: str) -> str:
        token = self._token(f"csrf-{purpose}")
        self._csrf_tokens[(request.client_label, purpose)] = token
        self._event("csrf_issued", request, detail=purpose)
        return token

    def _consume_csrf(self, request: _FixtureRequest, purpose: str) -> bool:
        key = (request.client_label, purpose)
        expected = self._csrf_tokens.pop(key, None)
        accepted = expected is not None and request.form.get("csrf_token") == expected
        self._event("csrf_accepted" if accepted else "csrf_rejected", request, detail=purpose)
        return accepted

    def _new_bearer_tokens(self, identity: str, *, generation: int) -> tuple[str, str]:
        access = self._token(f"access-{identity}")
        refresh = self._token(f"refresh-{identity}")
        self._access_tokens[access] = (identity, 1, generation)
        self._refresh_tokens[refresh] = (identity, generation)
        return access, refresh

    def _token(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:04d}"

    def _event(
        self,
        kind: str,
        request: _FixtureRequest,
        identity: str | None = None,
        detail: str | None = None,
    ) -> None:
        self._events.append(
            _TruthEvent(
                kind=kind,
                client_label=request.client_label,
                identity=identity,
                detail=detail,
            )
        )


def _login_form(action: str, *, csrf_token: str | None = None) -> str:
    csrf = ""
    if csrf_token is not None:
        csrf = f'<input type="hidden" name="csrf_token" value="{csrf_token}">'
    return (
        f'<form method="post" action="{action}">'
        '<input name="username">'
        '<input name="password" type="password">'
        f"{csrf}</form>"
    )


def _html(status: int, body: str) -> AuthBenchResponse:
    return AuthBenchResponse(status=status, body=body, headers=(("Content-Type", "text/html"),))


def _json(
    status: int,
    value: Mapping[str, object],
    *,
    set_cookie: str | None = None,
) -> AuthBenchResponse:
    headers: list[tuple[str, str]] = [("Content-Type", "application/json")]
    if set_cookie is not None:
        headers.append(("Set-Cookie", set_cookie))
    return AuthBenchResponse(
        status=status,
        body=json.dumps(dict(value), sort_keys=True, separators=(",", ":")),
        headers=tuple(headers),
    )


def _not_found() -> AuthBenchResponse:
    return _json(404, {"error": "not_found"})


def _session_cookie(session: str) -> str:
    return f"authbench_session={session}; Path=/; HttpOnly; SameSite=Lax"


def _cookie(headers: Mapping[str, str], name: str) -> str | None:
    cookie_header = _header(headers, "cookie")
    if cookie_header is None:
        return None
    for item in cookie_header.split(";"):
        if "=" not in item:
            continue
        item_name, value = item.strip().split("=", 1)
        if item_name == name:
            return value
    return None


def _bearer_token(headers: Mapping[str, str]) -> str | None:
    authorization = _header(headers, "authorization")
    if authorization is None:
        return None
    scheme, separator, token = authorization.partition(" ")
    if separator and scheme.casefold() == "bearer" and token:
        return token
    return None


def _has_header(headers: Mapping[str, str], name: str) -> bool:
    return _header(headers, name) is not None


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.casefold()
    for header_name, value in headers.items():
        if header_name.casefold() == wanted:
            return value
    return None
