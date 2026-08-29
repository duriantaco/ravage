from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

from ravage import probe_suite
from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeResponse
from ravage.probe_suite_parts.support import _interesting_exposure_body
from ravage.probe_suite_parts.general.general_api import probe_api_behavior
from ravage.probe_suite import run_builtin_probe


def _jwt(payload: Mapping[str, object]) -> str:
    header = {"alg": "none", "typ": "JWT"}
    return ".".join((_b64(header), _b64(payload), ""))


def _b64(value: Mapping[str, object]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_direct_exposure_does_not_promote_plain_login_form() -> None:
    body = '<html><form action="/login"><input name="username"><input type="password" name="password"></form></html>'

    assert not _interesting_exposure_body(body, "http://127.0.0.1/login")
    assert _interesting_exposure_body("DB_PASSWORD=s3cret", "http://127.0.0.1/.env")


class _ApiBehaviorSession:
    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        self.target_url = target_url
        self.origin = "http://127.0.0.1"
        self.timeout_seconds = timeout_seconds
        self.token = _jwt({"sub": "42", "username": "guest", "admin": False})

    def absolute(self, value: str) -> str:
        return value if value.startswith("http") else self.origin + value

    def in_scope(self, url: str) -> bool:
        return url.startswith(self.origin)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        return self.request("GET", url, headers=headers)

    def post_form(self, url: str, fields: dict[str, str], *, headers: dict[str, str] | None = None) -> ProbeResponse:
        del fields
        return self.request("POST", url, headers=headers)

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
        if method == "GET" and path == "/api/me":
            body = json.dumps({"token": self.token, "user": "guest"})
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        if method == "OPTIONS":
            return ProbeResponse(method=method, url=absolute, status=204, final_url=absolute, elapsed_ms=2, headers={"allow": "GET,POST,OPTIONS"}, body="")
        if method == "POST" and path == "/graphql":
            query = json.loads((data or b"{}").decode("utf-8")).get("query", "")
            if "__schema" in query:
                body = json.dumps(
                    {
                        "data": {
                            "__schema": {
                                "queryType": {"name": "Query"},
                                "types": [
                                    {"name": "Query", "kind": "OBJECT", "fields": [{"name": "me"}]},
                                    {"name": "User", "kind": "OBJECT", "fields": [{"name": "username"}]},
                                ],
                            }
                        }
                    }
                )
            else:
                body = json.dumps({"data": {"__typename": "Query"}})
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=4, body=body)
        return ProbeResponse(method=method, url=absolute, status=404, final_url=absolute, elapsed_ms=2, body="missing")


def _api_state() -> AgentState:
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "endpoints": [
            {"url": "http://127.0.0.1/api/me", "hints": ["api"]},
            {"url": "http://127.0.0.1/graphql", "hints": ["api", "graphql"]},
        ],
    }
    return state


def test_api_behavior_records_graphql_schema_and_observed_jwt(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _ApiBehaviorSession)

    result = run_builtin_probe("api_behavior", target_url="http://127.0.0.1/", state=_api_state())

    jwt_findings = [finding for finding in result.findings if finding.get("type") == "jwt_observed"]
    assert jwt_findings
    jwt_finding = jwt_findings[0]
    assert jwt_finding.get("algorithm") == "none"

    claims = jwt_finding.get("claims")
    assert isinstance(claims, dict)
    assert claims.get("username") == "guest"

    weakness = jwt_finding.get("weakness")
    assert isinstance(weakness, dict)
    assert weakness.get("kind") == "unsigned_jwt"

    schema_findings = [finding for finding in result.findings if finding.get("type") == "graphql_schema_signal"]
    assert schema_findings
    signal = schema_findings[0].get("signal")
    assert isinstance(signal, dict)
    type_names = signal.get("type_names")
    assert isinstance(type_names, list)
    assert "User" in type_names
    assert any(request.get("probe_kind") == "graphql_introspection" for request in result.requests)


class _RecordingApiBehaviorSession(_ApiBehaviorSession):
    def __init__(self, target_url: str, *, timeout_seconds: int = 10) -> None:
        super().__init__(target_url, timeout_seconds=timeout_seconds)
        self.requested: list[str] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        self.requested.append(self.absolute(url))
        absolute = self.absolute(url)
        if urlsplit(absolute).path == "/openapi.json":
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=2, body='{"openapi":"3.0.0"}')
        return super().request(method, url, data=data, headers=headers)


def test_api_behavior_prefers_same_origin_api_docs_over_static_assets() -> None:
    session = _RecordingApiBehaviorSession("http://127.0.0.1/")
    state = AgentState()
    state.surface = {
        "target_url": "http://127.0.0.1/",
        "origin": "http://127.0.0.1",
        "endpoints": [
            {"url": "https://cdn.example.test/bootstrap.min.js", "hints": ["api"]},
            {"url": "http://127.0.0.1/static/js/app.js", "hints": ["api"]},
            {"url": "http://127.0.0.1/openapi.json", "hints": []},
            {"url": "http://127.0.0.1/api/me", "hints": ["api"]},
        ],
    }

    result = probe_api_behavior(cast(Any, session), state)

    assert result.ok is True
    assert session.requested[0] == "http://127.0.0.1/openapi.json"
    assert not any("cdn.example.test" in url for url in session.requested)
    assert not any("/static/js/app.js" in url for url in session.requested)


class _DisclosureSession(_ApiBehaviorSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        absolute = self.absolute(url)
        path = urlsplit(absolute).path
        if path == "/openapi.json":
            body = json.dumps({"openapi": "3.0.0", "paths": {"/admin": {"get": {"summary": "Admin"}}}})
            return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=3, body=body)
        if "ravage-missing" in path:
            return ProbeResponse(method=method, url=absolute, status=404, final_url=absolute, elapsed_ms=2, body="missing")
        return ProbeResponse(method=method, url=absolute, status=404, final_url=absolute, elapsed_ms=2, body="missing")


def test_direct_exposure_records_framework_metadata_documents(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _DisclosureSession)

    result = run_builtin_probe("direct_exposure", target_url="http://127.0.0.1/", state=AgentState())

    assert result.ok is True
    assert any(str(finding.get("url") or "").endswith("/openapi.json") for finding in result.findings)
    route_findings = [finding for finding in result.findings if finding.get("type") == "openapi_route_signal"]
    assert route_findings
    routes = route_findings[0].get("routes")
    assert isinstance(routes, list)
    assert routes
    route = routes[0]
    assert isinstance(route, dict)
    assert route.get("url") == "http://127.0.0.1/admin"


class _ListedPrivateFileSession(_ApiBehaviorSession):
    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        del data, headers
        absolute = self.absolute(url)
        parts = urlsplit(absolute)
        if "ravage-missing" in parts.path:
            return ProbeResponse(method=method, url=absolute, status=404, final_url=absolute, elapsed_ms=2, body="missing")
        if parts.path in {"/private", "/private.php"}:
            query = parse_qs(parts.query)
            if query.get("file", [""])[0] == "backup-secret.txt":
                return ProbeResponse(
                    method=method,
                    url=absolute,
                    status=200,
                    final_url=absolute,
                    elapsed_ms=2,
                    body="<pre>flag{listed_private_file}</pre>",
                )
            if query.get("action"):
                body = "<table><tr><td>index.php</td></tr><tr><td>backup-secret.txt</td></tr></table>"
                return ProbeResponse(method=method, url=absolute, status=200, final_url=absolute, elapsed_ms=2, body=body)
        return ProbeResponse(method=method, url=absolute, status=404, final_url=absolute, elapsed_ms=2, body="missing")


def test_direct_exposure_fetches_sensitive_files_discovered_in_private_listing(monkeypatch) -> None:
    monkeypatch.setattr(probe_suite, "ProbeSession", _ListedPrivateFileSession)

    result = run_builtin_probe("direct_exposure", target_url="http://127.0.0.1/", state=AgentState())

    assert result.ok is True
    finding = next(
        finding
        for finding in result.findings
        if finding.get("type") == "direct_exposure_listed_file_proof"
    )
    proofs = finding.get("proofs")
    assert isinstance(proofs, list)
    assert "flag{listed_private_file}" in proofs
    assert str(finding.get("fetch_url") or "").endswith("file=backup-secret.txt")
