from __future__ import annotations

import json
from dataclasses import dataclass
from http import HTTPStatus
from http.client import HTTPConnection
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import pytest
import ravage.live_dashboard as dashboard

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@dataclass
class CockpitClient:
    port: int
    token: str
    calls: list[str]

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def authenticate(self) -> str:
        status, headers, body = self.request(
            "/api/session",
            method="POST",
            headers={"Authorization": f"Bearer {self.token}", "Origin": self.origin},
        )
        assert status == HTTPStatus.OK
        payload = json.loads(body)
        assert payload["authenticated"] is True
        assert "Set-Cookie" not in headers
        session = str(payload["session_token"])
        assert session != self.token
        return session


@pytest.fixture
def cockpit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[CockpitClient]:
    calls: list[str] = []

    def fake_teardown(_settings: dashboard.DashboardSettings, run_id: str) -> dict[str, bool]:
        calls.append(run_id)
        return {"ok": True}

    monkeypatch.setattr(dashboard, "teardown_active_run", fake_teardown)
    monkeypatch.setattr(
        dashboard, "build_dashboard_state", lambda _: {"private_run_data": "fixture only"}
    )
    server = dashboard.start_cockpit(dashboard.DashboardSettings(workspace_dir=tmp_path), port=0)
    parsed_url = urlsplit(server.url)
    assert parsed_url.port == server.server.server_port
    assert not parsed_url.query
    token = parse_qs(parsed_url.fragment)["token"][0]
    assert len(token) >= 43  # noqa: PLR2004 - 32 random bytes, URL-safe base64.
    assert token not in repr(server)
    try:
        yield CockpitClient(server.server.server_port, token, calls)
    finally:
        server.shutdown()


@pytest.mark.parametrize("path", ["/api/state", "/api/events/stream", "/api/session"])
def test_private_reads_require_authentication(cockpit: CockpitClient, path: str) -> None:
    status, headers, body = cockpit.request(path)
    assert status == HTTPStatus.UNAUTHORIZED
    assert headers["Cache-Control"] == "no-store"
    assert b"private_run_data" not in body
    status, _, _ = cockpit.request(path, headers={"Authorization": "Bearer incorrect"})
    assert status == HTTPStatus.UNAUTHORIZED


def test_bootstrap_contains_no_secret_or_run_data(cockpit: CockpitClient) -> None:
    for path in ("/", "/_cockpit/session.js", "/index.html", "/src/main.js", "/src/transport.js"):
        status, headers, body = cockpit.request(path)
        assert status == HTTPStatus.OK
        assert cockpit.token.encode() not in body
        assert b"private_run_data" not in body
        assert headers["Referrer-Policy"] == "no-referrer"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
        assert "Access-Control-Allow-Origin" not in headers
        assert "Set-Cookie" not in headers


def test_query_token_is_not_an_authentication_method(cockpit: CockpitClient) -> None:
    status, _, _ = cockpit.request(f"/api/state?token={cockpit.token}")
    assert status == HTTPStatus.UNAUTHORIZED


def test_session_and_bearer_can_read_state(cockpit: CockpitClient) -> None:
    session = cockpit.authenticate()
    for token in (session, cockpit.token):
        status, _, body = cockpit.request(
            "/api/state", headers={"Authorization": f"Bearer {token}"}
        )
        assert status == HTTPStatus.OK
        assert json.loads(body) == {"private_run_data": "fixture only"}


def test_session_exchange_requires_valid_capability(cockpit: CockpitClient) -> None:
    for authorization in (None, "Bearer incorrect", "Bearer \u00ff"):
        headers = {"Origin": cockpit.origin}
        if authorization is not None:
            headers["Authorization"] = authorization
        status, response_headers, _ = cockpit.request(
            "/api/session", method="POST", headers=headers
        )
        assert status == HTTPStatus.UNAUTHORIZED
        assert "Set-Cookie" not in response_headers


@pytest.mark.parametrize("path", ["/api/teardown", "/api/run/example/teardown"])
def test_teardown_requires_authenticated_same_origin_request(
    cockpit: CockpitClient, path: str
) -> None:
    status, _, _ = cockpit.request(path, method="POST", headers={"Origin": cockpit.origin})
    assert status == HTTPStatus.UNAUTHORIZED
    session = cockpit.authenticate()
    for origin in (None, "null", "http://untrusted.invalid", "http://127.0.0.1:1"):
        headers = {"Authorization": f"Bearer {session}"}
        if origin is not None:
            headers["Origin"] = origin
        status, _, _ = cockpit.request(path, method="POST", headers=headers)
        assert status == HTTPStatus.FORBIDDEN
        assert cockpit.calls == []
    status, _, body = cockpit.request(
        path,
        method="POST",
        headers={"Authorization": f"Bearer {session}", "Origin": cockpit.origin},
    )
    assert status == HTTPStatus.OK
    assert json.loads(body) == {"ok": True}
    assert cockpit.calls == ([""] if path == "/api/teardown" else ["example"])


@pytest.mark.parametrize("origin", [None, "null", "http://untrusted.invalid"])
def test_session_exchange_requires_same_origin(cockpit: CockpitClient, origin: str | None) -> None:
    headers = {"Authorization": f"Bearer {cockpit.token}"}
    if origin is not None:
        headers["Origin"] = origin
    status, response_headers, _ = cockpit.request("/api/session", method="POST", headers=headers)
    assert status == HTTPStatus.FORBIDDEN
    assert "Set-Cookie" not in response_headers


@pytest.mark.parametrize("host", ["untrusted.invalid", "localhost:1", "127.0.0.1", ""])
def test_unexpected_host_is_rejected_even_with_capability(
    cockpit: CockpitClient, host: str
) -> None:
    status, _, _ = cockpit.request(
        "/api/state", headers={"Host": host, "Authorization": f"Bearer {cockpit.token}"}
    )
    assert status == HTTPStatus.FORBIDDEN


def test_capability_and_session_are_isolated_between_servers(
    cockpit: CockpitClient, tmp_path: Path
) -> None:
    session = cockpit.authenticate()
    other_server = dashboard.start_cockpit(
        dashboard.DashboardSettings(workspace_dir=tmp_path), port=0
    )
    try:
        other_client = CockpitClient(other_server.server.server_port, cockpit.token, [])
        assert other_server.url != f"{other_client.origin}/#token={cockpit.token}"
        for headers in (
            {"Authorization": f"Bearer {cockpit.token}"},
            {"Authorization": f"Bearer {session}"},
        ):
            status, _, _ = other_client.request("/api/state", headers=headers)
            assert status == HTTPStatus.UNAUTHORIZED
    finally:
        other_server.shutdown()


def test_cookies_never_authenticate_cockpit_requests(cockpit: CockpitClient) -> None:
    session = cockpit.authenticate()
    for token in (session, cockpit.token):
        status, _, _ = cockpit.request(
            "/api/state", headers={"Cookie": f"ravage_cockpit_{cockpit.port}={token}"}
        )
        assert status == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize("duplicate", ["Host", "Origin", "Authorization"])
def test_ambiguous_security_headers_are_rejected(cockpit: CockpitClient, duplicate: str) -> None:
    connection = HTTPConnection("127.0.0.1", cockpit.port, timeout=3)
    headers = {
        "Host": f"127.0.0.1:{cockpit.port}",
        "Origin": cockpit.origin,
        "Authorization": f"Bearer {cockpit.token}",
    }
    try:
        connection.putrequest("POST", "/api/teardown", skip_host=True)
        for key, value in headers.items():
            connection.putheader(key, value)
        connection.putheader(duplicate, headers[duplicate])
        connection.endheaders()
        response = connection.getresponse()
        assert response.status in {HTTPStatus.FORBIDDEN, HTTPStatus.UNAUTHORIZED}
        assert cockpit.calls == []
    finally:
        connection.close()


def test_explicit_wildcard_bind_still_enforces_local_interface_host(tmp_path: Path) -> None:
    server = dashboard.start_cockpit(
        dashboard.DashboardSettings(workspace_dir=tmp_path),
        host="0.0.0.0",  # noqa: S104 - exercise explicit binding without target traffic.
        port=0,
    )
    try:
        parsed_url = urlsplit(server.url)
        assert parsed_url.hostname == "127.0.0.1"
        client = CockpitClient(
            server.server.server_port, parse_qs(parsed_url.fragment)["token"][0], []
        )
        status, _, _ = client.request("/api/state")
        assert status == HTTPStatus.UNAUTHORIZED
        client.authenticate()
        status, _, _ = client.request("/", headers={"Host": "untrusted.invalid"})
        assert status == HTTPStatus.FORBIDDEN
    finally:
        server.shutdown()
