from __future__ import annotations

import errno
import socket
import ssl
from email.message import Message
from http.client import HTTPException, IncompleteRead
from http.cookiejar import Cookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Barrier, Lock, Thread
from typing import cast
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request

import pytest
from ravage.traffic.policy import TrafficPolicyConfig, TrafficPolicyController
from ravage.web_core.http_probe import (
    ProbeNetworkContext,
    ProbeResponse,
    ProbeSession,
    _connect_pinned_socket,
    _headers,
    _NoRedirectHandler,
    _PinnedHTTPSConnection,
    form_defaults,
    response_secrets,
)


def test_probe_session_does_not_follow_redirects(monkeypatch) -> None:
    captured_handlers: list[object] = []

    def fake_build_opener(*handlers: object) -> _FakeOpener:
        captured_handlers.extend(handlers)
        return _FakeOpener()

    monkeypatch.setattr("ravage.web_core.http_probe.build_opener", fake_build_opener)

    target = "http://127.0.0.1:8000/"
    response = ProbeSession(target).get("/")

    assert response.status == 302
    assert response.url == target
    assert response.final_url == target
    assert any(isinstance(handler, _NoRedirectHandler) for handler in captured_handlers)
    proxy_handlers = [handler for handler in captured_handlers if isinstance(handler, ProxyHandler)]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}


def test_remote_probe_connects_to_resolver_pin_without_os_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received_hosts: list[str] = []

    class TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            received_hosts.append(self.headers["Host"])
            body = b"resolver-pinned"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    hostname = "resolver-only.example.test"
    port = server.server_port
    resolver_calls: list[tuple[str, int]] = []

    def resolver(host: str, requested_port: int) -> list[str]:
        resolver_calls.append((host, requested_port))
        return ["127.0.0.1"]

    def reject_os_dns(*_args: object, **_kwargs: object) -> object:
        pytest.fail("the pinned probe transport must not call OS DNS")

    try:
        session = ProbeSession(
            f"http://{hostname}:{port}/",
            allow_remote_target=True,
            resolver=resolver,
        )
        monkeypatch.setattr("socket.getaddrinfo", reject_os_dns)

        response = session.get("/")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert response.status == 200
    assert response.body == "resolver-pinned"
    assert resolver_calls == [(hostname, port)]
    assert received_hosts == [f"{hostname}:{port}"]


def test_pinned_https_connection_keeps_original_tls_hostname(monkeypatch) -> None:
    raw_socket = cast(socket.socket, object())
    tls_socket = cast(ssl.SSLSocket, object())
    connected: list[tuple[tuple[str, ...], int]] = []
    wrapped: list[tuple[object, str]] = []

    class FakeTLSContext:
        def wrap_socket(self, sock: object, *, server_hostname: str) -> ssl.SSLSocket:
            wrapped.append((sock, server_hostname))
            return tls_socket

    def fake_connect(
        addresses: tuple[str, ...],
        port: int,
        *,
        timeout: object,
        source_address: tuple[str, int] | None,
    ) -> socket.socket:
        del timeout, source_address
        connected.append((addresses, port))
        return raw_socket

    monkeypatch.setattr("ravage.web_core.http_probe._connect_pinned_socket", fake_connect)
    connection = _PinnedHTTPSConnection(
        "secure.example.test",
        pin_provider=lambda _host, _port: ("192.0.2.44",),
        timeout=5,
        context=cast(ssl.SSLContext, FakeTLSContext()),
    )

    connection.connect()

    assert connected == [(("192.0.2.44",), 443)]
    assert wrapped == [(raw_socket, "secure.example.test")]
    assert connection.sock is tls_socket


def test_pinned_socket_ignores_unsupported_tcp_nodelay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeSocket:
        closed = False

        def settimeout(self, _timeout: object) -> None:
            return

        def connect(self, _address: tuple[str, int]) -> None:
            return

        def setsockopt(self, _level: int, _option: int, _value: int) -> None:
            raise OSError(errno.ENOPROTOOPT, "TCP_NODELAY unsupported")

        def close(self) -> None:
            self.closed = True

    fake_socket = FakeSocket()
    monkeypatch.setattr(
        "ravage.web_core.http_probe.socket.socket",
        lambda *_args: fake_socket,
    )

    connected = _connect_pinned_socket(
        ("127.0.0.1",),
        8080,
        timeout=2,
        source_address=None,
    )

    assert connected is fake_socket
    assert fake_socket.closed is False


def test_remote_probe_requires_explicit_authorization() -> None:
    with pytest.raises(ValueError, match="localhost"):
        ProbeSession("https://staging.example.test/app")


def test_remote_probe_enforces_path_scope_and_dns_pin(monkeypatch) -> None:
    monkeypatch.setattr("ravage.web_core.http_probe.build_opener", lambda *_handlers: _FakeOpener())
    answers = [["203.0.113.25"], ["203.0.113.26"]]
    session = ProbeSession(
        "https://staging.example.test/app",
        allow_remote_target=True,
        in_scope=["https://staging.example.test/app"],
        out_of_scope=["https://staging.example.test/app/admin"],
        resolver=lambda _host, _port: answers.pop(0),
    )

    allowed = session.get("/app/dashboard")
    denied = session.get("/app/admin")
    changed = session.get("/app/profile")

    assert allowed.status == 302
    assert "outside target origin" in denied.error
    assert "changed after pinning" in changed.error


def test_network_context_shares_dns_pin_across_isolated_sessions_without_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ravage.web_core.http_probe.build_opener", lambda *_handlers: _FakeOpener())
    answers = iter((("203.0.113.25",), ("203.0.113.26",)))
    resolver_calls: list[tuple[str, int]] = []

    def resolver(host: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((host, port))
        return next(answers)

    network_context = ProbeNetworkContext(resolver)
    first = ProbeSession(
        "https://staging.example.test/",
        allow_remote_target=True,
        network_context=network_context,
    )
    second = ProbeSession(
        "https://staging.example.test/",
        allow_remote_target=True,
        network_context=network_context,
    )

    first_response = first.get("/first")
    second_response = second.get("/second")

    assert first.network_context is network_context
    assert second.network_context is network_context
    assert first_response.status == _FakeResponse.status
    assert second_response.status is None
    assert "changed after pinning" in second_response.error
    assert resolver_calls == [
        ("staging.example.test", 443),
        ("staging.example.test", 443),
    ]


def test_network_context_accepts_dns_reordering_but_never_races_pin_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ravage.web_core.http_probe.build_opener", lambda *_handlers: _FakeOpener())
    reordered = iter(
        (
            ("203.0.113.25", "203.0.113.26"),
            ("203.0.113.26", "203.0.113.25"),
        )
    )
    shared = ProbeNetworkContext(lambda _host, _port: next(reordered))
    first = ProbeSession(
        "https://staging.example.test/",
        allow_remote_target=True,
        network_context=shared,
    )
    second = ProbeSession(
        "https://staging.example.test/",
        allow_remote_target=True,
        network_context=shared,
    )

    assert first.get("/first").status == _FakeResponse.status
    assert second.get("/second").status == _FakeResponse.status

    barrier = Barrier(2)
    answer_lock = Lock()
    answers = iter((("203.0.113.30",), ("203.0.113.31",)))

    def racing_resolver(_host: str, _port: int) -> tuple[str, ...]:
        with answer_lock:
            answer = next(answers)
        barrier.wait(timeout=2)
        return answer

    racing = ProbeNetworkContext(racing_resolver)
    results: list[str] = []

    def pin() -> None:
        results.append(racing.pin("race.example.test", 443))

    threads = (Thread(target=pin), Thread(target=pin))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert sorted(results) == ["", "remote target DNS resolution changed after pinning"]
    assert racing.pinned_addresses("race.example.test", 443) in {
        ("203.0.113.30",),
        ("203.0.113.31",),
    }


def test_probe_forks_retain_network_context_and_mixed_dns_configuration_is_rejected() -> None:
    network_context = ProbeNetworkContext(lambda _host, _port: ("127.0.0.1",))
    session = ProbeSession(
        "http://127.0.0.1:8000/",
        network_context=network_context,
    )

    assert session.fork().network_context is network_context
    with pytest.raises(ValueError, match="cannot be combined"):
        ProbeSession(
            "http://127.0.0.1:8000/",
            resolver=lambda _host, _port: ("127.0.0.1",),
            network_context=network_context,
        )


@pytest.mark.parametrize("address", ["0.0.0.0", "::", "::ffff:0.0.0.0"])
def test_remote_probe_rejects_unspecified_dns_addresses(
    monkeypatch: pytest.MonkeyPatch,
    address: str,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: _FakeOpener(),
    )
    session = ProbeSession(
        "https://staging.example.test/",
        allow_remote_target=True,
        resolver=lambda _host, _port: (address,),
    )

    response = session.get("/")

    assert response.status is None
    assert "unspecified address" in response.error


@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1",),
        ("10.0.0.8",),
        ("169.254.169.254",),
        ("224.0.0.1",),
        ("ff0e::1",),
        ("::1",),
        ("8.8.8.8", "127.0.0.1"),
    ],
    ids=[
        "loopback",
        "private",
        "metadata",
        "ipv4-multicast",
        "ipv6-multicast",
        "ipv6-loopback",
        "mixed",
    ],
)
def test_public_only_policy_rejects_non_public_dns_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    addresses: tuple[str, ...],
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: _FakeOpener(),
    )
    target = "https://demo.testfire.net/login.jsp"
    policy = TrafficPolicyController.open(
        tmp_path / "traffic.json",
        target_url=target,
        config=TrafficPolicyConfig(require_public_addresses=True),
    )
    session = ProbeSession(
        target,
        allow_remote_target=True,
        resolver=lambda _host, _port: addresses,
        traffic_policy=policy,
    )

    response = session.get(target)

    assert response.status is None
    assert "non-public address" in response.error
    assert policy.snapshot().physical_request_count == 0


def test_public_only_policy_accepts_public_dns_answer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: _FakeOpener(),
    )
    target = "https://demo.testfire.net/login.jsp"
    policy = TrafficPolicyController.open(
        tmp_path / "traffic.json",
        target_url=target,
        config=TrafficPolicyConfig(require_public_addresses=True),
    )
    session = ProbeSession(
        target,
        allow_remote_target=True,
        resolver=lambda _host, _port: ("8.8.8.8",),
        traffic_policy=policy,
    )

    response = session.get(target)

    assert response.status == _FakeResponse.status
    assert policy.snapshot().physical_request_count == 1


def test_form_defaults_preserve_named_submit_controls() -> None:
    fields = form_defaults(
        {
            "inputs": [
                {"name": "email", "type": "email", "value": ""},
                {"name": "submit", "type": "submit", "value": ""},
            ]
        }
    )

    assert fields["email"] == "ravage@example.test"
    assert fields["submit"] == "submit"


def test_form_defaults_adds_common_post_submit_control() -> None:
    fields = form_defaults(
        {
            "method": "POST",
            "inputs": [
                {"name": "username", "type": "text", "value": ""},
                {"name": "password", "type": "password", "value": ""},
            ],
        }
    )

    assert fields["username"] == "ravage"
    assert fields["password"] == "RavagePass123!"
    assert fields["submit"] == "submit"


def test_response_secrets_surfaces_decoded_braced_artifacts_without_flag_prefix() -> None:
    response = ProbeResponse(
        method="GET",
        url="http://127.0.0.1/",
        status=200,
        final_url="http://127.0.0.1/",
        elapsed_ms=1,
        body="token=e0knbV9hX1NjcmlwdF9LaWRkaWV9",
    )

    assert "decoded_base64_braced:{I'm_a_Script_Kiddie}" in response_secrets(response)


def test_form_defaults_merges_script_extra_fields() -> None:
    fields = form_defaults(
        {
            "method": "POST",
            "script_extra_fields": {"action": "login", "submit": "submit"},
            "inputs": [{"name": "username", "type": "text", "value": ""}],
        }
    )

    assert fields["action"] == "login"
    assert fields["submit"] == "submit"


def test_headers_preserves_duplicate_set_cookie_values() -> None:
    message = Message()
    message.add_header("Set-Cookie", "data=serialized; Path=/")
    message.add_header("Set-Cookie", "PHPSESSID=abc123; Path=/")

    headers = _headers(message)

    assert "data=serialized" in headers["set-cookie"]
    assert "PHPSESSID=abc123" in headers["set-cookie"]


def test_probe_response_summary_redacts_sensitive_headers() -> None:
    response = ProbeResponse(
        method="GET",
        url="http://127.0.0.1/",
        status=200,
        final_url="http://127.0.0.1/",
        elapsed_ms=1,
        headers={
            "Content-Type": "text/html",
            "Set-Cookie": "session=super-secret; HttpOnly",
            "X-Api-Key": "super-secret",
        },
    )

    summary_headers = response.summary()["headers"]

    assert summary_headers == {
        "Content-Type": "text/html",
        "Set-Cookie": "[REDACTED]",
        "X-Api-Key": "[REDACTED]",
    }
    assert response.headers["Set-Cookie"] == "session=super-secret; HttpOnly"


def test_probe_session_emits_completed_traffic_to_shared_observer(monkeypatch) -> None:
    monkeypatch.setattr("ravage.web_core.http_probe.build_opener", lambda *_handlers: _FakeOpener())
    observed: list[dict[str, object]] = []
    session = ProbeSession(
        "http://127.0.0.1:8000/",
        default_headers={"Authorization": "Bearer private-token"},
        traffic_observer=observed.append,
    )

    response = session.fork().post_form("/search", {"query": "ravage"})

    assert response.status == 302
    assert len(observed) == 1
    assert observed[0]["source"] == "probe_session"
    assert observed[0]["disposition"] == "sent"
    assert observed[0]["method"] == "POST"
    assert observed[0]["request_body"] == b"query=ravage"
    assert observed[0]["request_headers"] == {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "application/json;q=0.8,text/plain;q=0.7,*/*;q=0.1"
        ),
        "Accept-Encoding": "identity",
        "Authorization": "Bearer private-token",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "ravage-probe/1.0",
    }


def test_managed_probe_forks_inherit_identity_unless_explicitly_anonymous() -> None:
    session = ProbeSession(
        "http://127.0.0.1:8000/",
        default_headers={
            "Authorization": "Bearer private-token",
            "Host": "app.test",
        },
    )
    session.cookies.set_cookie(
        Cookie(
            version=0,
            name="session",
            value="private-cookie",
            port=None,
            port_specified=False,
            domain="127.0.0.1",
            domain_specified=False,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=False,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": ""},
            rfc2109=False,
        )
    )
    session.configure_managed_identity_forks(
        header_names={"authorization", "cookie"},
    )

    inherited = session.fork()
    anonymous = session.fork(inherit_identity=False)

    assert inherited.default_headers == session.default_headers
    assert [(cookie.name, cookie.value) for cookie in inherited.cookies] == [
        ("session", "private-cookie")
    ]
    assert inherited.cookies is not session.cookies
    assert anonymous.default_headers == {"Host": "app.test"}
    assert list(anonymous.cookies) == []


def test_traffic_identity_binding_is_validated_and_inherited_by_forks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ravage.web_core.http_probe.build_opener", lambda *_handlers: _FakeOpener())
    observed: list[dict[str, object]] = []
    session = ProbeSession(
        "http://127.0.0.1:8000/",
        traffic_observer=observed.append,
    )

    session.bind_traffic_identity("alice", generation=4)
    session.bind_traffic_identity("alice")
    session.fork().get("/account")
    session.fork(inherit_identity=False).get("/public")

    assert [event.get("identity_alias") for event in observed] == ["alice", ""]
    assert [event.get("identity_generation") for event in observed] == [4, 0]
    with pytest.raises(RuntimeError, match="alias is already bound"):
        session.bind_traffic_identity("bob", generation=4)
    with pytest.raises(RuntimeError, match="generation is already bound"):
        session.bind_traffic_identity("alice", generation=5)
    with pytest.raises(ValueError, match="simple non-empty name"):
        ProbeSession("http://127.0.0.1:8000/").bind_traffic_identity("alice secret")
    with pytest.raises(TypeError, match="generation must be an integer"):
        ProbeSession("http://127.0.0.1:8000/").bind_traffic_identity(
            "alice",
            generation=True,
        )
    with pytest.raises(ValueError, match="generation must be non-negative"):
        ProbeSession("http://127.0.0.1:8000/").bind_traffic_identity(
            "alice",
            generation=-1,
        )


def test_probe_session_records_blocked_attempt_without_sensitive_material() -> None:
    observed: list[dict[str, object]] = []
    session = ProbeSession(
        "http://127.0.0.1:8000/app",
        in_scope=["http://127.0.0.1:8000/app"],
        default_headers={"Authorization": "Bearer private-token"},
        traffic_observer=observed.append,
    )

    response = session.get("/admin")

    assert response.status is None
    assert observed == [
        {
            "source": "probe_session",
            "disposition": "blocked",
            "reason": "URL is outside target origin",
            "method": "GET",
            "url": "http://127.0.0.1:8000/admin",
            "response_status": None,
            "response_url": "http://127.0.0.1:8000/admin",
            "response_headers": {},
            "response_body": b"",
            "elapsed_ms": 0,
            "error": "URL is outside target origin",
            "truncated": False,
        }
    ]


def test_probe_cookie_observation_uses_prepared_outbound_request_not_response_jar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CookieAwareOpener:
        calls = 0

        def open(self, request: object, *, timeout: int) -> _FakeResponse:
            del timeout
            assert isinstance(request, Request)
            self.calls += 1
            if self.calls == 2:
                request.add_unredirected_header("Cookie", "session=outbound-secret")
            return _FakeResponse(request.full_url)

    opener = CookieAwareOpener()
    monkeypatch.setattr("ravage.web_core.http_probe.build_opener", lambda *_handlers: opener)
    observed: list[dict[str, object]] = []
    session = ProbeSession(
        "http://127.0.0.1:8000/",
        traffic_observer=observed.append,
    )

    session.get("/login")
    session.get("/account")

    first_headers = observed[0]["request_headers"]
    second_headers = observed[1]["request_headers"]
    assert isinstance(first_headers, dict)
    assert isinstance(second_headers, dict)
    assert "Cookie" not in first_headers
    assert second_headers["Cookie"] == "session=outbound-secret"


def test_probe_session_records_incomplete_response_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    partial = b"partial response"

    class PartialResponse(_FakeResponse):
        status = 206

        def __init__(self, url: str) -> None:
            super().__init__(url)
            self.headers = Message()
            self.headers["Content-Type"] = "text/plain; charset=utf-8"
            self.headers["Server"] = "fixture"

        def read(self, _limit: int) -> bytes:
            raise IncompleteRead(partial, 8)

    class PartialOpener:
        def open(self, request: object, *, timeout: int) -> PartialResponse:
            del timeout
            return PartialResponse(str(getattr(request, "full_url")))

    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: PartialOpener(),
    )
    observed: list[dict[str, object]] = []
    session = ProbeSession(
        "http://127.0.0.1:8000/",
        traffic_observer=observed.append,
    )

    response = session.get("/partial")

    assert response.status == 206
    assert response.final_url == "http://127.0.0.1:8000/partial"
    assert response.headers == {
        "content-type": "text/plain; charset=utf-8",
        "server": "fixture",
    }
    assert response.body == partial.decode()
    assert response.error == "HTTP protocol error"
    assert len(observed) == 1
    assert observed[0]["disposition"] == "sent"
    assert observed[0]["response_status"] == 206
    assert observed[0]["response_body"] == partial
    assert observed[0]["error"] == "HTTP protocol error"


def test_probe_session_records_http_error_incomplete_body_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    partial = b"partial error response"
    private_detail = "private-http-error-detail"

    class PartialBody:
        def read(self, _limit: int) -> bytes:
            raise IncompleteRead(partial, 12)

        def close(self) -> None:
            return

    class ErrorOpener:
        def open(self, request: object, *, timeout: int) -> _FakeResponse:
            del timeout
            headers = Message()
            headers["Content-Type"] = "application/json; charset=utf-8"
            headers["Server"] = "error-fixture"
            raise HTTPError(
                str(getattr(request, "full_url")),
                502,
                private_detail,
                headers,
                PartialBody(),
            )

    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: ErrorOpener(),
    )
    observed: list[dict[str, object]] = []
    session = ProbeSession(
        "http://127.0.0.1:8000/",
        traffic_observer=observed.append,
    )

    response = session.get("/error")

    assert response.status == 502
    assert response.final_url == "http://127.0.0.1:8000/error"
    assert response.headers == {
        "content-type": "application/json; charset=utf-8",
        "server": "error-fixture",
    }
    assert response.body == partial.decode()
    assert response.error == "HTTP protocol error"
    assert private_detail not in response.error
    assert len(observed) == 1
    assert observed[0]["response_status"] == 502
    assert observed[0]["response_body"] == partial
    assert observed[0]["error"] == "HTTP protocol error"
    assert private_detail not in str(observed[0]["error"])


def test_probe_session_hides_untrusted_http_exception_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_detail = "private-protocol-detail"

    class ErrorOpener:
        def open(self, _request: object, *, timeout: int) -> _FakeResponse:
            del timeout
            raise HTTPException(private_detail)

    monkeypatch.setattr(
        "ravage.web_core.http_probe.build_opener",
        lambda *_handlers: ErrorOpener(),
    )
    observed: list[dict[str, object]] = []
    session = ProbeSession(
        "http://127.0.0.1:8000/",
        traffic_observer=observed.append,
    )

    response = session.get("/malformed")

    assert response.status is None
    assert response.body == ""
    assert response.error == "HTTP protocol error"
    assert private_detail not in response.error
    assert len(observed) == 1
    assert observed[0]["disposition"] == "sent"
    assert observed[0]["error"] == "HTTP protocol error"
    assert private_detail not in str(observed[0]["error"])


class _FakeOpener:
    def open(self, request: object, *, timeout: int) -> "_FakeResponse":
        del timeout
        return _FakeResponse(str(getattr(request, "full_url")))


class _FakeResponse:
    status = 302

    def __init__(self, url: str) -> None:
        self._url = url
        self.headers = Message()
        self.headers["Location"] = "https://example.com/out"

    def getcode(self) -> int:
        return self.status

    def geturl(self) -> str:
        return self._url

    def read(self, _limit: int) -> bytes:
        return b""
