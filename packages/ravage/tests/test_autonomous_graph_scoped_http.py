# ruff: noqa: ANN001, PLR0913, PLR2004, TC003

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import replace
from email.message import Message
from typing import TYPE_CHECKING
from urllib.parse import quote

import pytest
from pentest_schemas import Scope
from ravage.agent_core.autonomous_graph import scoped_http
from ravage.agent_core.autonomous_graph.operational_profile import (
    GraphOperationalProfileName,
    graph_operational_profile,
)
from ravage.agent_core.autonomous_graph.scoped_http import (
    ScopedGraphHttpExecutor,
    ScopedHttpError,
    ScopedHttpTransportRequest,
    ScopedHttpTransportResponse,
    UrllibScopedHttpTransport,
)
from ravage.traffic.policy import (
    TrafficCacheRecord,
    TrafficPolicyBlocked,
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyMode,
)
from ravage.traffic.recorders import ProbeTrafficRecorder, TrafficRecorderError
from ravage.traffic.store import TrafficStore, TrafficStoreError
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.traffic.contracts import CapturedHttpExchange

TARGET_URL = "https://target.example/app"
TARGET_ADDRESS = "203.0.113.10"


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


class QueuedTransport:
    def __init__(
        self,
        responses: Sequence[ScopedHttpTransportResponse],
    ) -> None:
        self.responses = list(responses)
        self.calls: list[ScopedHttpTransportRequest] = []

    def send(
        self,
        request: ScopedHttpTransportRequest,
    ) -> ScopedHttpTransportResponse:
        self.calls.append(request)
        return self.responses.pop(0)


class FakeManagedSession:
    def __init__(self, owner: FakeManagedAuthentication) -> None:
        self.owner = owner

    def request(self, *args: object, **kwargs: object) -> ProbeResponse:
        return self.owner.request(*args, **kwargs)  # type: ignore[arg-type]


class FakeBoundTrafficPolicy:
    target_origin = TARGET_URL


class FakeManagedAuthentication:
    identity = "analyst"

    def __init__(self, *, sensitive_value: str = "managed-auth-secret") -> None:
        self.secret = sensitive_value
        self.traffic_policy = FakeBoundTrafficPolicy()
        self.calls: list[dict[str, object]] = []
        self.retired_sessions: list[FakeManagedSession] = []
        self.request_gate: Callable[[str, str], object] | None = None

    def session_for_probe(self, *, timeout_seconds: int = 10) -> FakeManagedSession:
        del timeout_seconds
        return FakeManagedSession(self)

    def session_for_model_action(self, *, timeout_seconds: int = 10) -> FakeManagedSession:
        return self.session_for_probe(timeout_seconds=timeout_seconds)

    def retire_probe_session(self, session: FakeManagedSession) -> None:
        self.retired_sessions.append(session)

    def configure_request_gate(
        self,
        gate: Callable[[str, str], object] | None,
    ) -> None:
        self.request_gate = gate

    def assert_traffic_policy(self, candidate: object | None) -> None:
        if candidate is not self.traffic_policy:
            raise ValueError("traffic policy binding mismatch")

    def account_physical_request(self, method: str, url: str) -> None:
        if self.request_gate is None:
            return
        commit = self.request_gate(method, url)
        if callable(commit):
            commit()

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProbeResponse:
        self.account_physical_request(method, url)
        self.calls.append(
            {
                "method": method,
                "url": url,
                "data": data,
                "headers": dict(headers or {}),
                "timeout_seconds": timeout_seconds,
            }
        )
        return ProbeResponse(
            method=method,
            url=url,
            status=200,
            final_url=f"{url}?session={self.secret}",
            elapsed_ms=7,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "X-Debug": self.secret,
            },
            body=json.dumps({"session": self.secret, "ok": True}),
            error=f"diagnostic={self.secret}",
        )

    def redact_text(self, value: str) -> str:
        return value.replace(self.secret, "[REDACTED]")

    def contains_secret(self, value: str) -> bool:
        return self.secret in value


def _response(
    *,
    status: int = 200,
    url: str = TARGET_URL,
    headers: dict[str, str] | None = None,
    body: bytes = b"ok",
) -> ScopedHttpTransportResponse:
    return ScopedHttpTransportResponse(
        status=status,
        url=url,
        headers=headers or {"Content-Type": "text/plain; charset=utf-8"},
        body=body,
        elapsed_ms=12,
    )


def _executor(
    transport: QueuedTransport,
    *,
    scope: Scope | None = None,
    clock: FakeClock | None = None,
    max_requests: int = 10,
    resolver=None,
    state_path=None,
    traffic_observer=None,
    require_existing_state: bool = False,
    minimum_request_count: int = 0,
    traffic_policy: TrafficPolicyController | None = None,
    proof_recognition_enabled: bool = False,
) -> ScopedGraphHttpExecutor:
    selected_clock = clock or FakeClock()
    return ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=scope or Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=max_requests,
        ),
        transport=transport,
        resolver=resolver or (lambda _host, _port: (TARGET_ADDRESS,)),
        clock=selected_clock,
        sleeper=selected_clock.sleep,
        proof_recognition_enabled=proof_recognition_enabled,
        state_path=state_path,
        traffic_observer=traffic_observer,
        require_existing_state=require_existing_state,
        minimum_request_count=minimum_request_count,
        traffic_policy=traffic_policy,
    )


def test_urllib_transport_aggregates_duplicate_set_cookie_headers() -> None:
    headers = Message()
    headers.add_header("Set-Cookie", "session=first; Path=/")
    headers.add_header("Set-Cookie", "csrf=second; Path=/")
    headers.add_header("Content-Type", "text/plain")

    class Response:
        status = 200

        def getcode(self) -> int:
            return self.status

        def geturl(self) -> str:
            return TARGET_URL

        def read(self, _limit: int) -> bytes:
            return b"ok"

    class Opener:
        def open(self, _request: object, *, timeout: float) -> Response:
            assert timeout > 0
            response = Response()
            response.headers = headers
            return response

    transport = UrllibScopedHttpTransport()
    transport.opener = Opener()  # type: ignore[assignment]

    response = transport.send(
        ScopedHttpTransportRequest(
            method="GET",
            url=TARGET_URL,
            headers={},
            body=None,
            timeout_seconds=1,
        )
    )

    assert response.headers["Set-Cookie"].splitlines() == [
        "session=first; Path=/",
        "csrf=second; Path=/",
    ]


def test_default_urllib_transport_disables_environment_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    captured_handlers: list[object] = []
    real_build_opener = scoped_http.build_opener

    def capture_build_opener(*handlers: object) -> object:
        captured_handlers.extend(handlers)
        return real_build_opener(*handlers)

    monkeypatch.setattr(scoped_http, "build_opener", capture_build_opener)

    UrllibScopedHttpTransport(lambda _host, _port: (TARGET_ADDRESS,))

    proxy_handlers = [
        handler
        for handler in captured_handlers
        if isinstance(handler, scoped_http.ProxyHandler)
    ]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}
    assert any(
        isinstance(handler, scoped_http._PinnedHTTPHandler)  # noqa: SLF001
        for handler in captured_handlers
    )
    assert any(
        isinstance(handler, scoped_http._PinnedHTTPSHandler)  # noqa: SLF001
        for handler in captured_handlers
    )


def test_default_transport_uses_validated_pin_and_original_sni_during_dns_swap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = iter(((TARGET_ADDRESS,), ("203.0.113.99",)))
    resolver_calls: list[tuple[str, int]] = []

    def swapping_resolver(host: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((host, port))
        return next(answers)

    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=4,
        ),
        resolver=swapping_resolver,
    )
    executor._verify_dns_pin(TARGET_URL)  # noqa: SLF001
    connected: list[tuple[tuple[str, ...], int]] = []
    raw_socket = object()

    def connect_pinned(
        addresses: Sequence[str],
        port: int,
        *,
        timeout: object,
        source_address: tuple[str, int] | None,
    ) -> object:
        del timeout, source_address
        connected.append((tuple(addresses), port))
        return raw_socket

    wrapped: list[tuple[object, str]] = []

    class TlsContext:
        def wrap_socket(self, sock: object, *, server_hostname: str) -> object:
            wrapped.append((sock, server_hostname))
            return sock

    monkeypatch.setattr(scoped_http, "_connect_pinned_socket", connect_pinned)
    assert isinstance(executor.transport, UrllibScopedHttpTransport)
    handler = next(
        handler
        for handler in executor.transport.opener.handlers
        if isinstance(handler, scoped_http._PinnedHTTPSHandler)  # noqa: SLF001
    )
    connection = handler._connection("target.example", port=443)  # noqa: SLF001
    connection._tls_context = TlsContext()  # type: ignore[assignment]  # noqa: SLF001

    connection.connect()

    assert connection.host == "target.example"
    assert connected == [((TARGET_ADDRESS,), 443)]
    assert wrapped == [(raw_socket, "target.example")]
    assert resolver_calls == [("target.example", 443)]
    with pytest.raises(ScopedHttpError, match="changed after pinning"):
        executor._verify_dns_pin(TARGET_URL)  # noqa: SLF001


def test_remote_http_uses_stable_identity_and_auditable_receipt() -> None:
    transport = QueuedTransport([_response(body=b"remote body")])
    executor = _executor(transport)

    execution = executor(
        node_id="node-002",
        arguments={"method": "GET", "path": "/app/status"},
        action_id="action-1",
    )

    payload = json.loads(execution.result.evidence_observation)
    request = transport.calls[0]
    assert request.url == "https://target.example/app/status"
    assert request.headers["User-Agent"] == "ravage-authorized-assessment/1.0"
    assert payload["profile"]["name"] == "low-noise"
    assert payload["requests"][0]["sequence"] == 1
    assert payload["requests"][0]["request_body_sha256"] == "unavailable"
    assert payload["response"]["body"] == "remote body"
    assert execution.result.evidence_source_kind == "tool_http_request"
    assert execution.observation_id.startswith("http:")


def test_managed_authentication_owns_request_and_redacts_all_observations(
    tmp_path,
) -> None:
    authentication = FakeManagedAuthentication()
    store = TrafficStore.create(tmp_path / "workspace")
    recorder = ProbeTrafficRecorder(
        store,
        capture_session_id="agent-graph-auth-test",
        identity_alias=authentication.identity,
        source="agent_http",
        strict=True,
    )
    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=4,
        ),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        traffic_observer=recorder,
        authentication=authentication,
    )

    execution = executor(
        node_id="node-auth",
        arguments={"method": "GET", "path": "/app/private"},
        action_id="action-auth",
    )

    assert len(authentication.calls) == 1
    assert authentication.calls[0]["url"] == "https://target.example/app/private"
    evidence = execution.result.evidence_observation
    visible = execution.result.observation
    assert authentication.secret not in evidence
    assert authentication.secret not in visible
    payload = json.loads(evidence)
    assert payload["identity"] == authentication.identity
    assert payload["response"]["body"] == '{"session": "[REDACTED]", "ok": true}'
    assert payload["response"]["error"] == "diagnostic=[REDACTED]"
    assert payload["response"]["headers"]["X-Debug"] == "[REDACTED]"
    [exchange] = store.exchanges()
    assert exchange.identity_alias == authentication.identity
    assert authentication.secret not in (store.root / "exchanges.jsonl").read_text(encoding="utf-8")


def test_persistent_managed_authentication_reuses_and_retires_one_session() -> None:
    authentication = FakeManagedAuthentication()
    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=4,
        ),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        authentication=authentication,
        persistent_managed_session=True,
    )
    assert authentication.request_gate is None

    executor(
        node_id="node-auth-1",
        arguments={"method": "GET", "path": "/app/first"},
        action_id="action-auth-1",
    )
    assert authentication.request_gate is None
    assert executor.request_count == 1
    authentication.request("GET", TARGET_URL)
    assert executor.request_count == 1
    executor(
        node_id="node-auth-2",
        arguments={"method": "GET", "path": "/app/second"},
        action_id="action-auth-2",
    )

    assert authentication.request_gate is None
    assert executor.request_count == 2
    assert len(authentication.calls) == 3
    assert authentication.retired_sessions == []
    executor.close()
    assert len(authentication.retired_sessions) == 1
    executor.close()
    assert len(authentication.retired_sessions) == 1


def test_response_urls_locations_and_errors_are_secret_safe() -> None:
    secret = "plain-query-secret"  # noqa: S105 - redaction fixture.
    response_url = f"{TARGET_URL}?token={secret}#private-fragment"
    transport = QueuedTransport(
        [
            ScopedHttpTransportResponse(
                status=200,
                url=response_url,
                headers={
                    "Content-Type": "text/plain",
                    "Location": f"/next?password={secret}#private-fragment",
                },
                body=b"ok",
                elapsed_ms=3,
                error=f"upstream failed with password={secret}",
            )
        ]
    )

    execution = _executor(transport)(
        node_id="node-safe-artifact",
        arguments={"method": "GET", "path": "/app/safe"},
        action_id="action-safe-artifact",
    )

    evidence = execution.result.evidence_observation
    visible = execution.result.observation
    assert secret not in evidence
    assert secret not in visible
    assert "private-fragment" not in evidence
    payload = json.loads(evidence)
    assert "token" in payload["response"]["final_url"]
    assert "password" in payload["response"]["headers"]["Location"]


def test_request_rejects_case_insensitive_duplicate_headers_before_dispatch() -> None:
    transport = QueuedTransport([_response()])

    with pytest.raises(ScopedHttpError, match="duplicated"):
        _executor(transport)(
            node_id="node-duplicate-header",
            arguments={
                "method": "GET",
                "path": "/app/safe",
                "headers": {"X-Trace": "first", "x-trace": "second"},
            },
            action_id="action-duplicate-header",
        )

    assert transport.calls == []


def test_request_rejects_non_token_header_name_before_dispatch() -> None:
    transport = QueuedTransport([_response()])

    with pytest.raises(ScopedHttpError, match="header name is invalid"):
        _executor(transport)(
            node_id="node-invalid-header",
            arguments={
                "method": "GET",
                "path": "/app/safe",
                "headers": {"flag{caller_authored_header_name_7c2e91}": "1"},
            },
            action_id="action-invalid-header",
        )

    assert transport.calls == []


def test_executor_filters_proof_authored_in_encoded_header_name() -> None:
    proof = "flag{caller_authored_header_name_7c2e91}"
    encoded_header_name = quote(proof, safe="")
    transport = QueuedTransport([_response(body=proof.encode())])

    execution = _executor(
        transport,
        proof_recognition_enabled=True,
    )(
        node_id="node-encoded-header-proof",
        arguments={
            "method": "GET",
            "path": "/app/echo-headers",
            "headers": {encoded_header_name: "1"},
        },
        action_id="action-encoded-header-proof",
    )

    assert encoded_header_name in transport.calls[0].headers
    assert execution.result.flag == ""


def test_executor_filters_triple_percent_encoded_authored_proof() -> None:
    proof = "flag{caller_authored_triple_encoded_7c2e91}"
    encoded = proof
    for _index in range(3):
        encoded = quote(encoded, safe="")
    transport = QueuedTransport([_response(body=proof.encode())])

    execution = _executor(
        transport,
        proof_recognition_enabled=True,
    )(
        node_id="node-triple-encoded-proof",
        arguments={"method": "GET", "path": f"/app/echo?value={encoded}"},
        action_id="action-triple-encoded-proof",
    )

    assert execution.result.flag == ""


def test_managed_traffic_uses_exact_wire_bytes_without_persisting_content(tmp_path) -> None:
    secret = "managed-wire-secret"  # noqa: S105 - redaction fixture.
    wire_body = b"\xff\x00exact-wire-bytes\xfe"

    class BinaryManagedAuthentication(FakeManagedAuthentication):
        def request(
            self,
            method: str,
            url: str,
            **_kwargs: object,
        ) -> ProbeResponse:
            self.account_physical_request(method, url)
            return ProbeResponse(
                method=method,
                url=url,
                status=200,
                final_url=url,
                elapsed_ms=2,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Debug": secret,
                },
                body=wire_body.decode("utf-8", errors="replace"),
                body_bytes=wire_body,
                error=f"diagnostic={secret}",
            )

    store = TrafficStore.create(tmp_path / "workspace")
    recorder = ProbeTrafficRecorder(
        store,
        capture_session_id="managed-wire-test",
        identity_alias="analyst",
        known_secrets=(secret,),
        source="agent_http",
        strict=True,
    )
    observed: list[dict[str, object]] = []

    def record(event: dict[str, object]) -> CapturedHttpExchange | None:
        observed.append(dict(event))
        return recorder(event)

    authentication = BinaryManagedAuthentication(sensitive_value=secret)
    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=4,
        ),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        authentication=authentication,
        traffic_observer=record,
    )

    execution = executor(
        node_id="node-wire",
        arguments={"path": "/app/binary"},
        action_id="action-wire",
    )

    [exchange] = store.exchanges()
    persisted = (store.root / "exchanges.jsonl").read_bytes()
    observed_body = observed[0]["response_body"]
    assert isinstance(observed_body, bytes)
    assert observed_body == wire_body
    assert hashlib.sha256(observed_body).hexdigest() == hashlib.sha256(wire_body).hexdigest()
    assert exchange.response_body_bytes == len(wire_body)
    assert exchange.response_body_sha256 == "unavailable"
    assert wire_body not in persisted
    assert secret.encode() not in persisted
    assert secret not in execution.result.evidence_observation


@pytest.mark.parametrize("header", ["Authorization", "Cookie", "authorization", "cookie"])
def test_managed_authentication_rejects_model_auth_header_override(header: str) -> None:
    authentication = FakeManagedAuthentication()
    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=4,
        ),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        authentication=authentication,
    )

    with pytest.raises(ScopedHttpError, match="cannot override managed authentication"):
        executor(
            node_id="node-auth",
            arguments={"path": "/app/private", "headers": {header: "model-value"}},
            action_id="action-auth-override",
        )

    assert authentication.calls == []


def test_managed_authentication_redacts_transport_exceptions() -> None:
    class FailingManagedAuthentication(FakeManagedAuthentication):
        def request(self, *args: object, **kwargs: object) -> ProbeResponse:
            del args, kwargs
            message = f"session refresh failed for {self.secret}"
            raise RuntimeError(message)

    authentication = FailingManagedAuthentication()
    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=4,
        ),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        authentication=authentication,
    )

    with pytest.raises(ScopedHttpError) as error:
        executor(
            node_id="node-auth",
            arguments={"path": "/app/private"},
            action_id="action-auth-failure",
        )

    assert authentication.secret not in str(error.value)
    assert "[REDACTED]" in str(error.value)
    assert len(authentication.retired_sessions) == 1


def test_managed_graph_http_filters_identity_tainted_proof_independently() -> None:
    real_proof = "FLAG{graph_boundary_real_7c2e91}"

    class ContextualIdentityAuthentication(FakeManagedAuthentication):
        def __init__(self) -> None:
            super().__init__(sensitive_value="alice")

        def request(
            self,
            method: str,
            url: str,
            **_kwargs: object,
        ) -> ProbeResponse:
            self.account_physical_request(method, url)
            return ProbeResponse(
                method=method,
                url=url,
                status=200,
                final_url=url,
                elapsed_ms=1,
                headers={"Content-Type": "text/plain"},
                body=f"FLAG{{alice}} {real_proof}",
            )

        def redact_text(self, value: str) -> str:
            return "[REDACTED]" if value == self.secret else value

        def contains_secret(self, value: str) -> bool:
            return value == "FLAG{alice}" or value == self.secret

    authentication = ContextualIdentityAuthentication()
    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=4,
        ),
        proof_recognition_enabled=True,
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        authentication=authentication,
    )

    execution = executor(
        node_id="node-auth",
        arguments={"path": "/app/private"},
        action_id="action-proof-taint",
    )

    assert execution.result.flag == real_proof


def test_managed_auth_lifecycle_requests_share_persisted_target_ceiling(
    tmp_path: Path,
) -> None:
    class LifecycleManagedAuthentication(FakeManagedAuthentication):
        def request(
            self,
            method: str,
            url: str,
            *,
            data: bytes | None = None,
            headers: dict[str, str] | None = None,
            timeout_seconds: float | None = None,
        ) -> ProbeResponse:
            self.account_physical_request("GET", f"{TARGET_URL}/health")
            self.account_physical_request("POST", f"{TARGET_URL}/login")
            return super().request(
                method,
                url,
                data=data,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )

    state_path = tmp_path / "managed-http-state.json"
    profile = graph_operational_profile(
        GraphOperationalProfileName.LOW_NOISE,
        roe_max_rps=5,
        max_total_requests=3,
    )
    authentication = LifecycleManagedAuthentication()
    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=profile,
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        state_path=state_path,
        authentication=authentication,
    )

    result = executor(
        node_id="node-auth",
        arguments={"path": "/app/private"},
        action_id="action-auth-lifecycle",
    )

    assert result.result.ok
    assert executor.request_count == 3
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["request_count"] == 3

    resumed_authentication = LifecycleManagedAuthentication()
    resumed = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=profile,
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        state_path=state_path,
        require_existing_state=True,
        minimum_request_count=1,
        authentication=resumed_authentication,
    )
    with pytest.raises(ScopedHttpError, match="target-request ceiling"):
        resumed(
            node_id="node-auth-resume",
            arguments={"path": "/app/private"},
            action_id="action-auth-resume",
        )


def test_managed_internal_interrupt_does_not_fabricate_outer_route_traffic(
    tmp_path: Path,
) -> None:
    class HealthOnlyInterruptingAuthentication(FakeManagedAuthentication):
        def request(
            self,
            method: str,
            url: str,
            *,
            data: bytes | None = None,
            headers: dict[str, str] | None = None,
            timeout_seconds: float | None = None,
        ) -> ProbeResponse:
            del method, url, data, headers, timeout_seconds
            self.account_physical_request("GET", f"{TARGET_URL}/health")
            raise KeyboardInterrupt

    store = TrafficStore.create(tmp_path / "workspace")
    recorder = ProbeTrafficRecorder(
        store,
        capture_session_id="managed-interrupt-test",
        source="agent_http",
        strict=True,
    )
    state_path = tmp_path / "managed-http-state.json"
    authentication = HealthOnlyInterruptingAuthentication()
    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=3,
        ),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        state_path=state_path,
        traffic_observer=recorder,
        authentication=authentication,
    )

    with pytest.raises(KeyboardInterrupt):
        executor(
            node_id="node-auth-interrupt",
            arguments={"path": "/app/never-sent"},
            action_id="action-auth-interrupt",
        )

    assert executor.request_count == 1
    assert json.loads(state_path.read_text(encoding="utf-8"))["request_count"] == 1
    assert not store.exchanges()
    assert len(authentication.retired_sessions) == 1
    assert authentication.request_gate is None


def test_managed_begin_failure_is_not_masked_by_gate_cleanup_failure() -> None:
    class FailingAuthentication(FakeManagedAuthentication):
        def session_for_model_action(
            self,
            *,
            timeout_seconds: int = 10,
        ) -> FakeManagedSession:
            del timeout_seconds
            raise RuntimeError("session-start-primary")

        def configure_request_gate(
            self,
            gate: Callable[[str, str], object] | None,
        ) -> None:
            if gate is None:
                raise OSError("gate-cleanup-secondary")
            super().configure_request_gate(gate)

    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=3,
        ),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        authentication=FailingAuthentication(),
    )

    with pytest.raises(
        ScopedHttpError,
        match="managed authentication action session failed",
    ) as error:
        executor(
            node_id="node-auth-begin-failure",
            arguments={"path": "/app/private"},
            action_id="action-auth-begin-failure",
        )

    assert any(
        "managed authentication gate cleanup also failed: OSError" in note
        for note in getattr(error.value, "__notes__", ())
    )


def test_managed_action_failure_survives_end_and_gate_cleanup_failures() -> None:
    class FailingAuthentication(FakeManagedAuthentication):
        def request(
            self,
            method: str,
            url: str,
            *,
            data: bytes | None = None,
            headers: dict[str, str] | None = None,
            timeout_seconds: float | None = None,
        ) -> ProbeResponse:
            del data, headers, timeout_seconds
            self.account_physical_request(method, url)
            raise KeyboardInterrupt

        def retire_probe_session(self, session: FakeManagedSession) -> None:
            self.retired_sessions.append(session)
            raise RuntimeError("action-cleanup-secondary")

        def configure_request_gate(
            self,
            gate: Callable[[str, str], object] | None,
        ) -> None:
            if gate is None:
                raise OSError("gate-cleanup-tertiary")
            super().configure_request_gate(gate)

    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=3,
        ),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        authentication=FailingAuthentication(),
    )

    with pytest.raises(KeyboardInterrupt) as error:
        executor(
            node_id="node-auth-action-failure",
            arguments={"path": "/app/private"},
            action_id="action-auth-action-failure",
        )

    notes = getattr(error.value, "__notes__", ())
    assert any(
        "managed authentication action cleanup also failed: ScopedHttpError" in note
        for note in notes
    )
    assert any(
        "managed authentication gate cleanup also failed: OSError" in note
        for note in notes
    )


def test_managed_end_action_failure_is_not_masked_by_gate_cleanup_failure() -> None:
    class FailingAuthentication(FakeManagedAuthentication):
        def retire_probe_session(self, session: FakeManagedSession) -> None:
            self.retired_sessions.append(session)
            raise RuntimeError("action-cleanup-primary")

        def configure_request_gate(
            self,
            gate: Callable[[str, str], object] | None,
        ) -> None:
            if gate is None:
                raise OSError("gate-cleanup-secondary")
            super().configure_request_gate(gate)

    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=3,
        ),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        authentication=FailingAuthentication(),
    )

    with pytest.raises(
        ScopedHttpError,
        match="managed authentication action cleanup failed",
    ) as error:
        executor(
            node_id="node-auth-end-failure",
            arguments={"path": "/app/private"},
            action_id="action-auth-end-failure",
        )

    assert any(
        "managed authentication gate cleanup also failed: OSError" in note
        for note in getattr(error.value, "__notes__", ())
    )


def test_managed_close_failure_is_not_masked_by_gate_cleanup_failure() -> None:
    class FailingAuthentication(FakeManagedAuthentication):
        fail_gate_cleanup = False

        def retire_probe_session(self, session: FakeManagedSession) -> None:
            self.retired_sessions.append(session)
            raise RuntimeError("close-primary")

        def configure_request_gate(
            self,
            gate: Callable[[str, str], object] | None,
        ) -> None:
            if gate is None and self.fail_gate_cleanup:
                raise OSError("gate-cleanup-secondary")
            super().configure_request_gate(gate)

    authentication = FailingAuthentication()
    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=3,
        ),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        authentication=authentication,
        persistent_managed_session=True,
    )
    executor(
        node_id="node-auth-close",
        arguments={"path": "/app/private"},
        action_id="action-auth-close",
    )
    authentication.fail_gate_cleanup = True

    with pytest.raises(
        ScopedHttpError,
        match="managed authentication action cleanup failed",
    ) as error:
        executor.close()

    assert any(
        "managed authentication gate cleanup also failed: OSError" in note
        for note in getattr(error.value, "__notes__", ())
    )


def test_managed_begin_dispatch_block_does_not_increment_graph_count(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=4, max_rps=5),
    )
    session = ProbeSession(
        TARGET_URL,
        allow_remote_target=True,
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        traffic_policy=policy,
    )

    class PolicyManagedAuthentication(FakeManagedAuthentication):
        def session_for_model_action(self, *, timeout_seconds: int = 10) -> ProbeSession:
            del timeout_seconds
            return session

        def retire_probe_session(self, retired: ProbeSession) -> None:
            assert retired is session

        def assert_traffic_policy(self, candidate: TrafficPolicyController | None) -> None:
            assert candidate is policy

        def configure_request_gate(
            self,
            gate: Callable[[str, str], object] | None,
        ) -> None:
            session.configure_request_gate(gate)

    def block_begin(_lease: object) -> int:
        raise TrafficPolicyBlocked("dispatch blocked after graph preflight")

    monkeypatch.setattr(policy, "begin_dispatch", block_begin)
    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=4,
        ),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        authentication=PolicyManagedAuthentication(),
        traffic_policy=policy,
    )

    with pytest.raises(ScopedHttpError, match="unaccounted target request"):
        executor(
            node_id="node-blocked",
            arguments={"path": "/app/private"},
            action_id="action-blocked",
        )

    snapshot = policy.snapshot()
    assert executor.request_count == 0
    assert session.physical_request_count == 0
    assert snapshot.physical_request_count == 0
    assert snapshot.reservation_count == 0


def test_each_redirect_is_scope_checked_before_following() -> None:
    transport = QueuedTransport(
        [
            _response(
                status=302,
                headers={"Location": "https://outside.example/private"},
            )
        ]
    )
    executor = _executor(transport)

    with pytest.raises(ScopedHttpError, match="engagement scope"):
        executor(
            node_id="node-001",
            arguments={"path": "/app/start"},
            action_id="action-redirect",
        )

    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1",),
        ("10.0.0.8",),
        ("169.254.169.254",),
        ("224.0.0.1",),
        ("ff0e::1",),
        ("8.8.8.8", "127.0.0.1"),
    ],
)
def test_shared_public_only_policy_rejects_non_public_graph_dns(
    tmp_path: Path,
    addresses: tuple[str, ...],
) -> None:
    config = replace(
        TrafficPolicyConfig.low_noise(max_physical_requests=4, max_rps=0.5),
        require_public_addresses=True,
    )
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=config,
    )
    transport = QueuedTransport([_response(status=200)])
    executor = _executor(
        transport,
        resolver=lambda _host, _port: addresses,
        traffic_policy=policy,
    )

    with pytest.raises(ScopedHttpError, match="non-public address"):
        executor(
            node_id="node-public-only",
            arguments={"path": "/app"},
            action_id="action-public-only",
        )

    assert transport.calls == []
    assert policy.snapshot().physical_request_count == 0


def test_managed_out_of_scope_redirect_redacts_sensitive_location_from_failure() -> None:
    class RedirectingManagedAuthentication(FakeManagedAuthentication):
        def request(
            self,
            method: str,
            url: str,
            *,
            data: bytes | None = None,
            headers: dict[str, str] | None = None,
            timeout_seconds: float | None = None,
        ) -> ProbeResponse:
            del data, headers, timeout_seconds
            self.account_physical_request(method, url)
            return ProbeResponse(
                method=method,
                url=url,
                status=302,
                final_url=url,
                elapsed_ms=1,
                headers={
                    "Location": f"https://outside.example/private?token={self.secret}",
                },
                body="",
            )

    authentication = RedirectingManagedAuthentication()
    executor = ScopedGraphHttpExecutor(
        target_url=TARGET_URL,
        scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=4,
        ),
        resolver=lambda host, _port: (
            TARGET_ADDRESS if host == "target.example" else "198.51.100.20",
        ),
        authentication=authentication,
    )

    with pytest.raises(ScopedHttpError) as error:
        executor(
            node_id="node-auth-redirect",
            arguments={"path": "/app/start"},
            action_id="action-auth-redirect",
        )

    assert authentication.secret not in str(error.value)
    assert len(authentication.retired_sessions) == 1
    assert "[REDACTED]" in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__ is True


def test_out_of_scope_redirect_retains_the_sent_hop_as_unlinked_traffic(
    tmp_path,
) -> None:
    store = TrafficStore.create(tmp_path / "workspace")
    recorder = ProbeTrafficRecorder(
        store,
        capture_session_id="agent-graph-test",
        source="agent_http",
        strict=True,
    )
    transport = QueuedTransport(
        [
            _response(
                status=302,
                headers={"Location": "https://outside.example/private"},
            )
        ]
    )
    executor = _executor(transport, traffic_observer=recorder)

    with pytest.raises(ScopedHttpError, match="engagement scope"):
        executor(
            node_id="node-001",
            arguments={"path": "/app/start"},
            action_id="action-redirect",
        )

    [exchange] = store.exchanges()
    assert exchange.request_sent is True
    assert exchange.response_status == 302
    assert exchange.source_observation_id.startswith("http:obs-")


def test_scoped_redirect_is_counted_and_sensitive_headers_do_not_cross_origin() -> None:
    second_origin = "https://login.example/callback"
    scope = Scope(
        in_scope=[TARGET_URL, second_origin],
        out_of_scope=[],
    )
    transport = QueuedTransport(
        [
            _response(
                status=302,
                headers={"Location": second_origin},
            ),
            _response(url=second_origin, body=b"done"),
        ]
    )
    clock = FakeClock()
    executor = _executor(
        transport,
        scope=scope,
        clock=clock,
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
    )

    execution = executor(
        node_id="node-001",
        arguments={
            "path": "/app/start",
            "headers": {"Authorization": "Bearer scoped"},
        },
        action_id="action-scoped-redirect",
    )

    payload = json.loads(execution.result.evidence_observation)
    assert len(transport.calls) == 2
    assert "Authorization" in transport.calls[0].headers
    assert "Authorization" not in transport.calls[1].headers
    assert len(payload["requests"]) == 2
    assert clock.sleeps
    assert clock.sleeps[0] >= 1.15


def test_transport_timeout_is_rebounded_after_deadline_aware_pacing() -> None:
    transport = QueuedTransport([_response(), _response()])
    clock = FakeClock()
    executor = _executor(transport, clock=clock)
    executor(
        node_id="node-001",
        arguments={"path": "/app/first", "timeout_seconds": 10},
        action_id="action-first",
    )
    deadline = clock() + 2.0

    executor(
        node_id="node-001",
        arguments={"path": "/app/second", "timeout_seconds": 10},
        action_id="action-second",
        _deadline_monotonic=deadline,
    )

    assert len(transport.calls) == 2
    assert clock.sleeps
    assert transport.calls[-1].timeout_seconds == pytest.approx(deadline - clock())


def test_dns_change_after_first_request_fails_closed() -> None:
    transport = QueuedTransport([_response(), _response()])
    resolutions = iter(
        [
            (TARGET_ADDRESS,),
            ("203.0.113.11",),
        ]
    )
    executor = _executor(
        transport,
        resolver=lambda _host, _port: next(resolutions),
    )
    executor(
        node_id="node-001",
        arguments={"path": "/app/one"},
        action_id="action-one",
    )

    with pytest.raises(ScopedHttpError, match="changed after pinning"):
        executor(
            node_id="node-001",
            arguments={"path": "/app/two"},
            action_id="action-two",
        )

    assert len(transport.calls) == 1


def test_low_noise_route_blocks_header_rotation_and_request_overrun() -> None:
    transport = QueuedTransport([_response()])
    executor = _executor(transport, max_requests=1)

    with pytest.raises(ScopedHttpError, match="stable User-Agent"):
        executor(
            node_id="node-001",
            arguments={
                "path": "/app/one",
                "headers": {"User-Agent": "rotating-agent"},
            },
            action_id="action-header",
        )

    executor(
        node_id="node-001",
        arguments={"path": "/app/one"},
        action_id="action-one",
    )
    with pytest.raises(ScopedHttpError, match="ceiling"):
        executor(
            node_id="node-001",
            arguments={"path": "/app/two"},
            action_id="action-two",
        )


def test_request_ceiling_and_dns_pin_survive_executor_resume(tmp_path) -> None:
    state_path = tmp_path / "remote-http-state.json"
    first_transport = QueuedTransport([_response()])
    first = _executor(
        first_transport,
        max_requests=1,
        state_path=state_path,
    )
    first(
        node_id="node-001",
        arguments={"path": "/app/one"},
        action_id="action-one",
    )

    resumed_transport = QueuedTransport([_response()])
    resumed = _executor(
        resumed_transport,
        max_requests=1,
        state_path=state_path,
    )

    with pytest.raises(ScopedHttpError, match="ceiling"):
        resumed(
            node_id="node-001",
            arguments={"path": "/app/two"},
            action_id="action-two",
        )
    assert resumed_transport.calls == []

    with pytest.raises(ScopedHttpError, match="does not match captured traffic"):
        _executor(
            QueuedTransport([]),
            max_requests=1,
            state_path=state_path,
            require_existing_state=True,
            minimum_request_count=0,
        )


def test_resume_refuses_missing_or_behind_http_state(tmp_path) -> None:
    state_path = tmp_path / "remote-http-state.json"

    with pytest.raises(ScopedHttpError, match="missing.*refusing to reset"):
        _executor(
            QueuedTransport([]),
            state_path=state_path,
            require_existing_state=True,
        )

    _executor(QueuedTransport([]), state_path=state_path)
    with pytest.raises(ScopedHttpError, match="behind captured traffic"):
        _executor(
            QueuedTransport([]),
            state_path=state_path,
            require_existing_state=True,
            minimum_request_count=1,
        )


def test_http_state_is_private_and_does_not_persist_raw_target_secrets(tmp_path) -> None:
    state_path = tmp_path / "remote-http-state.json"
    secret = "state-secret-value"
    target_url = f"{TARGET_URL}?token={secret}"

    ScopedGraphHttpExecutor(
        target_url=target_url,
        scope=Scope(in_scope=[target_url], out_of_scope=[]),
        allow_remote_target=True,
        profile=graph_operational_profile(
            GraphOperationalProfileName.LOW_NOISE,
            roe_max_rps=5,
            max_total_requests=10,
        ),
        transport=QueuedTransport([]),
        resolver=lambda _host, _port: (TARGET_ADDRESS,),
        state_path=state_path,
    )

    state_text = state_path.read_text(encoding="utf-8")
    assert state_path.stat().st_mode & 0o077 == 0
    assert secret not in state_text
    assert target_url not in state_text
    assert "target_identity" in state_text


def test_session_credentials_in_response_headers_are_redacted_from_observations() -> None:
    transport = QueuedTransport(
        [
            _response(
                headers={
                    "Content-Type": "text/plain",
                    "Set-Cookie": "session=secret-cookie; HttpOnly",
                    "Authentication-Info": "nextnonce=secret-nonce",
                    "X-Api-Key": "secret-api-key",
                }
            )
        ]
    )

    execution = _executor(transport)(
        node_id="node-authenticated",
        arguments={"path": "/app/me"},
        action_id="action-authenticated",
    )

    evidence = execution.result.evidence_observation
    visible = execution.result.observation
    assert "secret-cookie" not in evidence
    assert "secret-nonce" not in evidence
    assert "secret-api-key" not in evidence
    assert "secret-cookie" not in visible
    assert "secret-nonce" not in visible
    assert json.loads(evidence)["response"]["headers"] == {
        "Authentication-Info": "[REDACTED]",
        "Content-Type": "text/plain",
        "Set-Cookie": "[REDACTED]",
        "X-Api-Key": "[REDACTED]",
    }


def test_agent_http_traffic_is_redacted_and_linked_to_its_evidence_observation(
    tmp_path,
) -> None:
    workspace = tmp_path / "workspace"
    store = TrafficStore.create(workspace)
    recorder = ProbeTrafficRecorder(
        store,
        capture_session_id="agent-graph-test",
        known_secrets=("agent-secret",),
        source="agent_http",
        strict=True,
    )
    transport = QueuedTransport(
        [
            _response(
                url="https://target.example/app/login",
                headers={
                    "Content-Type": "application/json",
                    "Set-Cookie": "session=agent-secret",
                },
                body=b'{"token":"agent-secret"}',
            )
        ]
    )
    execution = _executor(transport, traffic_observer=recorder)(
        node_id="node-auth",
        arguments={
            "method": "POST",
            "path": "/app/login?next=agent-secret",
            "headers": {"Authorization": "Bearer agent-secret"},
            "json": {"password": "agent-secret"},
        },
        action_id="action-login",
    )

    payload = json.loads(execution.result.evidence_observation)
    [exchange] = store.exchanges()
    persisted = (store.root / "exchanges.jsonl").read_text(encoding="utf-8")
    assert payload["traffic_exchange_ids"] == [exchange.exchange_id]
    assert exchange.source == "agent_http"
    assert exchange.source_observation_id == execution.observation_id
    assert exchange.request_resource_type == "agent_http"
    assert exchange.response_status == 200
    assert exchange.response_error == ""
    assert exchange.scope_reason == "authorized autonomous graph HTTP request"
    assert "agent-secret" not in persisted


def test_agent_http_fails_the_action_when_strict_provenance_cannot_be_saved(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = TrafficStore.create(tmp_path / "workspace")
    recorder = ProbeTrafficRecorder(
        store,
        capture_session_id="agent-graph-test",
        source="agent_http",
        strict=True,
    )

    def fail_append(_exchange: CapturedHttpExchange) -> CapturedHttpExchange:
        message = "traffic disk unavailable"
        raise TrafficStoreError(message)

    monkeypatch.setattr(store, "append_exchange", fail_append)
    transport = QueuedTransport([_response()])

    with pytest.raises(TrafficRecorderError, match="traffic disk unavailable"):
        _executor(transport, traffic_observer=recorder)(
            node_id="node-001",
            arguments={"path": "/app/status"},
            action_id="action-no-provenance",
        )

    assert len(transport.calls) == 1
    assert store.exchanges() == ()


def test_shared_traffic_policy_caches_anonymous_get_without_fake_physical_count(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=5, max_rps=5),
        clock=clock,
        sleep=clock.sleep,
    )
    transport = QueuedTransport([_response(url=f"{TARGET_URL}/status")])
    executor = _executor(transport, clock=clock, traffic_policy=policy)

    executor(
        node_id="node-cache-1",
        arguments={"path": "/app/status"},
        action_id="action-cache-1",
    )
    cached = executor(
        node_id="node-cache-2",
        arguments={"path": "/app/status"},
        action_id="action-cache-2",
    )

    payload = json.loads(cached.result.evidence_observation)
    snapshot = policy.snapshot()
    assert len(transport.calls) == 1
    assert executor.request_count == 1
    assert snapshot.physical_request_count == 1
    assert snapshot.cache_hit_count == 1
    [receipt] = payload["requests"]
    assert receipt["sequence"] is None
    assert receipt["attempt_index"] == 0
    assert receipt["physical_request"] is False
    assert receipt["cache_hit"] is True


def test_graph_policy_cache_preserves_exact_response_bytes() -> None:
    record = TrafficCacheRecord(
        status=200,
        final_url=f"{TARGET_URL}/binary",
        headers={"Content-Type": "application/octet-stream"},
        body="\ufffd\x00",
        body_bytes=b"\xff\x00",
    )

    cached = scoped_http._cached_transport_response(record)  # noqa: SLF001

    assert cached.body == b"\xff\x00"


def test_graph_state_persistence_failure_occurs_after_accounted_dispatch(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=5, max_rps=5),
        clock=clock,
        sleep=clock.sleep,
    )
    transport = QueuedTransport([_response()])
    executor = _executor(
        transport,
        clock=clock,
        state_path=tmp_path / "graph-http-state.json",
        traffic_policy=policy,
    )
    def fail_persist(_sequence: int) -> None:
        raise OSError("graph state disk unavailable")

    executor._gate._on_acquire = fail_persist  # noqa: SLF001

    with pytest.raises(OSError, match="disk unavailable"):
        executor(
            node_id="node-persist",
            arguments={"path": "/app/status"},
            action_id="action-persist",
        )

    snapshot = policy.snapshot()
    assert len(transport.calls) == 1
    assert snapshot.physical_request_count == 1
    assert snapshot.completed_request_count == 1


def test_shared_traffic_policy_counts_retry_and_redirect_as_physical_requests(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig.low_noise(max_physical_requests=5, max_rps=5),
        clock=clock,
        sleep=clock.sleep,
    )
    transport = QueuedTransport(
        [
            _response(status=503),
            _response(status=302, headers={"Location": "/app/final"}),
            _response(url=f"{TARGET_URL}/final"),
        ]
    )
    executor = _executor(transport, clock=clock, traffic_policy=policy)

    execution = executor(
        node_id="node-retry",
        arguments={"path": "/app/start"},
        action_id="action-retry",
    )

    payload = json.loads(execution.result.evidence_observation)
    snapshot = policy.snapshot()
    assert len(transport.calls) == 3
    assert executor.request_count == 3
    assert snapshot.physical_request_count == 3
    assert snapshot.completed_request_count == 3
    assert snapshot.retry_count == 1
    assert [item["status"] for item in payload["requests"]] == [503, 302, 200]
    assert [item["redirect_index"] for item in payload["requests"]] == [0, 0, 1]
    assert [item["attempt_index"] for item in payload["requests"]] == [0, 1, 0]


def test_shared_traffic_policy_completes_transport_failure_accounting(
    tmp_path: Path,
) -> None:
    class FailingTransport:
        def send(self, request: ScopedHttpTransportRequest) -> ScopedHttpTransportResponse:
            del request
            message = "connection reset"
            raise OSError(message)

    clock = FakeClock()
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_physical_requests=2,
            max_retries=0,
        ),
        clock=clock,
        sleep=clock.sleep,
    )
    executor = _executor(
        FailingTransport(),  # type: ignore[arg-type]
        clock=clock,
        traffic_policy=policy,
    )

    execution = executor(
        node_id="node-failure",
        arguments={"path": "/app/status"},
        action_id="action-failure",
    )

    snapshot = policy.snapshot()
    assert execution.result.outcome == "http_transport_error"
    assert executor.request_count == 1
    assert snapshot.physical_request_count == 1
    assert snapshot.completed_request_count == 1


def test_managed_authentication_rejects_an_unowned_graph_policy(
    tmp_path: Path,
) -> None:
    policy = TrafficPolicyController.open(
        tmp_path / "traffic-policy.json",
        target_url=TARGET_URL,
        config=TrafficPolicyConfig(),
    )

    with pytest.raises(ScopedHttpError, match="traffic policy binding is invalid"):
        ScopedGraphHttpExecutor(
            target_url=TARGET_URL,
            scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
            allow_remote_target=True,
            profile=graph_operational_profile(
                GraphOperationalProfileName.LOW_NOISE,
                roe_max_rps=5,
                max_total_requests=4,
            ),
            resolver=lambda _host, _port: (TARGET_ADDRESS,),
            authentication=FakeManagedAuthentication(),
            traffic_policy=policy,
        )


def test_managed_authentication_requires_a_bound_whole_run_policy() -> None:
    authentication = FakeManagedAuthentication()
    authentication.traffic_policy = None  # type: ignore[assignment]

    with pytest.raises(ScopedHttpError, match="requires a whole-run traffic policy"):
        ScopedGraphHttpExecutor(
            target_url=TARGET_URL,
            scope=Scope(in_scope=[TARGET_URL], out_of_scope=[]),
            allow_remote_target=True,
            profile=graph_operational_profile(
                GraphOperationalProfileName.LOW_NOISE,
                roe_max_rps=5,
                max_total_requests=4,
            ),
            resolver=lambda _host, _port: (TARGET_ADDRESS,),
            authentication=authentication,
        )
