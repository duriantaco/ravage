from __future__ import annotations

import base64
import hashlib
from email.message import Message
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.request import Request

import pytest
from ravage.probes import web_boundaries
from ravage.probes.cms.cms_exposure_archives import _fetch_bytes
from ravage.traffic.policy import (
    DispatchLease,
    RequestIntent,
    TrafficDecision,
    TrafficOutcome,
    TrafficPolicyBlocked,
    TrafficPolicyConfig,
    TrafficPolicyController,
    TrafficPolicyMode,
)
from ravage.web_core import http_probe
from ravage.web_core.http_probe import (
    ControlledTransportRequest,
    ControlledTransportResult,
    ProbeSession,
)

if TYPE_CHECKING:
    from urllib.parse import SplitResult


class _Clock:
    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class _Response:
    def __init__(self, url: str, *, status: int, body: bytes) -> None:
        self.status = status
        self._url = url
        self._body = body
        self.headers = Message()
        self.headers["Content-Type"] = "application/octet-stream"

    def getcode(self) -> int:
        return self.status

    def geturl(self) -> str:
        return self._url

    def read(self, limit: int) -> bytes:
        return self._body[:limit]


class _Opener:
    def __init__(self, *, status: int, body: bytes) -> None:
        self.status = status
        self.body = body
        self.calls = 0

    def open(self, request: object, *, timeout: float) -> _Response:
        assert isinstance(request, Request)
        assert timeout > 0
        self.calls += 1
        return _Response(request.full_url, status=self.status, body=self.body)


def _controller(
    tmp_path: Path,
    *,
    target_url: str = "http://127.0.0.1:8080/",
    config: TrafficPolicyConfig | None = None,
    clock: _Clock | None = None,
) -> TrafficPolicyController:
    selected_clock = clock or _Clock()
    return TrafficPolicyController.open(
        tmp_path / "traffic.json",
        target_url=target_url,
        config=config or TrafficPolicyConfig(),
        clock=selected_clock,
        sleep=selected_clock.sleep,
    )


def _record_completions(
    monkeypatch: pytest.MonkeyPatch,
    controller: TrafficPolicyController,
) -> list[TrafficOutcome]:
    completed: list[TrafficOutcome] = []
    original = controller.complete

    def complete(lease: DispatchLease, outcome: TrafficOutcome) -> None:
        completed.append(outcome)
        original(lease, outcome)

    monkeypatch.setattr(controller, "complete", complete)
    return completed


def _local_resolver(_host: str, _port: int) -> tuple[str, ...]:
    return ("127.0.0.1",)


def _websocket_response(
    status: int,
    reason: str,
    *,
    headers: dict[str, str] | None = None,
) -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}"]
    lines.extend(f"{name}: {value}" for name, value in (headers or {}).items())
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def _accept_for_websocket_request(request: bytes) -> str:
    key_line = next(
        line
        for line in request.decode("ascii").splitlines()
        if line.startswith("Sec-WebSocket-Key:")
    )
    key = key_line.partition(":")[2].strip()
    digest = hashlib.sha1(  # noqa: S324 - required by RFC 6455
        f"{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11".encode("ascii")
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def test_cms_binary_fetch_preserves_non_utf8_bytes_and_counts_once() -> None:
    raw = b"PK\x03\x04\xff\x00\x80archive"
    opener = _Opener(status=200, body=raw)
    session = ProbeSession(
        "http://127.0.0.1:8080/",
        resolver=_local_resolver,
    )
    session.opener = opener

    result = _fetch_bytes(session, "/backup.zip")

    assert result == raw
    assert opener.calls == 1
    assert session.physical_request_count == 1


@pytest.mark.parametrize("status", [404, 503])
def test_get_bytes_discards_http_error_bodies_but_completes_actual_outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: int,
) -> None:
    controller = _controller(tmp_path)
    completed = _record_completions(monkeypatch, controller)
    opener = _Opener(status=status, body=b"must-not-be-consumed")
    session = ProbeSession(
        "http://127.0.0.1:8080/",
        resolver=_local_resolver,
        traffic_policy=controller,
    )
    session.opener = opener

    result = session.get_bytes("/artifact.zip")

    assert result == b""
    assert opener.calls == 1
    assert session.physical_request_count == 1
    assert len(completed) == 1
    assert completed[0].status == status
    assert completed[0].transport_error is False
    assert controller.snapshot().physical_request_count == 1


def test_external_transport_receives_exact_canonical_request_context() -> None:
    received: list[ControlledTransportRequest] = []
    session = ProbeSession(
        "https://127.0.0.1:8443/app/",
        default_headers={"Host": "canonical.test", "X-Base": "base"},
        resolver=lambda _host, _port: ("::1", "127.0.0.7"),
    )
    expected = ControlledTransportResult(
        response_bytes=b"HTTP/1.1 204 No Content\r\n\r\n",
        outcome=TrafficOutcome(status=204, headers={"X-Result": "exact"}),
    )

    def transport(request: ControlledTransportRequest) -> ControlledTransportResult:
        received.append(request)
        return expected

    result = session.run_external_transport(
        "get",
        "https://canonical.test/ws?transport=websocket",
        transport,
        headers={"X-Base": "override", "X-Call": "present"},
        timeout_seconds=2.5,
        lane="websocket",
    )

    assert result is expected
    assert received == [
        ControlledTransportRequest(
            method="GET",
            url="https://127.0.0.1:8443/ws?transport=websocket",
            host="127.0.0.1",
            port=8443,
            pins=("127.0.0.7", "::1"),
            headers={
                "User-Agent": "ravage-probe/1.0",
                "Accept-Encoding": "identity",
                "Host": "canonical.test",
                "X-Base": "override",
                "X-Call": "present",
            },
            timeout_seconds=2.5,
        )
    ]
    assert session.physical_request_count == 1


@pytest.mark.parametrize("method", ["GE T", "GET\r\nX-Injected"])
def test_external_transport_rejects_non_token_method_before_policy_acquire(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    method: str,
) -> None:
    controller = _controller(tmp_path)
    acquire_calls = 0
    original_acquire = controller.acquire

    def acquire(intent: RequestIntent, *, retry: bool = False) -> TrafficDecision:
        nonlocal acquire_calls
        acquire_calls += 1
        return original_acquire(intent, retry=retry)

    monkeypatch.setattr(controller, "acquire", acquire)
    session = ProbeSession(
        "http://127.0.0.1:8080/",
        resolver=_local_resolver,
        traffic_policy=controller,
    )

    with pytest.raises(ValueError, match="method"):
        session.run_external_transport(
            method,
            "/ws",
            lambda _request: pytest.fail("transport must not run"),
        )

    snapshot = controller.snapshot()
    assert acquire_calls == 0
    assert session.physical_request_count == 0
    assert snapshot.physical_request_count == 0
    assert snapshot.reservation_count == 0


def test_oversized_external_result_counts_and_completes_transport_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(http_probe, "MAX_CONTROLLED_BODY_BYTES", 8)
    controller = _controller(tmp_path)
    completed = _record_completions(monkeypatch, controller)
    session = ProbeSession(
        "http://127.0.0.1:8080/",
        resolver=_local_resolver,
        traffic_policy=controller,
    )

    def oversized(_request: ControlledTransportRequest) -> ControlledTransportResult:
        return ControlledTransportResult(
            response_bytes=b"123456789",
            outcome=TrafficOutcome(status=200),
        )

    with pytest.raises(ValueError, match="bounded byte limit"):
        session.run_external_transport("GET", "/ws", oversized)

    snapshot = controller.snapshot()
    assert session.physical_request_count == 1
    assert snapshot.physical_request_count == 1
    assert snapshot.completed_request_count == 1
    assert completed == [TrafficOutcome(status=None, transport_error=True)]


def test_external_transport_scope_failure_never_reserves_or_dispatches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    acquire_calls = 0
    original_acquire = controller.acquire

    def acquire(intent: RequestIntent, *, retry: bool = False) -> TrafficDecision:
        nonlocal acquire_calls
        acquire_calls += 1
        return original_acquire(intent, retry=retry)

    monkeypatch.setattr(controller, "acquire", acquire)
    session = ProbeSession(
        "http://127.0.0.1:8080/app/",
        in_scope=["http://127.0.0.1:8080/app/"],
        resolver=_local_resolver,
        traffic_policy=controller,
    )

    with pytest.raises(TrafficPolicyBlocked, match="outside"):
        session.run_external_transport(
            "GET",
            "/outside",
            lambda _request: pytest.fail("transport must not run"),
        )

    snapshot = controller.snapshot()
    assert acquire_calls == 0
    assert session.physical_request_count == 0
    assert snapshot.physical_request_count == 0
    assert snapshot.pending_dispatch_count == 0
    assert snapshot.reservation_count == 0


def test_external_transport_dns_failure_never_reserves_or_dispatches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    acquire_calls = 0
    original_acquire = controller.acquire

    def acquire(intent: RequestIntent, *, retry: bool = False) -> TrafficDecision:
        nonlocal acquire_calls
        acquire_calls += 1
        return original_acquire(intent, retry=retry)

    monkeypatch.setattr(controller, "acquire", acquire)

    def fail_dns(_host: str, _port: int) -> tuple[str, ...]:
        raise OSError("resolver unavailable")

    session = ProbeSession(
        "http://127.0.0.1:8080/",
        resolver=fail_dns,
        traffic_policy=controller,
    )

    with pytest.raises(TrafficPolicyBlocked, match="DNS resolution failed"):
        session.run_external_transport(
            "GET",
            "/ws",
            lambda _request: pytest.fail("transport must not run"),
        )

    snapshot = controller.snapshot()
    assert acquire_calls == 0
    assert session.physical_request_count == 0
    assert snapshot.physical_request_count == 0
    assert snapshot.pending_dispatch_count == 0
    assert snapshot.reservation_count == 0


def test_external_transport_post_reservation_preflight_releases_lease_without_counting(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    events: list[str] = []
    original_acquire = controller.acquire
    original_cancel = controller.cancel

    def acquire(intent: RequestIntent, *, retry: bool = False) -> TrafficDecision:
        events.append("acquire")
        return original_acquire(intent, retry=retry)

    def cancel(lease: DispatchLease) -> None:
        events.append("cancel")
        original_cancel(lease)

    monkeypatch.setattr(controller, "acquire", acquire)
    monkeypatch.setattr(controller, "cancel", cancel)
    session = ProbeSession(
        "http://127.0.0.1:8080/",
        resolver=_local_resolver,
        traffic_policy=controller,
    )
    snapshots_during_failure: list[tuple[int, int, int]] = []

    def fail_preflight() -> None:
        events.append("preflight")
        snapshot = controller.snapshot()
        snapshots_during_failure.append(
            (
                snapshot.physical_request_count,
                snapshot.pending_dispatch_count,
                snapshot.reservation_count,
            )
        )
        raise RuntimeError("pacer preflight failed")

    monkeypatch.setattr(session._request_pacer, "wait", fail_preflight)

    with pytest.raises(RuntimeError, match="pacer preflight failed"):
        session.run_external_transport(
            "GET",
            "/ws",
            lambda _request: pytest.fail("transport must not run"),
        )

    snapshot = controller.snapshot()
    assert events == ["acquire", "preflight", "cancel"]
    assert snapshots_during_failure == [(0, 0, 1)]
    assert session.physical_request_count == 0
    assert snapshot.physical_request_count == 0
    assert snapshot.pending_dispatch_count == 0
    assert snapshot.reservation_count == 0


def test_external_transport_callback_exception_counts_and_completes_transport_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    completed = _record_completions(monkeypatch, controller)
    session = ProbeSession(
        "http://127.0.0.1:8080/",
        resolver=_local_resolver,
        traffic_policy=controller,
    )

    def fail_transport(
        _request: ControlledTransportRequest,
    ) -> ControlledTransportResult:
        raise OSError("socket failed")

    with pytest.raises(OSError, match="socket failed"):
        session.run_external_transport("GET", "/ws", fail_transport)

    snapshot = controller.snapshot()
    assert session.physical_request_count == 1
    assert snapshot.physical_request_count == 1
    assert snapshot.completed_request_count == 1
    assert completed == [TrafficOutcome(status=None, transport_error=True)]


def test_websocket_helper_reports_valid_101_without_real_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    completed = _record_completions(monkeypatch, controller)

    def send_handshake(
        _parts: SplitResult,
        request: bytes,
        *,
        pinned_addresses: tuple[str, ...],
        timeout_seconds: int,
    ) -> bytes:
        assert pinned_addresses == ("127.0.0.1",)
        assert timeout_seconds == 3
        return _websocket_response(
            101,
            "Switching Protocols",
            headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Accept": _accept_for_websocket_request(request),
            },
        )

    monkeypatch.setattr(web_boundaries, "_websocket_send_handshake", send_handshake)
    session = ProbeSession(
        "http://127.0.0.1:8080/",
        resolver=_local_resolver,
        traffic_policy=controller,
    )

    result = web_boundaries._websocket_handshake(
        session,
        "ws://127.0.0.1:8080/ws",
        origin="https://evil.example",
        timeout_seconds=3,
    )

    assert result["accepted"] is True
    assert result["accept_valid"] is True
    assert result["status_line"] == "HTTP/1.1 101 Switching Protocols"
    assert session.physical_request_count == 1
    assert len(completed) == 1
    assert completed[0].status == 101
    assert completed[0].transport_error is False


def test_websocket_429_retry_after_delays_retry_without_real_sleep(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    clock = _Clock()
    controller = _controller(
        tmp_path,
        config=TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_retries=1,
            backoff_max_seconds=10,
        ),
        clock=clock,
    )
    calls = 0

    def send_handshake(
        _parts: SplitResult,
        request: bytes,
        *,
        pinned_addresses: tuple[str, ...],
        timeout_seconds: int,
    ) -> bytes:
        nonlocal calls
        assert pinned_addresses == ("127.0.0.1",)
        assert timeout_seconds == 4
        calls += 1
        if calls == 1:
            return _websocket_response(
                429, "Too Many Requests", headers={"Retry-After": "5"}
            )
        return _websocket_response(
            101,
            "Switching Protocols",
            headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Accept": _accept_for_websocket_request(request),
            },
        )

    monkeypatch.setattr(web_boundaries, "_websocket_send_handshake", send_handshake)
    session = ProbeSession(
        "http://127.0.0.1:8080/",
        resolver=_local_resolver,
        traffic_policy=controller,
    )

    result = web_boundaries._websocket_handshake(
        session,
        "ws://127.0.0.1:8080/ws",
        origin="https://evil.example",
        timeout_seconds=4,
    )

    assert result["accepted"] is True
    assert calls == 2
    assert session.physical_request_count == 2
    assert controller.snapshot().retry_count == 1
    assert clock.sleeps == [5.0]


def test_websocket_503_opens_circuit_and_blocks_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    clock = _Clock()
    controller = _controller(
        tmp_path,
        config=TrafficPolicyConfig(
            mode=TrafficPolicyMode.ENFORCE,
            max_retries=1,
            circuit_failure_threshold=1,
            circuit_open_seconds=30,
        ),
        clock=clock,
    )
    calls = 0

    def send_handshake(
        _parts: SplitResult,
        _request: bytes,
        *,
        pinned_addresses: tuple[str, ...],
        timeout_seconds: int,
    ) -> bytes:
        nonlocal calls
        assert pinned_addresses == ("127.0.0.1",)
        assert timeout_seconds == 4
        calls += 1
        return _websocket_response(503, "Service Unavailable")

    monkeypatch.setattr(web_boundaries, "_websocket_send_handshake", send_handshake)
    session = ProbeSession(
        "http://127.0.0.1:8080/",
        resolver=_local_resolver,
        traffic_policy=controller,
    )

    result = web_boundaries._websocket_handshake(
        session,
        "ws://127.0.0.1:8080/ws",
        origin="https://evil.example",
        timeout_seconds=4,
    )

    assert result["accepted"] is False
    assert "circuit" in str(result["error"]).lower()
    assert calls == 1
    assert session.physical_request_count == 1
    assert controller.snapshot().circuit_open_count == 1
    assert clock.sleeps == []


def test_malformed_websocket_response_completes_transport_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    controller = _controller(tmp_path)
    completed = _record_completions(monkeypatch, controller)

    def send_handshake(
        _parts: SplitResult,
        _request: bytes,
        *,
        pinned_addresses: tuple[str, ...],
        timeout_seconds: int,
    ) -> bytes:
        assert pinned_addresses == ("127.0.0.1",)
        assert timeout_seconds == 4
        return b"this is not an HTTP response\r\nX-Test: value\r\n\r\n"

    monkeypatch.setattr(web_boundaries, "_websocket_send_handshake", send_handshake)
    session = ProbeSession(
        "http://127.0.0.1:8080/",
        resolver=_local_resolver,
        traffic_policy=controller,
    )

    result = web_boundaries._websocket_handshake(
        session,
        "ws://127.0.0.1:8080/ws",
        origin="https://evil.example",
        timeout_seconds=4,
    )

    assert result["accepted"] is False
    assert session.physical_request_count == 1
    assert len(completed) == 1
    assert completed[0].status is None
    assert completed[0].transport_error is True
