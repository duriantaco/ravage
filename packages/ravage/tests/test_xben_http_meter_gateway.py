from __future__ import annotations

import http.client
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from ravage.xben_parts.http_meter_gateway import (
    DEFAULT_MAX_REQUEST_BODY_BYTES,
    DEFAULT_MAX_RESPONSE_BODY_BYTES,
    HTTP_METER_PROTOCOL,
    HTTP_METER_SCHEMA_VERSION,
    MAX_CONCURRENT_REQUESTS,
    HttpRequestMeter,
    _MeterHandler,
    _MeterServer,
    _emit_receipt,
    _parser,
    _read_bounded_response,
    _ResponseTooLargeError,
    _sanitize_response_headers,
    program_sha256,
    validate_receipt_payload,
)


def test_cli_accepts_cross_daemon_loopback_access_boundary() -> None:
    args = _parser().parse_args(
        [
            "serve",
            "--listen-config",
            "/run/ravage-http-meter/listen.json",
            "--receipt",
            "/run/ravage-http-meter/receipt.json",
            "--instance-id",
            "xben-row-meter",
            "--listen-port",
            "49152",
            "--upstream-host",
            "target",
            "--upstream-port",
            "80",
            "--max-target-requests",
            "20",
            "--access-boundary",
            "root-owned-cross-daemon-loopback",
        ]
    )

    assert args.access_boundary == "root-owned-cross-daemon-loopback"


@pytest.mark.parametrize(
    ("request_version", "expected"),
    [
        ("HTTP/0.9", (False, 0)),
        ("HTTP/1.0", (True, 0)),
        ("HTTP/1.1", (True, 0)),
        ("HTTP/1.9", (False, 0)),
        ("HTTP/2.0", (False, 0)),
    ],
)
def test_handler_accepts_only_declared_http_versions(
    request_version: str,
    expected: tuple[bool, int],
) -> None:
    handler = object.__new__(_MeterHandler)
    handler.server = SimpleNamespace(  # type: ignore[assignment]
        meter=SimpleNamespace(max_request_body_bytes=DEFAULT_MAX_REQUEST_BODY_BYTES)
    )
    handler.headers = Message()
    handler.path = "/"
    handler.command = "GET"
    handler.request_version = request_version

    assert handler._supported_request(force_unsupported=False) == expected


def test_http_meter_enforces_hard_inbound_allowance_before_forwarding(tmp_path: Path) -> None:
    meter = HttpRequestMeter(
        receipt_path=tmp_path / "receipt.json",
        instance_id="xben-row-meter",
        listen_host="172.30.0.8",
        listen_port=8080,
        upstream_host="web",
        upstream_port=80,
        max_target_requests=2,
    )
    meter.mark_ready()

    assert meter.begin_request(supported=True) == "accepted"
    meter.mark_target_attempt()
    meter.finish_request(upstream_error=False)
    assert meter.begin_request(supported=False) == "unsupported"
    assert meter.begin_request(supported=True) == "over_limit"

    receipt = validate_receipt_payload(
        json.loads((tmp_path / "receipt.json").read_text(encoding="utf-8"))
    )
    assert receipt["observed_requests"] == 3
    assert receipt["accepted_requests"] == 1
    assert receipt["target_request_attempts"] == 1
    assert receipt["unsupported_requests"] == 1
    assert receipt["rejected_over_limit"] == 1
    assert receipt["accepted_requests"] <= receipt["max_target_requests"]


def test_http_meter_hard_limit_is_atomic_under_concurrent_requests(tmp_path: Path) -> None:
    meter = HttpRequestMeter(
        receipt_path=tmp_path / "receipt.json",
        instance_id="xben-row-concurrent-meter",
        listen_host="172.30.0.8",
        listen_port=8080,
        upstream_host="web",
        upstream_port=80,
        max_target_requests=5,
    )
    meter.mark_ready()

    def request() -> str:
        decision = meter.begin_request(supported=True)
        if decision == "accepted":
            meter.mark_target_attempt()
            meter.finish_request(upstream_error=False)
        return decision

    with ThreadPoolExecutor(max_workers=20) as executor:
        decisions = list(executor.map(lambda _ordinal: request(), range(20)))

    receipt = validate_receipt_payload(
        json.loads((tmp_path / "receipt.json").read_text(encoding="utf-8"))
    )
    assert decisions.count("accepted") == 5
    assert decisions.count("over_limit") == 15
    assert receipt["accepted_requests"] == 5
    assert receipt["target_request_attempts"] == 5
    assert receipt["rejected_over_limit"] == 15


def test_request_after_hard_limit_never_reaches_real_upstream(tmp_path: Path) -> None:
    upstream_hits: list[str] = []

    class UpstreamHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
            upstream_hits.append(self.path)
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    upstream_port = int(upstream.server_address[1])
    meter = HttpRequestMeter(
        receipt_path=tmp_path / "receipt.json",
        instance_id="xben-row-real-socket-limit",
        listen_host="127.0.0.1",
        listen_port=1,
        upstream_host="127.0.0.1",
        upstream_port=upstream_port,
        max_target_requests=1,
    )
    gateway = _MeterServer(
        ("127.0.0.1", 0),
        _MeterHandler,
        meter=meter,
        upstream_timeout_seconds=2,
    )
    meter.listen_port = int(gateway.server_address[1])
    meter.mark_ready()
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    gateway_thread = threading.Thread(target=gateway.serve_forever, daemon=True)
    upstream_thread.start()
    gateway_thread.start()

    def request() -> int:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            meter.listen_port,
            timeout=2,
        )
        try:
            connection.request("GET", "/proof")
            response = connection.getresponse()
            response.read()
            return int(response.status)
        finally:
            connection.close()

    try:
        assert request() == 204
        assert request() == 429
    finally:
        gateway.shutdown()
        upstream.shutdown()
        gateway.server_close()
        upstream.server_close()
        gateway_thread.join(timeout=2)
        upstream_thread.join(timeout=2)

    assert upstream_hits == ["/proof"]
    receipt = validate_receipt_payload(
        json.loads((tmp_path / "receipt.json").read_text(encoding="utf-8"))
    )
    assert receipt["accepted_requests"] == 1
    assert receipt["target_request_attempts"] == 1
    assert receipt["rejected_over_limit"] == 1


def test_zero_wait_receipt_still_reads_once(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "receipt.json"
    meter = HttpRequestMeter(
        receipt_path=path,
        instance_id="xben-row-zero-wait",
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_host="target",
        upstream_port=80,
        max_target_requests=1,
    )
    meter.mark_ready()

    result = _emit_receipt(
        SimpleNamespace(
            path=str(path),
            wait_seconds=0.0,
            require_idle=False,
            require_sealed=False,
        )
    )

    assert result == 0
    assert validate_receipt_payload(json.loads(capsys.readouterr().out))["instance_id"] == (
        "xben-row-zero-wait"
    )


def test_http_meter_seal_closes_admission_and_freezes_terminal_receipt(tmp_path: Path) -> None:
    receipt_path = tmp_path / "receipt.json"
    meter = HttpRequestMeter(
        receipt_path=receipt_path,
        instance_id="xben-row-sealed-meter",
        listen_host="172.30.0.8",
        listen_port=8080,
        upstream_host="web",
        upstream_port=80,
        max_target_requests=3,
    )
    meter.mark_ready()
    assert meter.begin_request(supported=True) == "accepted"
    meter.mark_target_attempt()
    meter.seal()
    meter.finish_request(upstream_error=False)
    terminal = receipt_path.read_bytes()

    assert meter.begin_request(supported=True) == "sealed"
    assert meter.begin_request(supported=False) == "sealed"
    assert receipt_path.read_bytes() == terminal
    receipt = validate_receipt_payload(json.loads(terminal))
    assert receipt["sealed"] is True
    assert receipt["in_flight_requests"] == 0
    assert receipt["observed_requests"] == 1


def test_http_meter_counts_upstream_failure_without_leaking_request_content(
    tmp_path: Path,
) -> None:
    meter = HttpRequestMeter(
        receipt_path=tmp_path / "receipt.json",
        instance_id="xben-row-errors",
        listen_host="172.30.0.8",
        listen_port=8080,
        upstream_host="web",
        upstream_port=80,
        max_target_requests=3,
    )
    meter.mark_ready()
    assert meter.begin_request(supported=True) == "accepted"
    meter.mark_target_attempt()
    meter.finish_request(upstream_error=True)

    raw = (tmp_path / "receipt.json").read_text(encoding="utf-8")
    assert "secret-path" not in raw
    receipt = validate_receipt_payload(json.loads(raw))
    assert receipt["target_request_attempts"] == 1
    assert receipt["upstream_errors"] == 1


def test_http_meter_records_oversize_response_as_an_upstream_error(tmp_path: Path) -> None:
    meter = HttpRequestMeter(
        receipt_path=tmp_path / "receipt.json",
        instance_id="xben-row-oversize",
        listen_host="172.30.0.8",
        listen_port=8080,
        upstream_host="web",
        upstream_port=80,
        max_target_requests=3,
    )
    meter.mark_ready()
    assert meter.begin_request(supported=True) == "accepted"
    meter.mark_target_attempt()
    meter.finish_request(upstream_error=True, oversize_response=True)

    receipt = validate_receipt_payload(
        json.loads((tmp_path / "receipt.json").read_text(encoding="utf-8"))
    )
    assert receipt["upstream_errors"] == 1
    assert receipt["oversize_responses"] == 1


def test_handler_turns_oversize_response_into_counted_closed_502(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    meter = HttpRequestMeter(
        receipt_path=tmp_path / "receipt.json",
        instance_id="xben-row-handler-oversize",
        listen_host="172.30.0.8",
        listen_port=8080,
        upstream_host="web",
        upstream_port=80,
        max_target_requests=3,
    )
    meter.mark_ready()
    handler = object.__new__(_MeterHandler)
    handler.server = SimpleNamespace(meter=meter, upstream_timeout_seconds=3)  # type: ignore[assignment]
    handler.connection = _FakeConnection()  # type: ignore[assignment]
    handler.rfile = BytesIO()
    handler.headers = Message()
    handler.path = "/"
    handler.command = "GET"
    handler.request_version = "HTTP/1.1"
    responses: list[tuple[int, bytes]] = []

    def raise_oversize(*, body: bytes | None) -> None:
        del body
        raise _ResponseTooLargeError("secret response content is never retained")

    monkeypatch.setattr(handler, "_forward", raise_oversize)
    monkeypatch.setattr(
        handler,
        "_generic_response",
        lambda status, body: responses.append((status, body)),
    )

    handler._handle_request()

    receipt = validate_receipt_payload(
        json.loads((tmp_path / "receipt.json").read_text(encoding="utf-8"))
    )
    assert responses == [(502, b"upstream response exceeded limit\n")]
    assert receipt["target_request_attempts"] == 1
    assert receipt["upstream_errors"] == 1
    assert receipt["oversize_responses"] == 1
    assert "secret response content" not in json.dumps(receipt)


@pytest.mark.parametrize("framing_header", [None, ("Transfer-Encoding", "chunked")])
def test_response_without_length_or_with_chunking_is_buffered_for_fresh_framing(
    framing_header: tuple[str, str] | None,
) -> None:
    headers = Message()
    if framing_header is not None:
        headers.add_header(*framing_header)
    response = _FakeResponse(headers=headers, body=b"complete-body")

    body, length = _read_bounded_response(response, max_bytes=64, is_head=False)  # type: ignore[arg-type]

    assert body == b"complete-body"
    assert length == len(body)
    assert _sanitize_response_headers(list(headers.items())) == []


@pytest.mark.parametrize("framing_header", [None, ("Transfer-Encoding", "chunked")])
def test_forwarded_response_has_fresh_length_and_forced_close_without_network(
    framing_header: tuple[str, str] | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = Message()
    if framing_header is not None:
        headers.add_header(*framing_header)
    response = _FakeResponse(
        headers=headers,
        body=b"complete-body",
        reason="unsafe\r\nX-Split: injected",
    )
    upstream = _FakeUpstreamConnection(response)
    monkeypatch.setattr(http.client, "HTTPConnection", lambda *_args, **_kwargs: upstream)
    meter = HttpRequestMeter(
        receipt_path=tmp_path / "unused-receipt.json",
        instance_id="xben-row-framing",
        listen_host="172.30.0.8",
        listen_port=8080,
        upstream_host="web",
        upstream_port=80,
        max_target_requests=3,
    )
    handler = object.__new__(_MeterHandler)
    handler.server = SimpleNamespace(meter=meter, upstream_timeout_seconds=3)  # type: ignore[assignment]
    handler.headers = Message()
    handler.path = "/result"
    handler.command = "GET"
    handler.close_connection = False
    handler.wfile = BytesIO()
    statuses: list[tuple[object, ...]] = []
    sent_headers: list[tuple[str, str]] = []
    monkeypatch.setattr(handler, "send_response", lambda *args: statuses.append(args))
    monkeypatch.setattr(
        handler, "send_header", lambda name, value: sent_headers.append((name, value))
    )
    monkeypatch.setattr(handler, "end_headers", lambda: None)

    handler._forward(body=None)

    assert statuses == [(200,)]
    assert ("Content-Length", str(len(b"complete-body"))) in sent_headers
    assert ("Connection", "close") in sent_headers
    assert all(name.lower() != "transfer-encoding" for name, _value in sent_headers)
    assert handler.close_connection is True
    assert handler.wfile.getvalue() == b"complete-body"
    assert upstream.closed is True


def test_response_buffer_rejects_declared_or_observed_oversize_body() -> None:
    declared = Message()
    declared["Content-Length"] = "65"
    with pytest.raises(_ResponseTooLargeError):
        _read_bounded_response(  # type: ignore[arg-type]
            _FakeResponse(headers=declared, body=b""),
            max_bytes=64,
            is_head=False,
        )

    with pytest.raises(_ResponseTooLargeError):
        _read_bounded_response(  # type: ignore[arg-type]
            _FakeResponse(headers=Message(), body=b"x" * 65),
            max_bytes=64,
            is_head=False,
        )


def test_response_header_sanitizer_drops_framing_hop_and_crlf_values() -> None:
    retained = _sanitize_response_headers(
        [
            ("Content-Type", "text/plain"),
            ("Content-Length", "999"),
            ("Transfer-Encoding", "chunked"),
            ("Connection", "X-Remove"),
            ("X-Remove", "hop-value"),
            ("Bad Header", "invalid-name"),
            ("X-Split", "safe\r\nInjected: bad"),
            ("X-Nul", "unsafe\x00value"),
        ]
    )

    assert retained == [("Content-Type", "text/plain")]


def test_generic_gateway_response_is_framed_and_connection_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = object.__new__(_MeterHandler)
    handler.command = "GET"
    handler.close_connection = False
    handler.wfile = BytesIO()
    sent_headers: list[tuple[str, str]] = []
    monkeypatch.setattr(handler, "send_response", lambda _status: None)
    monkeypatch.setattr(
        handler, "send_header", lambda name, value: sent_headers.append((name, value))
    )
    monkeypatch.setattr(handler, "end_headers", lambda: None)

    handler._generic_response(429, b"bounded\n")

    assert ("Content-Length", str(len(b"bounded\n"))) in sent_headers
    assert ("Connection", "close") in sent_headers
    assert handler.close_connection is True
    assert handler.wfile.getvalue() == b"bounded\n"


@pytest.mark.parametrize(
    "mutation",
    [
        {"accepted_requests": 4, "max_target_requests": 3},
        {"observed_requests": 2, "accepted_requests": 1},
        {"target_request_attempts": 2, "accepted_requests": 1},
        {"in_flight_requests": -1},
    ],
)
def test_receipt_validator_rejects_impossible_or_limit_violating_counts(
    mutation: dict[str, int],
) -> None:
    payload = _receipt()
    payload.update(mutation)

    with pytest.raises(ValueError):
        validate_receipt_payload(payload)


def test_receipt_contains_only_bounded_metadata_not_request_logs() -> None:
    payload = _receipt()

    assert set(payload) == {
        "schema_version",
        "program_sha256",
        "protocol",
        "instance_id",
        "ready",
        "sealed",
        "access_boundary",
        "caller_authentication",
        "trusted_host_no_concurrent_local_adversary",
        "listen_host",
        "listen_port",
        "upstream_host",
        "upstream_port",
        "max_target_requests",
        "max_request_body_bytes",
        "max_response_body_bytes",
        "max_concurrent_requests",
        "observed_requests",
        "accepted_requests",
        "target_request_attempts",
        "unsupported_requests",
        "rejected_over_limit",
        "upstream_errors",
        "oversize_responses",
        "in_flight_requests",
        "sequence",
        "updated_at",
    }
    assert validate_receipt_payload(payload) == payload


def _receipt() -> dict[str, object]:
    return {
        "schema_version": HTTP_METER_SCHEMA_VERSION,
        "program_sha256": program_sha256(),
        "protocol": HTTP_METER_PROTOCOL,
        "instance_id": "xben-row-receipt",
        "ready": True,
        "sealed": False,
        "access_boundary": "evaluator-owned-docker-network",
        "caller_authentication": "none",
        "trusted_host_no_concurrent_local_adversary": False,
        "listen_host": "172.30.0.8",
        "listen_port": 8080,
        "upstream_host": "web",
        "upstream_port": 80,
        "max_target_requests": 3,
        "max_request_body_bytes": DEFAULT_MAX_REQUEST_BODY_BYTES,
        "max_response_body_bytes": DEFAULT_MAX_RESPONSE_BODY_BYTES,
        "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
        "observed_requests": 1,
        "accepted_requests": 1,
        "target_request_attempts": 1,
        "unsupported_requests": 0,
        "rejected_over_limit": 0,
        "upstream_errors": 0,
        "oversize_responses": 0,
        "in_flight_requests": 0,
        "sequence": 4,
        "updated_at": "2026-09-11T00:00:00+00:00",
    }


class _FakeResponse:
    def __init__(
        self,
        *,
        headers: Message,
        body: bytes,
        reason: str = "OK",
    ) -> None:
        self.headers = headers
        self._body = body
        self.status = 200
        self.reason = reason

    def read(self, amount: int) -> bytes:
        return self._body[:amount]

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self.headers.items())


class _FakeConnection:
    def settimeout(self, timeout: int) -> None:
        assert timeout == 3


class _FakeUpstreamConnection:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.closed = False

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None,
        headers: dict[str, str],
    ) -> None:
        assert method == "GET"
        assert path == "/result"
        assert body is None
        assert headers["Host"] == "web:80"
        assert headers["Connection"] == "close"

    def getresponse(self) -> _FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True
