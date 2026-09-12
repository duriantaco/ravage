"""Minimal HTTP-only reverse proxy with a hard request allowance.

This module is designed to run inside a digest-pinned evaluator gateway image.
It has no management HTTP endpoint: configuration and receipt reads happen only
through evaluator-owned ``docker exec`` invocations.  Request paths, headers,
bodies, and responses are never logged or written to the receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import re
import signal
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

HTTP_METER_SCHEMA_VERSION = "ravage.xben.http-request-meter.v2"
HTTP_METER_PROTOCOL = "http/1.0-1.1-origin-form"
DEFAULT_MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_RESPONSE_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_UPSTREAM_TIMEOUT_SECONDS = 30
DEFAULT_STARTUP_WAIT_SECONDS = 60
MAX_RECEIPT_BYTES = 64 * 1024
MAX_BUFFERED_BODY_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_HEADER_VALUE_BYTES = 16 * 1024
MAX_CONCURRENT_REQUESTS = 4

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_HEADER_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_RECEIPT_KEYS = {
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

RequestDecision = Literal["accepted", "unsupported", "over_limit", "sealed"]
AccessBoundary = Literal[
    "evaluator-owned-docker-network",
    "root-owned-cross-daemon-loopback",
    "trusted-host-loopback",
]
_ACCESS_BOUNDARIES: tuple[AccessBoundary, ...] = (
    "evaluator-owned-docker-network",
    "root-owned-cross-daemon-loopback",
    "trusted-host-loopback",
)


class _ResponseTooLargeError(RuntimeError):
    """Raised before an oversized upstream response reaches the caller."""


def program_sha256() -> str:
    """Return the digest of the exact meter module running in this process."""

    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


@dataclass
class HttpRequestMeter:
    """Thread-safe hard allowance and atomic, metadata-only receipt writer."""

    receipt_path: Path
    instance_id: str
    listen_host: str
    listen_port: int
    upstream_host: str
    upstream_port: int
    max_target_requests: int
    access_boundary: AccessBoundary = "evaluator-owned-docker-network"
    max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES
    max_response_body_bytes: int = DEFAULT_MAX_RESPONSE_BODY_BYTES
    ready: bool = False
    sealed: bool = False
    observed_requests: int = 0
    accepted_requests: int = 0
    target_request_attempts: int = 0
    unsupported_requests: int = 0
    rejected_over_limit: int = 0
    upstream_errors: int = 0
    oversize_responses: int = 0
    in_flight_requests: int = 0
    sequence: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if self.max_target_requests <= 0:
            raise ValueError("target request limit must be positive")
        if not 0 < self.max_request_body_bytes <= MAX_BUFFERED_BODY_BYTES:
            raise ValueError("request body limit is invalid")
        if not 0 < self.max_response_body_bytes <= MAX_BUFFERED_BODY_BYTES:
            raise ValueError("response body limit is invalid")
        if not 1 <= self.listen_port <= 65535 or not 1 <= self.upstream_port <= 65535:
            raise ValueError("meter port is invalid")
        if self.access_boundary not in _ACCESS_BOUNDARIES:
            raise ValueError("meter access boundary is invalid")

    def mark_ready(self) -> None:
        with self._lock:
            if self.ready:
                raise RuntimeError("request meter was already marked ready")
            self.ready = True
            self._write_locked()

    def begin_request(self, *, supported: bool) -> RequestDecision:
        """Reserve one inbound request before reading or forwarding its body."""

        with self._lock:
            if not self.ready:
                raise RuntimeError("request meter is not ready")
            # Sealing is the evaluator's terminal accounting boundary. Requests
            # serialized after it cannot reach the target or mutate the receipt.
            if self.sealed:
                return "sealed"
            self.observed_requests += 1
            if self.observed_requests > self.max_target_requests:
                self.rejected_over_limit += 1
                decision: RequestDecision = "over_limit"
            elif not supported:
                self.unsupported_requests += 1
                decision = "unsupported"
            else:
                self.accepted_requests += 1
                self.in_flight_requests += 1
                decision = "accepted"
            self._write_locked()
            return decision

    def seal(self) -> None:
        """Close admission exactly once while allowing accepted work to drain."""

        with self._lock:
            if not self.ready:
                raise RuntimeError("request meter is not ready")
            if self.sealed:
                return
            self.sealed = True
            self._write_locked()

    def mark_target_attempt(self) -> None:
        with self._lock:
            self.target_request_attempts += 1
            if self.target_request_attempts > self.accepted_requests:
                raise RuntimeError("target attempt exceeds accepted request count")
            self._write_locked()

    def finish_request(
        self,
        *,
        upstream_error: bool,
        oversize_response: bool = False,
    ) -> None:
        with self._lock:
            if oversize_response and not upstream_error:
                raise ValueError("oversize response must also be an upstream error")
            if self.in_flight_requests <= 0:
                raise RuntimeError("no in-flight request to finish")
            self.in_flight_requests -= 1
            if upstream_error:
                self.upstream_errors += 1
            if oversize_response:
                self.oversize_responses += 1
            self._write_locked()

    def _snapshot_locked(self) -> dict[str, object]:
        return {
            "schema_version": HTTP_METER_SCHEMA_VERSION,
            "program_sha256": program_sha256(),
            "protocol": HTTP_METER_PROTOCOL,
            "instance_id": self.instance_id,
            "ready": self.ready,
            "sealed": self.sealed,
            "access_boundary": self.access_boundary,
            "caller_authentication": "none",
            "trusted_host_no_concurrent_local_adversary": (
                self.access_boundary == "trusted-host-loopback"
            ),
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "upstream_host": self.upstream_host,
            "upstream_port": self.upstream_port,
            "max_target_requests": self.max_target_requests,
            "max_request_body_bytes": self.max_request_body_bytes,
            "max_response_body_bytes": self.max_response_body_bytes,
            "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
            "observed_requests": self.observed_requests,
            "accepted_requests": self.accepted_requests,
            "target_request_attempts": self.target_request_attempts,
            "unsupported_requests": self.unsupported_requests,
            "rejected_over_limit": self.rejected_over_limit,
            "upstream_errors": self.upstream_errors,
            "oversize_responses": self.oversize_responses,
            "in_flight_requests": self.in_flight_requests,
            "sequence": self.sequence,
            "updated_at": datetime.now(UTC).isoformat(),
        }

    def _write_locked(self) -> None:
        self.sequence += 1
        payload = self._snapshot_locked()
        payload["sequence"] = self.sequence
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(encoded) > MAX_RECEIPT_BYTES:
            raise RuntimeError("request meter receipt exceeds its fixed size limit")
        temporary = self.receipt_path.with_suffix(".tmp")
        with temporary.open("wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.receipt_path)


class _MeterServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        meter: HttpRequestMeter,
        upstream_timeout_seconds: int,
    ) -> None:
        self.meter = meter
        self.upstream_timeout_seconds = upstream_timeout_seconds
        self._worker_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        super().__init__(server_address, handler_class)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        request, client_address = super().get_request()
        request.settimeout(self.upstream_timeout_seconds)
        return request, client_address

    def process_request(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
    ) -> None:
        self._worker_slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class _MeterHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _MeterServer

    def __getattr__(self, name: str) -> object:
        # BaseHTTPRequestHandler dispatches extension methods through do_*.
        # Count syntactically valid unknown methods as unsupported allowance
        # consumers instead of letting the base class emit an unmetered 501.
        if name.startswith("do_"):
            return self._handle_unsupported_method
        raise AttributeError(name)

    def _handle_unsupported_method(self) -> None:
        self._handle_request(force_unsupported=True)

    def do_CONNECT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle_request(force_unsupported=True)

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle_request()

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle_request()

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle_request()

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle_request()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle_request()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle_request()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        self._handle_request()

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress request logs so credentials, paths, and proofs never escape."""

    def _handle_request(self, *, force_unsupported: bool = False) -> None:
        supported, content_length = self._supported_request(force_unsupported=force_unsupported)
        decision = self.server.meter.begin_request(supported=supported)
        if decision == "sealed":
            self._generic_response(503, b"gateway is sealed\n")
            return
        if decision == "over_limit":
            self._generic_response(429, b"request limit reached\n")
            return
        if decision == "unsupported":
            self._generic_response(501, b"unsupported gateway request\n")
            return
        upstream_error = False
        oversize_response = False
        try:
            self.connection.settimeout(self.server.upstream_timeout_seconds)
            body = self.rfile.read(content_length) if content_length else None
            if body is not None and len(body) != content_length:
                raise http.client.IncompleteRead(body, content_length - len(body))
            self.server.meter.mark_target_attempt()
            self._forward(body=body)
        except _ResponseTooLargeError:
            upstream_error = True
            oversize_response = True
            self._generic_response(502, b"upstream response exceeded limit\n")
        except (OSError, TimeoutError, http.client.HTTPException, ValueError):
            upstream_error = True
            self._generic_response(502, b"upstream request failed\n")
        finally:
            self.server.meter.finish_request(
                upstream_error=upstream_error,
                oversize_response=oversize_response,
            )

    def _supported_request(self, *, force_unsupported: bool) -> tuple[bool, int]:
        transfer_encodings = self.headers.get_all("Transfer-Encoding", [])
        upgrades = self.headers.get_all("Upgrade", [])
        if (
            force_unsupported
            or self.request_version not in {"HTTP/1.0", "HTTP/1.1"}
            or not (self.path.startswith("/") or (self.command == "OPTIONS" and self.path == "*"))
            or self.path.startswith("//")
            or "#" in self.path
            or bool(upgrades)
            or bool(transfer_encodings)
        ):
            return False, 0
        raw_lengths = self.headers.get_all("Content-Length", [])
        if not raw_lengths:
            return True, 0
        if len(raw_lengths) != 1:
            return False, 0
        raw_length = raw_lengths[0]
        if not raw_length.isascii() or not raw_length.isdigit():
            return False, 0
        normalized_length = raw_length.lstrip("0") or "0"
        if len(normalized_length) > len(str(MAX_BUFFERED_BODY_BYTES)):
            return False, 0
        content_length = int(normalized_length)
        if not 0 <= content_length <= self.server.meter.max_request_body_bytes:
            return False, 0
        return True, content_length

    def _forward(self, *, body: bytes | None) -> None:
        split = urlsplit(self.path)
        path = split.path or "/"
        if split.query:
            path = f"{path}?{split.query}"
        headers = _sanitize_request_headers(list(self.headers.items()))
        headers["Host"] = f"{self.server.meter.upstream_host}:{self.server.meter.upstream_port}"
        headers["Connection"] = "close"
        connection = http.client.HTTPConnection(
            self.server.meter.upstream_host,
            self.server.meter.upstream_port,
            timeout=self.server.upstream_timeout_seconds,
        )
        try:
            connection.request(self.command, path, body=body, headers=headers)
            response = connection.getresponse()
            response_body, response_length = _read_bounded_response(
                response,
                max_bytes=self.server.meter.max_response_body_bytes,
                is_head=self.command == "HEAD",
            )
            response_headers = _sanitize_response_headers(response.getheaders())
            if not 100 <= response.status <= 599:
                raise http.client.BadStatusLine(str(response.status))
            # Never copy the upstream reason phrase: BaseHTTPRequestHandler does
            # not validate it against response-splitting characters.
            self.close_connection = True
            self.send_response(response.status)
            for name, value in response_headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(response_length))
            self.send_header("Connection", "close")
            self.end_headers()
            if response_body:
                self.wfile.write(response_body)
        finally:
            connection.close()

    def _generic_response(self, status: int, body: bytes) -> None:
        try:
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            return


def _read_bounded_response(
    response: http.client.HTTPResponse,
    *,
    max_bytes: int,
    is_head: bool,
) -> tuple[bytes, int]:
    """Buffer one response so the downstream framing is complete and bounded."""

    declared_length = _upstream_content_length(response.headers)
    if declared_length is not None and declared_length > max_bytes:
        raise _ResponseTooLargeError("declared response body exceeds the frozen limit")
    if is_head:
        return b"", declared_length or 0
    body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise _ResponseTooLargeError("response body exceeds the frozen limit")
    return body, len(body)


def _upstream_content_length(headers: object) -> int | None:
    """Parse unambiguous upstream Content-Length metadata, if present."""

    get_all = getattr(headers, "get_all", None)
    if not callable(get_all):
        return None
    raw_values = get_all("Content-Length", [])
    values: list[str] = []
    for raw_value in raw_values:
        values.extend(part.strip() for part in str(raw_value).split(","))
    if not values:
        return None
    if any(not value.isascii() or not value.isdigit() for value in values):
        raise http.client.HTTPException("upstream Content-Length is invalid")
    normalized = [value.lstrip("0") or "0" for value in values]
    if any(len(value) > len(str(MAX_BUFFERED_BODY_BYTES)) for value in normalized):
        raise _ResponseTooLargeError("declared response body exceeds the hard safety cap")
    parsed = {int(value) for value in normalized}
    if len(parsed) != 1:
        raise http.client.HTTPException("upstream Content-Length is ambiguous")
    return parsed.pop()


def _sanitize_response_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Drop unsafe, hop-by-hop, and evaluator-owned framing headers."""

    connection_tokens = set(_HOP_BY_HOP_HEADERS)
    for name, value in headers:
        if isinstance(name, str) and name.lower() == "connection" and isinstance(value, str):
            for token in value.split(","):
                normalized = token.strip().lower()
                if _HEADER_NAME_RE.fullmatch(normalized):
                    connection_tokens.add(normalized)
    retained: list[tuple[str, str]] = []
    for name, value in headers:
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        if (
            name.lower() in connection_tokens
            or name.lower() == "content-length"
            or not _safe_header(name, value, max_value_bytes=MAX_RESPONSE_HEADER_VALUE_BYTES)
        ):
            continue
        retained.append((name, value))
    return retained


def _sanitize_request_headers(headers: list[tuple[str, str]]) -> dict[str, str]:
    """Remove client-controlled routing, framing, and hop-by-hop headers."""

    connection_tokens = set(_HOP_BY_HOP_HEADERS)
    for name, value in headers:
        if isinstance(name, str) and name.lower() == "connection" and isinstance(value, str):
            for token in value.split(","):
                normalized = token.strip().lower()
                if _HEADER_NAME_RE.fullmatch(normalized):
                    connection_tokens.add(normalized)
    retained: dict[str, str] = {}
    for name, value in headers:
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        if (
            name.lower() in connection_tokens
            or name.lower() in {"host", "content-length"}
            or not _safe_header(name, value, max_value_bytes=MAX_RESPONSE_HEADER_VALUE_BYTES)
        ):
            continue
        retained[name] = value
    return retained


def _safe_header(name: str, value: str, *, max_value_bytes: int) -> bool:
    if _HEADER_NAME_RE.fullmatch(name) is None:
        return False
    if any(
        (ord(character) < 32 and character != "\t") or ord(character) == 127 for character in value
    ):
        return False
    try:
        encoded = value.encode("latin-1")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= max_value_bytes


def validate_receipt_payload(payload: object) -> dict[str, object]:
    """Validate shape and arithmetic without trusting unknown receipt fields."""

    if not isinstance(payload, dict) or set(payload) != _RECEIPT_KEYS:
        raise ValueError("request meter receipt has an invalid field set")
    if payload.get("schema_version") != HTTP_METER_SCHEMA_VERSION:
        raise ValueError("request meter receipt schema is invalid")
    if payload.get("protocol") != HTTP_METER_PROTOCOL:
        raise ValueError("request meter receipt protocol is invalid")
    integer_names = (
        "listen_port",
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
    )
    integers: dict[str, int] = {}
    for name in integer_names:
        value = payload.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"request meter receipt field {name!r} is not a nonnegative integer")
        integers[name] = value
    if integers["max_target_requests"] <= 0:
        raise ValueError("request meter maximum must be positive")
    if not 1 <= integers["listen_port"] <= 65535:
        raise ValueError("request meter listen port is invalid")
    if not 1 <= integers["upstream_port"] <= 65535:
        raise ValueError("request meter upstream port is invalid")
    if not 0 < integers["max_request_body_bytes"] <= MAX_BUFFERED_BODY_BYTES:
        raise ValueError("request meter request body limit is invalid")
    if not 0 < integers["max_response_body_bytes"] <= MAX_BUFFERED_BODY_BYTES:
        raise ValueError("request meter response body limit is invalid")
    if integers["max_concurrent_requests"] != MAX_CONCURRENT_REQUESTS:
        raise ValueError("request meter concurrency limit is invalid")
    if integers["sequence"] <= 0:
        raise ValueError("request meter receipt sequence must be positive")
    if integers["observed_requests"] != (
        integers["accepted_requests"]
        + integers["unsupported_requests"]
        + integers["rejected_over_limit"]
    ):
        raise ValueError("request meter receipt counts do not balance")
    if integers["accepted_requests"] > integers["max_target_requests"]:
        raise ValueError("accepted request count exceeds the hard limit")
    expected_rejections = max(
        0,
        integers["observed_requests"] - integers["max_target_requests"],
    )
    if integers["rejected_over_limit"] != expected_rejections:
        raise ValueError("rejected request count does not match the hard-limit transition")
    if integers["target_request_attempts"] > integers["accepted_requests"]:
        raise ValueError("target request attempts exceed accepted requests")
    if integers["in_flight_requests"] > integers["accepted_requests"]:
        raise ValueError("in-flight request count exceeds accepted requests")
    completed_requests = integers["accepted_requests"] - integers["in_flight_requests"]
    if integers["upstream_errors"] > completed_requests:
        raise ValueError("upstream error count exceeds accepted requests")
    if integers["oversize_responses"] > integers["upstream_errors"]:
        raise ValueError("oversize response count exceeds upstream errors")
    if integers["oversize_responses"] > integers["target_request_attempts"]:
        raise ValueError("oversize response count exceeds target attempts")
    expected_sequence = (
        1
        + integers["observed_requests"]
        + integers["target_request_attempts"]
        + completed_requests
        + (1 if payload.get("sealed") is True else 0)
    )
    if integers["sequence"] != expected_sequence:
        raise ValueError("request meter receipt sequence does not match its transitions")
    for name in ("program_sha256", "instance_id", "listen_host", "upstream_host", "updated_at"):
        value = payload.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(f"request meter receipt field {name!r} is invalid")
    try:
        ipaddress.ip_address(str(payload["listen_host"]))
    except ValueError as exc:
        raise ValueError("request meter listen host is invalid") from exc
    program_digest = str(payload["program_sha256"])
    if len(program_digest) != 64 or any(
        character not in "0123456789abcdef" for character in program_digest
    ):
        raise ValueError("request meter program SHA-256 is invalid")
    if payload.get("ready") is not True:
        raise ValueError("request meter is not ready")
    if type(payload.get("sealed")) is not bool:
        raise ValueError("request meter sealed state is invalid")
    access_boundary = payload.get("access_boundary")
    if access_boundary not in _ACCESS_BOUNDARIES:
        raise ValueError("request meter access boundary is invalid")
    if payload.get("caller_authentication") != "none":
        raise ValueError("request meter caller-authentication declaration is invalid")
    trusted_host = payload.get("trusted_host_no_concurrent_local_adversary")
    if type(trusted_host) is not bool or trusted_host is not (
        access_boundary == "trusted-host-loopback"
    ):
        raise ValueError("request meter trusted-host assumption is invalid")
    try:
        updated_at = datetime.fromisoformat(str(payload["updated_at"]))
    except ValueError as exc:
        raise ValueError("request meter receipt timestamp is invalid") from exc
    if updated_at.tzinfo is None:
        raise ValueError("request meter receipt timestamp lacks a timezone")
    return dict(payload)


def _serve(args: argparse.Namespace) -> int:
    config_path = Path(args.listen_config)
    deadline = time.monotonic() + args.startup_wait_seconds
    listen_host: str | None = None
    while time.monotonic() < deadline:
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and set(raw) == {"listen_host"}:
                listen_host = str(ipaddress.ip_address(str(raw["listen_host"])))
                break
        except (FileNotFoundError, OSError, ValueError):
            pass
        time.sleep(0.05)
    if listen_host is None:
        return 2
    try:
        meter = HttpRequestMeter(
            receipt_path=Path(args.receipt),
            instance_id=args.instance_id,
            listen_host=listen_host,
            listen_port=args.listen_port,
            upstream_host=args.upstream_host,
            upstream_port=args.upstream_port,
            max_target_requests=args.max_target_requests,
            access_boundary=args.access_boundary,
            max_request_body_bytes=args.max_request_body_bytes,
            max_response_body_bytes=args.max_response_body_bytes,
        )
        server = _MeterServer(
            (listen_host, args.listen_port),
            _MeterHandler,
            meter=meter,
            upstream_timeout_seconds=args.upstream_timeout_seconds,
        )
    except (OSError, TypeError, ValueError):
        return 2
    seal_signal = getattr(signal, "SIGUSR1", None)
    if seal_signal is None:
        return 2
    signal.signal(seal_signal, lambda _signum, _frame: meter.seal())
    meter.mark_ready()
    server.serve_forever(poll_interval=0.25)
    return 0


def _write_listen_config(args: argparse.Namespace) -> int:
    host = str(ipaddress.ip_address(args.listen_host))
    path = Path(args.path)
    encoded = (json.dumps({"listen_host": host}, sort_keys=True) + "\n").encode()
    with path.open("xb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())
    return 0


def _emit_receipt(args: argparse.Namespace) -> int:
    path = Path(args.path)
    deadline = time.monotonic() + args.wait_seconds
    while True:
        try:
            payload = path.read_bytes()
            if len(payload) > MAX_RECEIPT_BYTES:
                return 2
            parsed = validate_receipt_payload(json.loads(payload))
            idle = parsed["in_flight_requests"] == 0
            sealed = parsed["sealed"] is True
            if (not args.require_idle or idle) and (not args.require_sealed or sealed):
                sys.stdout.write(json.dumps(parsed, sort_keys=True, separators=(",", ":")) + "\n")
                return 0
        except (FileNotFoundError, OSError, ValueError):
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return 2
        time.sleep(min(0.05, remaining))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ravage-http-meter")
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("identity")
    identity.set_defaults(handler=lambda _args: _emit_identity())

    configure = subparsers.add_parser("configure")
    configure.add_argument("--path", required=True)
    configure.add_argument("--listen-host", required=True)
    configure.set_defaults(handler=_write_listen_config)

    receipt = subparsers.add_parser("receipt")
    receipt.add_argument("--path", required=True)
    receipt.add_argument("--wait-seconds", type=float, default=0.0)
    receipt.add_argument("--require-idle", action="store_true")
    receipt.add_argument("--require-sealed", action="store_true")
    receipt.set_defaults(handler=_emit_receipt)

    serve = subparsers.add_parser("serve")
    serve.add_argument("--listen-config", required=True)
    serve.add_argument("--receipt", required=True)
    serve.add_argument("--instance-id", required=True)
    serve.add_argument("--listen-port", type=int, required=True)
    serve.add_argument("--upstream-host", required=True)
    serve.add_argument("--upstream-port", type=int, required=True)
    serve.add_argument("--max-target-requests", type=int, required=True)
    serve.add_argument(
        "--access-boundary",
        choices=_ACCESS_BOUNDARIES,
        required=True,
    )
    serve.add_argument("--max-request-body-bytes", type=int, default=DEFAULT_MAX_REQUEST_BODY_BYTES)
    serve.add_argument(
        "--max-response-body-bytes",
        type=int,
        default=DEFAULT_MAX_RESPONSE_BODY_BYTES,
    )
    serve.add_argument(
        "--upstream-timeout-seconds",
        type=int,
        default=DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
    )
    serve.add_argument("--startup-wait-seconds", type=int, default=DEFAULT_STARTUP_WAIT_SECONDS)
    serve.set_defaults(handler=_serve)
    return parser


def _emit_identity() -> int:
    sys.stdout.write(
        json.dumps(
            {
                "schema_version": HTTP_METER_SCHEMA_VERSION,
                "program_sha256": program_sha256(),
                "protocol": HTTP_METER_PROTOCOL,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "serve":
        if (
            args.max_target_requests <= 0
            or args.max_request_body_bytes <= 0
            or args.max_request_body_bytes > MAX_BUFFERED_BODY_BYTES
            or args.max_response_body_bytes <= 0
            or args.max_response_body_bytes > MAX_BUFFERED_BODY_BYTES
            or args.upstream_timeout_seconds <= 0
            or args.startup_wait_seconds <= 0
            or not 1 <= args.listen_port <= 65535
            or not 1 <= args.upstream_port <= 65535
        ):
            return 2
    if args.command == "receipt" and args.wait_seconds < 0:
        return 2
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
