"""Evaluator-owned, fail-closed model gateway for paired XBEN runs.

Both systems receive only a row-scoped opaque credential and this loopback
gateway URL.  The upstream OpenAI credential remains inside the evaluator.
Requests are forced onto one frozen Chat Completions model contract and are
admitted under atomic per-row and campaign request/cost reservations.

The evidence deliberately retains no prompt, completion, authorization header,
or upstream error body.  It records hashes, token accounting, model identity,
and exact decimal costs.  A response without trustworthy usage is charged at
its conservative reservation and makes the row non-quotable.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import math
import re
import secrets
import socket
import ssl
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, ROUND_FLOOR
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Protocol

MODEL_GATEWAY_SCHEMA = "ravage.xben.model-gateway-receipt.v1"
MODEL_GATEWAY_POLICY_SCHEMA = "ravage.xben.model-gateway-policy.v1"
OPENAI_CHAT_PATH = "/v1/chat/completions"
OPENAI_HOST = "api.openai.com"
_ROW_ID_RE = re.compile(r"primary-(?:00[1-9]|0[1-9][0-9]|[1-9][0-9]{2})")
_BEARER_RE = re.compile(r"Bearer ([A-Za-z0-9_-]{32,256})")
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
_MILLION = Decimal(1_000_000)
_ZERO = Decimal(0)
_INPUT_TOKEN_OVERHEAD = 4096
_MAX_HEADER_VALUE_CHARS = 512
_MAX_REASONING_EFFORT_CHARS = 50
_MAX_REQUESTS_PER_ROW = 4096
_MAX_RECEIPT_BYTES = 8 * 1024 * 1024


class ModelGatewayError(RuntimeError):
    """Base error for comparison gateway contract failures."""


class RowRegistrationError(ModelGatewayError):
    """Raised when a row identity is reused or malformed."""


class RowSealError(ModelGatewayError):
    """Raised when a row cannot be sealed into immutable evidence."""


@dataclass(frozen=True)
class ModelPricing:
    """USD prices per one million tokens."""

    input_per_million: Decimal
    cached_input_per_million: Decimal
    output_per_million: Decimal

    @classmethod
    def from_numbers(
        cls,
        *,
        input_per_million: float | str | Decimal,
        cached_input_per_million: float | str | Decimal,
        output_per_million: float | str | Decimal,
    ) -> ModelPricing:
        return cls(
            input_per_million=_decimal(input_per_million, "input price"),
            cached_input_per_million=_decimal(cached_input_per_million, "cached-input price"),
            output_per_million=_decimal(output_per_million, "output price"),
        )

    def to_json(self) -> dict[str, str]:
        return {
            "input_per_million": _money(self.input_per_million),
            "cached_input_per_million": _money(self.cached_input_per_million),
            "output_per_million": _money(self.output_per_million),
        }


@dataclass(frozen=True)
class ModelGatewayPolicy:
    model: str
    reasoning_effort: str
    pricing: ModelPricing
    campaign_max_cost_usd: Decimal
    max_completion_tokens_per_request: int = 8192
    max_request_body_bytes: int = 8 * 1024 * 1024
    max_upstream_response_bytes: int = 64 * 1024 * 1024
    upstream_timeout_seconds: int = 600
    max_parallel_requests: int = 8

    @classmethod
    def build(
        cls,
        *,
        model: str,
        reasoning_effort: str,
        pricing: ModelPricing,
        campaign_max_cost_usd: float | str | Decimal,
        max_completion_tokens_per_request: int = 8192,
        max_request_body_bytes: int = 8 * 1024 * 1024,
        max_upstream_response_bytes: int = 64 * 1024 * 1024,
        upstream_timeout_seconds: int = 600,
        max_parallel_requests: int = 8,
    ) -> ModelGatewayPolicy:
        policy = cls(
            model=model,
            reasoning_effort=reasoning_effort,
            pricing=pricing,
            campaign_max_cost_usd=_decimal(campaign_max_cost_usd, "campaign cost ceiling"),
            max_completion_tokens_per_request=max_completion_tokens_per_request,
            max_request_body_bytes=max_request_body_bytes,
            max_upstream_response_bytes=max_upstream_response_bytes,
            upstream_timeout_seconds=upstream_timeout_seconds,
            max_parallel_requests=max_parallel_requests,
        )
        policy.validate()
        return policy

    def validate(self) -> None:
        if not self.model.strip() or self.model != self.model.strip() or len(self.model) > 200:
            raise ValueError("gateway model must be nonempty and normalized")
        if (
            not self.reasoning_effort.strip()
            or self.reasoning_effort != self.reasoning_effort.strip()
            or len(self.reasoning_effort) > _MAX_REASONING_EFFORT_CHARS
        ):
            raise ValueError("gateway reasoning effort must be nonempty and normalized")
        for label, value in (
            ("input price", self.pricing.input_per_million),
            ("cached-input price", self.pricing.cached_input_per_million),
            ("output price", self.pricing.output_per_million),
            ("campaign cost ceiling", self.campaign_max_cost_usd),
        ):
            if (
                not value.is_finite()
                or value < 0
                or (label == "campaign cost ceiling" and value <= 0)
            ):
                raise ValueError(f"{label} is invalid")
        if self.pricing.input_per_million <= 0 or self.pricing.output_per_million <= 0:
            raise ValueError("input and output prices must both be positive")
        for label, integer_value in (
            ("completion-token cap", self.max_completion_tokens_per_request),
            ("request-body cap", self.max_request_body_bytes),
            ("response-body cap", self.max_upstream_response_bytes),
            ("upstream timeout", self.upstream_timeout_seconds),
            ("parallel-request cap", self.max_parallel_requests),
        ):
            if (
                isinstance(integer_value, bool)
                or not isinstance(integer_value, int)
                or integer_value <= 0
            ):
                raise ValueError(f"gateway {label} must be a positive integer")

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": MODEL_GATEWAY_POLICY_SCHEMA,
            "upstream": f"https://{OPENAI_HOST}{OPENAI_CHAT_PATH}",
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "pricing_usd_per_million_tokens": self.pricing.to_json(),
            "campaign_max_cost_usd": _money(self.campaign_max_cost_usd),
            "max_completion_tokens_per_request": self.max_completion_tokens_per_request,
            "max_request_body_bytes": self.max_request_body_bytes,
            "max_upstream_response_bytes": self.max_upstream_response_bytes,
            "upstream_timeout_seconds": self.upstream_timeout_seconds,
            "max_parallel_requests": self.max_parallel_requests,
            "input_token_reservation": {
                "algorithm": "utf8_body_bytes_plus_fixed_overhead",
                "fixed_overhead_tokens": _INPUT_TOKEN_OVERHEAD,
                "cached_discount_assumed": False,
            },
            "retry_policy": "gateway_never_retries",
            "unknown_usage_policy": "charge_full_reservation_and_invalidate_row",
        }


@dataclass(frozen=True)
class UpstreamResponse:
    status: int
    body: bytes
    content_type: str = "application/json"


class UpstreamTransport(Protocol):
    def send(
        self,
        body: bytes,
        *,
        api_key: str,
        timeout_seconds: int,
        maximum_response_bytes: int,
    ) -> UpstreamResponse: ...


@dataclass(frozen=True)
class OpenAIHTTPSTransport:
    """Direct TLS transport with no ambient proxy or redirect behavior."""

    def send(
        self,
        body: bytes,
        *,
        api_key: str,
        timeout_seconds: int,
        maximum_response_bytes: int,
    ) -> UpstreamResponse:
        connection = http.client.HTTPSConnection(
            OPENAI_HOST,
            443,
            timeout=timeout_seconds,
            context=ssl.create_default_context(),
        )
        try:
            connection.request(
                "POST",
                OPENAI_CHAT_PATH,
                body=body,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream, application/json",
                    "Accept-Encoding": "identity",
                    "User-Agent": "ravage-paired-xben-model-gateway/1",
                },
            )
            response = connection.getresponse()
            content_type = response.getheader("content-type") or "application/octet-stream"
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum_response_bytes:
                    raise ModelGatewayError("upstream model response exceeds the byte limit")
                chunks.append(chunk)
            return UpstreamResponse(
                status=int(response.status),
                body=b"".join(chunks),
                content_type=_safe_content_type(content_type),
            )
        finally:
            connection.close()


@dataclass
class _RowState:
    row_id: str
    token_sha256: str
    max_requests: int
    max_cost_usd: Decimal
    requests_started: int = 0
    active_requests: int = 0
    active_reserved_cost_usd: Decimal = _ZERO
    charged_cost_usd: Decimal = _ZERO
    known_actual_cost_usd: Decimal = _ZERO
    invalid: bool = False
    closing: bool = False
    sealed: bool = False
    records: list[dict[str, object]] = field(default_factory=list)
    active_ordinals: set[int] = field(default_factory=set)
    admitted_monotonic: dict[int, float] = field(default_factory=dict)
    reservations: dict[int, _Reservation] = field(default_factory=dict)
    abandoned_ordinals: set[int] = field(default_factory=set)


@dataclass(frozen=True)
class _Reservation:
    row_id: str
    ordinal: int
    raw_request_sha256: str
    forwarded_request_sha256: str
    input_token_upper_bound: int
    output_token_cap: int
    reserved_cost_usd: Decimal
    stream: bool
    started_at: str
    started_monotonic: float


class _GatewayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True
    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        request_timeout_seconds: int,
        maximum_workers: int,
    ) -> None:
        self.request_timeout_seconds = request_timeout_seconds
        self._worker_slots = threading.BoundedSemaphore(maximum_workers)
        super().__init__(server_address, handler_class)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout_seconds)
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


class ComparisonModelGateway:
    """Thread-safe loopback service and immutable usage-receipt owner."""

    def __init__(
        self,
        *,
        policy: ModelGatewayPolicy,
        upstream_api_key: str,
        transport: UpstreamTransport | None = None,
    ) -> None:
        policy.validate()
        if not upstream_api_key or len(upstream_api_key) > 10_000:
            raise ValueError("upstream API key is absent or invalid")
        self.policy = policy
        self._upstream_api_key = upstream_api_key
        self._transport = transport or OpenAIHTTPSTransport()
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._rows: dict[str, _RowState] = {}
        self._row_by_token_hash: dict[str, str] = {}
        self._campaign_charged_cost_usd = _ZERO
        self._campaign_active_reserved_cost_usd = _ZERO
        self._server: _GatewayHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        server = self._server
        if server is None:
            raise ModelGatewayError("model gateway is not running")
        host, port = server.server_address[:2]
        if not isinstance(host, str) or not isinstance(port, int):
            raise ModelGatewayError("model gateway has an invalid loopback address")
        return f"http://{host}:{port}/v1"

    @property
    def policy_digest(self) -> str:
        return _sha256(_canonical_json(self.policy.to_json()))

    def start(self) -> None:
        with self._lock:
            if self._server is not None:
                raise ModelGatewayError("model gateway is already running")
            gateway = self

            class Handler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
                    gateway._serve_post(self)

                def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
                    _write_http_error(self, 405, "method_not_allowed")

                def log_message(self, _format: str, *_args: object) -> None:
                    return

            server = _GatewayHTTPServer(
                ("127.0.0.1", 0),
                Handler,
                request_timeout_seconds=self.policy.upstream_timeout_seconds,
                maximum_workers=self.policy.max_parallel_requests,
            )
            self._server = server
            self._thread = threading.Thread(
                target=server.serve_forever,
                name="paired-xben-model-gateway",
                daemon=True,
            )
            self._thread.start()

    def close(self) -> None:
        with self._lock:
            server = self._server
            thread = self._thread
            self._server = None
            self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)
            if thread.is_alive():
                raise ModelGatewayError("model gateway thread did not stop")

    def register_row(
        self,
        row_id: str,
        *,
        max_requests: int,
        max_cost_usd: float | str | Decimal,
    ) -> str:
        if _ROW_ID_RE.fullmatch(row_id) is None:
            raise RowRegistrationError("model gateway row ID is invalid")
        if (
            isinstance(max_requests, bool)
            or not isinstance(max_requests, int)
            or not 0 < max_requests <= _MAX_REQUESTS_PER_ROW
        ):
            raise RowRegistrationError("model gateway row request limit is invalid")
        maximum = _decimal(max_cost_usd, "row cost ceiling")
        if maximum <= 0 or maximum > self.policy.campaign_max_cost_usd:
            raise RowRegistrationError("model gateway row cost ceiling is invalid")
        token = secrets.token_urlsafe(48)
        token_hash = _sha256(token.encode())
        with self._lock:
            if row_id in self._rows:
                raise RowRegistrationError("model gateway row is already registered")
            self._rows[row_id] = _RowState(
                row_id=row_id,
                token_sha256=token_hash,
                max_requests=max_requests,
                max_cost_usd=maximum,
            )
            self._row_by_token_hash[token_hash] = row_id
        return token

    def seal_row(self, row_id: str, output_path: Path) -> dict[str, object]:
        """Close admission and immediately seal a quiescent row.

        Existing callers historically used this method only after the request
        path had returned.  It now also closes admission atomically so a handler
        authenticated just before this call cannot begin after the receipt is
        written.  If work is unexpectedly active it is terminalized
        conservatively; production callers that want to allow an in-flight
        upstream request to finish should use :meth:`close_row_and_seal`.
        """

        return self.close_row_and_seal(
            row_id,
            output_path,
            drain_timeout_seconds=0.0,
        )

    def close_row_and_seal(
        self,
        row_id: str,
        output_path: Path,
        *,
        drain_timeout_seconds: float,
    ) -> dict[str, object]:
        """Atomically close admission, drain boundedly, and seal exactly once.

        A timed-out upstream operation may continue in a daemon request thread,
        but it can no longer mutate the sealed ledger.  Its full reservation is
        charged and the row is marked invalid, which is conservative for both
        budget accounting and comparison claims.
        """

        if (
            isinstance(drain_timeout_seconds, bool)
            or not isinstance(drain_timeout_seconds, int | float)
            or not math.isfinite(float(drain_timeout_seconds))
            or drain_timeout_seconds < 0
        ):
            raise ValueError("model gateway drain timeout must be finite and nonnegative")
        deadline = time.monotonic() + float(drain_timeout_seconds)
        with self._condition:
            row = self._rows.get(row_id)
            if row is None:
                raise RowSealError("model gateway row is unknown")
            if row.sealed:
                raise RowSealError("model gateway row is already sealed")
            if row.closing:
                raise RowSealError("model gateway row is already closing")
            row.closing = True
            while row.active_requests:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._terminalize_active_requests(row)
                    break
                self._condition.wait(timeout=remaining)
            if row.active_requests or row.active_reserved_cost_usd != 0:
                raise RowSealError("model gateway row did not become terminal")
            receipt = self._row_receipt(row)
            _write_json_exclusive(output_path, receipt)
            row.sealed = True
            return receipt

    def _terminalize_active_requests(self, row: _RowState) -> None:
        """Turn every admitted request into immutable conservative evidence."""

        completed_at = _now()
        for ordinal in sorted(row.active_ordinals):
            record = next(
                (value for value in row.records if value.get("request_ordinal") == ordinal),
                None,
            )
            if record is None:
                raise ModelGatewayError("active model request record disappeared")
            row.abandoned_ordinals.add(ordinal)
            reservation = row.reservations.pop(ordinal, None)
            started_at = str(record.get("started_at") or completed_at)
            started_monotonic = row.admitted_monotonic.pop(ordinal, time.monotonic())
            elapsed = round(max(0.0, time.monotonic() - started_monotonic), 6)
            if reservation is None:
                replacement = {
                    "request_ordinal": ordinal,
                    "status": "rejected",
                    "failure_code": "row_seal_drain_timeout_before_forward",
                    "raw_request_sha256": record["raw_request_sha256"],
                    "charged_cost_usd": "0",
                    "accounting_status": "not_sent",
                    "started_at": started_at,
                    "completed_at": completed_at,
                }
            else:
                charged = reservation.reserved_cost_usd
                row.active_reserved_cost_usd -= charged
                self._campaign_active_reserved_cost_usd -= charged
                row.charged_cost_usd += charged
                self._campaign_charged_cost_usd += charged
                replacement = {
                    "request_ordinal": ordinal,
                    "status": "failed",
                    "failure_code": "row_seal_drain_timeout",
                    "raw_request_sha256": reservation.raw_request_sha256,
                    "forwarded_request_sha256": reservation.forwarded_request_sha256,
                    "response_sha256": None,
                    "upstream_status": None,
                    "input_token_upper_bound": reservation.input_token_upper_bound,
                    "output_token_cap": reservation.output_token_cap,
                    "reserved_cost_usd": _money(charged),
                    "charged_cost_usd": _money(charged),
                    "accounting_status": "unknown",
                    "stream": reservation.stream,
                    "started_at": reservation.started_at,
                    "completed_at": completed_at,
                    "elapsed_seconds": elapsed,
                }
            self._replace_record(row, ordinal, replacement)
        row.active_ordinals.clear()
        row.admitted_monotonic.clear()
        row.active_requests = 0
        row.invalid = True
        if row.active_reserved_cost_usd != 0 or self._campaign_active_reserved_cost_usd < 0:
            raise ModelGatewayError("model gateway drain ledger became inconsistent")
        self._condition.notify_all()

    def _row_receipt(self, row: _RowState) -> dict[str, object]:
        records = sorted(row.records, key=_request_record_ordinal)
        complete = len(records) == row.requests_started
        valid = bool(
            complete
            and not row.invalid
            and row.active_requests == 0
            and row.active_reserved_cost_usd == 0
            and row.requests_started <= row.max_requests
            and row.charged_cost_usd <= row.max_cost_usd
        )
        body: dict[str, object] = {
            "schema_version": MODEL_GATEWAY_SCHEMA,
            "created_at": _now(),
            "row_id": row.row_id,
            "row_token_sha256": row.token_sha256,
            "policy": self.policy.to_json(),
            "policy_sha256": self.policy_digest,
            "limits": {
                "max_requests": row.max_requests,
                "max_cost_usd": _money(row.max_cost_usd),
            },
            "totals": {
                "requests_started": row.requests_started,
                "requests_recorded": len(records),
                "charged_cost_usd": _money(row.charged_cost_usd),
                "known_actual_cost_usd": _money(row.known_actual_cost_usd),
                "within_request_limit": row.requests_started <= row.max_requests,
                "within_cost_limit": row.charged_cost_usd <= row.max_cost_usd,
            },
            "records": records,
            "valid": valid,
        }
        body["document_sha256"] = _sha256(_canonical_json(body))
        return body

    def _serve_post(self, handler: BaseHTTPRequestHandler) -> None:
        if handler.path != OPENAI_CHAT_PATH:
            _write_http_error(handler, 404, "unsupported_endpoint")
            return
        row = self._authenticate(handler.headers.get("Authorization"))
        if row is None:
            _write_http_error(handler, 401, "invalid_gateway_credential")
            return
        if handler.headers.get_all("Transfer-Encoding", []):
            self._record_preflight_rejection(row, b"", "transfer_encoding_forbidden")
            _write_http_error(handler, 400, "transfer_encoding_forbidden")
            return
        length_values = handler.headers.get_all("Content-Length", [])
        if not length_values:
            self._record_preflight_rejection(row, b"", "content_length_required")
            _write_http_error(handler, 411, "content_length_required")
            return
        if len(length_values) != 1:
            self._record_preflight_rejection(row, b"", "content_length_ambiguous")
            _write_http_error(handler, 400, "content_length_ambiguous")
            return
        length_text = length_values[0]
        normalized_length = length_text.lstrip("0") or "0"
        if (
            not length_text.isascii()
            or not length_text.isdigit()
            or len(normalized_length) > len(str(self.policy.max_request_body_bytes))
        ):
            self._record_preflight_rejection(row, b"", "content_length_invalid")
            _write_http_error(handler, 400, "content_length_invalid")
            return
        length = int(normalized_length)
        if length <= 0 or length > self.policy.max_request_body_bytes:
            self._record_preflight_rejection(row, b"", "request_body_size_invalid")
            _write_http_error(handler, 413, "request_body_size_invalid")
            return
        try:
            raw = handler.rfile.read(length)
        except (OSError, TimeoutError):
            self._record_preflight_rejection(row, b"", "request_body_read_timeout")
            _write_http_error(handler, 408, "request_body_read_timeout")
            return
        if len(raw) != length:
            self._record_preflight_rejection(row, raw, "request_body_incomplete")
            _write_http_error(handler, 400, "request_body_incomplete")
            return
        try:
            reservation, forwarded = self._prepare_request(row, raw)
        except _GatewayHTTPFailure as exc:
            _write_http_error(handler, exc.status, exc.code)
            return
        try:
            upstream = self._transport.send(
                forwarded,
                api_key=self._upstream_api_key,
                timeout_seconds=self.policy.upstream_timeout_seconds,
                maximum_response_bytes=self.policy.max_upstream_response_bytes,
            )
        except Exception as exc:  # noqa: BLE001 - boundary records and fails closed.
            self._finalize_failure(
                reservation,
                f"upstream_transport:{type(exc).__name__}",
                charge_reservation=True,
            )
            _write_http_error(handler, 502, "upstream_transport_failed")
            return
        valid, accounting = self._validate_upstream(reservation, upstream)
        if not valid:
            _write_http_error(handler, 502, str(accounting["failure_code"]))
            return
        _write_http_response(
            handler,
            upstream.status,
            upstream.body,
            upstream.content_type,
        )

    def _authenticate(self, authorization: str | None) -> _RowState | None:
        if authorization is None or len(authorization) > _MAX_HEADER_VALUE_CHARS:
            return None
        match = _BEARER_RE.fullmatch(authorization)
        if match is None:
            return None
        token_hash = _sha256(match.group(1).encode())
        with self._lock:
            row_id = self._row_by_token_hash.get(token_hash)
            row = self._rows.get(row_id or "")
            if (
                row is None
                or row.closing
                or row.sealed
                or not hmac.compare_digest(row.token_sha256, token_hash)
            ):
                return None
            return row

    def _begin_ordinal(self, row: _RowState, request_hash: str) -> int:
        with self._condition:
            if row.closing or row.sealed:
                raise _GatewayHTTPFailure(401, "row_is_sealed")
            if row.requests_started >= row.max_requests:
                raise _GatewayHTTPFailure(429, "model_request_limit_reached")
            row.requests_started += 1
            ordinal = row.requests_started
            # Count the request as active before parsing.  Sealing therefore
            # cannot slip between ordinal allocation and cost reservation.
            row.active_requests += 1
            row.active_ordinals.add(ordinal)
            row.admitted_monotonic[ordinal] = time.monotonic()
            # A placeholder guarantees the receipt exposes interrupted handler
            # paths instead of silently losing an admitted request.
            row.records.append(
                {
                    "request_ordinal": ordinal,
                    "status": "admitted",
                    "raw_request_sha256": request_hash,
                    "started_at": _now(),
                }
            )
            return ordinal

    def _prepare_request(self, row: _RowState, raw: bytes) -> tuple[_Reservation, bytes]:
        request_hash = _sha256(raw)
        ordinal = self._begin_ordinal(row, request_hash)
        started_at = _now()
        started_monotonic = time.monotonic()
        try:
            payload = _decode_json_object(raw, "model request")
            if payload.get("model") != self.policy.model:
                raise _GatewayHTTPFailure(400, "model_mismatch")
            if payload.get("reasoning_effort") != self.policy.reasoning_effort:
                raise _GatewayHTTPFailure(400, "reasoning_effort_mismatch")
            if not isinstance(payload.get("messages"), list) or not payload["messages"]:
                raise _GatewayHTTPFailure(400, "messages_required")
            if payload.get("n", 1) != 1:
                raise _GatewayHTTPFailure(400, "single_choice_required")
            if "max_tokens" in payload:
                raise _GatewayHTTPFailure(400, "legacy_max_tokens_forbidden")
            requested_cap = payload.get(
                "max_completion_tokens", self.policy.max_completion_tokens_per_request
            )
            if (
                isinstance(requested_cap, bool)
                or not isinstance(requested_cap, int)
                or requested_cap != self.policy.max_completion_tokens_per_request
            ):
                raise _GatewayHTTPFailure(400, "completion_token_contract_mismatch")
            stream = payload.get("stream", False)
            if not isinstance(stream, bool):
                raise _GatewayHTTPFailure(400, "stream_flag_invalid")
            service_tier = payload.get("service_tier", "default")
            if service_tier != "default":
                raise _GatewayHTTPFailure(400, "service_tier_mismatch")
            if payload.get("store") not in {None, False}:
                raise _GatewayHTTPFailure(400, "stored_completion_forbidden")
            payload["service_tier"] = "default"
            payload["store"] = False
            if stream:
                payload["stream_options"] = {"include_usage": True}
            forwarded_without_dynamic_cap = _canonical_json(payload)
            input_upper = len(forwarded_without_dynamic_cap) + _INPUT_TOKEN_OVERHEAD
            input_reservation = _token_cost(input_upper, self.policy.pricing.input_per_million)
            # Cost admission and ledger mutation are one critical section.  If
            # they were separated, concurrent requests could each observe the
            # same unreserved row/campaign balance and oversubscribe the cap.
            with self._lock:
                if ordinal in row.abandoned_ordinals or row.sealed:
                    raise _GatewayHTTPFailure(409, "row_closed_during_admission")
                output_cap, reservation_cost = self._reserve_cost(
                    row=row,
                    input_reservation=input_reservation,
                    requested_output_cap=requested_cap,
                )
                payload["max_completion_tokens"] = output_cap
                forwarded = _canonical_json(payload)
                reservation = _Reservation(
                    row_id=row.row_id,
                    ordinal=ordinal,
                    raw_request_sha256=request_hash,
                    forwarded_request_sha256=_sha256(forwarded),
                    input_token_upper_bound=input_upper,
                    output_token_cap=output_cap,
                    reserved_cost_usd=reservation_cost,
                    stream=stream,
                    started_at=started_at,
                    started_monotonic=started_monotonic,
                )
                row.active_reserved_cost_usd += reservation_cost
                self._campaign_active_reserved_cost_usd += reservation_cost
                row.reservations[ordinal] = reservation
                self._replace_record(
                    row,
                    ordinal,
                    {
                        "request_ordinal": ordinal,
                        "status": "forwarding",
                        "raw_request_sha256": request_hash,
                        "forwarded_request_sha256": reservation.forwarded_request_sha256,
                        "input_token_upper_bound": input_upper,
                        "output_token_cap": output_cap,
                        "reserved_cost_usd": _money(reservation_cost),
                        "stream": stream,
                        "started_at": started_at,
                    },
                )
            return reservation, forwarded
        except _GatewayHTTPFailure as exc:
            self._complete_rejection(row, ordinal, request_hash, exc.code, started_at)
            raise
        except Exception as exc:  # noqa: BLE001 - malformed input is a recorded rejection.
            self._complete_rejection(
                row,
                ordinal,
                request_hash,
                f"malformed_request:{type(exc).__name__}",
                started_at,
            )
            raise _GatewayHTTPFailure(400, "malformed_request") from exc

    def _reserve_cost(
        self,
        *,
        row: _RowState,
        input_reservation: Decimal,
        requested_output_cap: int,
    ) -> tuple[int, Decimal]:
        with self._lock:
            row_available = row.max_cost_usd - row.charged_cost_usd - row.active_reserved_cost_usd
            campaign_available = (
                self.policy.campaign_max_cost_usd
                - self._campaign_charged_cost_usd
                - self._campaign_active_reserved_cost_usd
            )
            available = min(row_available, campaign_available)
            output_price = self.policy.pricing.output_per_million
            if available <= input_reservation:
                raise _GatewayHTTPFailure(429, "model_cost_limit_reached")
            affordable = int(
                ((available - input_reservation) * _MILLION / output_price).to_integral_value(
                    rounding=ROUND_FLOOR
                )
            )
            output_cap = min(requested_output_cap, affordable)
            if output_cap <= 0:
                raise _GatewayHTTPFailure(429, "model_cost_limit_reached")
            reserved = input_reservation + _token_cost(output_cap, output_price)
            if reserved > available:
                raise _GatewayHTTPFailure(429, "model_cost_reservation_failed")
            return output_cap, reserved

    def _validate_upstream(
        self,
        reservation: _Reservation,
        upstream: UpstreamResponse,
    ) -> tuple[bool, dict[str, object]]:
        response_hash = _sha256(upstream.body)
        if len(upstream.body) > self.policy.max_upstream_response_bytes:
            self._finalize_failure(
                reservation,
                "upstream_response_too_large",
                charge_reservation=True,
                upstream_status=upstream.status,
                response_sha256=response_hash,
            )
            return False, {"failure_code": "upstream_response_too_large"}
        if upstream.status != 200:
            self._finalize_failure(
                reservation,
                f"upstream_http_{upstream.status}",
                charge_reservation=True,
                upstream_status=upstream.status,
                response_sha256=response_hash,
            )
            return False, {"failure_code": "upstream_model_error"}
        try:
            model, usage = _response_model_and_usage(upstream.body, stream=reservation.stream)
            if model != self.policy.model:
                raise ModelGatewayError("upstream response model differs from frozen model")
            prompt_tokens = _usage_integer(usage, "prompt_tokens")
            completion_tokens = _usage_integer(usage, "completion_tokens")
            details = usage.get("prompt_tokens_details")
            cached_tokens = 0
            if details is not None:
                if not isinstance(details, dict):
                    raise ModelGatewayError("prompt token details are malformed")
                cached_tokens = _usage_integer(details, "cached_tokens", default=0)
            if cached_tokens > prompt_tokens:
                raise ModelGatewayError("cached input tokens exceed input tokens")
            actual_cost = (
                _token_cost(
                    prompt_tokens - cached_tokens,
                    self.policy.pricing.input_per_million,
                )
                + _token_cost(
                    cached_tokens,
                    self.policy.pricing.cached_input_per_million,
                )
                + _token_cost(
                    completion_tokens,
                    self.policy.pricing.output_per_million,
                )
            )
        except Exception as exc:  # noqa: BLE001 - any accounting ambiguity fails closed.
            self._finalize_failure(
                reservation,
                f"accounting_invalid:{type(exc).__name__}",
                charge_reservation=True,
                upstream_status=upstream.status,
                response_sha256=response_hash,
            )
            return False, {"failure_code": "upstream_accounting_invalid"}
        if (
            prompt_tokens > reservation.input_token_upper_bound
            or completion_tokens > reservation.output_token_cap
            or actual_cost > reservation.reserved_cost_usd
        ):
            self._finalize_failure(
                reservation,
                "provider_usage_out_of_bounds",
                charge_reservation=True,
                upstream_status=upstream.status,
                response_sha256=response_hash,
                observed_usage=(prompt_tokens, cached_tokens, completion_tokens),
                observed_usage_cost_usd=actual_cost,
                response_model=model,
            )
            return False, {"failure_code": "upstream_accounting_invalid"}

        completed_at = _now()
        with self._lock:
            row = self._rows[reservation.row_id]
            if reservation.ordinal in row.abandoned_ordinals or row.sealed:
                return False, {"failure_code": "row_sealed_before_upstream_completed"}
            self._release_reservation(row, reservation)
            row.charged_cost_usd += actual_cost
            row.known_actual_cost_usd += actual_cost
            self._campaign_charged_cost_usd += actual_cost
            self._replace_record(
                row,
                reservation.ordinal,
                {
                    "request_ordinal": reservation.ordinal,
                    "status": "completed",
                    "raw_request_sha256": reservation.raw_request_sha256,
                    "forwarded_request_sha256": reservation.forwarded_request_sha256,
                    "response_sha256": response_hash,
                    "upstream_status": upstream.status,
                    "response_model": model,
                    "reasoning_effort": self.policy.reasoning_effort,
                    "input_token_upper_bound": reservation.input_token_upper_bound,
                    "output_token_cap": reservation.output_token_cap,
                    "reserved_cost_usd": _money(reservation.reserved_cost_usd),
                    "actual_cost_usd": _money(actual_cost),
                    "usage": {
                        "input_tokens": prompt_tokens,
                        "cached_input_tokens": cached_tokens,
                        "output_tokens": completion_tokens,
                    },
                    "accounting_status": "verified",
                    "stream": reservation.stream,
                    "started_at": reservation.started_at,
                    "completed_at": completed_at,
                    "elapsed_seconds": round(
                        max(0.0, time.monotonic() - reservation.started_monotonic), 6
                    ),
                },
            )
        return True, {"actual_cost_usd": _money(actual_cost)}

    def _finalize_failure(
        self,
        reservation: _Reservation,
        failure_code: str,
        *,
        charge_reservation: bool,
        upstream_status: int | None = None,
        response_sha256: str | None = None,
        observed_usage: tuple[int, int, int] | None = None,
        observed_usage_cost_usd: Decimal | None = None,
        response_model: str | None = None,
    ) -> None:
        if (observed_usage is None) is not (observed_usage_cost_usd is None):
            raise ModelGatewayError("observed model usage evidence is incomplete")
        if observed_usage is not None and (not charge_reservation or response_model is None):
            raise ModelGatewayError("observed model usage evidence is inconsistent")
        completed_at = _now()
        with self._lock:
            row = self._rows[reservation.row_id]
            if reservation.ordinal in row.abandoned_ordinals or row.sealed:
                return
            self._release_reservation(row, reservation)
            charged = reservation.reserved_cost_usd if charge_reservation else _ZERO
            if observed_usage_cost_usd is not None:
                charged = max(charged, observed_usage_cost_usd)
            row.charged_cost_usd += charged
            self._campaign_charged_cost_usd += charged
            row.invalid = True
            record: dict[str, object] = {
                "request_ordinal": reservation.ordinal,
                "status": "failed",
                "failure_code": failure_code[:200],
                "raw_request_sha256": reservation.raw_request_sha256,
                "forwarded_request_sha256": reservation.forwarded_request_sha256,
                "response_sha256": response_sha256,
                "upstream_status": upstream_status,
                "input_token_upper_bound": reservation.input_token_upper_bound,
                "output_token_cap": reservation.output_token_cap,
                "reserved_cost_usd": _money(reservation.reserved_cost_usd),
                "charged_cost_usd": _money(charged),
                "accounting_status": "unknown" if charge_reservation else "not_sent",
                "stream": reservation.stream,
                "started_at": reservation.started_at,
                "completed_at": completed_at,
                "elapsed_seconds": round(
                    max(0.0, time.monotonic() - reservation.started_monotonic), 6
                ),
            }
            if observed_usage is not None and observed_usage_cost_usd is not None:
                prompt_tokens, cached_tokens, completion_tokens = observed_usage
                record.update(
                    {
                        "response_model": response_model,
                        "usage": {
                            "input_tokens": prompt_tokens,
                            "cached_input_tokens": cached_tokens,
                            "output_tokens": completion_tokens,
                        },
                        "observed_usage_cost_usd": _money(observed_usage_cost_usd),
                        "accounting_status": "provider_usage_out_of_bounds",
                    }
                )
            self._replace_record(row, reservation.ordinal, record)

    def _release_reservation(self, row: _RowState, reservation: _Reservation) -> None:
        amount = reservation.reserved_cost_usd
        retained = row.reservations.pop(reservation.ordinal, None)
        if retained != reservation:
            raise ModelGatewayError("model gateway active reservation disappeared")
        row.active_requests -= 1
        row.active_reserved_cost_usd -= amount
        self._campaign_active_reserved_cost_usd -= amount
        row.active_ordinals.discard(reservation.ordinal)
        row.admitted_monotonic.pop(reservation.ordinal, None)
        if (
            row.active_requests < 0
            or row.active_reserved_cost_usd < 0
            or self._campaign_active_reserved_cost_usd < 0
        ):
            raise ModelGatewayError("model gateway reservation ledger became inconsistent")
        self._condition.notify_all()

    def _record_preflight_rejection(self, row: _RowState, raw: bytes, failure_code: str) -> None:
        request_hash = _sha256(raw)
        try:
            ordinal = self._begin_ordinal(row, request_hash)
        except _GatewayHTTPFailure:
            return
        self._complete_rejection(row, ordinal, request_hash, failure_code, _now())

    def _complete_rejection(
        self,
        row: _RowState,
        ordinal: int,
        request_hash: str,
        failure_code: str,
        started_at: str,
    ) -> None:
        with self._condition:
            if ordinal in row.abandoned_ordinals or row.sealed:
                return
            row.invalid = True
            self._replace_record(
                row,
                ordinal,
                {
                    "request_ordinal": ordinal,
                    "status": "rejected",
                    "failure_code": failure_code[:200],
                    "raw_request_sha256": request_hash,
                    "charged_cost_usd": "0",
                    "accounting_status": "not_sent",
                    "started_at": started_at,
                    "completed_at": _now(),
                },
            )
            if ordinal not in row.active_ordinals:
                raise ModelGatewayError("model gateway active admission disappeared")
            row.active_ordinals.remove(ordinal)
            row.admitted_monotonic.pop(ordinal, None)
            row.active_requests -= 1
            if row.active_requests < 0:
                raise ModelGatewayError("model gateway admission ledger became inconsistent")
            self._condition.notify_all()

    @staticmethod
    def _replace_record(row: _RowState, ordinal: int, replacement: dict[str, object]) -> None:
        for index, record in enumerate(row.records):
            if record.get("request_ordinal") == ordinal:
                row.records[index] = replacement
                return
        raise ModelGatewayError("model gateway request record disappeared")


def validate_model_gateway_receipt(
    payload: object,
    *,
    expected_row_id: str,
    expected_policy_sha256: str,
    expected_max_requests: int,
    expected_max_cost_usd: float | str | Decimal,
) -> dict[str, object]:
    """Recompute a sealed row receipt and its request/cost accounting."""

    if not isinstance(payload, dict):
        raise ModelGatewayError("model gateway receipt must be a JSON object")
    required = {
        "schema_version",
        "created_at",
        "row_id",
        "row_token_sha256",
        "policy",
        "policy_sha256",
        "limits",
        "totals",
        "records",
        "valid",
        "document_sha256",
    }
    if set(payload) != required or payload.get("schema_version") != MODEL_GATEWAY_SCHEMA:
        raise ModelGatewayError("model gateway receipt fields are invalid")
    body = {key: value for key, value in payload.items() if key != "document_sha256"}
    if payload.get("document_sha256") != _sha256(_canonical_json(body)):
        raise ModelGatewayError("model gateway receipt document digest is invalid")
    _receipt_timestamp(payload.get("created_at"), "receipt creation time")
    if payload.get("row_id") != expected_row_id or _ROW_ID_RE.fullmatch(expected_row_id) is None:
        raise ModelGatewayError("model gateway receipt row binding is invalid")
    _receipt_sha256(payload.get("row_token_sha256"), "row token digest")

    policy = _validate_policy_receipt(payload.get("policy"))
    policy_digest = _sha256(_canonical_json(policy))
    if (
        payload.get("policy_sha256") != policy_digest
        or policy_digest != expected_policy_sha256
        or _SHA256_RE.fullmatch(expected_policy_sha256) is None
    ):
        raise ModelGatewayError("model gateway receipt policy binding is invalid")

    limits = payload.get("limits")
    if not isinstance(limits, dict) or set(limits) != {"max_requests", "max_cost_usd"}:
        raise ModelGatewayError("model gateway receipt limits are invalid")
    if (
        isinstance(expected_max_requests, bool)
        or not isinstance(expected_max_requests, int)
        or not 0 < expected_max_requests <= _MAX_REQUESTS_PER_ROW
        or limits.get("max_requests") != expected_max_requests
    ):
        raise ModelGatewayError("model gateway receipt request limit is invalid")
    expected_cost = _receipt_money(expected_max_cost_usd, "expected row cost ceiling")
    if limits.get("max_cost_usd") != expected_cost:
        raise ModelGatewayError("model gateway receipt cost limit is invalid")

    records = payload.get("records")
    totals = payload.get("totals")
    if not isinstance(records, list) or not isinstance(totals, dict):
        raise ModelGatewayError("model gateway receipt accounting is malformed")
    if set(totals) != {
        "requests_started",
        "requests_recorded",
        "charged_cost_usd",
        "known_actual_cost_usd",
        "within_request_limit",
        "within_cost_limit",
    }:
        raise ModelGatewayError("model gateway receipt total fields are invalid")
    started = _receipt_nonnegative_integer(totals.get("requests_started"), "requests started")
    recorded = _receipt_nonnegative_integer(totals.get("requests_recorded"), "requests recorded")
    if started != recorded or recorded != len(records) or started > expected_max_requests:
        raise ModelGatewayError("model gateway receipt request totals are inconsistent")

    charged_total = _ZERO
    actual_total = _ZERO
    all_records_valid = True
    for expected_ordinal, raw_record in enumerate(records, start=1):
        charged, actual, record_valid = _validate_request_receipt(
            raw_record,
            expected_ordinal=expected_ordinal,
            policy=policy,
        )
        charged_total += charged
        actual_total += actual
        all_records_valid = all_records_valid and record_valid
    maximum_cost = _decimal(expected_cost, "row cost ceiling")
    if totals.get("charged_cost_usd") != _money(charged_total):
        raise ModelGatewayError("model gateway receipt charged total is inconsistent")
    if totals.get("known_actual_cost_usd") != _money(actual_total):
        raise ModelGatewayError("model gateway receipt actual total is inconsistent")
    if totals.get("within_request_limit") is not (started <= expected_max_requests):
        raise ModelGatewayError("model gateway receipt request-limit verdict is inconsistent")
    if totals.get("within_cost_limit") is not (charged_total <= maximum_cost):
        raise ModelGatewayError("model gateway receipt cost-limit verdict is inconsistent")
    expected_valid = bool(
        all_records_valid and started <= expected_max_requests and charged_total <= maximum_cost
    )
    if payload.get("valid") is not expected_valid:
        raise ModelGatewayError("model gateway receipt validity verdict is inconsistent")
    return dict(payload)


def _validate_policy_receipt(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ModelGatewayError("model gateway receipt policy is malformed")
    fields = {
        "schema_version",
        "upstream",
        "model",
        "reasoning_effort",
        "pricing_usd_per_million_tokens",
        "campaign_max_cost_usd",
        "max_completion_tokens_per_request",
        "max_request_body_bytes",
        "max_upstream_response_bytes",
        "upstream_timeout_seconds",
        "max_parallel_requests",
        "input_token_reservation",
        "retry_policy",
        "unknown_usage_policy",
    }
    if set(value) != fields:
        raise ModelGatewayError("model gateway receipt policy fields are invalid")
    if (
        value.get("schema_version") != MODEL_GATEWAY_POLICY_SCHEMA
        or value.get("upstream") != f"https://{OPENAI_HOST}{OPENAI_CHAT_PATH}"
        or value.get("retry_policy") != "gateway_never_retries"
        or value.get("unknown_usage_policy") != "charge_full_reservation_and_invalidate_row"
    ):
        raise ModelGatewayError("model gateway receipt policy constants are invalid")
    model = value.get("model")
    if not isinstance(model, str) or not model or model != model.strip() or len(model) > 200:
        raise ModelGatewayError("model gateway receipt policy model is invalid")
    reasoning_effort = value.get("reasoning_effort")
    if (
        not isinstance(reasoning_effort, str)
        or not reasoning_effort
        or reasoning_effort != reasoning_effort.strip()
        or len(reasoning_effort) > _MAX_REASONING_EFFORT_CHARS
    ):
        raise ModelGatewayError("model gateway receipt policy reasoning_effort is invalid")
    pricing = value.get("pricing_usd_per_million_tokens")
    if not isinstance(pricing, dict) or set(pricing) != {
        "input_per_million",
        "cached_input_per_million",
        "output_per_million",
    }:
        raise ModelGatewayError("model gateway receipt pricing fields are invalid")
    for name, raw in pricing.items():
        _receipt_money(raw, f"model price {name}", allow_zero=True)
    if (
        _decimal(pricing["input_per_million"], "input price") <= 0
        or _decimal(pricing["output_per_million"], "output price") <= 0
    ):
        raise ModelGatewayError("input and output model prices must be positive")
    _receipt_money(value.get("campaign_max_cost_usd"), "campaign cost ceiling")
    for name in (
        "max_completion_tokens_per_request",
        "max_request_body_bytes",
        "max_upstream_response_bytes",
        "upstream_timeout_seconds",
        "max_parallel_requests",
    ):
        _receipt_positive_integer(value.get(name), f"gateway policy {name}")
    reservation = value.get("input_token_reservation")
    if reservation != {
        "algorithm": "utf8_body_bytes_plus_fixed_overhead",
        "fixed_overhead_tokens": _INPUT_TOKEN_OVERHEAD,
        "cached_discount_assumed": False,
    }:
        raise ModelGatewayError("model gateway receipt reservation policy is invalid")
    return dict(value)


def _validate_request_receipt(
    value: object,
    *,
    expected_ordinal: int,
    policy: Mapping[str, object],
) -> tuple[Decimal, Decimal, bool]:
    if not isinstance(value, dict) or value.get("request_ordinal") != expected_ordinal:
        raise ModelGatewayError("model gateway receipt request ordinal is invalid")
    status = value.get("status")
    _receipt_sha256(value.get("raw_request_sha256"), "raw model request digest")
    _receipt_timestamp(value.get("started_at"), "model request start time")
    _receipt_timestamp(value.get("completed_at"), "model request completion time")
    if status == "completed":
        fields = {
            "request_ordinal",
            "status",
            "raw_request_sha256",
            "forwarded_request_sha256",
            "response_sha256",
            "upstream_status",
            "response_model",
            "reasoning_effort",
            "input_token_upper_bound",
            "output_token_cap",
            "reserved_cost_usd",
            "actual_cost_usd",
            "usage",
            "accounting_status",
            "stream",
            "started_at",
            "completed_at",
            "elapsed_seconds",
        }
        if set(value) != fields or value.get("accounting_status") != "verified":
            raise ModelGatewayError("completed model request receipt fields are invalid")
        _receipt_sha256(value.get("forwarded_request_sha256"), "forwarded request digest")
        _receipt_sha256(value.get("response_sha256"), "model response digest")
        if (
            value.get("upstream_status") != 200
            or value.get("response_model") != policy["model"]
            or value.get("reasoning_effort") != policy["reasoning_effort"]
            or not isinstance(value.get("stream"), bool)
        ):
            raise ModelGatewayError("completed model request identity is invalid")
        elapsed = value.get("elapsed_seconds")
        if isinstance(elapsed, bool) or not isinstance(elapsed, int | float) or elapsed < 0:
            raise ModelGatewayError("completed model request elapsed time is invalid")
        input_upper = _receipt_positive_integer(
            value.get("input_token_upper_bound"), "model input token upper bound"
        )
        output_cap = _receipt_positive_integer(
            value.get("output_token_cap"), "model output token cap"
        )
        maximum_output = policy.get("max_completion_tokens_per_request")
        if not isinstance(maximum_output, int) or output_cap > maximum_output:
            raise ModelGatewayError("model output token cap exceeds frozen policy")
        usage = value.get("usage")
        if not isinstance(usage, dict) or set(usage) != {
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
        }:
            raise ModelGatewayError("model request usage fields are invalid")
        input_tokens = _receipt_nonnegative_integer(usage["input_tokens"], "model input tokens")
        cached_tokens = _receipt_nonnegative_integer(
            usage["cached_input_tokens"], "cached model input tokens"
        )
        output_tokens = _receipt_nonnegative_integer(usage["output_tokens"], "model output tokens")
        if cached_tokens > input_tokens or input_tokens > input_upper or output_tokens > output_cap:
            raise ModelGatewayError("model request token accounting exceeds its reservation")
        prices = policy.get("pricing_usd_per_million_tokens")
        if not isinstance(prices, Mapping):
            raise ModelGatewayError("model request pricing is unavailable")
        expected_reserved = _token_cost(
            input_upper, _decimal(prices["input_per_million"], "input price")
        ) + _token_cost(output_cap, _decimal(prices["output_per_million"], "output price"))
        expected_actual = (
            _token_cost(
                input_tokens - cached_tokens,
                _decimal(prices["input_per_million"], "input price"),
            )
            + _token_cost(
                cached_tokens,
                _decimal(prices["cached_input_per_million"], "cached-input price"),
            )
            + _token_cost(
                output_tokens,
                _decimal(prices["output_per_million"], "output price"),
            )
        )
        if value.get("reserved_cost_usd") != _money(expected_reserved):
            raise ModelGatewayError("model request reservation cost is inconsistent")
        if value.get("actual_cost_usd") != _money(expected_actual):
            raise ModelGatewayError("model request actual cost is inconsistent")
        return expected_actual, expected_actual, True
    if status == "failed":
        base_fields = {
            "request_ordinal",
            "status",
            "failure_code",
            "raw_request_sha256",
            "forwarded_request_sha256",
            "response_sha256",
            "upstream_status",
            "input_token_upper_bound",
            "output_token_cap",
            "reserved_cost_usd",
            "charged_cost_usd",
            "accounting_status",
            "stream",
            "started_at",
            "completed_at",
            "elapsed_seconds",
        }
        accounting = value.get("accounting_status")
        observed_fields = {"response_model", "usage", "observed_usage_cost_usd"}
        expected_fields = (
            base_fields | observed_fields
            if accounting == "provider_usage_out_of_bounds"
            else base_fields
        )
        if set(value) != expected_fields:
            raise ModelGatewayError("failed model request receipt fields are invalid")
        _receipt_sha256(value.get("forwarded_request_sha256"), "forwarded request digest")
        response_digest = value.get("response_sha256")
        if response_digest is not None:
            _receipt_sha256(response_digest, "model response digest")
        failure = value.get("failure_code")
        if not isinstance(failure, str) or not failure or len(failure) > 200:
            raise ModelGatewayError("failed model request code is invalid")
        if not isinstance(value.get("stream"), bool):
            raise ModelGatewayError("failed model request stream flag is invalid")
        elapsed = value.get("elapsed_seconds")
        if (
            isinstance(elapsed, bool)
            or not isinstance(elapsed, int | float)
            or not math.isfinite(float(elapsed))
            or elapsed < 0
        ):
            raise ModelGatewayError("failed model request elapsed time is invalid")
        input_upper = _receipt_positive_integer(
            value.get("input_token_upper_bound"), "model input token upper bound"
        )
        output_cap = _receipt_positive_integer(value.get("output_token_cap"), "output token cap")
        prices = policy.get("pricing_usd_per_million_tokens")
        if not isinstance(prices, Mapping):
            raise ModelGatewayError("model request pricing is unavailable")
        reservation = _token_cost(
            input_upper, _decimal(prices["input_per_million"], "input price")
        ) + _token_cost(output_cap, _decimal(prices["output_per_million"], "output price"))
        if value.get("reserved_cost_usd") != _money(reservation):
            raise ModelGatewayError("failed model request reservation is inconsistent")
        if accounting == "provider_usage_out_of_bounds":
            if (
                failure != "provider_usage_out_of_bounds"
                or value.get("upstream_status") != 200
                or response_digest is None
                or value.get("response_model") != policy.get("model")
            ):
                raise ModelGatewayError("out-of-bounds provider usage identity is invalid")
            usage = value.get("usage")
            if not isinstance(usage, dict) or set(usage) != {
                "input_tokens",
                "cached_input_tokens",
                "output_tokens",
            }:
                raise ModelGatewayError("out-of-bounds provider usage fields are invalid")
            input_tokens = _receipt_nonnegative_integer(
                usage["input_tokens"], "observed model input tokens"
            )
            cached_tokens = _receipt_nonnegative_integer(
                usage["cached_input_tokens"], "observed cached model input tokens"
            )
            output_tokens = _receipt_nonnegative_integer(
                usage["output_tokens"], "observed model output tokens"
            )
            if cached_tokens > input_tokens:
                raise ModelGatewayError("observed cached input exceeds observed input")
            observed_cost = (
                _token_cost(
                    input_tokens - cached_tokens,
                    _decimal(prices["input_per_million"], "input price"),
                )
                + _token_cost(
                    cached_tokens,
                    _decimal(prices["cached_input_per_million"], "cached-input price"),
                )
                + _token_cost(
                    output_tokens,
                    _decimal(prices["output_per_million"], "output price"),
                )
            )
            if value.get("observed_usage_cost_usd") != _money(observed_cost):
                raise ModelGatewayError("observed model usage cost is inconsistent")
            if not (
                input_tokens > input_upper
                or output_tokens > output_cap
                or observed_cost > reservation
            ):
                raise ModelGatewayError("provider usage does not exceed its reservation")
            expected_charge = max(reservation, observed_cost)
            if value.get("charged_cost_usd") != _money(expected_charge):
                raise ModelGatewayError("out-of-bounds provider usage charge is inconsistent")
            return expected_charge, _ZERO, False
        expected_charge = reservation if accounting == "unknown" else _ZERO
        if accounting not in {"unknown", "not_sent"}:
            raise ModelGatewayError("failed model request accounting status is invalid")
        if value.get("charged_cost_usd") != _money(expected_charge):
            raise ModelGatewayError("failed model request charge is inconsistent")
        return expected_charge, _ZERO, False
    if status == "rejected":
        fields = {
            "request_ordinal",
            "status",
            "failure_code",
            "raw_request_sha256",
            "charged_cost_usd",
            "accounting_status",
            "started_at",
            "completed_at",
        }
        failure = value.get("failure_code")
        if (
            set(value) != fields
            or not isinstance(failure, str)
            or not failure
            or len(failure) > 200
            or value.get("charged_cost_usd") != "0"
            or value.get("accounting_status") != "not_sent"
        ):
            raise ModelGatewayError("rejected model request receipt fields are invalid")
        return _ZERO, _ZERO, False
    raise ModelGatewayError("model gateway receipt contains a nonterminal request")


def _receipt_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ModelGatewayError(f"{label} is invalid")
    return value


def _receipt_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ModelGatewayError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ModelGatewayError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ModelGatewayError(f"{label} must include a timezone")
    return value


def _receipt_nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ModelGatewayError(f"{label} is invalid")
    return value


def _receipt_positive_integer(value: object, label: str) -> int:
    result = _receipt_nonnegative_integer(value, label)
    if result <= 0:
        raise ModelGatewayError(f"{label} is invalid")
    return result


def _receipt_money(
    value: object,
    label: str,
    *,
    allow_zero: bool = False,
) -> str:
    if not isinstance(value, str | float | int | Decimal) or isinstance(value, bool):
        raise ModelGatewayError(f"{label} is invalid")
    try:
        parsed = _decimal(value, label)
    except ValueError as exc:
        raise ModelGatewayError(f"{label} is invalid") from exc
    if not allow_zero and parsed <= 0:
        raise ModelGatewayError(f"{label} is invalid")
    normalized = _money(parsed)
    if isinstance(value, str) and value != normalized:
        raise ModelGatewayError(f"{label} is not canonically encoded")
    return normalized


class _GatewayHTTPFailure(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


def _response_model_and_usage(body: bytes, *, stream: bool) -> tuple[str, dict[str, object]]:
    if not stream:
        payload = _decode_json_object(body, "model response")
        model = payload.get("model")
        usage = payload.get("usage")
        if not isinstance(model, str) or not isinstance(usage, dict):
            raise ModelGatewayError("model response lacks identity or usage")
        return model, usage
    models: set[str] = set()
    usage_records: list[dict[str, object]] = []
    saw_done = False
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(b":"):
            continue
        if not stripped.startswith(b"data:"):
            continue
        data = stripped[5:].strip()
        if data == b"[DONE]":
            saw_done = True
            continue
        payload = _decode_json_object(data, "streaming model response chunk")
        model = payload.get("model")
        if isinstance(model, str):
            models.add(model)
        usage = payload.get("usage")
        if isinstance(usage, dict) and usage:
            usage_records.append(usage)
    if not saw_done or len(models) != 1 or len(usage_records) != 1:
        raise ModelGatewayError("streaming response lacks one terminal usage record")
    return next(iter(models)), usage_records[0]


def _usage_integer(usage: Mapping[str, object], name: str, *, default: int | None = None) -> int:
    value = usage.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ModelGatewayError(f"provider usage field {name} is invalid")
    return value


def _request_record_ordinal(record: Mapping[str, object]) -> int:
    value = record.get("request_ordinal")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelGatewayError("model gateway request ordinal is invalid")
    return value


def _decode_json_object(content: bytes, label: str) -> dict[str, object]:
    try:
        payload = json.loads(
            content,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ModelGatewayError(f"{label} is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ModelGatewayError(f"{label} must be a JSON object")
    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ModelGatewayError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise ModelGatewayError(f"non-finite JSON number is forbidden: {value}")


def _write_http_error(handler: BaseHTTPRequestHandler, status: int, code: str) -> None:
    body = _canonical_json({"error": {"code": code, "message": "request rejected by evaluator"}})
    _write_http_response(handler, status, body, "application/json")


def _write_http_response(
    handler: BaseHTTPRequestHandler,
    status: int,
    body: bytes,
    content_type: str,
) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", _safe_content_type(content_type))
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(body)
    handler.close_connection = True


def _safe_content_type(value: str) -> str:
    """Return a bounded single-line media type safe for an HTTP response header."""

    if not isinstance(value, str) or not value or "\r" in value or "\n" in value:
        return "application/octet-stream"
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return "application/octet-stream"
    return value[:200]


def _decimal(value: float | str | Decimal, label: str) -> Decimal:
    if isinstance(value, bool):
        raise ValueError(f"{label} is invalid")
    try:
        result = Decimal(str(value))
    except Exception as exc:  # noqa: BLE001 - normalized into a public validation error.
        raise ValueError(f"{label} is invalid") from exc
    if not result.is_finite() or result < 0:
        raise ValueError(f"{label} is invalid")
    return result


def _token_cost(tokens: int, price_per_million: Decimal) -> Decimal:
    if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
        raise ValueError("token count is invalid")
    return Decimal(tokens) * price_per_million / _MILLION


def _money(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError("non-finite cost cannot enter evidence")
    text = format(value.normalize(), "f")
    return "0" if text in {"-0", ""} else text


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _write_json_exclusive(path: Path, payload: Mapping[str, object]) -> None:
    target = path.expanduser()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    serialized = (json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )
    if len(serialized) > _MAX_RECEIPT_BYTES:
        raise RowSealError("model gateway receipt exceeds the byte limit")
    try:
        with target.open("xb") as output:
            output.write(serialized)
    except FileExistsError as exc:
        raise RowSealError(f"refusing to replace model gateway evidence: {target}") from exc


__all__ = [
    "ComparisonModelGateway",
    "MODEL_GATEWAY_POLICY_SCHEMA",
    "MODEL_GATEWAY_SCHEMA",
    "ModelGatewayError",
    "ModelGatewayPolicy",
    "ModelPricing",
    "RowRegistrationError",
    "RowSealError",
    "UpstreamResponse",
    "UpstreamTransport",
    "validate_model_gateway_receipt",
]
