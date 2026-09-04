# HTTP-route errors preserve scope and request-boundary context.
# ruff: noqa: EM101, EM102, PLR0913, PLR0917, S310, TC001, TC003, TRY003

from __future__ import annotations

import errno
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPMessage, HTTPResponse, HTTPSConnection
from http.cookiejar import CookieJar
from typing import IO, TYPE_CHECKING, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import unquote_plus, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)
from uuid import uuid4

from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.autonomous_graph.action_bridge import ActionExecution
from ravage.agent_core.autonomous_graph.operational_profile import (
    GraphOperationalProfile,
)
from ravage.traffic.contracts import CapturedHttpExchange
from ravage.traffic.policy import (
    RequestIntent,
    TrafficCacheRecord,
    TrafficDecisionKind,
    TrafficOutcome,
    TrafficPolicyBlocked,
    TrafficPolicyController,
    TrafficPolicyError,
)
from ravage.traffic.redaction import redact_text as redact_traffic_text
from ravage.traffic.redaction import sanitize_url
from ravage.web_core.proof_recognizer import recognize_proofs
from ravage.web_core.scope_policy import (
    assert_authorized_target,
    assert_scoped_same_origin,
)

if TYPE_CHECKING:
    from pathlib import Path

    from pentest_schemas import Scope

    from ravage.web_core.http_probe import ProbeResponse, ProbeSession

_ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"})
_BLOCKED_REQUEST_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "proxy-authorization",
        "proxy-connection",
        "transfer-encoding",
    }
)
_CROSS_ORIGIN_SENSITIVE_HEADERS = frozenset({"authorization", "cookie"})
_SENSITIVE_RESPONSE_HEADERS = frozenset(
    {
        "authentication-info",
        "authorization",
        "cookie",
        "proxy-authentication-info",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
    }
)
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_MAX_REQUEST_BODY_BYTES = 256_000
_MAX_RESPONSE_BODY_BYTES = 600_000
_VISIBLE_BODY_CHARS = 20_000
_MAX_TIMEOUT_SECONDS = 30
_SEE_OTHER_STATUS = 303
_LEGACY_POST_REDIRECT_STATUSES = frozenset({301, 302})
_HTTP_STATE_VERSION = 2
_MAX_HTTP_STATE_BYTES = 262_144
_HTTP_STATE_READ_CHUNK_BYTES = 65_536
_PRIVATE_FILE_MODE = 0o600
_MAX_NETWORK_PORT = 65_535
_MAX_PROOF_CANONICALIZATION_PASSES = 16
_IPV6_VERSION = 6
_MANAGED_AUTH_HEADERS = frozenset({"authorization", "cookie"})
_REQUEST_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class ScopedHttpError(ValueError):
    """Raised before an unsafe or unaccountable HTTP request is sent."""


def _remaining_deadline(
    deadline_monotonic: float | None,
    *,
    clock: Callable[[], float],
) -> float | None:
    if deadline_monotonic is None:
        return None
    if isinstance(deadline_monotonic, bool) or not isinstance(
        deadline_monotonic,
        (int, float),
    ):
        raise ScopedHttpError("probe wall-clock deadline is invalid")
    deadline = float(deadline_monotonic)
    if not math.isfinite(deadline):
        raise ScopedHttpError("probe wall-clock deadline is invalid")
    remaining = deadline - clock()
    if remaining <= 0:
        raise TimeoutError("probe wall-clock deadline exceeded")
    return remaining


def _require_wait_within_deadline(
    delay_seconds: float,
    deadline_monotonic: float | None,
    *,
    clock: Callable[[], float],
) -> None:
    remaining = _remaining_deadline(deadline_monotonic, clock=clock)
    if remaining is not None and delay_seconds >= remaining:
        raise TimeoutError("probe wall-clock deadline exceeded")


def _deadline_bounded_timeout(
    timeout_seconds: float,
    deadline_monotonic: float | None,
    *,
    clock: Callable[[], float],
) -> float:
    remaining = _remaining_deadline(deadline_monotonic, clock=clock)
    return timeout_seconds if remaining is None else min(timeout_seconds, remaining)


def _cleanup_preserving(
    primary: BaseException,
    cleanup: Callable[[], object],
    *,
    message: str,
) -> None:
    try:
        cleanup()
    except BaseException as cleanup_error:
        with suppress(BaseException):
            primary.add_note(f"{message}: {type(cleanup_error).__name__}")


@dataclass(frozen=True)
class ScopedHttpTransportRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None
    timeout_seconds: float


@dataclass(frozen=True)
class ScopedHttpTransportResponse:
    status: int | None
    url: str
    headers: dict[str, str]
    body: bytes
    elapsed_ms: int
    error: str = ""
    truncated: bool = False


@dataclass(frozen=True)
class _ScopedDispatch:
    response: ScopedHttpTransportResponse
    sequence: int | None
    delay_seconds: float
    cache_hit: bool = False
    traffic_policy_sequence: int | None = None
    intent: RequestIntent | None = None
    outcome: TrafficOutcome | None = None


class ScopedHttpTransport(Protocol):
    def send(
        self,
        request: ScopedHttpTransportRequest,
    ) -> ScopedHttpTransportResponse: ...


class ManagedGraphAuthentication(Protocol):
    """Secret-owning request boundary supplied by the configured-auth runtime."""

    @property
    def identity(self) -> str: ...

    @property
    def traffic_policy(self) -> TrafficPolicyController | None: ...

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProbeResponse: ...

    def session_for_model_action(self, *, timeout_seconds: int = 10) -> ProbeSession: ...

    def assert_traffic_policy(
        self,
        traffic_policy: TrafficPolicyController | None,
    ) -> None: ...

    def retire_probe_session(self, session: ProbeSession) -> None: ...

    def redact_text(self, value: str) -> str: ...

    def contains_secret(self, value: str) -> bool: ...

    def configure_request_gate(
        self,
        gate: Callable[[str, str], object] | None,
    ) -> None: ...


class ManagedAuthenticationScopedHttpTransport:
    """Adapt managed ``ProbeSession`` requests to the graph HTTP transport."""

    def __init__(
        self,
        authentication: ManagedGraphAuthentication,
        *,
        persistent_session: bool = False,
    ) -> None:
        identity = str(getattr(authentication, "identity", "")).strip()
        if not identity:
            raise ScopedHttpError("managed graph authentication identity is required")
        self.authentication = authentication
        self.persistent_session = persistent_session
        self._session: ProbeSession | None = None
        self._action_active = False

    @property
    def cookies(self) -> object | None:
        session = self._session
        return getattr(session, "cookies", None) if session is not None else None

    def begin_action(self, *, timeout_seconds: float) -> None:
        """Lease one disposable identity lane for a complete redirect chain."""
        if self._action_active:
            raise ScopedHttpError("managed authentication action session is already active")
        if self._session is None:
            try:
                self._session = self.authentication.session_for_model_action(
                    timeout_seconds=max(int(timeout_seconds), 1)
                )
            except Exception:  # noqa: BLE001 - owner failures are never artifact-safe.
                raise ScopedHttpError("managed authentication action session failed") from None
        self._action_active = True

    def end_action(self) -> None:
        if not self._action_active:
            return
        self._action_active = False
        if self.persistent_session:
            return
        session = self._session
        self._session = None
        if session is None:
            return
        try:
            self.authentication.retire_probe_session(session)
        except Exception:  # noqa: BLE001 - cleanup details can contain auth material.
            raise ScopedHttpError("managed authentication action cleanup failed") from None

    def close(self) -> None:
        """Retire a retained managed session exactly once at lane shutdown."""
        if self._action_active:
            raise ScopedHttpError("managed authentication action session is still active")
        session = self._session
        self._session = None
        if session is None:
            return
        try:
            self.authentication.retire_probe_session(session)
        except Exception:  # noqa: BLE001 - cleanup details can contain auth material.
            raise ScopedHttpError("managed authentication action cleanup failed") from None

    def send(
        self,
        request: ScopedHttpTransportRequest,
    ) -> ScopedHttpTransportResponse:
        session = self._session
        if session is None:
            raise ScopedHttpError("managed authentication action session is unavailable")
        try:
            response = session.request(
                request.method,
                request.url,
                data=request.body,
                headers=dict(request.headers),
                timeout_seconds=request.timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - redact owner failures at the trust boundary.
            safe_error = self.authentication.redact_text(str(exc))
            raise ScopedHttpError(f"managed authentication request failed: {safe_error}") from None
        return _managed_transport_response(response)


def _managed_transport_response(response: ProbeResponse) -> ScopedHttpTransportResponse:
    """Translate a managed probe response without exposing its session internals."""
    headers = {str(name): str(value) for name, value in response.headers.items()}
    body = response.body_bytes
    return ScopedHttpTransportResponse(
        status=response.status,
        url=response.final_url or response.url,
        headers=headers,
        body=body,
        elapsed_ms=response.elapsed_ms,
        error=response.error,
        truncated=response.truncated,
    )


def _encode_response_body(body: str, *, headers: Mapping[str, str]) -> bytes:
    content_type = _header(headers, "content-type")
    charset = "utf-8"
    for part in content_type.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value.strip():
            charset = value.strip().strip("\"'")
            break
    try:
        return body.encode(charset, errors="replace")
    except LookupError:
        return body.encode("utf-8", errors="replace")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        del req, fp, code, msg, headers, newurl
        return None


class _PinnedHTTPConnection(HTTPConnection):
    """Connect to an approved numeric peer while retaining the URL authority."""

    def __init__(
        self,
        host: str,
        port: int | None = None,
        *,
        pin_provider: Callable[[str, int], Sequence[str]],
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
        blocksize: int = 8192,
    ) -> None:
        super().__init__(
            host,
            port=port,
            timeout=timeout,
            source_address=source_address,
            blocksize=blocksize,
        )
        self._pinned_addresses = tuple(pin_provider(self.host, self.port))
        self._source_address = source_address

    def connect(self) -> None:
        sys.audit("http.client.connect", self, self.host, self.port)
        self.sock = _connect_pinned_socket(
            self._pinned_addresses,
            self.port,
            timeout=self.timeout,
            source_address=self._source_address,
        )
        tunnel_host = getattr(self, "_tunnel_host", None)
        if tunnel_host:
            getattr(self, "_tunnel")()


class _PinnedHTTPSConnection(HTTPSConnection):
    """Pin the TCP peer without replacing the original TLS server name."""

    def __init__(
        self,
        host: str,
        port: int | None = None,
        *,
        pin_provider: Callable[[str, int], Sequence[str]],
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
        context: ssl.SSLContext | None = None,
        blocksize: int = 8192,
    ) -> None:
        tls_context = context or _default_https_context()
        super().__init__(
            host,
            port=port,
            timeout=timeout,
            source_address=source_address,
            context=tls_context,
            blocksize=blocksize,
        )
        self._pinned_addresses = tuple(pin_provider(self.host, self.port))
        self._source_address = source_address
        self._tls_context = tls_context

    def connect(self) -> None:
        sys.audit("http.client.connect", self, self.host, self.port)
        self.sock = _connect_pinned_socket(
            self._pinned_addresses,
            self.port,
            timeout=self.timeout,
            source_address=self._source_address,
        )
        tunnel_host = getattr(self, "_tunnel_host", None)
        server_hostname = tunnel_host or self.host
        if tunnel_host:
            getattr(self, "_tunnel")()
        self.sock = self._tls_context.wrap_socket(self.sock, server_hostname=server_hostname)


class _PinnedHTTPHandler(HTTPHandler):
    def __init__(self, pin_provider: Callable[[str, int], Sequence[str]]) -> None:
        super().__init__()
        self._pin_provider = pin_provider

    def http_open(self, req: Request) -> HTTPResponse:
        return self.do_open(self._connection, req)

    def _connection(
        self,
        host: str,
        *,
        port: int | None = None,
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
        blocksize: int = 8192,
    ) -> _PinnedHTTPConnection:
        return _PinnedHTTPConnection(
            host,
            port=port,
            pin_provider=self._pin_provider,
            timeout=timeout,
            source_address=source_address,
            blocksize=blocksize,
        )


class _PinnedHTTPSHandler(HTTPSHandler):
    def __init__(self, pin_provider: Callable[[str, int], Sequence[str]]) -> None:
        tls_context = _default_https_context()
        super().__init__(context=tls_context)
        self._pin_provider = pin_provider
        self._tls_context = tls_context

    def https_open(self, req: Request) -> HTTPResponse:
        return self.do_open(self._connection, req, context=self._tls_context)

    def _connection(
        self,
        host: str,
        *,
        port: int | None = None,
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
        context: ssl.SSLContext | None = None,
        blocksize: int = 8192,
    ) -> _PinnedHTTPSConnection:
        return _PinnedHTTPSConnection(
            host,
            port=port,
            pin_provider=self._pin_provider,
            timeout=timeout,
            source_address=source_address,
            context=context,
            blocksize=blocksize,
        )


def _default_https_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


def _connect_pinned_socket(
    addresses: Sequence[str],
    port: int,
    *,
    timeout: object,
    source_address: tuple[str, int] | None,
) -> socket.socket:
    """Connect directly to numeric pins without invoking DNS or proxy routing."""
    last_error: OSError | None = None
    for address in addresses:
        parsed = _validated_transport_address(address)
        family = socket.AF_INET6 if parsed.version == _IPV6_VERSION else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            if timeout is None or isinstance(timeout, (int, float)):
                sock.settimeout(timeout)
            if source_address is not None:
                sock.bind(source_address)
            sock.connect((str(parsed), port))
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError as exc:
                if exc.errno != errno.ENOPROTOOPT:
                    raise
        except OSError as exc:
            last_error = exc
            sock.close()
        else:
            return sock
    if last_error is not None:
        raise last_error
    raise OSError("remote HTTP resolver returned no addresses")


def _validated_transport_address(
    address: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise OSError("remote HTTP resolver returned a non-IP address") from exc
    effective = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
    if (effective or parsed).is_unspecified:
        raise OSError("remote HTTP resolver returned an unspecified address")
    return parsed


def _validated_public_transport_address(
    address: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    parsed = _validated_transport_address(address)
    effective = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
    candidate = effective or parsed
    if not candidate.is_global or candidate.is_multicast:
        raise OSError("remote HTTP resolver returned a non-public address")
    return parsed


class UrllibScopedHttpTransport:
    """One stable cookie session with redirects disabled for external validation."""

    def __init__(
        self,
        pin_provider: Callable[[str, int], Sequence[str]] | None = None,
    ) -> None:
        provider = pin_provider or self._missing_pin_provider
        self.cookies = CookieJar()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPCookieProcessor(self.cookies),
            _PinnedHTTPHandler(provider),
            _PinnedHTTPSHandler(provider),
            _NoRedirectHandler(),
        )

    @staticmethod
    def _missing_pin_provider(_host: str, _port: int) -> Sequence[str]:
        raise ScopedHttpError("remote HTTP transport has no validated DNS pin provider")

    def send(
        self,
        request: ScopedHttpTransportRequest,
    ) -> ScopedHttpTransportResponse:
        started = time.monotonic()
        outbound = Request(
            request.url,
            data=request.body,
            headers=request.headers,
            method=request.method,
        )
        try:
            response = self.opener.open(
                outbound,
                timeout=request.timeout_seconds,
            )
            status = int(getattr(response, "status", response.getcode()))
            final_url = response.geturl()
            raw_headers = response.headers
            body = response.read(_MAX_RESPONSE_BODY_BYTES + 1)
        except HTTPError as exc:
            status = exc.code
            final_url = exc.geturl()
            raw_headers = exc.headers
            body = exc.read(_MAX_RESPONSE_BODY_BYTES + 1)
        except (OSError, URLError) as exc:
            return ScopedHttpTransportResponse(
                status=None,
                url=request.url,
                headers={},
                body=b"",
                elapsed_ms=int((time.monotonic() - started) * 1000),
                error=f"{type(exc).__name__}:{exc}",
            )
        truncated = len(body) > _MAX_RESPONSE_BODY_BYTES
        return ScopedHttpTransportResponse(
            status=status,
            url=final_url,
            headers=_aggregate_response_headers(raw_headers),
            body=body[:_MAX_RESPONSE_BODY_BYTES],
            elapsed_ms=int((time.monotonic() - started) * 1000),
            truncated=truncated,
        )


def _aggregate_response_headers(raw_headers: object) -> dict[str, str]:
    """Retain every Set-Cookie line while preserving ordinary header behavior."""
    items = getattr(raw_headers, "items", None)
    if not callable(items):
        return {}
    headers: dict[str, str] = {}
    set_cookie_name = "Set-Cookie"
    set_cookie_values: list[str] = []
    for raw_name, raw_value in cast("Iterable[tuple[object, object]]", items()):
        name = str(raw_name)
        value = str(raw_value)
        if name.casefold() == "set-cookie":
            set_cookie_name = name
            set_cookie_values.append(value)
        else:
            headers[name] = value
    get_all = getattr(raw_headers, "get_all", None)
    if callable(get_all):
        cookie_values = cast("Iterable[object]", get_all("Set-Cookie", []))
        set_cookie_values.extend(str(value) for value in cookie_values)
    unique_cookie_values = tuple(dict.fromkeys(set_cookie_values))
    if unique_cookie_values:
        headers[set_cookie_name] = "\n".join(unique_cookie_values)
    return headers


class _RequestGate:
    """Serialize, rate-limit, jitter, and globally account target requests."""

    def __init__(
        self,
        profile: GraphOperationalProfile,
        *,
        clock: Callable[[], float],
        sleeper: Callable[[float], None],
        initial_request_count: int = 0,
        on_acquire: Callable[[int], None] | None = None,
    ) -> None:
        self.profile = profile
        self.clock = clock
        self.sleeper = sleeper
        self._lock = threading.Lock()
        if not 0 <= initial_request_count <= profile.max_total_requests:
            raise ScopedHttpError("persisted remote HTTP request count is invalid")
        self._request_count = initial_request_count
        self._last_started_at: float | None = None
        self._on_acquire = on_acquire

    def wait_until_available(
        self,
        *,
        _deadline_monotonic: float | None = None,
    ) -> float:
        """Apply route-local pacing without claiming a physical request."""
        with self._lock:
            _remaining_deadline(_deadline_monotonic, clock=self.clock)
            if self._request_count >= self.profile.max_total_requests:
                raise ScopedHttpError("remote HTTP target-request ceiling reached")
            sequence = self._request_count + 1
            delay = 0.0
            if self._last_started_at is not None:
                earliest = (
                    self._last_started_at
                    + self.profile.minimum_interval_seconds
                    + self.profile.jitter_seconds(sequence)
                )
                delay = max(earliest - self.clock(), 0.0)
                if delay:
                    _require_wait_within_deadline(
                        delay,
                        _deadline_monotonic,
                        clock=self.clock,
                    )
                    self.sleeper(delay)
                    _remaining_deadline(_deadline_monotonic, clock=self.clock)
            return delay

    def acquire(
        self,
        *,
        pace: bool = True,
        _deadline_monotonic: float | None = None,
    ) -> tuple[int, float]:
        with self._lock:
            _remaining_deadline(_deadline_monotonic, clock=self.clock)
            if self._request_count >= self.profile.max_total_requests:
                raise ScopedHttpError("remote HTTP target-request ceiling reached")
            sequence = self._request_count + 1
            delay = 0.0
            if pace and self._last_started_at is not None:
                earliest = (
                    self._last_started_at
                    + self.profile.minimum_interval_seconds
                    + self.profile.jitter_seconds(sequence)
                )
                delay = max(earliest - self.clock(), 0.0)
                if delay:
                    _require_wait_within_deadline(
                        delay,
                        _deadline_monotonic,
                        clock=self.clock,
                    )
                    self.sleeper(delay)
                    _remaining_deadline(_deadline_monotonic, clock=self.clock)
            self._request_count = sequence
            self._last_started_at = self.clock()
            if self._on_acquire is not None:
                self._on_acquire(sequence)
            return sequence, delay

    @property
    def request_count(self) -> int:
        with self._lock:
            return self._request_count


class ScopedGraphHttpExecutor:
    """
    Execute one structured HTTP action under brief scope and low-noise controls.

    This route intentionally exposes no generic shell or browser. Every outbound
    request, including each redirect hop, is validated and independently counted.
    """

    def __init__(  # noqa: C901 - validates all executor ownership boundaries.
        self,
        *,
        target_url: str,
        scope: Scope,
        allow_remote_target: bool,
        profile: GraphOperationalProfile,
        proof_recognition_enabled: bool = False,
        transport: ScopedHttpTransport | None = None,
        resolver: Callable[[str, int], Sequence[str]] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        state_path: Path | None = None,
        traffic_observer: Callable[[dict[str, object]], CapturedHttpExchange | None] | None = None,
        require_existing_state: bool = False,
        minimum_request_count: int = 0,
        authentication: ManagedGraphAuthentication | None = None,
        traffic_policy: TrafficPolicyController | None = None,
        cache_anonymous_gets: bool = True,
        persistent_managed_session: bool = False,
    ) -> None:
        assert_authorized_target(
            target_url,
            scope=scope,
            allow_remote_target=allow_remote_target,
            agent_name="autonomous graph HTTP",
        )
        if (
            isinstance(minimum_request_count, bool)
            or not isinstance(minimum_request_count, int)
            or minimum_request_count < 0
        ):
            raise ScopedHttpError("minimum persisted HTTP request count is invalid")
        self._target_identity = _target_identity(target_url)
        self.target_url = _canonical_url(target_url)
        self.scope = scope
        self.allow_remote_target = allow_remote_target
        self.profile = profile
        self.proof_recognition_enabled = proof_recognition_enabled
        if authentication is not None and transport is not None:
            raise ScopedHttpError(
                "managed graph authentication cannot be combined with a custom HTTP transport"
            )
        bound_traffic_policy = traffic_policy
        if authentication is not None and bound_traffic_policy is None:
            bound_traffic_policy = authentication.traffic_policy
        if authentication is not None:
            if bound_traffic_policy is None:
                raise ScopedHttpError(
                    "managed graph authentication requires a whole-run traffic policy"
                )
            try:
                authentication.assert_traffic_policy(bound_traffic_policy)
            except Exception as exc:
                raise ScopedHttpError(
                    "managed graph authentication traffic policy binding is invalid"
                ) from exc
        if bound_traffic_policy is not None and _origin(
            bound_traffic_policy.target_origin
        ) != _origin(
            self.target_url
        ):
            raise ScopedHttpError("traffic policy belongs to a different target origin")
        self.authentication = authentication
        self.cache_anonymous_gets = cache_anonymous_gets
        policy_config = getattr(bound_traffic_policy, "config", None)
        self._require_public_addresses = bool(
            getattr(policy_config, "require_public_addresses", False)
        )
        # Managed ProbeSession owns the same controller and accounts each auth,
        # health, refresh, redirect, and action dispatch. Do not double-wrap it.
        self.traffic_policy = None if authentication is not None else bound_traffic_policy
        self.identity_alias = (
            str(getattr(authentication, "identity", "")).strip()
            if authentication is not None
            else ""
        )
        self.transport = (
            ManagedAuthenticationScopedHttpTransport(
                authentication,
                persistent_session=persistent_managed_session,
            )
            if authentication is not None
            else transport or UrllibScopedHttpTransport(self._validated_transport_pins)
        )
        self.resolver = resolver or _resolve_addresses
        self.state_path = _optional_path(state_path)
        self.traffic_observer = traffic_observer
        self._require_existing_state = require_existing_state
        self._minimum_request_count = minimum_request_count
        request_count, pins, session_dirty = self._load_state()
        if request_count < minimum_request_count:
            raise ScopedHttpError(
                "remote HTTP state request count is behind captured traffic history"
            )
        if (
            require_existing_state
            and authentication is None
            and request_count != minimum_request_count
        ):
            raise ScopedHttpError(
                "remote HTTP state request count does not match captured traffic history"
            )
        self._pins = pins
        self._session_dirty = session_dirty
        self._pin_lock = threading.Lock()
        self._execution_lock = threading.Lock()
        self._clock = clock
        self._gate = _RequestGate(
            profile,
            clock=clock,
            sleeper=sleeper,
            initial_request_count=request_count,
            on_acquire=self._persist_state,
        )
        self._managed_request_acquisitions: list[tuple[int, float]] = []
        self._persist_state(request_count)

    @property
    def request_count(self) -> int:
        return self._gate.request_count

    @property
    def session_dirty(self) -> bool:
        """Whether an anonymous cookie jar changed since its last clean start."""
        return self._session_dirty

    def mark_session_dirty(self) -> None:
        if self._session_dirty:
            return
        self._session_dirty = True
        self._persist_state(self.request_count)

    def clear_session_dirty(self) -> None:
        if not self._session_dirty:
            return
        self._session_dirty = False
        self._persist_state(self.request_count)

    def close(self) -> None:
        transport = self.transport
        if isinstance(transport, ManagedAuthenticationScopedHttpTransport):
            try:
                transport.close()
            except BaseException as exc:
                if self.authentication is not None:
                    _cleanup_preserving(
                        exc,
                        lambda: self.authentication.configure_request_gate(None),
                        message="managed authentication gate cleanup also failed",
                    )
                raise
            if self.authentication is not None:
                self.authentication.configure_request_gate(None)

    def __call__(
        self,
        *,
        node_id: str,
        arguments: dict[str, object],
        action_id: str,
        _deadline_monotonic: float | None = None,
    ) -> ActionExecution:
        with self._execution_lock:
            return self._execute(
                node_id=node_id,
                arguments=arguments,
                action_id=action_id,
                _deadline_monotonic=_deadline_monotonic,
            )

    def _execute(  # noqa: C901, PLR0912, PLR0915 - redirect/retry lifecycle.
        self,
        *,
        node_id: str,
        arguments: dict[str, object],
        action_id: str,
        _deadline_monotonic: float | None,
    ) -> ActionExecution:
        _remaining_deadline(_deadline_monotonic, clock=self._clock)
        authored_proofs = _request_authored_proofs(arguments)
        method, url, headers, body, timeout = _request_from_arguments(
            arguments,
            target_url=self.target_url,
            stable_user_agent=self.profile.stable_user_agent,
            managed_authentication=self.authentication is not None,
        )
        # Keep the join key short enough that secret redaction does not mistake a
        # full UUID for credential material when it is persisted with traffic.
        observation_id = f"http:obs-{uuid4().hex[:12]}"
        requests: list[dict[str, object]] = []
        traffic_exchange_ids: list[str] = []
        response: ScopedHttpTransportResponse | None = None
        decoded_body = ""
        # Reject an unsafe model-authored destination before authentication
        # performs even a health-check request for the action lease.
        self._authorize_url(url)
        self._verify_dns_pin(url)
        managed_transport: ManagedAuthenticationScopedHttpTransport | None = None
        if self.authentication is not None:
            if not isinstance(self.transport, ManagedAuthenticationScopedHttpTransport):
                raise ScopedHttpError("managed authentication transport binding is invalid")
            managed_transport = self.transport
            self.authentication.configure_request_gate(
                cast(
                    "Callable[[str, str], None]",
                    lambda method, request_url: self._account_managed_request(
                        method,
                        request_url,
                        _deadline_monotonic=_deadline_monotonic,
                    ),
                )
            )
            try:
                managed_transport.begin_action(
                    timeout_seconds=_deadline_bounded_timeout(
                        timeout,
                        _deadline_monotonic,
                        clock=self._clock,
                    )
                )
            except BaseException as exc:
                _cleanup_preserving(
                    exc,
                    lambda: self.authentication.configure_request_gate(None),
                    message="managed authentication gate cleanup also failed",
                )
                raise
        action_error: BaseException | None = None
        try:
            for redirect_index in range(self.profile.max_redirects + 1):
                if redirect_index > 0:
                    self._authorize_url(url)
                    self._verify_dns_pin(url)
                attempt_index = 0
                while True:
                    request_count_before = self.request_count
                    try:
                        dispatch = self._dispatch_request(
                            method=method,
                            url=url,
                            headers=headers,
                            body=body,
                            timeout=timeout,
                            attempt_index=attempt_index,
                            _deadline_monotonic=_deadline_monotonic,
                        )
                    except BaseException as exc:
                        # The gate commits at the physical dispatch boundary. If
                        # transport control flow is then interrupted, close the
                        # matching traffic half before preserving the interrupt.
                        if (
                            self.authentication is None
                            and self.request_count > request_count_before
                        ):
                            interrupted = ScopedHttpTransportResponse(
                                status=None,
                                url=self._safe_url(url),
                                headers={},
                                body=b"",
                                elapsed_ms=0,
                                error=(
                                    f"{type(exc).__name__}:"
                                    "transport dispatch interrupted"
                                ),
                            )
                            try:
                                self._record_traffic(
                                    observation_id=observation_id,
                                    method=method,
                                    url=self._safe_url(url),
                                    headers=headers,
                                    body=body,
                                    response=interrupted,
                                    response_body=b"",
                                )
                            except BaseException as capture_error:
                                exc.add_note(
                                    "interrupted HTTP traffic capture also failed: "
                                    f"{type(capture_error).__name__}"
                                )
                        raise
                    raw_response = dispatch.response
                    raw_location = _header(raw_response.headers, "location")
                    response, decoded_body = self._redacted_response(raw_response)
                    if not dispatch.cache_hit:
                        traffic_exchange_id = self._record_traffic(
                            observation_id=observation_id,
                            method=method,
                            url=self._safe_url(url),
                            headers=headers,
                            body=body,
                            response=response,
                            response_body=raw_response.body,
                        )
                        if traffic_exchange_id:
                            traffic_exchange_ids.append(traffic_exchange_id)
                    requests.append(
                        _request_receipt(
                            sequence=dispatch.sequence,
                            redirect_index=redirect_index,
                            attempt_index=attempt_index,
                            method=method,
                            url=self._safe_url(url),
                            headers=headers,
                            body=body,
                            delay_seconds=dispatch.delay_seconds,
                            response=response,
                            cache_hit=dispatch.cache_hit,
                            traffic_policy_sequence=dispatch.traffic_policy_sequence,
                        )
                    )
                    if (
                        self.traffic_policy is not None
                        and dispatch.intent is not None
                        and dispatch.outcome is not None
                        and self.traffic_policy.should_retry(
                            dispatch.intent,
                            dispatch.outcome,
                            attempt_index,
                        )
                    ):
                        attempt_index += 1
                        continue
                    break
                if response.status not in _REDIRECT_STATUSES or not raw_location:
                    break
                if redirect_index >= self.profile.max_redirects:
                    raise ScopedHttpError("remote HTTP redirect limit reached")
                next_url = _canonical_url(urljoin(url, raw_location))
                next_headers = dict(headers)
                if _origin(url) != _origin(next_url):
                    next_headers = {
                        key: value
                        for key, value in next_headers.items()
                        if key.lower() not in _CROSS_ORIGIN_SENSITIVE_HEADERS
                    }
                method, body = _redirect_method_and_body(
                    status=response.status,
                    method=method,
                    body=body,
                )
                if body is None:
                    next_headers = {
                        key: value
                        for key, value in next_headers.items()
                        if key.lower() != "content-type"
                    }
                headers = next_headers
                url = next_url
        except BaseException as exc:
            action_error = exc
            raise
        finally:
            cleanup_error = action_error
            if managed_transport is not None:
                if cleanup_error is None:
                    try:
                        managed_transport.end_action()
                    except BaseException as exc:
                        cleanup_error = exc
                else:
                    _cleanup_preserving(
                        cleanup_error,
                        managed_transport.end_action,
                        message="managed authentication action cleanup also failed",
                    )
            if self.authentication is not None:
                if cleanup_error is None:
                    try:
                        self.authentication.configure_request_gate(None)
                    except BaseException as exc:
                        cleanup_error = exc
                else:
                    _cleanup_preserving(
                        cleanup_error,
                        lambda: self.authentication.configure_request_gate(None),
                        message="managed authentication gate cleanup also failed",
                    )
            if action_error is None and cleanup_error is not None:
                raise cleanup_error
        if response is None:
            raise RuntimeError("remote HTTP executor produced no response")

        observation_payload = {
            "profile": self.profile.to_json(),
            "node_id": node_id,
            "action_id": action_id,
            "identity": self.identity_alias or "anonymous",
            "traffic_exchange_ids": traffic_exchange_ids,
            "requests": requests,
            "response": {
                "status": response.status,
                "final_url": response.url,
                "headers": _observation_response_headers(response.headers),
                "body": decoded_body,
                "body_sha256": hashlib.sha256(response.body).hexdigest(),
                "truncated": response.truncated,
                "error": response.error,
            },
        }
        evidence_observation = json.dumps(
            observation_payload,
            ensure_ascii=False,
            sort_keys=True,
        )
        visible_payload = dict(observation_payload)
        visible_response = dict(observation_payload["response"])
        visible_response["body"] = decoded_body[:_VISIBLE_BODY_CHARS]
        visible_response["body_visible_chars"] = min(
            len(decoded_body),
            _VISIBLE_BODY_CHARS,
        )
        visible_payload["response"] = visible_response
        visible_observation = json.dumps(
            visible_payload,
            ensure_ascii=False,
            sort_keys=True,
        )
        proofs = []
        if (
            self.proof_recognition_enabled
            and response.status is not None
            and authored_proofs is not None
        ):
            proofs = [
                proof
                for proof in recognize_proofs(decoded_body)
                if proof not in authored_proofs and not self._contains_secret(proof)
            ]
        return ActionExecution(
            result=ActionResult(
                ok=response.status is not None,
                observation=visible_observation,
                outcome=(
                    "http_response_observed"
                    if response.status is not None
                    else "http_transport_error"
                ),
                flag=proofs[0] if proofs else "",
                evidence_source_kind="tool_http_request",
                evidence_observation=evidence_observation,
            ),
            observation_id=observation_id,
        )

    def _dispatch_request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
        attempt_index: int,
        _deadline_monotonic: float | None,
    ) -> _ScopedDispatch:
        self._managed_request_acquisitions.clear()
        if self.authentication is not None:
            request_timeout = _deadline_bounded_timeout(
                timeout,
                _deadline_monotonic,
                clock=self._clock,
            )
            response = self.transport.send(
                _transport_request(method, url, headers, body, request_timeout)
            )
            if not self._managed_request_acquisitions:
                raise ScopedHttpError(
                    "managed authentication dispatched an unaccounted target request"
                )
            sequence, delay = self._managed_request_acquisitions[-1]
            return _ScopedDispatch(response, sequence, delay)
        if self.traffic_policy is not None:
            return self._dispatch_with_policy(
                method=method,
                url=url,
                headers=headers,
                body=body,
                timeout=timeout,
                attempt_index=attempt_index,
                _deadline_monotonic=_deadline_monotonic,
            )
        sequence, delay = self._gate.acquire(
            _deadline_monotonic=_deadline_monotonic,
        )
        request_timeout = _deadline_bounded_timeout(
            timeout,
            _deadline_monotonic,
            clock=self._clock,
        )
        response = self.transport.send(
            _transport_request(method, url, headers, body, request_timeout)
        )
        return _ScopedDispatch(response, sequence, delay)

    def _dispatch_with_policy(  # noqa: C901, PLR0912, PLR0915 - policy state machine.
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
        attempt_index: int,
        _deadline_monotonic: float | None,
    ) -> _ScopedDispatch:
        policy = self.traffic_policy
        if policy is None:
            raise ScopedHttpError("whole-run traffic policy is unavailable")
        intent = RequestIntent(
            method=method,
            url=url,
            headers=headers,
            body=body,
            lane="agent_http",
            identity_alias="anonymous",
            identity_generation=0,
            cacheable=self.cache_anonymous_gets and method in {"GET", "HEAD"},
            retryable=method in {"GET", "HEAD"},
        )
        try:
            if _deadline_monotonic is None:
                decision = policy.acquire(intent, retry=attempt_index > 0)
            else:
                decision = policy.acquire(
                    intent,
                    retry=attempt_index > 0,
                    _deadline_monotonic=_deadline_monotonic,
                    _monotonic_clock=self._clock,
                )
        except TrafficPolicyError as exc:
            detail = f"whole-run traffic policy failed: {exc}"
            raise ScopedHttpError(detail) from exc
        if decision.kind is TrafficDecisionKind.BLOCKED:
            raise ScopedHttpError(
                decision.reason or "whole-run traffic policy blocked the request"
            )
        if decision.kind is TrafficDecisionKind.CACHE_HIT:
            if decision.cached is None:
                raise ScopedHttpError("whole-run traffic policy returned an empty cache hit")
            return _ScopedDispatch(
                _cached_transport_response(decision.cached),
                None,
                0.0,
                cache_hit=True,
                intent=intent,
            )
        lease = decision.lease
        if lease is None:
            raise ScopedHttpError("whole-run traffic policy returned an empty dispatch lease")
        try:
            delay = self._gate.wait_until_available(
                _deadline_monotonic=_deadline_monotonic,
            )
        except BaseException as exc:
            _cleanup_preserving(
                exc,
                lambda: policy.cancel(lease),
                message="whole-run traffic policy could not cancel graph reservation",
            )
            raise
        try:
            if _deadline_monotonic is None:
                policy_sequence = policy.begin_dispatch(lease)
            else:
                policy_sequence = policy.begin_dispatch(
                    lease,
                    _deadline_monotonic=_deadline_monotonic,
                    _monotonic_clock=self._clock,
                )
        except TrafficPolicyBlocked as exc:
            _cleanup_preserving(
                exc,
                lambda: policy.cancel(lease),
                message="whole-run traffic policy could not cancel blocked graph dispatch",
            )
            detail = f"whole-run traffic policy blocked dispatch: {exc}"
            raise ScopedHttpError(detail) from exc
        except TrafficPolicyError as exc:
            _cleanup_preserving(
                exc,
                lambda: policy.cancel(lease),
                message="whole-run traffic policy could not cancel failed graph dispatch",
            )
            detail = f"whole-run traffic policy failed at dispatch: {exc}"
            raise ScopedHttpError(detail) from exc
        except BaseException as exc:
            _cleanup_preserving(
                exc,
                lambda: policy.cancel(lease),
                message="whole-run traffic policy could not cancel failed graph dispatch",
            )
            raise
        try:
            request_timeout = _deadline_bounded_timeout(
                timeout,
                _deadline_monotonic,
                clock=self._clock,
            )
        except TimeoutError as exc:
            _cleanup_preserving(
                exc,
                lambda: policy.complete(
                    lease,
                    TrafficOutcome(status=None, transport_error=True),
                ),
                message="whole-run traffic policy could not close expired dispatch",
            )
            _cleanup_preserving(
                exc,
                lambda: self._gate.acquire(pace=False),
                message="graph HTTP state could not close expired dispatch",
            )
            raise
        try:
            response = self.transport.send(
                _transport_request(method, url, headers, body, request_timeout)
            )
        except (OSError, URLError, TimeoutError) as exc:
            response = _transport_error_response(url, exc)
        except BaseException as exc:
            _cleanup_preserving(
                exc,
                lambda: policy.complete(
                    lease,
                    TrafficOutcome(status=None, transport_error=True),
                ),
                message="whole-run traffic policy could not persist graph transport failure",
            )
            _cleanup_preserving(
                exc,
                lambda: self._gate.acquire(pace=False),
                message="graph HTTP state could not record dispatch",
            )
            raise
        outcome = _traffic_outcome(response)
        try:
            policy.complete(lease, outcome)
        except TrafficPolicyError as exc:
            detail = f"whole-run traffic policy failed at completion: {exc}"
            raise ScopedHttpError(detail) from exc
        # Durable graph-local state is committed only after the physical outcome
        # has been durably completed in the authoritative whole-run ledger.
        sequence, _ = self._gate.acquire(pace=False)
        return _ScopedDispatch(
            response,
            sequence,
            delay,
            traffic_policy_sequence=policy_sequence,
            intent=intent,
            outcome=outcome,
        )

    def _account_managed_request(
        self,
        method: str,
        url: str,
        *,
        _deadline_monotonic: float | None = None,
    ) -> Callable[[], None]:
        del method, url
        delay = self._gate.wait_until_available(
            _deadline_monotonic=_deadline_monotonic,
        )
        committed = False

        def commit() -> None:
            nonlocal committed
            if committed:
                return
            committed = True
            sequence, _ = self._gate.acquire(pace=False)
            self._managed_request_acquisitions.append((sequence, delay))

        return commit

    def _redacted_response(
        self,
        response: ScopedHttpTransportResponse,
    ) -> tuple[ScopedHttpTransportResponse, str]:
        decoded_body = _decode_body(response.body, response.headers)
        safe_body = (
            decoded_body if self.authentication is None else self._redact_text(decoded_body)
        )
        safe_error = redact_traffic_text(self._redact_text(response.error), max_chars=2_048)
        safe_headers = (
            dict(response.headers)
            if self.authentication is None
            else {
                str(name): self._redact_text(str(value))
                for name, value in response.headers.items()
            }
        )
        return (
            ScopedHttpTransportResponse(
                status=response.status,
                url=self._safe_url(response.url),
                headers=safe_headers,
                body=safe_body.encode("utf-8"),
                elapsed_ms=response.elapsed_ms,
                error=safe_error,
                truncated=response.truncated,
            ),
            safe_body,
        )

    def _safe_url(self, value: str) -> str:
        return sanitize_url(self._redact_text(value))

    def _redact_text(self, value: str) -> str:
        authentication = self.authentication
        if authentication is None:
            return value
        return authentication.redact_text(value)

    def _contains_secret(self, value: str) -> bool:
        authentication = self.authentication
        if authentication is None:
            return False
        checker = getattr(authentication, "contains_secret", None)
        if callable(checker):
            return bool(checker(value))
        return authentication.redact_text(value) != value

    def _record_traffic(
        self,
        *,
        observation_id: str,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        response: ScopedHttpTransportResponse,
        response_body: bytes,
    ) -> str:
        if self.traffic_observer is None:
            return ""
        stored = self.traffic_observer(
            {
                "disposition": "sent",
                "source_observation_id": observation_id,
                "resource_type": "agent_http",
                "method": method,
                "url": url,
                "request_headers": dict(headers),
                "request_body": body,
                "response_status": response.status,
                "response_url": response.url,
                "response_headers": dict(response.headers),
                "response_body": response_body,
                "elapsed_ms": response.elapsed_ms,
                "error": response.error,
                "scope_reason": (
                    f"authorized autonomous graph HTTP request as identity {self.identity_alias}"
                    if self.identity_alias
                    else "authorized autonomous graph HTTP request"
                ),
            }
        )
        return stored.exchange_id if stored is not None else ""

    def _authorize_url(self, url: str) -> None:
        try:
            assert_scoped_same_origin(
                self.target_url,
                url,
                scope=self.scope,
                allow_remote_target=self.allow_remote_target,
            )
        except ValueError as exc:
            safe_error = self._redact_text(str(exc))
            if self.authentication is not None:
                raise ScopedHttpError(safe_error) from None
            raise ScopedHttpError(safe_error) from exc

    def _verify_dns_pin(self, url: str) -> None:
        parsed = urlsplit(url)
        host = parsed.hostname
        if host is None:
            raise ScopedHttpError("remote HTTP URL has no host")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            addresses = tuple(sorted(set(self.resolver(host, port))))
        except OSError as exc:
            raise ScopedHttpError(f"remote HTTP DNS resolution failed: {exc}") from exc
        if not addresses:
            raise ScopedHttpError("remote HTTP DNS resolution returned no addresses")
        if self._require_public_addresses:
            try:
                addresses = tuple(
                    str(_validated_public_transport_address(address)) for address in addresses
                )
            except OSError as exc:
                raise ScopedHttpError(
                    f"remote HTTP DNS resolution rejected an address: {exc}"
                ) from exc
        key = (host.lower(), port)
        with self._pin_lock:
            pinned = self._pins.setdefault(key, addresses)
            if addresses != pinned:
                raise ScopedHttpError("remote HTTP DNS resolution changed after pinning")
        self._persist_state(self.request_count)

    def _validated_transport_pins(self, host: str, port: int) -> tuple[str, ...]:
        key = (host.lower(), port)
        with self._pin_lock:
            addresses = self._pins.get(key)
        if not addresses:
            raise ScopedHttpError("remote HTTP transport has no validated DNS pins")
        return addresses

    def _load_state(  # noqa: C901, PLR0912, PLR0915 - one fail-closed state boundary.
        self,
    ) -> tuple[int, dict[tuple[str, int], tuple[str, ...]], bool]:
        if self.state_path is None:
            if self._require_existing_state or self._minimum_request_count:
                raise ScopedHttpError("remote HTTP resume state path is required")
            return 0, {}, False
        try:
            descriptor = os.open(
                self.state_path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            if self._require_existing_state or self._minimum_request_count:
                raise ScopedHttpError(
                    "remote HTTP resume state is missing; refusing to reset request limits"
                ) from None
            return 0, {}, False
        except OSError as exc:
            raise ScopedHttpError(f"cannot read remote HTTP state: {exc}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ScopedHttpError("remote HTTP state must be one regular file")
            if metadata.st_mode & 0o077:
                raise ScopedHttpError("remote HTTP state permissions must be owner-only")
            if metadata.st_size > _MAX_HTTP_STATE_BYTES:
                raise ScopedHttpError("remote HTTP state exceeds the size limit")
            raw = _read_http_state(descriptor)
            current = self.state_path.stat(follow_symlinks=False)
            if current.st_dev != metadata.st_dev or current.st_ino != metadata.st_ino:
                raise ScopedHttpError("remote HTTP state changed during inspection")
        except OSError as exc:
            raise ScopedHttpError(f"cannot read remote HTTP state: {exc}") from exc
        finally:
            os.close(descriptor)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ScopedHttpError("remote HTTP state is not valid JSON") from exc
        if not isinstance(payload, Mapping):
            raise ScopedHttpError("remote HTTP state must be an object")
        if payload.get("version") != _HTTP_STATE_VERSION:
            raise ScopedHttpError("remote HTTP state version is unsupported")
        if payload.get("target_identity") != self._target_identity:
            raise ScopedHttpError("remote HTTP state target does not match")
        if payload.get("profile") != self.profile.to_json():
            raise ScopedHttpError("remote HTTP state profile does not match")
        raw_count = payload.get("request_count")
        if isinstance(raw_count, bool) or not isinstance(raw_count, int):
            raise ScopedHttpError("remote HTTP state request count is invalid")
        pins: dict[tuple[str, int], tuple[str, ...]] = {}
        raw_pins = payload.get("dns_pins", [])
        if not isinstance(raw_pins, list):
            raise ScopedHttpError("remote HTTP state DNS pins are invalid")
        for item in raw_pins:
            if not isinstance(item, Mapping):
                raise ScopedHttpError("remote HTTP state DNS pin is invalid")
            host = str(item.get("host") or "").strip().lower()
            port = item.get("port")
            addresses = item.get("addresses")
            if (
                not host
                or isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= _MAX_NETWORK_PORT
                or not isinstance(addresses, list)
                or not addresses
                or not all(isinstance(value, str) and value for value in addresses)
            ):
                raise ScopedHttpError("remote HTTP state DNS pin is invalid")
            key = (host, port)
            if key in pins:
                raise ScopedHttpError("remote HTTP state DNS pin is duplicated")
            pins[key] = tuple(sorted(set(addresses)))
        raw_session_dirty = payload.get("session_dirty", False)
        if not isinstance(raw_session_dirty, bool):
            raise ScopedHttpError("remote HTTP state session marker is invalid")
        return raw_count, pins, raw_session_dirty

    def _persist_state(self, request_count: int) -> None:
        if self.state_path is None:
            return
        with self._pin_lock:
            pins = [
                {
                    "host": host,
                    "port": port,
                    "addresses": list(addresses),
                }
                for (host, port), addresses in sorted(self._pins.items())
            ]
        payload = {
            "version": _HTTP_STATE_VERSION,
            "target_identity": self._target_identity,
            "profile": self.profile.to_json(),
            "request_count": request_count,
            "dns_pins": pins,
            "session_dirty": self._session_dirty,
        }
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
        if len(encoded) > _MAX_HTTP_STATE_BYTES:
            raise ScopedHttpError("remote HTTP state exceeds the size limit")
        parent = self.state_path.parent
        if parent.is_symlink():
            raise ScopedHttpError("remote HTTP state directory cannot be a symlink")
        parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(
            f".{self.state_path.name}.{os.getpid()}.{uuid4().hex}.tmp"
        )
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                _PRIVATE_FILE_MODE,
            )
            _write_http_state(descriptor, encoded)
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            temporary.replace(self.state_path)
            self.state_path.chmod(_PRIVATE_FILE_MODE)
        except OSError as exc:
            raise ScopedHttpError(f"cannot persist remote HTTP state: {exc}") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                temporary.unlink()


def _read_http_state(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = _MAX_HTTP_STATE_BYTES + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(_HTTP_STATE_READ_CHUNK_BYTES, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > _MAX_HTTP_STATE_BYTES:
        raise ScopedHttpError("remote HTTP state exceeds the size limit")
    return raw


def _write_http_state(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write while persisting remote HTTP state")
        offset += written


def _target_identity(target_url: str) -> str:
    digest = hashlib.sha256(target_url.strip().encode()).hexdigest()
    return f"target:{digest}"


def _request_authored_proofs(
    arguments: Mapping[str, object],
) -> frozenset[str] | None:
    """Return proof-shaped tokens supplied by the caller, including URL encoding."""
    texts: list[str] = []
    for key in ("url", "path", "body"):
        value = arguments.get(key)
        if value is not None:
            texts.append(str(value))
    for key in ("form", "json"):
        value = arguments.get(key)
        if value is not None:
            texts.append(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str))
    headers = arguments.get("headers")
    if isinstance(headers, Mapping):
        for name, value in headers.items():
            texts.extend((str(name), str(value)))

    proofs: set[str] = set()
    for text in texts:
        decoded = text
        for _index in range(_MAX_PROOF_CANONICALIZATION_PASSES):
            proofs.update(recognize_proofs(decoded))
            unquoted = unquote_plus(decoded)
            if unquoted == decoded:
                break
            decoded = unquoted
        else:
            # If canonicalization cannot reach a stable form within the work
            # bound, fail closed by disabling automatic proof capture.
            return None
    return frozenset(proofs)


def _request_from_arguments(
    arguments: Mapping[str, object],
    *,
    target_url: str,
    stable_user_agent: str,
    managed_authentication: bool = False,
) -> tuple[str, str, dict[str, str], bytes | None, float]:
    method = str(arguments.get("method") or "GET").strip().upper()
    if method not in _ALLOWED_METHODS:
        raise ScopedHttpError(f"remote HTTP method is not allowed: {method}")
    raw_url = str(arguments.get("url") or arguments.get("path") or "").strip()
    if not raw_url:
        raise ScopedHttpError("http_request requires url or path")
    url = _canonical_url(urljoin(target_url, raw_url))
    headers = _request_headers(
        arguments.get("headers"),
        stable_user_agent=stable_user_agent,
        managed_authentication=managed_authentication,
    )
    body = _request_body(arguments, headers=headers)
    if method in {"GET", "HEAD", "OPTIONS"} and body is not None:
        raise ScopedHttpError(f"{method} http_request cannot include a body")
    timeout_raw = arguments.get("timeout_seconds", 10)
    if isinstance(timeout_raw, bool) or not isinstance(timeout_raw, (int, float)):
        raise ScopedHttpError("http_request timeout_seconds must be a number")
    timeout = float(timeout_raw)
    if not 0 < timeout <= _MAX_TIMEOUT_SECONDS:
        raise ScopedHttpError("http_request timeout_seconds must be between 0 and 30")
    return method, url, headers, body, timeout


def _request_headers(  # noqa: C901 - validates each header trust boundary.
    value: object,
    *,
    stable_user_agent: str,
    managed_authentication: bool = False,
) -> dict[str, str]:
    if value is None:
        raw_headers: Mapping[object, object] = {}
    elif isinstance(value, Mapping):
        raw_headers = value
    else:
        raise ScopedHttpError("http_request headers must be an object")
    headers: dict[str, str] = {
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "User-Agent": stable_user_agent,
    }
    seen_names: set[str] = set()
    for raw_name, raw_value in raw_headers.items():
        name = str(raw_name)
        if _REQUEST_HEADER_NAME_RE.fullmatch(name) is None:
            raise ScopedHttpError("http_request header name is invalid")
        lowered = name.lower()
        if lowered in seen_names:
            raise ScopedHttpError(f"http_request header is duplicated: {name}")
        seen_names.add(lowered)
        if lowered in _BLOCKED_REQUEST_HEADERS:
            raise ScopedHttpError(f"http_request header is blocked: {name}")
        if managed_authentication and lowered in _MANAGED_AUTH_HEADERS:
            raise ScopedHttpError(
                f"http_request cannot override managed authentication header: {name}"
            )
        if lowered == "user-agent" and str(raw_value) != stable_user_agent:
            raise ScopedHttpError("http_request cannot rotate the stable User-Agent")
        rendered = str(raw_value)
        if "\n" in rendered or "\r" in rendered:
            raise ScopedHttpError(f"http_request header value is invalid: {name}")
        for existing_name in tuple(headers):
            if existing_name.casefold() == lowered:
                headers.pop(existing_name)
        headers[name] = rendered
    return headers


def _request_body(
    arguments: Mapping[str, object],
    *,
    headers: dict[str, str],
) -> bytes | None:
    present = [
        key
        for key in ("body", "json", "form")
        if key in arguments and arguments.get(key) is not None
    ]
    if len(present) > 1:
        raise ScopedHttpError("http_request accepts only one of body, json, or form")
    if not present:
        return None
    kind = present[0]
    value = arguments[kind]
    if kind == "body":
        if not isinstance(value, str):
            raise ScopedHttpError("http_request body must be a string")
        encoded = value.encode()
    elif kind == "json":
        if not isinstance(value, (Mapping, list)):
            raise ScopedHttpError("http_request json must be an object or list")
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
        _set_default_header(headers, "Content-Type", "application/json")
    else:
        if not isinstance(value, Mapping):
            raise ScopedHttpError("http_request form must be an object")
        fields = {
            str(key): str(item)
            for key, item in value.items()
            if isinstance(item, (str, int, float, bool))
        }
        if len(fields) != len(value):
            raise ScopedHttpError("http_request form values must be scalar")
        encoded = urlencode(fields).encode()
        _set_default_header(
            headers,
            "Content-Type",
            "application/x-www-form-urlencoded",
        )
    if len(encoded) > _MAX_REQUEST_BODY_BYTES:
        raise ScopedHttpError("http_request body exceeds the byte limit")
    return encoded


def _set_default_header(headers: dict[str, str], name: str, value: str) -> None:
    if any(existing.casefold() == name.casefold() for existing in headers):
        return
    headers[name] = value


def _request_receipt(
    *,
    sequence: int | None,
    redirect_index: int,
    attempt_index: int = 0,
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    delay_seconds: float,
    response: ScopedHttpTransportResponse,
    cache_hit: bool = False,
    traffic_policy_sequence: int | None = None,
) -> dict[str, object]:
    return {
        "sequence": sequence,
        "redirect_index": redirect_index,
        "attempt_index": attempt_index,
        "physical_request": not cache_hit,
        "cache_hit": cache_hit,
        "traffic_policy_sequence": traffic_policy_sequence,
        "method": method,
        "url": url,
        "request_header_names": sorted(headers),
        "request_body_bytes": len(body or b""),
        # A digest of a password, token, or short form value is an offline
        # verifier. Preserve size/shape only, matching the traffic contract.
        "request_body_sha256": "unavailable",
        "scheduled_delay_seconds": round(delay_seconds, 6),
        "status": response.status,
        "response_url": response.url,
        "response_bytes": len(response.body),
        "elapsed_ms": response.elapsed_ms,
        "error": response.error,
    }


def _transport_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
) -> ScopedHttpTransportRequest:
    return ScopedHttpTransportRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
        timeout_seconds=timeout,
    )


def _cached_transport_response(record: TrafficCacheRecord) -> ScopedHttpTransportResponse:
    return ScopedHttpTransportResponse(
        status=record.status,
        url=record.final_url,
        headers=dict(record.headers),
        body=(
            record.body_bytes
            if record.body_bytes is not None
            else record.body.encode("utf-8")
        ),
        elapsed_ms=0,
        truncated=record.truncated,
    )


def _transport_error_response(
    url: str,
    error: OSError | URLError | TimeoutError,
) -> ScopedHttpTransportResponse:
    return ScopedHttpTransportResponse(
        status=None,
        url=url,
        headers={},
        body=b"",
        elapsed_ms=0,
        error=f"{type(error).__name__}:{error}",
    )


def _traffic_outcome(response: ScopedHttpTransportResponse) -> TrafficOutcome:
    return TrafficOutcome(
        status=response.status,
        headers=response.headers,
        transport_error=response.status is None or bool(response.error),
        cache_record=(
            TrafficCacheRecord(
                status=response.status,
                final_url=response.url,
                headers=dict(response.headers),
                body=_decode_body(response.body, response.headers),
                body_bytes=response.body,
                truncated=response.truncated,
            )
            if response.status is not None
            else None
        ),
    )


def _canonical_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ScopedHttpError("http_request URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ScopedHttpError("http_request URL cannot contain userinfo")
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if parsed.hostname is None:
        raise ScopedHttpError("http_request URL has no host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def _redirect_method_and_body(
    *,
    status: int,
    method: str,
    body: bytes | None,
) -> tuple[str, bytes | None]:
    if status == _SEE_OTHER_STATUS or (
        status in _LEGACY_POST_REDIRECT_STATUSES and method == "POST"
    ):
        return "GET", None
    return method, body


def _header(headers: Mapping[str, str], name: str) -> str:
    lowered = name.lower()
    return next(
        (str(value).strip() for key, value in headers.items() if str(key).lower() == lowered),
        "",
    )


def _observation_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        str(name): (
            "[REDACTED]"
            if str(name).lower() in _SENSITIVE_RESPONSE_HEADERS
            else sanitize_url(value)
            if str(name).lower() == "location"
            else redact_traffic_text(value, max_chars=1_024)
        )
        for name, value in headers.items()
    }


def _decode_body(body: bytes, headers: Mapping[str, str]) -> str:
    content_type = _header(headers, "content-type")
    charset = "utf-8"
    for part in content_type.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value.strip():
            charset = value.strip().strip("\"'")
            break
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _resolve_addresses(host: str, port: int) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(item[4][0])
                for item in socket.getaddrinfo(
                    host,
                    port,
                    type=socket.SOCK_STREAM,
                )
            }
        )
    )


def _optional_path(value: Path | None) -> Path | None:
    if value is None:
        return None
    from pathlib import Path  # noqa: PLC0415

    return Path(value)


__all__ = [
    "ManagedAuthenticationScopedHttpTransport",
    "ManagedGraphAuthentication",
    "ScopedGraphHttpExecutor",
    "ScopedHttpError",
    "ScopedHttpTransport",
    "ScopedHttpTransportRequest",
    "ScopedHttpTransportResponse",
    "UrllibScopedHttpTransport",
]
