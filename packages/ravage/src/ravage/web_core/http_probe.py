from __future__ import annotations

import errno
import hashlib
import ipaddress
import math
import re
import socket
import ssl
import sys
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from copy import copy
from dataclasses import dataclass, field
from http.client import (
    HTTPConnection,
    HTTPException,
    HTTPResponse,
    HTTPSConnection,
    IncompleteRead,
)
from http.cookiejar import CookieJar
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import SplitResult, parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from ravage.runtime.common import assert_tool_target_url, clip
from ravage.traffic.policy import (
    RequestIntent,
    TrafficCacheRecord,
    TrafficDecisionKind,
    TrafficOutcome,
    TrafficPolicyBlocked,
    TrafficPolicyController,
)
from ravage.web_core.proof_recognizer import decoded_braced_fragments, recognize_proofs
from ravage.web_core.scope_policy import same_origin, url_in_scope_entries

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence
    from http.client import HTTPMessage
    from typing import IO

MAX_BODY_BYTES = 600_000
MAX_TIMEOUT_SECONDS = 60
MAX_CONTROLLED_BODY_BYTES = 32_000_000
MAX_REQUEST_BODY_BYTES = 32_000_000
DEFAULT_USER_AGENT = "ravage-probe/1.0"
_HTTP_PROTOCOL_ERROR = "HTTP protocol error"
_IPV6_VERSION = 6
_HTTP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_SENSITIVE_SUMMARY_HEADERS = frozenset(
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
        _ = req, fp, code, msg, headers, newurl
        return None


class _PinnedHTTPConnection(HTTPConnection):
    """HTTP connection whose TCP peer is chosen from a resolver-approved pin."""

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


class _PinnedHTTPSConnection(HTTPSConnection):
    """HTTPS connection pinned at TCP while retaining the URL host for TLS."""

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
        self.sock = self._tls_context.wrap_socket(self.sock, server_hostname=self.host)


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
    """Connect directly to numeric pins without performing another DNS lookup."""
    last_error: OSError | None = None
    for address in addresses:
        try:
            parsed = _validated_connection_address(address)
        except ValueError as exc:
            message = "probe resolver returned a non-IP address"
            raise OSError(message) from exc
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
                # Match HTTPConnection.connect on platforms that do not expose
                # TCP_NODELAY for this socket family.
                if exc.errno != errno.ENOPROTOOPT:
                    raise
        except OSError as exc:
            last_error = exc
            sock.close()
        else:
            return sock
    if last_error is not None:
        raise last_error
    message = "probe resolver returned no addresses"
    raise OSError(message)


def _validated_connection_address(
    address: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    parsed = ipaddress.ip_address(address)
    effective = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
    if (effective or parsed).is_unspecified:
        message = "probe resolver returned an unspecified address"
        raise ValueError(message)
    return parsed


class _RequestPacer:
    def __init__(self, max_rps: float | None) -> None:
        normalized_rate: float | None = None
        if max_rps is not None:
            if isinstance(max_rps, bool) or not isinstance(max_rps, (int, float)):
                raise ValueError("max_rps must be a finite positive number")
            try:
                normalized_rate = float(max_rps)
            except (OverflowError, ValueError) as exc:
                raise ValueError("max_rps must be a finite positive number") from exc
            if not math.isfinite(normalized_rate) or normalized_rate <= 0:
                raise ValueError("max_rps must be a finite positive number")
        minimum_interval = 0.0 if normalized_rate is None else 1.0 / normalized_rate
        if not math.isfinite(minimum_interval):
            raise ValueError("max_rps must yield a finite pacing interval")
        self.minimum_interval = minimum_interval
        self._last_started = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.minimum_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delay = self.minimum_interval - (now - self._last_started)
            if delay > 0:
                time.sleep(delay)
            self._last_started = time.monotonic()


class _SharedPhysicalRequestCounter:
    """Thread-safe count of transport dispatches shared by session forks."""

    def __init__(self) -> None:
        self._value = 0
        self._lock = threading.Lock()

    def increment(self) -> int:
        with self._lock:
            self._value += 1
            return self._value

    def snapshot(self) -> int:
        with self._lock:
            return self._value


def _prepare_request_gate(
    gate: Callable[[str, str], object] | None,
    method: str,
    url: str,
) -> Callable[[], None] | None:
    """Run gate preflight and return its optional post-dispatch commit."""
    if gate is None:
        return None
    commit = gate(method, url)
    if commit is None:
        return None
    if not callable(commit):
        raise TypeError("request gate must return a callable dispatch commit or None")
    return cast("Callable[[], None]", commit)


def _note_cleanup_failure(
    primary: BaseException,
    message: str,
    cleanup_error: BaseException,
) -> None:
    with suppress(BaseException):
        primary.add_note(f"{message}: {type(cleanup_error).__name__}")


def _cancel_policy_lease_preserving(
    policy: TrafficPolicyController,
    lease: Any,
    primary: BaseException,
    *,
    message: str,
) -> None:
    try:
        policy.cancel(lease)
    except BaseException as cleanup_error:
        _note_cleanup_failure(primary, message, cleanup_error)


def _complete_policy_lease_preserving(
    policy: TrafficPolicyController,
    lease: Any,
    outcome: TrafficOutcome,
    primary: BaseException,
    *,
    message: str,
) -> None:
    try:
        policy.complete(lease, outcome)
    except BaseException as cleanup_error:
        _note_cleanup_failure(primary, message, cleanup_error)


def _commit_request_gate_preserving(
    commit: Callable[[], None] | None,
    primary: BaseException,
    *,
    message: str,
) -> None:
    if commit is None:
        return
    try:
        commit()
    except BaseException as cleanup_error:
        _note_cleanup_failure(primary, message, cleanup_error)


@dataclass(frozen=True)
class ControlledTransportRequest:
    """Fully preflighted context for one non-urllib HTTP exchange."""

    method: str
    url: str
    host: str
    port: int
    pins: tuple[str, ...]
    headers: Mapping[str, str]
    timeout_seconds: float


@dataclass(frozen=True)
class ControlledTransportResult:
    """Raw response bytes paired with the exchange's real policy outcome."""

    response_bytes: bytes
    outcome: TrafficOutcome


@dataclass(frozen=True, init=False)
class ProbeResponse:
    method: str
    url: str
    status: int | None
    final_url: str
    elapsed_ms: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_bytes: bytes = b""
    error: str = ""
    truncated: bool = False

    def __init__(  # noqa: PLR0913
        self,
        method: str,
        url: str,
        status: int | None,
        final_url: str,
        elapsed_ms: int,
        headers: dict[str, str] | None = None,
        body: str = "",
        error: str = "",
        *,
        body_bytes: bytes | None = None,
        truncated: bool = False,
    ) -> None:
        if body_bytes is not None and not isinstance(body_bytes, bytes):
            raise TypeError("body_bytes must be bytes")
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "final_url", final_url)
        object.__setattr__(self, "elapsed_ms", elapsed_ms)
        object.__setattr__(self, "headers", headers or {})
        object.__setattr__(self, "body", body)
        object.__setattr__(
            self,
            "body_bytes",
            body.encode("utf-8") if body_bytes is None else body_bytes,
        )
        object.__setattr__(self, "error", error)
        object.__setattr__(self, "truncated", truncated)

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 400

    def summary(self, *, body_chars: int = 500) -> dict[str, object]:
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "final_url": self.final_url,
            "elapsed_ms": self.elapsed_ms,
            "headers": _summary_headers(self.headers),
            "body_len": len(self.body),
            "body_sha_hint": hashlib.sha256(
                self.body[:20_000].encode("utf-8", errors="replace")
            ).hexdigest()[:16],
            "body_snippet": clip(self.body, body_chars),
            "truncated": self.truncated,
            "error": self.error,
        }


def _summary_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: "[REDACTED]" if name.lower() in _SENSITIVE_SUMMARY_HEADERS else value
        for name, value in headers.items()
    }


@dataclass(frozen=True)
class ResponseDelta:
    status_changed: bool
    length_delta: int
    elapsed_delta_ms: int
    marker_reflected: bool
    new_error_markers: list[str]
    interesting_markers: list[str]

    def to_json(self) -> dict[str, object]:
        return {
            "status_changed": self.status_changed,
            "length_delta": self.length_delta,
            "elapsed_delta_ms": self.elapsed_delta_ms,
            "marker_reflected": self.marker_reflected,
            "new_error_markers": list(self.new_error_markers),
            "interesting_markers": list(self.interesting_markers),
        }


class ProbeSession:
    def __init__(  # noqa: PLR0913
        self,
        target_url: str,
        *,
        timeout_seconds: int = 10,
        default_headers: dict[str, str] | None = None,
        allow_remote_target: bool = False,
        in_scope: Sequence[str] | None = None,
        out_of_scope: Sequence[str] = (),
        max_rps: float | None = None,
        resolver: Callable[[str, int], Sequence[str]] | None = None,
        _request_pacer: _RequestPacer | None = None,
        _physical_request_counter: _SharedPhysicalRequestCounter | None = None,
        _dns_pins: dict[tuple[str, int], tuple[str, ...]] | None = None,
        _dns_pin_lock: threading.Lock | None = None,
        traffic_observer: Callable[[dict[str, object]], None] | None = None,
        traffic_policy: TrafficPolicyController | None = None,
        traffic_policy_reference: dict[str, object] | None = None,
        traffic_lane: str = "probe",
        traffic_cacheable: bool = False,
        traffic_retryable: bool = False,
        traffic_timing_sensitive: bool = False,
        max_body_bytes: int = MAX_BODY_BYTES,
    ) -> None:
        parsed = assert_tool_target_url(
            target_url,
            allow_remote_target=allow_remote_target,
        )
        self.target_url = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")
        )
        self.origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        self.timeout_seconds = max(1, min(timeout_seconds, 60))
        self.allow_remote_target = allow_remote_target
        self.scope_in_scope = tuple(str(item) for item in (in_scope or ()))
        self.scope_out_of_scope = tuple(str(item) for item in out_of_scope)
        if self.scope_in_scope and not url_in_scope_entries(
            self.target_url,
            in_scope=self.scope_in_scope,
            out_of_scope=self.scope_out_of_scope,
        ):
            raise ValueError("probe target URL must be listed in engagement scope")
        self.max_rps = max_rps
        self._request_pacer = _request_pacer or _RequestPacer(max_rps)
        self._physical_request_counter = (
            _physical_request_counter or _SharedPhysicalRequestCounter()
        )
        self._resolver = resolver or _resolve_addresses
        self._dns_pins = _dns_pins if _dns_pins is not None else {}
        self._dns_pin_lock = _dns_pin_lock or threading.Lock()
        self._traffic_observer = traffic_observer
        if traffic_policy is not None and traffic_policy_reference is not None:
            raise ValueError("traffic_policy and traffic_policy_reference are mutually exclusive")
        self._traffic_policy = traffic_policy
        if traffic_policy_reference is not None:
            self._traffic_policy = TrafficPolicyController.from_reference(
                traffic_policy_reference,
                require_existing=True,
            )
        self._traffic_lane = str(traffic_lane).strip() or "probe"
        self._traffic_cacheable = bool(traffic_cacheable)
        self._traffic_retryable = bool(traffic_retryable)
        self._traffic_timing_sensitive = bool(traffic_timing_sensitive)
        self.max_body_bytes = _validated_body_limit(max_body_bytes)
        # Ordinary probe sessions deliberately fork without cookies. A managed
        # authenticated owner opts its live identity into inheritance so
        # internal isolation does not silently downgrade form-cookie probes.
        self._fork_inherits_managed_identity = False
        self._managed_identity_header_names: frozenset[str] = frozenset()
        self._managed_request_delegate: Callable[..., ProbeResponse] | None = None
        self._managed_identity_generation: int | None = None
        self._managed_identity_lease: object | None = None
        self._managed_session_observer: (
            Callable[[object, ProbeSession, ProbeSession | None], None] | None
        ) = None
        self._request_gate: Callable[[str, str], object] | None = None
        self._traffic_identity_alias_override: str | None = None
        # Applied to every request (e.g. a confirmed canonical Host header) so a
        # host-sensitive app serves canonical content for all probes, not just the
        # one that discovered the redirect. Per-call headers still override these.
        self.default_headers = dict(default_headers or {})
        self.cookies = CookieJar()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPCookieProcessor(self.cookies),
            _PinnedHTTPHandler(self._pinned_addresses_for_connection),
            _PinnedHTTPSHandler(self._pinned_addresses_for_connection),
            _NoRedirectHandler(),
        )

    def configure_managed_identity_forks(self, *, header_names: Iterable[str]) -> None:
        """Make ordinary forks inherit this managed identity's headers and cookies.

        Credential values remain in the session. Only normalized header names are
        retained as policy metadata so explicitly anonymous differential forks can
        remove the managed identity without discarding a canonical Host header.
        """
        self._managed_identity_header_names = frozenset(
            str(name).strip().casefold() for name in header_names if str(name).strip()
        )
        self._fork_inherits_managed_identity = True

    def configure_request_gate(
        self,
        gate: Callable[[str, str], object] | None,
    ) -> None:
        """Install owner preflight with an optional post-dispatch accounting commit."""
        self._request_gate = gate

    def bind_managed_request_delegate(
        self,
        delegate: Callable[..., ProbeResponse],
        *,
        generation: int,
        lease: object,
        session_observer: Callable[[object, ProbeSession, ProbeSession | None], None],
        source_session: ProbeSession | None = None,
    ) -> None:
        """Route this session and ordinary descendants through a managed owner."""
        self._managed_request_delegate = delegate
        self._managed_identity_generation = generation
        self._managed_identity_lease = lease
        self._managed_session_observer = session_observer
        session_observer(lease, self, source_session)

    @property
    def physical_request_count(self) -> int:
        """Physical transport attempts made by this session and its forks."""
        return self._physical_request_counter.snapshot()

    @property
    def traffic_policy(self) -> TrafficPolicyController | None:
        return self._traffic_policy

    def traffic_policy_reference(self) -> dict[str, object] | None:
        if self._traffic_policy is None:
            return None
        return self._traffic_policy.to_reference()

    @property
    def managed_identity_generation(self) -> int | None:
        return self._managed_identity_generation

    @property
    def managed_identity_lease(self) -> object | None:
        return self._managed_identity_lease

    def update_managed_identity_generation(self, generation: int) -> None:
        if self._managed_request_delegate is None:
            raise RuntimeError("cannot update an unbound managed probe session")
        self._managed_identity_generation = generation

    def unbind_managed_request_delegate(self) -> None:
        self._managed_request_delegate = None
        self._managed_identity_generation = None
        self._managed_identity_lease = None
        self._managed_session_observer = None

    def fork(
        self,
        *,
        timeout_seconds: int | None = None,
        inherit_identity: bool | None = None,
        max_body_bytes: int | None = None,
    ) -> ProbeSession:
        """Create an isolated session with an explicit managed-identity policy.

        Unmanaged sessions preserve the historical behavior: default headers are
        copied and cookies are not. A managed owner enables identity inheritance;
        callers performing an intentional auth differential can pass
        ``inherit_identity=False`` to remove managed headers and cookies.
        """
        copy_identity = (
            self._fork_inherits_managed_identity if inherit_identity is None else inherit_identity
        )
        default_headers = dict(self.default_headers)
        if not copy_identity and self._managed_identity_header_names:
            default_headers = {
                name: value
                for name, value in default_headers.items()
                if name.casefold() not in self._managed_identity_header_names
            }
        forked = ProbeSession(
            self.target_url,
            timeout_seconds=self.timeout_seconds if timeout_seconds is None else timeout_seconds,
            default_headers=default_headers,
            allow_remote_target=self.allow_remote_target,
            in_scope=self.scope_in_scope,
            out_of_scope=self.scope_out_of_scope,
            max_rps=self.max_rps,
            resolver=self._resolver,
            _request_pacer=self._request_pacer,
            _physical_request_counter=self._physical_request_counter,
            _dns_pins=self._dns_pins,
            _dns_pin_lock=self._dns_pin_lock,
            traffic_observer=self._traffic_observer,
            traffic_policy=self._traffic_policy,
            traffic_lane=self._traffic_lane,
            traffic_cacheable=self._traffic_cacheable,
            traffic_retryable=self._traffic_retryable,
            traffic_timing_sensitive=self._traffic_timing_sensitive,
            max_body_bytes=self.max_body_bytes if max_body_bytes is None else max_body_bytes,
        )
        forked._fork_inherits_managed_identity = self._fork_inherits_managed_identity
        forked._managed_identity_header_names = self._managed_identity_header_names
        forked._request_gate = self._request_gate
        forked._traffic_identity_alias_override = self._traffic_identity_alias_override
        if not copy_identity and self._managed_identity_header_names:
            forked._traffic_identity_alias_override = ""
        if copy_identity:
            for cookie in self.cookies:
                forked.cookies.set_cookie(copy(cookie))
            if self._managed_request_delegate is not None:
                generation = self._managed_identity_generation
                lease = self._managed_identity_lease
                observer = self._managed_session_observer
                if generation is None or lease is None or observer is None:
                    raise RuntimeError("managed probe session is missing its identity generation")
                forked.bind_managed_request_delegate(
                    self._managed_request_delegate,
                    generation=generation,
                    lease=lease,
                    session_observer=observer,
                    source_session=self,
                )
        return forked

    def absolute(self, value: str) -> str:
        return urljoin(self.target_url, value)

    def in_scope(self, url: str) -> bool:
        try:
            absolute = self.absolute(url)
            if not same_origin(self.target_url, absolute):
                return False
            if not self.scope_in_scope:
                return True
            return url_in_scope_entries(
                absolute,
                in_scope=self.scope_in_scope,
                out_of_scope=self.scope_out_of_scope,
            )
        except ValueError:
            return False

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> ProbeResponse:
        return self.request("GET", url, headers=headers)

    def get_bytes(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int = MAX_BODY_BYTES,
    ) -> bytes:
        """Return exact bounded response bytes for a clean 2xx request."""
        if self._managed_request_delegate is not None:
            raise RuntimeError("managed binary downloads require an owner-controlled adapter")
        response = self._request_direct(
            "GET",
            url,
            headers=headers,
            max_body_bytes=max_bytes,
        )
        if response.error or response.status is None or not 200 <= response.status < 300:
            return b""
        return response.body_bytes

    def run_external_transport(  # noqa: PLR0913
        self,
        method: str,
        url: str,
        transport: Callable[[ControlledTransportRequest], ControlledTransportResult],
        *,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
        lane: str = "external_http",
        retryable: bool = False,
        timing_sensitive: bool = False,
    ) -> ControlledTransportResult:
        """Run a pinned non-urllib exchange through the shared policy boundary.

        The callback receives only preflighted HTTP context, including numeric
        resolver pins, and must perform exactly one physical exchange without DNS.
        """
        normalized_method = _validated_http_method(method)
        rewritten_url = self._rewrite_canonical_url(url)
        parsed = urlsplit(self.absolute(rewritten_url))
        absolute_url = urlunsplit(
            (parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, "")
        )
        if not self.in_scope(absolute_url):
            raise TrafficPolicyBlocked("URL is outside target origin")
        if parsed.username is not None or parsed.password is not None or not parsed.hostname:
            raise TrafficPolicyBlocked("external transport URL has an invalid host")
        try:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError as exc:
            raise TrafficPolicyBlocked("external transport URL has an invalid port") from exc
        request_timeout = _validated_timeout(
            self.timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        request_headers = _controlled_transport_headers(
            parsed,
            default_headers=self.default_headers,
            headers=headers,
        )
        dns_error = self._dns_scope_error(absolute_url)
        if dns_error:
            raise TrafficPolicyBlocked(dns_error)
        pins = self._pinned_addresses_for_connection(parsed.hostname, port)
        context = ControlledTransportRequest(
            method=normalized_method,
            url=absolute_url,
            host=parsed.hostname,
            port=port,
            pins=pins,
            headers=MappingProxyType(request_headers),
            timeout_seconds=request_timeout,
        )
        identity_alias = self._traffic_identity_alias_override
        if identity_alias is None:
            identity_alias = (
                "managed" if self._managed_request_delegate is not None else "anonymous"
            )
        intent = RequestIntent(
            method=normalized_method,
            url=absolute_url,
            headers=request_headers,
            lane=lane,
            identity_alias=identity_alias or "anonymous",
            identity_generation=self._managed_identity_generation or 0,
            retryable=retryable,
            timing_sensitive=timing_sensitive,
        )
        policy = self._traffic_policy
        attempt = 0
        while True:
            lease = None
            gate_commit: Callable[[], None] | None = None
            if policy is not None:
                decision = policy.acquire(intent, retry=attempt > 0)
                if decision.kind is TrafficDecisionKind.BLOCKED:
                    raise TrafficPolicyBlocked(decision.reason)
                if decision.kind is not TrafficDecisionKind.DISPATCH or decision.lease is None:
                    raise TrafficPolicyBlocked(
                        "external transport did not receive a dispatch lease"
                    )
                lease = decision.lease
            try:
                self._request_pacer.wait()
                gate_commit = _prepare_request_gate(
                    self._request_gate,
                    normalized_method,
                    absolute_url,
                )
            except BaseException as exc:
                if policy is not None and lease is not None:
                    _cancel_policy_lease_preserving(
                        policy,
                        lease,
                        exc,
                        message="traffic policy could not cancel external transport reservation",
                    )
                raise
            if policy is not None and lease is not None:
                try:
                    policy.begin_dispatch(lease)
                except BaseException as exc:
                    _cancel_policy_lease_preserving(
                        policy,
                        lease,
                        exc,
                        message="traffic policy could not cancel failed external dispatch",
                    )
                    raise
            self._physical_request_counter.increment()
            try:
                result = transport(context)
                _validate_controlled_transport_result(result)
            except BaseException as exc:
                if policy is not None and lease is not None:
                    _complete_policy_lease_preserving(
                        policy,
                        lease,
                        TrafficOutcome(status=None, transport_error=True),
                        exc,
                        message="traffic policy could not persist external transport failure",
                    )
                _commit_request_gate_preserving(
                    gate_commit,
                    exc,
                    message="request gate could not record external dispatch",
                )
                raise
            if policy is not None and lease is not None:
                try:
                    policy.complete(lease, result.outcome)
                except BaseException as exc:
                    _commit_request_gate_preserving(
                        gate_commit,
                        exc,
                        message="request gate could not record external dispatch",
                    )
                    raise
            if gate_commit is not None:
                gate_commit()
            if policy is None or not policy.should_retry(intent, result.outcome, attempt):
                return result
            attempt += 1

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        encoded = urlencode(fields).encode("utf-8")
        merged = {"Content-Type": "application/x-www-form-urlencoded"}
        if headers:
            merged.update(headers)
        return self.request("POST", url, data=encoded, headers=merged)

    def _rewrite_canonical_url(self, url: str) -> str:
        """Rewrite an absolute link pointing at the canonical Host back to the real
        target host:port, so a host-sensitive app's absolute links (e.g.
        ``http://localhost/wp-json/``) reach the target instead of failing scope/port."""
        host = self.default_headers.get("Host") or self.default_headers.get("host")
        if not host:
            return url
        parsed = urlsplit(url)
        if not parsed.hostname:
            return url
        canonical = host.split(":")[0].strip("[]").lower()
        if parsed.hostname.strip("[]").lower() != canonical:
            return url
        target = urlsplit(self.target_url)
        return urlunsplit((target.scheme, target.netloc, parsed.path or "/", parsed.query, ""))

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
        max_body_bytes: int | None = None,
    ) -> ProbeResponse:
        delegate = self._managed_request_delegate
        if delegate is not None:
            if max_body_bytes is not None:
                requested_limit = _validated_body_limit(max_body_bytes)
                if requested_limit != self.max_body_bytes:
                    raise RuntimeError(
                        "managed requests require the owner-controlled response body limit"
                    )
            return delegate(
                self,
                method,
                url,
                data=data,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
        if max_body_bytes is None:
            return self._request_direct(
                method,
                url,
                data=data,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
        return self._request_direct(
            method,
            url,
            data=data,
            headers=headers,
            timeout_seconds=timeout_seconds,
            max_body_bytes=max_body_bytes,
        )

    def _request_direct(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
        max_body_bytes: int | None = None,
    ) -> ProbeResponse:
        normalized_method = _validated_http_method(method)
        url = self._rewrite_canonical_url(url)
        absolute_url = self.absolute(url)
        if not self.in_scope(absolute_url):
            response = ProbeResponse(
                method=normalized_method,
                url=absolute_url,
                status=None,
                final_url=absolute_url,
                elapsed_ms=0,
                error="URL is outside target origin",
            )
            self._observe_traffic(response, disposition="blocked", reason=response.error)
            return response
        dns_error = self._dns_scope_error(absolute_url)
        if dns_error:
            response = ProbeResponse(
                method=normalized_method,
                url=absolute_url,
                status=None,
                final_url=absolute_url,
                elapsed_ms=0,
                error=dns_error,
            )
            self._observe_traffic(response, disposition="blocked", reason=response.error)
            return response
        request_headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "application/json;q=0.8,text/plain;q=0.7,*/*;q=0.1"
            ),
            "Accept-Encoding": "identity",
        }
        request_headers.update(self.default_headers)
        if headers:
            request_headers.update(headers)
        _validate_http_request_headers(request_headers)
        normalized_timeout = _validated_timeout(
            self.timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        response_body_limit = _validated_body_limit(
            self.max_body_bytes if max_body_bytes is None else max_body_bytes
        )
        identity_alias = self._traffic_identity_alias_override
        if identity_alias is None:
            identity_alias = (
                "managed" if self._managed_request_delegate is not None else "anonymous"
            )
        attempt = 0
        while True:
            intent = RequestIntent(
                method=normalized_method,
                url=absolute_url,
                headers=request_headers,
                body=data,
                lane=self._traffic_lane,
                identity_alias=identity_alias or "anonymous",
                identity_generation=self._managed_identity_generation or 0,
                cacheable=self._traffic_cacheable and not any(self.cookies),
                retryable=self._traffic_retryable,
                timing_sensitive=self._traffic_timing_sensitive,
            )
            lease = None
            policy = self._traffic_policy
            if policy is not None:
                try:
                    decision = policy.acquire(intent, retry=attempt > 0)
                except TrafficPolicyBlocked as exc:
                    return self._policy_blocked_response(
                        normalized_method,
                        absolute_url,
                        str(exc),
                    )
                if decision.kind is TrafficDecisionKind.BLOCKED:
                    return self._policy_blocked_response(
                        normalized_method,
                        absolute_url,
                        decision.reason,
                    )
                if decision.kind is TrafficDecisionKind.CACHE_HIT:
                    cached = decision.cached
                    if cached is None:
                        raise RuntimeError("traffic cache decision is missing its response")
                    result = ProbeResponse(
                        method=normalized_method,
                        url=absolute_url,
                        status=cached.status,
                        final_url=cached.final_url,
                        elapsed_ms=0,
                        headers=dict(cached.headers),
                        body=cached.body,
                        body_bytes=cached.body_bytes,
                        truncated=cached.truncated,
                    )
                    self._observe_traffic(result, disposition="cache_hit")
                    return result
                lease = decision.lease
                if lease is None:
                    raise RuntimeError("traffic dispatch decision is missing its lease")

            try:
                request = Request(
                    absolute_url,
                    data=data,
                    headers=request_headers,
                    method=normalized_method,
                )
                self._request_pacer.wait()
                gate_commit = _prepare_request_gate(
                    self._request_gate,
                    normalized_method,
                    absolute_url,
                )
            except BaseException as exc:
                if policy is not None and lease is not None:
                    _cancel_policy_lease_preserving(
                        policy,
                        lease,
                        exc,
                        message="traffic policy could not cancel request reservation",
                    )
                raise
            if policy is not None and lease is not None:
                try:
                    policy.begin_dispatch(lease)
                except TrafficPolicyBlocked as exc:
                    _cancel_policy_lease_preserving(
                        policy,
                        lease,
                        exc,
                        message="traffic policy could not cancel blocked dispatch",
                    )
                    return self._policy_blocked_response(
                        normalized_method,
                        absolute_url,
                        str(exc),
                    )
                except BaseException as exc:
                    _cancel_policy_lease_preserving(
                        policy,
                        lease,
                        exc,
                        message="traffic policy could not cancel failed dispatch",
                    )
                    raise

            started = time.monotonic()
            try:
                # This is the accounting boundary: every path below has entered
                # the physical transport, including HTTP, socket, and protocol
                # failures.
                self._physical_request_counter.increment()
                result = self._execute_transport_request(
                    request,
                    method=normalized_method,
                    absolute_url=absolute_url,
                    request_timeout=normalized_timeout,
                    started=started,
                    max_body_bytes=response_body_limit,
                )
            except BaseException as exc:
                if policy is not None and lease is not None:
                    _complete_policy_lease_preserving(
                        policy,
                        lease,
                        TrafficOutcome(status=None, transport_error=True),
                        exc,
                        message=(
                            "traffic policy could not persist unexpected dispatch completion"
                        ),
                    )
                _commit_request_gate_preserving(
                    gate_commit,
                    exc,
                    message="request gate could not record dispatch",
                )
                raise

            outcome = TrafficOutcome(
                status=result.status,
                headers=result.headers,
                transport_error=result.status is None or bool(result.error),
                cache_record=(
                    TrafficCacheRecord(
                        status=result.status,
                        final_url=result.final_url,
                        headers=dict(result.headers),
                        body=result.body,
                        body_bytes=result.body_bytes,
                        truncated=result.truncated,
                    )
                    if result.status is not None and not result.error
                    else None
                ),
            )
            if policy is not None and lease is not None:
                try:
                    policy.complete(lease, outcome)
                except BaseException as exc:
                    _commit_request_gate_preserving(
                        gate_commit,
                        exc,
                        message="request gate could not record dispatch",
                    )
                    raise
            if gate_commit is not None:
                gate_commit()
            self._observe_traffic(
                result,
                disposition="sent",
                reason="retry" if attempt else "",
                request_headers=_prepared_request_headers(request, request_headers),
                request_body=data,
            )
            if policy is None or not policy.should_retry(intent, outcome, attempt):
                return result
            attempt += 1

    def _execute_transport_request(
        self,
        request: Request,
        *,
        method: str,
        absolute_url: str,
        request_timeout: float,
        started: float,
        max_body_bytes: int,
    ) -> ProbeResponse:
        status: int | None = None
        final_url = absolute_url
        raw_headers: Any | None = None
        body = b""
        protocol_error = ""
        try:
            try:
                transport_response = self.opener.open(request, timeout=request_timeout)
            except HTTPError as exc:
                # An HTTP status error still has a response body worth preserving.
                transport_response = exc
            response_status = getattr(transport_response, "status", None)
            status = transport_response.getcode() if response_status is None else response_status
            final_url = transport_response.geturl()
            raw_headers = transport_response.headers
            body = transport_response.read(max_body_bytes + 1)
        except HTTPException as exc:
            # Exception text can include untrusted response bytes (for example a
            # malformed status line), so expose only a stable error label. An
            # IncompleteRead is the one protocol failure that safely carries the
            # response bytes already received.
            body = _incomplete_read_body(exc)
            protocol_error = _HTTP_PROTOCOL_ERROR
        except (OSError, URLError) as exc:
            return ProbeResponse(
                method=method,
                url=absolute_url,
                status=None,
                final_url=absolute_url,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                error=str(exc),
            )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        truncated = len(body) > max_body_bytes
        bounded_body = body[:max_body_bytes]
        response_headers = _headers(raw_headers) if raw_headers is not None else {}
        charset = (
            raw_headers.get_content_charset()
            if raw_headers is not None and hasattr(raw_headers, "get_content_charset")
            else None
        )
        return ProbeResponse(
            method=method,
            url=absolute_url,
            status=status,
            final_url=final_url,
            elapsed_ms=elapsed_ms,
            headers=response_headers,
            body=_decode_body(bounded_body, charset),
            body_bytes=bounded_body,
            error=protocol_error,
            truncated=truncated,
        )

    def _policy_blocked_response(
        self,
        method: str,
        absolute_url: str,
        reason: str,
    ) -> ProbeResponse:
        response = ProbeResponse(
            method=method,
            url=absolute_url,
            status=None,
            final_url=absolute_url,
            elapsed_ms=0,
            error=reason or "traffic policy blocked request",
        )
        self._observe_traffic(response, disposition="blocked", reason=response.error)
        return response

    def _observe_traffic(
        self,
        response: ProbeResponse,
        *,
        disposition: str,
        reason: str = "",
        request_headers: dict[str, str] | None = None,
        request_body: bytes | None = None,
    ) -> None:
        observer = self._traffic_observer
        if observer is None:
            return
        event: dict[str, object] = {
            "source": "probe_session",
            "disposition": disposition,
            "reason": reason,
            "method": response.method,
            "url": response.url,
            "response_status": response.status,
            "response_url": response.final_url,
            "response_headers": dict(response.headers),
            "response_body": response.body_bytes,
            "elapsed_ms": response.elapsed_ms,
            "error": response.error,
            "truncated": response.truncated,
        }
        if self._traffic_identity_alias_override is not None:
            event["identity_alias"] = self._traffic_identity_alias_override
        if disposition == "sent":
            event["request_headers"] = dict(request_headers or {})
            event["request_body"] = request_body
        with suppress(Exception):
            observer(event)

    def _dns_scope_error(self, url: str) -> str:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            resolved = self._resolver(host, port)
            parsed_addresses = tuple(
                _validated_connection_address(str(address).strip()) for address in resolved
            )
        except OSError as exc:
            return f"remote target DNS resolution failed: {exc}"
        except ValueError as exc:
            return f"remote target DNS resolution rejected an address: {exc}"
        addresses = tuple(sorted({str(address) for address in parsed_addresses}))
        if not addresses:
            return "remote target DNS resolution returned no addresses"
        key = (host.lower(), port)
        with self._dns_pin_lock:
            pinned = self._dns_pins.setdefault(key, addresses)
            if pinned != addresses:
                return "remote target DNS resolution changed after pinning"
        return ""

    def _pinned_addresses_for_connection(self, host: str, port: int) -> tuple[str, ...]:
        key = (host.lower(), port)
        with self._dns_pin_lock:
            addresses = self._dns_pins.get(key)
        if addresses is None:
            message = "probe connection attempted before DNS pinning"
            raise OSError(message)
        return addresses


def _validated_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("request timeout must be a number")
    try:
        timeout = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError("request timeout must be between 0 and 60 seconds") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError("request timeout must be between 0 and 60 seconds")
    return timeout


def _validated_http_method(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("request method must be a string")
    method = value.strip().upper()
    if not method or _HTTP_HEADER_NAME_RE.fullmatch(method) is None:
        raise ValueError("request method must be a valid HTTP token")
    return method


def _validate_http_request_headers(headers: Mapping[Any, Any]) -> None:
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("request headers must contain string names and values")
        if not name or _HTTP_HEADER_NAME_RE.fullmatch(name) is None:
            raise ValueError("request header name is invalid")
        if not _safe_http_header_value(value):
            raise ValueError("request header value is invalid")


def _validated_body_limit(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("max_body_bytes must be an integer")
    if not 1 <= value <= MAX_REQUEST_BODY_BYTES:
        raise ValueError("max_body_bytes must be between 1 and 32000000")
    return value


def _controlled_transport_headers(
    parts: SplitResult,
    *,
    default_headers: Mapping[str, str],
    headers: Mapping[str, str] | None,
) -> dict[str, str]:
    host = parts.hostname or ""
    authority = f"[{host}]" if ":" in host else host
    if parts.port is not None:
        authority = f"{authority}:{parts.port}"
    merged: dict[str, str] = {
        "Host": authority,
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept-Encoding": "identity",
    }
    for source in (default_headers, headers or {}):
        for raw_name, raw_value in source.items():
            if not isinstance(raw_name, str) or not isinstance(raw_value, str):
                raise TypeError("external transport headers must be strings")
            name = raw_name.strip()
            if not name or _HTTP_HEADER_NAME_RE.fullmatch(name) is None:
                raise ValueError("external transport header name is invalid")
            if not _safe_http_header_value(raw_value):
                raise ValueError("external transport header value is invalid")
            for existing in tuple(merged):
                if existing.casefold() == name.casefold():
                    merged.pop(existing)
            merged[name] = raw_value
    return merged


def _safe_http_header_value(value: str) -> bool:
    try:
        value.encode("iso-8859-1")
    except UnicodeEncodeError:
        return False
    return all(character == "\t" or 32 <= ord(character) != 127 for character in value)


def _validate_controlled_transport_result(result: object) -> None:
    if not isinstance(result, ControlledTransportResult):
        raise TypeError("external transport callback must return ControlledTransportResult")
    if not isinstance(result.response_bytes, bytes):
        raise TypeError("controlled transport response_bytes must be bytes")
    if len(result.response_bytes) > MAX_CONTROLLED_BODY_BYTES:
        raise ValueError("controlled transport response exceeds the bounded byte limit")
    if not isinstance(result.outcome, TrafficOutcome):
        raise TypeError("controlled transport outcome must be TrafficOutcome")
    status = result.outcome.status
    if status is not None and (
        isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599
    ):
        raise ValueError("controlled transport outcome status is invalid")
    if not isinstance(result.outcome.headers, Mapping):
        raise TypeError("controlled transport outcome headers must be a mapping")
    if not isinstance(result.outcome.transport_error, bool):
        raise TypeError("controlled transport outcome transport_error must be a boolean")


def _resolve_addresses(host: str, port: int) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(sockaddr[0])
                for family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(
                    host,
                    port,
                    type=socket.SOCK_STREAM,
                )
                if family in {socket.AF_INET, socket.AF_INET6} and sockaddr
            }
        )
    )


def _prepared_request_headers(
    request: Request,
    fallback: dict[str, str],
) -> dict[str, str]:
    """Snapshot headers after urllib handlers add outbound cookies."""
    prepared = dict(fallback)
    try:
        outbound = tuple(request.header_items())
    except (AttributeError, TypeError, ValueError):
        return prepared
    # CookieProcessor mutates the urllib Request after Ravage builds the
    # original mapping. Preserve only that additional outbound header; retain
    # stable casing for the headers Ravage supplied itself.
    for name, value in outbound:
        if str(name).casefold() == "cookie":
            prepared["Cookie"] = str(value)
    return prepared


def _incomplete_read_body(exc: HTTPException) -> bytes:
    if not isinstance(exc, IncompleteRead):
        return b""
    partial = exc.partial
    if isinstance(partial, bytes):
        return partial
    if isinstance(partial, bytearray):
        return bytes(partial)
    return b""


def inject_query_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    next_query = []
    for key, raw_value in query:
        if key == name:
            next_query.append((key, value))
            replaced = True
        else:
            next_query.append((key, raw_value))
    if not replaced:
        next_query.append((name, value))
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(next_query), parts.fragment)
    )


def form_defaults(
    form: dict[str, object], *, marker_name: str = "", marker: str = ""
) -> dict[str, str]:
    fields: dict[str, str] = {}
    saw_named_submit = False
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        if not name or input_field.get("disabled"):
            continue
        input_type = str(input_field.get("type") or "text").lower()
        if input_type in {"reset", "image", "file"}:
            continue
        saw_named_submit = saw_named_submit or input_type in {"submit", "button"}
        value = str(input_field.get("value") or "")
        if input_type in {"submit", "button"} and not value:
            value = name
        if input_type in {"checkbox", "radio"} and not value:
            value = "on"
        if name == marker_name:
            value = marker
        elif not value:
            value = _default_input_value(name, input_type)
        fields[name] = value
    raw_extra = form.get("script_extra_fields")
    if isinstance(raw_extra, dict):
        for key, value in raw_extra.items():
            name = str(key).strip()
            if name and name not in fields:
                fields[name] = str(value)
    if _needs_default_submit_control(form, fields, saw_named_submit):
        fields["submit"] = "submit"
    if marker_name and marker_name not in fields:
        fields[marker_name] = marker
    return fields


def compare_responses(
    baseline: ProbeResponse,
    probe: ProbeResponse,
    *,
    marker: str = "",
) -> ResponseDelta:
    baseline_markers = set(_markers(baseline.body + "\n" + str(baseline.headers)))
    probe_markers = set(_markers(probe.body + "\n" + str(probe.headers)))
    return ResponseDelta(
        status_changed=baseline.status != probe.status,
        length_delta=len(probe.body) - len(baseline.body),
        elapsed_delta_ms=probe.elapsed_ms - baseline.elapsed_ms,
        marker_reflected=bool(marker and marker in probe.body),
        new_error_markers=sorted(probe_markers - baseline_markers),
        interesting_markers=sorted(probe_markers),
    )


def response_secrets(response: ProbeResponse) -> list[str]:
    text = response.body
    findings = []
    patterns = {
        "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "aws_key": r"\bAKIA[0-9A-Z]{16}\b",
        "jwt": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "password_assignment": r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^'\"\s<]{6,}",
        "filesystem_path": r"/(?:home|var|etc|app|srv|tmp)/[A-Za-z0-9_./-]{3,}",
    }
    for label, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            snippet = re.sub(r"\s+", " ", match.group(0))[:180]
            if snippet not in findings:
                findings.append(f"{label}:{snippet}")
    for fragment in decoded_braced_fragments(text):
        if not _decoded_braced_fragment_is_actionable_secret(fragment):
            continue
        snippet = re.sub(r"\s+", " ", fragment)[:180]
        marker = f"decoded_base64_braced:{snippet}"
        if marker not in findings:
            findings.append(marker)
    return findings[:30]


def _decoded_braced_fragment_is_actionable_secret(fragment: str) -> bool:
    if recognize_proofs(fragment):
        return True
    match = re.fullmatch(r"([A-Za-z0-9_-]{0,32})\{([^}]*)\}", fragment.strip(), flags=re.DOTALL)
    if match is None:
        return False
    prefix = match.group(1).lower()
    body = match.group(2).strip()
    if prefix and not any(
        marker in prefix for marker in ("secret", "token", "key", "pass", "auth", "credential")
    ):
        return False
    compact = re.sub(r"\s+", "", body)
    if len(compact) < 12 or "," in body:
        return False
    return bool(
        re.search(r"[A-Za-z]", compact)
        and (re.search(r"\d", compact) or re.search(r"[_./+=@#-]", compact))
    )


def _headers(raw_headers: Any) -> dict[str, str]:
    wanted = {
        "access-control-allow-credentials",
        "access-control-allow-headers",
        "access-control-allow-methods",
        "access-control-allow-origin",
        "access-control-expose-headers",
        "cache-control",
        "content-security-policy",
        "content-type",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "location",
        "permissions-policy",
        "referrer-policy",
        "retry-after",
        "server",
        "vary",
        "x-content-type-options",
        "x-frame-options",
        "x-powered-by",
    }
    headers = {}
    set_cookie_values: list[str] = []
    for name, value in raw_headers.items():
        lowered = name.lower()
        if lowered == "set-cookie":
            set_cookie_values.append(re.sub(r"\s+", " ", str(value)).strip())
        elif lowered in wanted:
            headers[lowered] = re.sub(r"\s+", " ", str(value)).strip()
    if hasattr(raw_headers, "get_all"):
        for value in raw_headers.get_all("Set-Cookie", []):
            set_cookie_values.append(re.sub(r"\s+", " ", str(value)).strip())
    if set_cookie_values:
        headers["set-cookie"] = "\n".join(
            dict.fromkeys(value for value in set_cookie_values if value)
        )
    return headers


def _decode_body(body: bytes, charset: str | None) -> str:
    return body[:MAX_BODY_BYTES].decode(charset or "utf-8", errors="replace")


def _markers(text: str) -> list[str]:
    lowered = text.lower()
    markers = []
    for marker in (
        "sql syntax",
        "sqlite",
        "mysql",
        "postgres",
        "traceback",
        "exception",
        "warning:",
        "jinja",
        "template",
        "jwt",
        "xml",
        "forbidden",
        "unauthorized",
        "root:",
    ):
        if marker in lowered:
            markers.append(marker)
    return markers


def _default_input_value(name: str, input_type: str) -> str:
    lowered = name.lower()
    if input_type == "email" or "email" in lowered:
        return "ravage@example.test"
    if input_type == "password" or "pass" in lowered:
        return "RavagePass123!"
    if input_type in {"number", "range"} or lowered.endswith("id") or lowered == "id":
        return "1"
    if "url" in lowered or "uri" in lowered:
        return "http://127.0.0.1/"
    if "host" in lowered or "domain" in lowered:
        return "127.0.0.1"
    return "ravage"


def _needs_default_submit_control(
    form: dict[str, object], fields: dict[str, str], saw_named_submit: bool
) -> bool:
    if str(form.get("method") or "GET").upper() != "POST":
        return False
    if saw_named_submit or any(
        name.lower() in {"submit", "login", "signin", "sign_in"} for name in fields
    ):
        return False
    text = repr(form).lower()
    return any(
        marker in text
        for marker in ("password", "login", "signin", "sign in", "register", "search", "upload")
    )


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]
