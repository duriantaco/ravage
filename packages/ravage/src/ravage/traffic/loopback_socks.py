from __future__ import annotations

import ipaddress
import select
import socket
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from types import TracebackType
    from typing import Self

_SOCKS_VERSION = 5
_NO_AUTH = 0
_NO_ACCEPTABLE_METHOD = 0xFF
_CONNECT = 1
_IPV4 = 1
_DOMAIN = 3
_IPV6 = 4
_SUCCEEDED = 0
_GENERAL_FAILURE = 1
_CONNECTION_NOT_ALLOWED = 2
_CONNECTION_REFUSED = 5
_COMMAND_NOT_SUPPORTED = 7
_ADDRESS_TYPE_NOT_SUPPORTED = 8
_MAX_PORT = 65_535
_MAX_DOMAIN_BYTES = 255
_MAX_TIMEOUT_SECONDS = 3_600.0
_ACCEPT_POLL_SECONDS = 0.2
_CLOSE_JOIN_SECONDS = 2.0
_TUNNEL_CHUNK_BYTES = 65_536
_LISTEN_BACKLOG = 32
_MAX_CLIENTS = 64
_IPV6_VERSION = 6
_LOOPBACK_HOST = "127.0.0.1"


class _SocksRequestError(Exception):
    def __init__(self, reply_code: int) -> None:
        super().__init__()
        self.reply_code = reply_code


@dataclass(slots=True)
class LoopbackSocks5Proxy:
    """A loopback-only SOCKS5 CONNECT proxy restricted to one pinned origin."""

    original_host: str
    original_port: int
    pinned_addresses: Sequence[str]
    handshake_timeout: float = 5.0
    connect_timeout: float = 10.0
    idle_timeout: float = 60.0
    _normalized_host: str = field(init=False, repr=False)
    _origin_port: int = field(init=False, repr=False)
    _pins: tuple[str, ...] = field(init=False, repr=False)
    _listener: socket.socket | None = field(default=None, init=False, repr=False)
    _accept_thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _handler_threads: set[threading.Thread] = field(
        default_factory=set,
        init=False,
        repr=False,
    )
    _connections: set[socket.socket] = field(default_factory=set, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _stopping: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self._normalized_host = _normalize_host(self.original_host)
        self.original_port = _valid_port(self.original_port)
        self._origin_port = self.original_port
        self._pins = _normalize_pins(self.pinned_addresses)
        self.handshake_timeout = _valid_timeout(
            self.handshake_timeout,
            name="handshake timeout",
        )
        self.connect_timeout = _valid_timeout(
            self.connect_timeout,
            name="connect timeout",
        )
        self.idle_timeout = _valid_timeout(self.idle_timeout, name="idle timeout")

    @property
    def host(self) -> str:
        return _LOOPBACK_HOST

    @property
    def port(self) -> int:
        with self._lock:
            listener = self._listener
            if listener is None:
                message = "SOCKS proxy is not running"
                raise RuntimeError(message)
            return int(listener.getsockname()[1])

    @property
    def address(self) -> tuple[str, int]:
        return (self.host, self.port)

    @property
    def proxy_url(self) -> str:
        return f"socks5://{self.host}:{self.port}"

    def start(self) -> Self:
        with self._lock:
            if self._closed:
                message = "SOCKS proxy is closed"
                raise RuntimeError(message)
            if self._listener is not None:
                return self
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                exclusive_address_use = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
                if isinstance(exclusive_address_use, int):
                    listener.setsockopt(socket.SOL_SOCKET, exclusive_address_use, 1)
                listener.bind((_LOOPBACK_HOST, 0))
                listener.listen(_LISTEN_BACKLOG)
                listener.settimeout(_ACCEPT_POLL_SECONDS)
            except BaseException:
                listener.close()
                raise
            self._listener = listener
            thread = threading.Thread(
                target=self._accept_loop,
                name="ravage-loopback-socks",
                daemon=True,
            )
            self._accept_thread = thread
            try:
                thread.start()
            except RuntimeError:
                self._listener = None
                self._accept_thread = None
                listener.close()
                raise
        return self

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stopping.set()
            listener = self._listener
            self._listener = None
            accept_thread = self._accept_thread
            connections = tuple(self._connections)
        _close_socket(listener)
        for connection in connections:
            _close_socket(connection)
        if accept_thread is not None and accept_thread is not threading.current_thread():
            accept_thread.join(timeout=_CLOSE_JOIN_SECONDS)
        with self._lock:
            handlers = tuple(self._handler_threads)
        join_deadline = time.monotonic() + _CLOSE_JOIN_SECONDS
        for handler in handlers:
            if handler is not threading.current_thread():
                remaining = join_deadline - time.monotonic()
                if remaining <= 0:
                    break
                handler.join(timeout=remaining)

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            with self._lock:
                listener = self._listener
            if listener is None:
                return
            try:
                client, _peer = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            if self._stopping.is_set():
                _close_socket(client)
                return
            if not self._register_connection(client):
                return
            if not self._start_handler(client):
                _close_socket(client)

    def _start_handler(self, client: socket.socket) -> bool:
        handler = threading.Thread(
            target=self._run_handler,
            args=(client,),
            name="ravage-loopback-socks-client",
            daemon=True,
        )
        handler_started = False
        with self._lock:
            if len(self._handler_threads) >= _MAX_CLIENTS:
                self._connections.discard(client)
            else:
                self._handler_threads.add(handler)
                try:
                    handler.start()
                except RuntimeError:
                    self._connections.discard(client)
                    self._handler_threads.discard(handler)
                else:
                    handler_started = True
        return handler_started

    def _run_handler(self, client: socket.socket) -> None:
        try:
            self._handle_client(client)
        except (OSError, TimeoutError, ValueError):
            pass
        finally:
            self._unregister_connection(client)
            _close_socket(client)
            with self._lock:
                self._handler_threads.discard(threading.current_thread())

    def _handle_client(self, client: socket.socket) -> None:
        deadline = time.monotonic() + self.handshake_timeout
        if not _negotiate_no_auth(client, deadline=deadline):
            return
        try:
            destination, port = _read_connect_request(client, deadline=deadline)
            addresses = self._authorized_addresses(destination, port)
        except _SocksRequestError as exc:
            _send_reply(client, exc.reply_code)
            return
        try:
            upstream = self._connect_upstream(
                addresses,
            )
        except OSError:
            _send_reply(client, _CONNECTION_REFUSED)
            return
        try:
            _send_reply(client, _SUCCEEDED)
            _tunnel(
                client,
                upstream,
                idle_timeout=self.idle_timeout,
                stopping=self._stopping,
            )
        finally:
            self._unregister_connection(upstream)
            _close_socket(upstream)

    def _authorized_addresses(self, destination: str, port: int) -> tuple[str, ...]:
        if port != self._origin_port:
            raise _SocksRequestError(_CONNECTION_NOT_ALLOWED)
        try:
            numeric = str(ipaddress.ip_address(destination))
        except ValueError:
            try:
                host = _normalize_host(destination)
            except ValueError as exc:
                raise _SocksRequestError(_CONNECTION_NOT_ALLOWED) from exc
            if host != self._normalized_host:
                raise _SocksRequestError(_CONNECTION_NOT_ALLOWED) from None
            return self._pins
        if numeric not in self._pins:
            raise _SocksRequestError(_CONNECTION_NOT_ALLOWED)
        return (numeric,)

    def _connect_upstream(self, addresses: Sequence[str]) -> socket.socket:
        deadline = time.monotonic() + self.connect_timeout
        last_error: OSError | None = None
        for address in addresses:
            parsed = ipaddress.ip_address(address)
            family = socket.AF_INET6 if parsed.version == _IPV6_VERSION else socket.AF_INET
            upstream = socket.socket(family, socket.SOCK_STREAM)
            if not self._register_connection(upstream):
                raise OSError
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                upstream.settimeout(remaining)
                upstream.connect((str(parsed), self._origin_port))
                upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError as exc:
                last_error = exc
                self._unregister_connection(upstream)
                upstream.close()
            else:
                return upstream
        if last_error is not None:
            raise last_error
        raise TimeoutError

    def _register_connection(self, connection: socket.socket) -> bool:
        with self._lock:
            if self._closed:
                _close_socket(connection)
                return False
            self._connections.add(connection)
            return True

    def _unregister_connection(self, connection: socket.socket) -> None:
        with self._lock:
            self._connections.discard(connection)


class PinnedSocksProxy(LoopbackSocks5Proxy):
    """Convenient public API for a SOCKS proxy bound to one pinned origin."""

    def __init__(  # noqa: PLR0913
        self,
        host: str,
        port: int,
        pinned_addresses: Sequence[str],
        *,
        handshake_timeout: float = 5.0,
        connect_timeout: float = 10.0,
        idle_timeout: float = 60.0,
    ) -> None:
        super().__init__(
            original_host=host,
            original_port=port,
            pinned_addresses=pinned_addresses,
            handshake_timeout=handshake_timeout,
            connect_timeout=connect_timeout,
            idle_timeout=idle_timeout,
        )

    @property
    def url(self) -> str:
        return self.proxy_url

    def start(self) -> Self:
        super().start()
        return self

    def __enter__(self) -> Self:
        return self.start()


def _negotiate_no_auth(client: socket.socket, *, deadline: float) -> bool:
    header = _recv_exact(client, 2, deadline=deadline)
    version, method_count = header
    methods = _recv_exact(client, method_count, deadline=deadline)
    if version != _SOCKS_VERSION or _NO_AUTH not in methods:
        with suppress(OSError):
            client.sendall(bytes((_SOCKS_VERSION, _NO_ACCEPTABLE_METHOD)))
        return False
    client.sendall(bytes((_SOCKS_VERSION, _NO_AUTH)))
    return True


def _read_connect_request(client: socket.socket, *, deadline: float) -> tuple[str, int]:
    version, command, reserved, address_type = _recv_exact(client, 4, deadline=deadline)
    if version != _SOCKS_VERSION or reserved != 0:
        raise _SocksRequestError(_GENERAL_FAILURE)
    if command != _CONNECT:
        raise _SocksRequestError(_COMMAND_NOT_SUPPORTED)
    if address_type == _IPV4:
        destination = str(ipaddress.IPv4Address(_recv_exact(client, 4, deadline=deadline)))
    elif address_type == _IPV6:
        destination = str(ipaddress.IPv6Address(_recv_exact(client, 16, deadline=deadline)))
    elif address_type == _DOMAIN:
        domain_length = _recv_exact(client, 1, deadline=deadline)[0]
        if domain_length == 0:
            raise _SocksRequestError(_CONNECTION_NOT_ALLOWED)
        try:
            destination = _recv_exact(client, domain_length, deadline=deadline).decode("ascii")
        except UnicodeDecodeError as exc:
            raise _SocksRequestError(_CONNECTION_NOT_ALLOWED) from exc
    else:
        raise _SocksRequestError(_ADDRESS_TYPE_NOT_SUPPORTED)
    port = int.from_bytes(_recv_exact(client, 2, deadline=deadline), "big")
    return destination, port


def _recv_exact(connection: socket.socket, size: int, *, deadline: float) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        connection.settimeout(remaining)
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise OSError
        chunks.extend(chunk)
    return bytes(chunks)


def _send_reply(client: socket.socket, reply_code: int) -> None:
    with suppress(OSError):
        client.sendall(bytes((_SOCKS_VERSION, reply_code, 0, _IPV4, 0, 0, 0, 0, 0, 0)))


def _tunnel(
    client: socket.socket,
    upstream: socket.socket,
    *,
    idle_timeout: float,
    stopping: threading.Event,
) -> None:
    client.settimeout(idle_timeout)
    upstream.settimeout(idle_timeout)
    peers = {client: upstream, upstream: client}
    readable_peers = set(peers)
    deadline = time.monotonic() + idle_timeout
    while readable_peers and not stopping.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        try:
            readable, _, _ = select.select(
                tuple(readable_peers),
                (),
                (),
                min(remaining, 1.0),
            )
        except OSError:
            return
        if not readable:
            continue
        for source in readable:
            try:
                data = source.recv(_TUNNEL_CHUNK_BYTES)
                if not data:
                    readable_peers.discard(source)
                    with suppress(OSError):
                        peers[source].shutdown(socket.SHUT_WR)
                    deadline = time.monotonic() + idle_timeout
                    continue
                peers[source].sendall(data)
            except (OSError, TimeoutError):
                return
            deadline = time.monotonic() + idle_timeout


def _normalize_host(host: str) -> str:
    candidate = str(host).strip().rstrip(".")
    if not candidate or "\x00" in candidate:
        message = "SOCKS origin host is invalid"
        raise ValueError(message)
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        try:
            normalized = candidate.encode("idna").decode("ascii").casefold()
        except UnicodeError as exc:
            message = "SOCKS origin host is invalid"
            raise ValueError(message) from exc
        if not normalized or len(normalized.encode("ascii")) > _MAX_DOMAIN_BYTES:
            message = "SOCKS origin host is invalid"
            raise ValueError(message) from None
        return normalized


def _normalize_pins(addresses: Sequence[str]) -> tuple[str, ...]:
    pins: list[str] = []
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(str(address).strip())
        except ValueError as exc:
            message = "SOCKS pins must be numeric IP addresses"
            raise ValueError(message) from exc
        if parsed.is_unspecified:
            message = "SOCKS pins cannot use unspecified IP addresses"
            raise ValueError(message)
        normalized = str(parsed)
        if normalized not in pins:
            pins.append(normalized)
    if not pins:
        message = "SOCKS proxy requires at least one pinned address"
        raise ValueError(message)
    return tuple(pins)


def _valid_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= _MAX_PORT:
        message = "SOCKS origin port is invalid"
        raise ValueError(message)
    return port


def _valid_timeout(value: float, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        message = f"{name} is invalid"
        raise TypeError(message)
    normalized = float(value)
    if not 0 < normalized <= _MAX_TIMEOUT_SECONDS:
        message = f"{name} is invalid"
        raise ValueError(message)
    return normalized


def _close_socket(connection: socket.socket | None) -> None:
    if connection is None:
        return
    with suppress(OSError):
        connection.shutdown(socket.SHUT_RDWR)
    with suppress(OSError):
        connection.close()


__all__ = ["LoopbackSocks5Proxy", "PinnedSocksProxy"]
