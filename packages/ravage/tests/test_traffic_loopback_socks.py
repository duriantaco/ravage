from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING

import pytest
from ravage.traffic.loopback_socks import LoopbackSocks5Proxy, PinnedSocksProxy

if TYPE_CHECKING:
    from collections.abc import Iterator

_IPV6_VERSION = 6
_CONNECTION_NOT_ALLOWED = 2
_COMMAND_NOT_SUPPORTED = 7


@contextmanager
def _echo_server(*, ipv6: bool = False) -> Iterator[tuple[str, int]]:
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    host = "::1" if ipv6 else "127.0.0.1"
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.bind((host, 0))
    listener.listen(4)
    listener.settimeout(0.2)
    stopping = threading.Event()

    def serve() -> None:
        while not stopping.is_set():
            try:
                connection, _peer = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                while True:
                    data = connection.recv(65_536)
                    if not data:
                        break
                    connection.sendall(data)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield host, int(listener.getsockname()[1])
    finally:
        stopping.set()
        listener.close()
        thread.join(timeout=2)


def _open_socks_client(proxy: LoopbackSocks5Proxy) -> socket.socket:
    client = socket.create_connection(proxy.address, timeout=2)
    client.settimeout(2)
    client.sendall(b"\x05\x01\x00")
    assert _recv_exact(client, 2) == b"\x05\x00"
    return client


def _connect_domain(client: socket.socket, host: str, port: int, *, command: int = 1) -> int:
    encoded = host.encode("ascii")
    client.sendall(bytes((5, command, 0, 3, len(encoded))) + encoded + port.to_bytes(2, "big"))
    return _recv_exact(client, 10)[1]


def _connect_ip(client: socket.socket, address: str, port: int) -> int:
    parsed = ipaddress.ip_address(address)
    address_type = 4 if parsed.version == _IPV6_VERSION else 1
    client.sendall(bytes((5, 1, 0, address_type)) + parsed.packed + port.to_bytes(2, "big"))
    return _recv_exact(client, 10)[1]


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def test_proxy_is_loopback_ephemeral_and_closes_with_context_manager() -> None:
    proxy = PinnedSocksProxy(
        host="target.example.test",
        port=443,
        pinned_addresses=["192.0.2.10"],
    )

    with proxy:
        host, port = proxy.address
        assert host == "127.0.0.1"
        assert port > 0
        assert proxy.proxy_url == f"socks5://127.0.0.1:{port}"
        assert proxy.url == proxy.proxy_url
        with socket.create_connection(proxy.address, timeout=2):
            pass

    with pytest.raises(RuntimeError, match="not running"):
        _ = proxy.port
    with pytest.raises(RuntimeError, match="closed"):
        proxy.start()


def test_domain_connect_uses_pin_without_os_dns_and_tunnels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _echo_server() as (_host, target_port):
        proxy = LoopbackSocks5Proxy(
            "Target.Example.Test.",
            target_port,
            ["127.0.0.1"],
        )
        with proxy:
            client = _open_socks_client(proxy)
            with client:
                monkeypatch.setattr(
                    "socket.getaddrinfo",
                    lambda *_args, **_kwargs: pytest.fail("proxy must not perform DNS"),
                )
                assert _connect_domain(client, "target.example.test", target_port) == 0
                client.sendall(b"through-the-pin")
                assert _recv_exact(client, 15) == b"through-the-pin"


def test_proxy_preserves_tls_client_hello_and_original_sni() -> None:
    context = ssl.create_default_context()
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(
        incoming,
        outgoing,
        server_hostname="target.example.test",
    )
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    client_hello = outgoing.read()
    assert b"target.example.test" in client_hello

    with (
        _echo_server() as (_host, target_port),
        LoopbackSocks5Proxy(
            "target.example.test",
            target_port,
            ["127.0.0.1"],
        ) as proxy,
    ):
        client = _open_socks_client(proxy)
        with client:
            assert _connect_domain(client, "target.example.test", target_port) == 0
            client.sendall(client_hello)
            assert _recv_exact(client, len(client_hello)) == client_hello


def test_numeric_destination_must_be_a_pin_and_use_original_port() -> None:
    with (
        _echo_server() as (_host, target_port),
        LoopbackSocks5Proxy(
            "target.example.test",
            target_port,
            ["127.0.0.1"],
        ) as proxy,
    ):
        allowed = _open_socks_client(proxy)
        with allowed:
            assert _connect_ip(allowed, "127.0.0.1", target_port) == 0
            allowed.sendall(b"ok")
            allowed.shutdown(socket.SHUT_WR)
            assert _recv_exact(allowed, 2) == b"ok"

        wrong_ip = _open_socks_client(proxy)
        with wrong_ip:
            assert _connect_ip(wrong_ip, "127.0.0.2", target_port) == _CONNECTION_NOT_ALLOWED

        wrong_port = _open_socks_client(proxy)
        with wrong_port:
            assert (
                _connect_domain(
                    wrong_port,
                    "target.example.test",
                    target_port + 1,
                )
                == _CONNECTION_NOT_ALLOWED
            )


def test_proxy_rejects_other_hosts_and_non_connect_commands() -> None:
    proxy = LoopbackSocks5Proxy("target.example.test", 443, ["192.0.2.10"])
    with proxy:
        other_host = _open_socks_client(proxy)
        with other_host:
            assert _connect_domain(other_host, "other.example.test", 443) == _CONNECTION_NOT_ALLOWED

        bind_request = _open_socks_client(proxy)
        with bind_request:
            assert (
                _connect_domain(bind_request, "target.example.test", 443, command=2)
                == _COMMAND_NOT_SUPPORTED
            )


def test_proxy_requires_no_auth_method() -> None:
    with LoopbackSocks5Proxy("target.example.test", 443, ["192.0.2.10"]) as proxy:
        client = socket.create_connection(proxy.address, timeout=2)
        with client:
            client.sendall(b"\x05\x01\x02")
            assert _recv_exact(client, 2) == b"\x05\xff"


def test_partial_handshake_is_bounded() -> None:
    proxy = LoopbackSocks5Proxy(
        "target.example.test",
        443,
        ["192.0.2.10"],
        handshake_timeout=0.1,
    )
    with proxy:
        client = socket.create_connection(proxy.address, timeout=2)
        with client:
            started = time.monotonic()
            client.sendall(b"\x05")
            assert client.recv(1) == b""
            assert time.monotonic() - started < 1.0


def test_close_terminates_an_active_handshake_and_is_idempotent() -> None:
    proxy = LoopbackSocks5Proxy("target.example.test", 443, ["192.0.2.10"]).start()
    client = _open_socks_client(proxy)
    try:
        proxy.close()
        assert client.recv(1) == b""
        proxy.close()
    finally:
        client.close()


def test_ipv6_pin_connects_when_loopback_ipv6_is_available() -> None:
    try:
        server = _echo_server(ipv6=True)
        target = server.__enter__()
    except OSError:
        pytest.skip("IPv6 loopback is unavailable")
    try:
        _host, target_port = target
        with LoopbackSocks5Proxy(
            "target.example.test",
            target_port,
            ["::1"],
        ) as proxy:
            client = _open_socks_client(proxy)
            with client:
                assert _connect_ip(client, "::1", target_port) == 0
                client.sendall(b"ipv6")
                assert _recv_exact(client, 4) == b"ipv6"
    finally:
        server.__exit__(None, None, None)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"pinned_addresses": []}, "at least one"),
        ({"pinned_addresses": ["not-an-ip"]}, "numeric IP"),
        ({"pinned_addresses": ["0.0.0.0"]}, "unspecified IP"),  # noqa: S104
        ({"pinned_addresses": ["::"]}, "unspecified IP"),
        ({"pinned_addresses": ["::ffff:0.0.0.0"]}, "unspecified IP"),
        ({"original_port": 0}, "port"),
        ({"handshake_timeout": 0}, "timeout"),
    ],
)
def test_proxy_rejects_invalid_configuration(
    kwargs: dict[str, object],
    message: str,
) -> None:
    options: dict[str, object] = {
        "original_host": "target.example.test",
        "original_port": 443,
        "pinned_addresses": ["192.0.2.10"],
    }
    options.update(kwargs)

    with pytest.raises(ValueError, match=message):
        LoopbackSocks5Proxy(**options)  # type: ignore[arg-type]
