from __future__ import annotations

import ipaddress
import posixpath
from collections.abc import Sequence
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlparse, urlunparse

if TYPE_CHECKING:
    from pentest_schemas import Scope

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
HTTP_SCHEMES = {"http", "https"}
MAX_IPV4_PARTS = 4
TWO_PART_IPV4 = 2
THREE_PART_IPV4 = 3
HEX_PREFIX_LEN = 2
IPV4_OCTET_MAX = 0xFF
IPV4_16BIT_MAX = 0xFFFF
IPV4_24BIT_MAX = 0xFFFFFF
IPV4_32BIT_MAX = 0xFFFFFFFF


def is_local_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in HTTP_SCHEMES and is_local_host(parsed.hostname)


def is_local_host(host: str | None) -> bool:
    if host is None:
        return False
    normalized = host.rstrip(".").lower()
    if normalized in LOCAL_HOSTS:
        return True
    parsed_ip = _parse_ip_host(normalized)
    if parsed_ip is None:
        return False
    return _is_local_ip(parsed_ip)


def _parse_ip_host(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return _parse_legacy_ipv4_host(host)


def _parse_legacy_ipv4_host(host: str) -> ipaddress.IPv4Address | None:
    if not host.isascii() or ":" in host:
        return None
    parts = host.split(".")
    if not 1 <= len(parts) <= MAX_IPV4_PARTS:
        return None
    try:
        numbers = [_parse_legacy_ipv4_part(part) for part in parts]
        return _legacy_ipv4_from_numbers(numbers)
    except ValueError:
        return None


def _legacy_ipv4_from_numbers(numbers: list[int]) -> ipaddress.IPv4Address:
    if len(numbers) == 1:
        value = numbers[0]
        max_value = IPV4_32BIT_MAX
    elif len(numbers) == TWO_PART_IPV4:
        value = (numbers[0] << 24) | numbers[1]
        max_value = IPV4_24BIT_MAX
    elif len(numbers) == THREE_PART_IPV4:
        value = (numbers[0] << 24) | (numbers[1] << 16) | numbers[2]
        max_value = IPV4_16BIT_MAX
    else:
        value = (numbers[0] << 24) | (numbers[1] << 16) | (numbers[2] << 8) | numbers[3]
        max_value = IPV4_OCTET_MAX
    if any(number < 0 for number in numbers[:-1]) or numbers[-1] < 0:
        raise ValueError
    if any(number > IPV4_OCTET_MAX for number in numbers[:-1]) or numbers[-1] > max_value:
        raise ValueError
    return ipaddress.IPv4Address(value)


def _parse_legacy_ipv4_part(part: str) -> int:
    if not part:
        raise ValueError
    lowered = part.lower()
    if lowered.startswith(("+", "-")):
        raise ValueError
    if lowered.startswith("0x"):
        if len(lowered) == HEX_PREFIX_LEN:
            raise ValueError
        return int(lowered, 0)
    if len(lowered) > 1 and lowered.startswith("0"):
        return int(lowered, 8)
    return int(lowered, 10)


def _is_local_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_unspecified


def assert_authorized_target(
    target_url: str,
    *,
    scope: Scope,
    allow_remote_target: bool,
    agent_name: str,
) -> None:
    parsed = urlparse(target_url)
    if parsed.scheme not in HTTP_SCHEMES or parsed.hostname is None:
        message = f"{agent_name} target must be an http(s) URL"
        raise ValueError(message)

    if not is_local_url(target_url) and not allow_remote_target:
        message = (
            f"{agent_name} agent only runs against localhost targets unless "
            "--allow-remote-target is passed"
        )
        raise ValueError(message)
    prefix = "local target" if is_local_url(target_url) else "remote target"
    _assert_url_in_scope(target_url, scope=scope, prefix=prefix)


def assert_scoped_same_origin(
    target_url: str,
    candidate_url: str,
    *,
    scope: Scope,
    allow_remote_target: bool,
) -> None:
    if not is_local_url(candidate_url) and not allow_remote_target:
        message = "tool target must stay on localhost unless --allow-remote-target is passed"
        raise ValueError(message)

    _ = target_url
    _assert_url_in_scope(candidate_url, scope=scope, prefix="tool target")


def remap_local_default_origin(target_url: str, candidate_url: str) -> str:
    target = urlparse(target_url)
    candidate = urlparse(candidate_url)
    if (
        target.scheme not in HTTP_SCHEMES
        or candidate.scheme not in HTTP_SCHEMES
        or target.hostname is None
        or candidate.hostname is None
        or not is_local_host(target.hostname)
        or not is_local_host(candidate.hostname)
        or target.scheme.lower() != candidate.scheme.lower()
    ):
        return candidate_url
    target_port = target.port or _default_port(target.scheme)
    candidate_port = candidate.port or _default_port(candidate.scheme)
    if target_port in {None, _default_port(target.scheme)}:
        return candidate_url
    if candidate_port != _default_port(candidate.scheme):
        return candidate_url
    return urlunparse(
        (
            target.scheme,
            target.netloc,
            candidate.path or "/",
            candidate.params,
            candidate.query,
            candidate.fragment,
        )
    )


def same_origin(first_url: str, second_url: str) -> bool:
    return _origin(first_url) == _origin(second_url)


def url_in_scope(url: str, *, scope: Scope) -> bool:
    return url_in_scope_entries(
        url,
        in_scope=scope.in_scope,
        out_of_scope=scope.out_of_scope,
    )


def url_in_scope_entries(
    url: str,
    *,
    in_scope: Sequence[str],
    out_of_scope: Sequence[str] = (),
) -> bool:
    return any(_scope_entry_allows_url(entry, url) for entry in in_scope) and not any(
        _scope_entry_allows_url(entry, url) for entry in out_of_scope
    )


def _assert_url_in_scope(url: str, *, scope: Scope, prefix: str) -> None:
    if any(_scope_entry_allows_url(entry, url) for entry in scope.out_of_scope):
        message = f"{prefix} is explicitly out of scope: {url}"
        raise ValueError(message)
    if not any(_scope_entry_allows_url(entry, url) for entry in scope.in_scope):
        message = f"{prefix} must be listed in engagement scope: {url}"
        raise ValueError(message)


def _scope_entry_allows_url(scope_entry: str, candidate_url: str) -> bool:
    entry = urlparse(scope_entry)
    candidate = urlparse(candidate_url)
    if entry.scheme not in HTTP_SCHEMES or candidate.scheme not in HTTP_SCHEMES:
        return False
    if entry.hostname is None or candidate.hostname is None:
        return False
    if _origin(scope_entry) != _origin(candidate_url):
        return False

    entry_path = _normalize_path(entry.path)
    candidate_path = _normalize_path(candidate.path)
    if entry_path == "/":
        return True
    scoped_path = entry_path.rstrip("/")
    return candidate_path == scoped_path or candidate_path.startswith(f"{scoped_path}/")


def _normalize_path(path: str) -> str:
    normalized = posixpath.normpath(unquote(path or "/"))
    if normalized == ".":
        return "/"
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


def _origin(url: str) -> tuple[str, str | None, int | None]:
    parsed = urlparse(url)
    hostname = parsed.hostname.lower() if parsed.hostname is not None else None
    return (parsed.scheme.lower(), hostname, parsed.port or _default_port(parsed.scheme))


def _default_port(scheme: str) -> int | None:
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None
