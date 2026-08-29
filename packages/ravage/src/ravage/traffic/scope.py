from __future__ import annotations

import ipaddress
import socket
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from ravage.runtime.common import assert_http_url
from ravage.web_core.scope_policy import is_local_url, url_in_scope_entries

Resolver = Callable[[str, int], Sequence[str]]


@dataclass(frozen=True, slots=True)
class TrafficScopeDecision:
    allowed: bool
    reason: str = ""


@dataclass(slots=True)
class TrafficScope:
    """Fail-closed URL and DNS admission for captured or replayed traffic."""

    target_url: str
    allow_remote_target: bool = False
    in_scope: tuple[str, ...] = ()
    out_of_scope: tuple[str, ...] = ()
    resolver: Resolver | None = field(default=None, repr=False)
    _dns_pins: dict[tuple[str, int], tuple[str, ...]] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        parsed = assert_http_url(self.target_url)
        if parsed.username is not None or parsed.password is not None:
            message = "traffic target URL cannot contain userinfo"
            raise ValueError(message)
        if not is_local_url(self.target_url) and not self.allow_remote_target:
            message = "remote traffic targets require --authorized-remote-target"
            raise ValueError(message)
        if not self.in_scope:
            object.__setattr__(self, "in_scope", (self.origin + "/",))
        if not url_in_scope_entries(
            self.target_url,
            in_scope=self.in_scope,
            out_of_scope=self.out_of_scope,
        ):
            message = "traffic target URL must be inside the authorized scope"
            raise ValueError(message)
        if self.resolver is None:
            self.resolver = _resolve_addresses

    @property
    def origin(self) -> str:
        parsed = assert_http_url(self.target_url)
        return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), "", "", ""))

    def decide(self, url: str) -> TrafficScopeDecision:
        rejection = self._url_rejection(url)
        if rejection is not None:
            return rejection
        if is_local_url(url):
            return TrafficScopeDecision(allowed=True)
        return self._remote_dns_decision(url)

    def decide_using_pins(self, url: str) -> TrafficScopeDecision:
        """Authorize a route against an already-frozen remote DNS pin set."""
        rejection = self._url_rejection(url)
        if rejection is not None:
            return rejection
        if is_local_url(url):
            return TrafficScopeDecision(allowed=True)
        if not self.pinned_addresses(url):
            return TrafficScopeDecision(
                allowed=False,
                reason="target DNS was not pinned before browser launch",
            )
        return TrafficScopeDecision(allowed=True)

    def _url_rejection(self, url: str) -> TrafficScopeDecision | None:
        try:
            parsed = assert_http_url(url)
        except ValueError as exc:
            return TrafficScopeDecision(allowed=False, reason=str(exc))
        if parsed.username is not None or parsed.password is not None:
            return TrafficScopeDecision(
                allowed=False,
                reason="request URL cannot contain userinfo",
            )
        if not url_in_scope_entries(
            url,
            in_scope=self.in_scope,
            out_of_scope=self.out_of_scope,
        ):
            return TrafficScopeDecision(allowed=False, reason="outside authorized scope")
        if not is_local_url(url) and not self.allow_remote_target:
            return TrafficScopeDecision(
                allowed=False,
                reason="remote traffic is not authorized",
            )
        return None

    def _remote_dns_decision(self, url: str) -> TrafficScopeDecision:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        assert self.resolver is not None
        try:
            resolved = self.resolver(host, port)
            parsed_addresses = tuple(
                ipaddress.ip_address(str(address).strip()) for address in resolved
            )
        except (OSError, ValueError):
            return TrafficScopeDecision(
                allowed=False,
                reason="target DNS resolution failed",
            )
        if any(_is_unspecified_address(address) for address in parsed_addresses):
            return TrafficScopeDecision(
                allowed=False,
                reason="target DNS resolution returned an unspecified address",
            )
        addresses = tuple(sorted({str(address) for address in parsed_addresses}))
        if not addresses:
            return TrafficScopeDecision(
                allowed=False,
                reason="target DNS resolution returned no addresses",
            )
        key = (host.rstrip(".").lower(), port)
        with self._lock:
            pinned = self._dns_pins.setdefault(key, addresses)
        if pinned != addresses:
            return TrafficScopeDecision(
                allowed=False,
                reason="target DNS changed after pinning",
            )
        return TrafficScopeDecision(allowed=True)

    def pinned_addresses(self, url: str) -> tuple[str, ...]:
        """Return the exact remote addresses approved by a prior decision."""
        parsed = urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        with self._lock:
            return self._dns_pins.get((host, port), ())


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


def _is_unspecified_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    effective = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    return (effective or address).is_unspecified


__all__ = ["TrafficScope", "TrafficScopeDecision"]
