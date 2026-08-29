from __future__ import annotations

import ipaddress
import shlex
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from pentest_schemas import Scope

IPV4_VERSION = 4


def generate_iptables_commands(scope: Scope) -> str:
    return "\n".join(render_rules(scope)) + "\n"


def render_rules(scope: Scope) -> list[str]:
    rules = [
        "iptables -F OUTPUT",
        "iptables -P OUTPUT DROP",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]

    for raw in scope.out_of_scope:
        target, _port, stable = _normalize_target(raw)
        if not stable:
            rules.append(_skip_comment(raw, reason="hostname out_of_scope entry"))
            continue
        rules.append(_drop_rule(target))

    for raw in scope.in_scope:
        target, port, stable = _normalize_target(raw)
        if not stable:
            rules.append(_skip_comment(raw, reason="hostname in_scope entry"))
            continue
        rules.append(_accept_rule(target, port))

    return rules


def _normalize_target(raw: str) -> tuple[str, int | None, bool]:
    parsed = urlparse(raw)
    if parsed.scheme and parsed.hostname:
        port = parsed.port
        if port is None and parsed.scheme == "http":
            port = 80
        if port is None and parsed.scheme == "https":
            port = 443
        destination = _stable_ipv4_destination(parsed.hostname)
        return (destination or parsed.hostname, port, destination is not None)

    destination = _stable_ipv4_destination(raw)
    return (destination or raw, None, destination is not None)


def _stable_ipv4_destination(raw: str) -> str | None:
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    if network.version != IPV4_VERSION:
        return None
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return str(network)


def _drop_rule(target: str) -> str:
    return f"iptables -A OUTPUT -d {shlex.quote(target)} -j DROP"


def _accept_rule(target: str, port: int | None) -> str:
    if port is None:
        return f"iptables -A OUTPUT -d {shlex.quote(target)} -j ACCEPT"
    return f"iptables -A OUTPUT -p tcp -d {shlex.quote(target)} --dport {port} -j ACCEPT"


def _skip_comment(raw: str, *, reason: str) -> str:
    safe_raw = raw.replace("\r", "\\r").replace("\n", "\\n")
    return f"# skipped {reason}; use an IPv4 address or CIDR for firewall rules: {safe_raw}"
