from __future__ import annotations

import ipaddress
import json
import shlex
import sys
from pathlib import Path
from urllib.parse import urlparse

EXPECTED_ARG_COUNT = 2
USAGE = "usage: generate_iptables.py <scope-json-path|->"
IN_SCOPE_LIST_ERROR = "scope.in_scope must be a non-empty list"
OUT_OF_SCOPE_LIST_ERROR = "scope.out_of_scope must be a list"
IN_SCOPE_ENTRY_ERROR = "scope.in_scope entries must be strings"
OUT_OF_SCOPE_ENTRY_ERROR = "scope.out_of_scope entries must be strings"
IPV4_VERSION = 4


def read_scope(path_arg: str) -> dict[str, object]:
    if path_arg == "-":
        return json.loads(sys.stdin.read())
    return json.loads(Path(path_arg).read_text(encoding="utf-8"))


def normalize_target(raw: str) -> tuple[str, int | None, bool]:
    parsed = urlparse(raw)
    if parsed.scheme and parsed.hostname:
        port = parsed.port
        if port is None and parsed.scheme == "http":
            port = 80
        if port is None and parsed.scheme == "https":
            port = 443
        destination = stable_ipv4_destination(parsed.hostname)
        return (destination or parsed.hostname, port, destination is not None)

    destination = stable_ipv4_destination(raw)
    return (destination or raw, None, destination is not None)


def stable_ipv4_destination(raw: str) -> str | None:
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    if network.version != IPV4_VERSION:
        return None
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return str(network)


def drop_rule(target: str) -> str:
    return f"iptables -A OUTPUT -d {shlex.quote(target)} -j DROP"


def accept_rule(target: str, port: int | None) -> str:
    if port is None:
        return f"iptables -A OUTPUT -d {shlex.quote(target)} -j ACCEPT"
    return f"iptables -A OUTPUT -p tcp -d {shlex.quote(target)} --dport {port} -j ACCEPT"


def skip_comment(raw: str, *, reason: str) -> str:
    safe_raw = raw.replace("\r", "\\r").replace("\n", "\\n")
    return f"# skipped {reason}; use an IPv4 address or CIDR for firewall rules: {safe_raw}"


def render_rules(scope: dict[str, object]) -> list[str]:
    in_scope = scope.get("in_scope", [])
    out_of_scope = scope.get("out_of_scope", [])

    if not isinstance(in_scope, list) or not in_scope:
        raise ValueError(IN_SCOPE_LIST_ERROR)
    if not isinstance(out_of_scope, list):
        raise TypeError(OUT_OF_SCOPE_LIST_ERROR)

    rules = [
        "iptables -F OUTPUT",
        "iptables -P OUTPUT DROP",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]

    for raw in out_of_scope:
        if not isinstance(raw, str):
            raise TypeError(OUT_OF_SCOPE_ENTRY_ERROR)
        target, _port, stable = normalize_target(raw)
        if not stable:
            rules.append(skip_comment(raw, reason="hostname out_of_scope entry"))
            continue
        rules.append(drop_rule(target))

    for raw in in_scope:
        if not isinstance(raw, str):
            raise TypeError(IN_SCOPE_ENTRY_ERROR)
        target, port, stable = normalize_target(raw)
        if not stable:
            rules.append(skip_comment(raw, reason="hostname in_scope entry"))
            continue
        rules.append(accept_rule(target, port))

    return rules


def main() -> None:
    if len(sys.argv) != EXPECTED_ARG_COUNT:
        raise SystemExit(USAGE)

    try:
        rules = render_rules(read_scope(sys.argv[1]))
    except (TypeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

    sys.stdout.write("\n".join(rules))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
