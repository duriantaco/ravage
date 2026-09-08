"""Process-local cockpit capabilities and an origin-scoped browser handoff."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from email.message import Message

BOOTSTRAP_PATH = "/_cockpit/session.js"
BOOTSTRAP_HTML = b"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ravage Cockpit</title></head><body>
<p id="session-status">Opening Ravage Cockpit...</p>
<script type="module" src="/_cockpit/session.js"></script>
</body></html>
"""
BOOTSTRAP_SCRIPT = b"""import { openCockpitSession } from "/src/transport.js";
openCockpitSession();
"""
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self'; connect-src 'self'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'none'"
)
_WILDCARD_HOSTS = frozenset({"", "0.0.0.0", "::"})  # noqa: S104


def _authority(host: str, port: int) -> str:
    rendered = f"[{host}]" if ":" in host else host.lower()
    return f"{rendered}:{port}"


def _matches(presented: str, expected: str) -> bool:
    return secrets.compare_digest(presented.encode("utf-8"), expected.encode("ascii"))


@dataclass(frozen=True)
class CockpitAccess:
    bind_host: str
    capability: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    session: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)

    def launch_url(self, port: int) -> str:
        host = "127.0.0.1" if self.bind_host in _WILDCARD_HOSTS else self.bind_host
        return f"http://{_authority(host, port)}/#token={self.capability}"

    def request_origin(self, headers: Message, *, local_host: str, port: int) -> str | None:
        """Accept only the configured host or this connection's local interface."""
        hosts = headers.get_all("Host", [])
        if len(hosts) != 1:
            return None
        host = hosts[0].lower()
        allowed_hosts = {local_host}
        if self.bind_host not in _WILDCARD_HOSTS:
            allowed_hosts.add(self.bind_host)
        authorities = {_authority(value, port) for value in allowed_hosts}
        if port == 80:  # noqa: PLR2004
            authorities.update(value.lower() for value in allowed_hosts)
        return f"http://{host}" if host in authorities else None

    def bearer_authorized(self, headers: Message) -> bool:
        values = headers.get_all("Authorization", [])
        return (
            len(values) == 1
            and values[0].startswith("Bearer ")
            and _matches(values[0][len("Bearer ") :], self.capability)
        )

    def authorized(self, headers: Message) -> bool:
        values = headers.get_all("Authorization", [])
        if len(values) != 1 or not values[0].startswith("Bearer "):
            return False
        token = values[0][len("Bearer ") :]
        return _matches(token, self.capability) or _matches(token, self.session)
