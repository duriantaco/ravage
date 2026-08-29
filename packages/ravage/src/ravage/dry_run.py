from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Callable
from urllib.parse import parse_qsl, urljoin, urlsplit
from urllib.request import urlopen

from ravage.run_data.audit import AuditStore
from ravage.run_data.brief import load_engagement_brief

PROBE_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class RouteParam:
    name: str
    location: str = "query"
    example_value: str = ""


@dataclass(frozen=True)
class RouteProbe:
    method: str
    path: str
    params: list[RouteParam] = field(default_factory=list)


@dataclass(frozen=True)
class PageProbe:
    path: str
    url: str
    status_code: int | None
    body: str
    error: str | None = None


@dataclass(frozen=True)
class DryRunSettings:
    db_path: Path | None = None
    stdout: IO[str] | None = None
    fetcher: Callable[[str, float], tuple[int, str]] | None = None


def parse_openapi_routes(body: str) -> list[RouteProbe]:
    raw = json.loads(body)
    routes: list[RouteProbe] = []
    for path, methods in sorted(raw.get("paths", {}).items()):
        if not isinstance(methods, dict):
            continue
        for method, detail in sorted(methods.items()):
            params: list[RouteParam] = []
            if isinstance(detail, dict):
                for item in detail.get("parameters", []):
                    if isinstance(item, dict):
                        params.append(
                            RouteParam(str(item.get("name") or ""), str(item.get("in") or "query"))
                        )
                content = (
                    detail.get("requestBody", {}).get("content", {})
                    if isinstance(detail.get("requestBody"), dict)
                    else {}
                )
                for media in content.values() if isinstance(content, dict) else []:
                    schema = media.get("schema", {}) if isinstance(media, dict) else {}
                    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
                    for name in properties:
                        params.append(RouteParam(str(name), "body"))
            routes.append(RouteProbe(method.upper(), path, params))
    return routes


def discover_bwapp_routes(base_url: str, probes: tuple[PageProbe, ...]) -> list[RouteProbe]:
    routes = [RouteProbe("GET", "login.php"), RouteProbe("GET", "portal.php")]
    base_path = urlsplit(base_url).path.rstrip("/") + "/"
    for probe in probes:
        for href in re.findall(r"""href=['"]([^'"]+)['"]""", probe.body):
            if "sqli" in href:
                absolute = urljoin(base_url, href)
                parsed = urlsplit(absolute)
                path = parsed.path
                if path.startswith(base_path):
                    path = path[len(base_path) :]
                else:
                    path = path.lstrip("/")
                route_path = path + (f"?{parsed.query}" if parsed.query else "")
                params = [RouteParam(name) for name, _value in parse_qsl(parsed.query)]
                routes.append(RouteProbe("GET", route_path, params))
    return routes


def run_dry_run(*, brief_path: Path, target_url: str, settings: DryRunSettings) -> Path | None:
    brief = load_engagement_brief(brief_path)
    openapi_url = urljoin(target_url.rstrip("/") + "/", "openapi.json")
    fetcher = settings.fetcher or _fetch_text
    stdout = settings.stdout
    if stdout is not None:
        stdout.write("[plan] mode=dry-run profile=openapi real_agents=not_started\n")
        stdout.write("[state] recon_started\n")
        stdout.write(f"[tool:http_get] GET {openapi_url}\n")

    status, body = fetcher(openapi_url, PROBE_TIMEOUT_SECONDS)
    routes = parse_openapi_routes(body)
    endpoints = [
        {
            "method": route.method,
            "url": urljoin(target_url.rstrip("/") + "/", route.path.lstrip("/")),
            "params": [
                {
                    "name": param.name,
                    "location": param.location,
                    "example_value": param.example_value,
                }
                for param in route.params
            ],
        }
        for route in routes
    ]
    if stdout is not None:
        for route in routes:
            suffix = ""
            if route.params:
                suffix = " params=" + ",".join(param.name for param in route.params)
            stdout.write(f"[recon] discovered {route.method} {route.path}{suffix}\n")
        stdout.write(f"[attack_surface] endpoints={len(endpoints)}\n")
        stdout.write("[state] exploit_skipped\n")

    if settings.db_path is not None:
        audit = AuditStore(settings.db_path, scope=brief.scope)
        try:
            records = (
                (
                    "orchestrator",
                    "engagement_loaded",
                    {"brief_path": str(brief_path)},
                ),
                (
                    "orchestrator",
                    "scope_firewall_plan_generated",
                    {
                        "in_scope": [str(item) for item in brief.scope.in_scope],
                        "out_of_scope": [str(item) for item in brief.scope.out_of_scope],
                    },
                ),
                (
                    "recon_dry_run",
                    "http_probe_completed",
                    {"url": openapi_url, "status_code": status},
                ),
                (
                    "recon_dry_run",
                    "attack_surface_emitted",
                    {"endpoints": endpoints},
                ),
                (
                    "exploit_dry_run",
                    "phase_skipped",
                    {"reason": "dry_run"},
                ),
                (
                    "orchestrator",
                    "run_completed",
                    {"mode": "dry-run"},
                ),
            )
            for actor, action, payload in records:
                audit.record(
                    engagement_id=brief.engagement_id,
                    actor=actor,
                    action=action,
                    payload=payload,
                )
        finally:
            audit.close()
    return settings.db_path


def _fetch_text(url: str, timeout: float) -> tuple[int, str]:
    with urlopen(url, timeout=timeout) as response:  # noqa: S310 - caller supplies scoped target.
        body = response.read().decode("utf-8", errors="replace")
        return int(response.status), body
