from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol
from urllib.parse import urlsplit, urlunsplit

from ravage.run_data.brief import load_engagement_brief
from ravage.run_data.workspace import AgentWorkspace
from ravage.web_core.scope_policy import is_local_url

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from pathlib import Path

    from pentest_schemas import EngagementBrief


HOSTING_LAYER_EVENT_KIND = "hosting_layer_checked"
HOSTING_LAYER_AGENT_NAME = "hosting-layer"
DEFAULT_TIMEOUT_SECONDS = 15
MAX_CAPTURE_CHARS = 12_000
HTTP_REDIRECT_MIN = 300
HTTP_REDIRECT_MAX = 400

_STATUS_RE = re.compile(r"^HTTP/\S+\s+(\d{3})(?:\s+(.*))?$", re.IGNORECASE)
_HEADER_RE = re.compile(r"^([^:\s][^:]*):\s*(.*)$")
_LIVE_SITE_KEYS = (
    "live_website",
    "live_site",
    "live_url",
    "production_url",
    "public_url",
)
_LIVE_SITE_LIST_KEYS = (
    "live_websites",
    "live_sites",
    "live_urls",
    "production_urls",
    "public_urls",
)
_HOSTING_CONTEXT_KEYS = ("hosting_check", "hosting_layer", "live_hosting")


@dataclass(frozen=True)
class HostingCommandResult:
    exit_code: int | None
    stdout: str
    stderr: str
    error: str = ""
    timed_out: bool = False


class HostingCommandRunner(Protocol):
    def __call__(
        self,
        command: tuple[str, ...],
        *,
        timeout_seconds: int,
    ) -> HostingCommandResult: ...


def run_configured_hosting_layer_agent(
    *,
    brief_path: Path,
    target_url: str,
    workspace_dir: Path,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    runner: HostingCommandRunner | None = None,
) -> dict[str, object] | None:
    brief = load_engagement_brief(brief_path)
    live_sites = configured_live_websites(brief, target_url=target_url)
    if not live_sites:
        return None
    workspace = AgentWorkspace.open(workspace_dir)
    return run_hosting_layer_agent(
        live_sites=live_sites,
        workspace=workspace,
        timeout_seconds=timeout_seconds,
        runner=runner,
    )


def configured_live_websites(brief: EngagementBrief, *, target_url: str = "") -> list[str]:
    context = getattr(brief, "context", {})
    if not isinstance(context, dict):
        return []

    raw_sites: list[object] = []
    raw_sites.extend(_values_for_keys(context, _LIVE_SITE_KEYS, list_keys=False))
    raw_sites.extend(_values_for_keys(context, _LIVE_SITE_LIST_KEYS, list_keys=True))
    raw_sites.extend(_nested_live_site_values(context))

    normalized_target = _normalized_origin(target_url)
    sites: list[str] = []
    for raw in raw_sites:
        site = _normalized_origin(str(raw))
        if not site:
            continue
        if site == normalized_target:
            continue
        if site not in sites:
            sites.append(site)
    return sites


def _nested_live_site_values(context: Mapping[object, object]) -> list[object]:
    raw_sites: list[object] = []
    for key in _HOSTING_CONTEXT_KEYS:
        nested = context.get(key)
        if nested is False:
            continue
        if isinstance(nested, dict):
            if nested.get("enabled") is False:
                continue
            raw_sites.extend(_values_for_keys(nested, _LIVE_SITE_KEYS, list_keys=False))
            raw_sites.extend(_values_for_keys(nested, _LIVE_SITE_LIST_KEYS, list_keys=True))
            raw_sites.extend(_values_for_keys(nested, ("url", "site", "website"), list_keys=False))
            raw_sites.extend(
                _values_for_keys(nested, ("urls", "sites", "websites"), list_keys=True)
            )
        elif isinstance(nested, list | tuple | set):
            raw_sites.extend(nested)
        elif nested:
            raw_sites.append(nested)
    return raw_sites


def run_hosting_layer_agent(
    *,
    live_sites: Iterable[str],
    workspace: AgentWorkspace,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    runner: HostingCommandRunner | None = None,
) -> dict[str, object]:
    normalized_sites = _dedupe(
        site for site in (_normalized_origin(item) for item in live_sites) if site
    )
    commands = _hosting_commands(normalized_sites)
    checks: list[dict[str, object]] = []
    command_runner = runner or _run_curl_head
    timeout = max(1, min(timeout_seconds, 60))

    for command in commands:
        started = time.monotonic()
        result = command_runner(command, timeout_seconds=timeout)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        checks.append(_check_payload(command, result, elapsed_ms=elapsed_ms))

    payload: dict[str, object] = {
        "agent": HOSTING_LAYER_AGENT_NAME,
        "mode": "curl_head_matrix",
        "configured_live_sites": normalized_sites,
        "checks": checks,
        "findings": _hosting_findings(checks),
    }
    payload["summary"] = _hosting_summary(checks)
    workspace.record_event(kind=HOSTING_LAYER_EVENT_KIND, payload=payload)
    return payload


def _values_for_keys(
    mapping: Mapping[object, object],
    keys: tuple[str, ...],
    *,
    list_keys: bool,
) -> list[object]:
    values: list[object] = []
    for key in keys:
        if key not in mapping:
            continue
        value = mapping.get(key)
        if list_keys and isinstance(value, list | tuple | set):
            values.extend(value)
        elif list_keys or value is not None:
            values.append(value)
    return values


def _normalized_origin(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    try:
        parsed = urlsplit(text)
        _ = parsed.port
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return ""
    if parsed.username or parsed.password:
        return ""
    origin = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), "", "", ""))
    if is_local_url(origin):
        return ""
    return origin.rstrip("/")


def _hosting_commands(live_sites: list[str]) -> list[tuple[str, ...]]:
    urls: list[str] = []
    for site in live_sites:
        urls.extend(_head_urls_for_site(site))
    return [("curl", "-I", url) for url in _dedupe(urls)]


def _head_urls_for_site(site: str) -> list[str]:
    parsed = urlsplit(site)
    host = parsed.hostname
    if host is None:
        return []
    apex = host[4:] if host.lower().startswith("www.") else host
    hosts = [apex]
    if _www_variant_supported(apex):
        hosts.append(f"www.{apex}")
    return [
        urlunsplit((scheme, _netloc_for(hostname, parsed.port), "", "", ""))
        for scheme in ("https", "http")
        for hostname in hosts
    ]


def _www_variant_supported(host: str) -> bool:
    return "." in host and ":" not in host and not re.fullmatch(r"[\d.]+", host)


def _netloc_for(host: str, port: int | None) -> str:
    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    return netloc


def _run_curl_head(
    command: tuple[str, ...],
    *,
    timeout_seconds: int,
) -> HostingCommandResult:
    if shutil.which(command[0]) is None:
        return HostingCommandResult(
            exit_code=None,
            stdout="",
            stderr="",
            error=f"{command[0]} not found",
        )
    try:
        completed = subprocess.run(  # noqa: S603
            list(command),
            capture_output=True,
            text=False,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return HostingCommandResult(
            exit_code=None,
            stdout=_clip(_decode(exc.stdout), MAX_CAPTURE_CHARS),
            stderr=_clip(_decode(exc.stderr), MAX_CAPTURE_CHARS),
            error=f"timed out after {timeout_seconds}s",
            timed_out=True,
        )
    except OSError as exc:
        return HostingCommandResult(
            exit_code=None,
            stdout="",
            stderr=str(exc),
            error=str(exc),
        )
    return HostingCommandResult(
        exit_code=completed.returncode,
        stdout=_clip(_decode(completed.stdout), MAX_CAPTURE_CHARS),
        stderr=_clip(_decode(completed.stderr), MAX_CAPTURE_CHARS),
    )


def _check_payload(
    command: tuple[str, ...],
    result: HostingCommandResult,
    *,
    elapsed_ms: int,
) -> dict[str, object]:
    status_line, status_code = _status_from_headers(result.stdout)
    headers = _headers_from_stdout(result.stdout)
    return {
        "command": " ".join(command),
        "url": command[-1],
        "ok": result.exit_code == 0 and not result.error and not result.timed_out,
        "exit_code": result.exit_code,
        "status_code": status_code,
        "status_line": status_line,
        "elapsed_ms": elapsed_ms,
        "headers": headers,
        "location": headers.get("location", ""),
        "server": headers.get("server", ""),
        "cloudflare": _cloudflare_observed(headers),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "error": result.error,
        "timed_out": result.timed_out,
    }


def _status_from_headers(stdout: str) -> tuple[str, int | None]:
    for line in stdout.replace("\r\n", "\n").splitlines():
        stripped = line.strip()
        match = _STATUS_RE.match(stripped)
        if match:
            return stripped, int(match.group(1))
    return "", None


def _headers_from_stdout(stdout: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in stdout.replace("\r\n", "\n").splitlines():
        match = _HEADER_RE.match(line.strip())
        if not match:
            continue
        key = match.group(1).strip().lower()
        value = match.group(2).strip()
        if key in headers:
            headers[key] = f"{headers[key]}, {value}"
        else:
            headers[key] = value
    return headers


def _cloudflare_observed(headers: dict[str, str]) -> bool:
    server = headers.get("server", "").lower()
    return server == "cloudflare" or any(key.startswith("cf-") for key in headers)


def _hosting_findings(checks: list[dict[str, object]]) -> list[str]:
    findings: list[str] = []
    for check in checks:
        url = str(check.get("url") or "")
        status = check.get("status_code")
        location = str(check.get("location") or "")
        if isinstance(status, int):
            if HTTP_REDIRECT_MIN <= status < HTTP_REDIRECT_MAX and location:
                findings.append(f"{url} returned HTTP {status} and redirects to {location}.")
            else:
                findings.append(f"{url} returned HTTP {status}.")
            continue
        error = str(check.get("error") or check.get("stderr") or "").strip()
        findings.append(f"{url} did not return headers: {_clip(error or 'no response', 180)}.")

    if any(bool(check.get("cloudflare")) for check in checks):
        findings.append("Cloudflare response headers were observed on at least one live endpoint.")
    findings.extend(_variant_findings(checks))
    return _dedupe(findings)


def _variant_findings(checks: list[dict[str, object]]) -> list[str]:
    by_url = {str(check.get("url") or ""): check for check in checks}
    findings: list[str] = []
    for url, check in by_url.items():
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if host.startswith("www."):
            continue
        paired = urlunsplit((parsed.scheme, _netloc_for(f"www.{host}", parsed.port), "", "", ""))
        other = by_url.get(paired)
        if other is None:
            continue
        status = check.get("status_code")
        other_status = other.get("status_code")
        if isinstance(status, int) and isinstance(other_status, int) and status != other_status:
            findings.append(
                f"{parsed.scheme.upper()} apex and www variants returned different statuses "
                f"({status} vs {other_status})."
            )
    return findings


def _hosting_summary(checks: list[dict[str, object]]) -> str:
    if not checks:
        return "No hosting-layer checks were run."
    successes = sum(1 for check in checks if check.get("ok") is True)
    status_codes = [
        str(check.get("status_code"))
        for check in checks
        if isinstance(check.get("status_code"), int)
    ]
    codes = ", ".join(status_codes) if status_codes else "none"
    return (
        f"Ran {len(checks)} curl -I hosting check(s); "
        f"successful commands={successes}; HTTP statuses={codes}."
    )


def _dedupe(items: Iterable[str]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        values.append(text)
    return values


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", errors="replace")


def _clip(value: str, limit: int) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 15)].rstrip() + " [truncated]"
