from __future__ import annotations

import json
import secrets
from typing import cast
from urllib.parse import unquote_plus, urljoin, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeResponse, ProbeSession
from ravage.web_core.proof_recognizer import recognize_proofs


def _probe_catalog() -> tuple[tuple[str, str], ...]:
    return (
        ("surface_map", "fetch common paths and known endpoints; summarize status, headers, and body markers"),
        ("secret_sweep", "search common files, scripts, and known endpoints for credentials, configs, and paths"),
        ("input_reflection", "submit unique markers to parameters/forms and measure reflected or changed responses"),
        ("xss_context", "map reflected canary contexts and XSS filter behavior before browser execution"),
        ("stateful_session", "exercise login/register-like forms with cookies and CSRF-ish hidden fields"),
        ("csrf_session", "test CSRF token omission/reuse, logout invalidation, fixation hints, and session cookie attributes"),
        ("default_credentials", "try a bounded set of generic default credentials and immediately sweep authenticated proof pages"),
        ("server_rendering", "test controllable inputs for harmless template/expression evaluation"),
        ("ssti_fingerprint", "fingerprint server-side template engines with bounded harmless expression probes"),
        ("data_query", "run SQL-shaped baseline/error/boolean/timing probes with response deltas"),
        ("sqli_differential", "run paired SQLi/blind-SQLi probes across parameters, forms, and query-like endpoints"),
        ("sqli_exploit", "after SQLi evidence, run bounded error/UNION/boolean extraction and credential replay"),
        ("filtered_query_bypass", "for search/login inputs with blocked SQL keywords, try bounded filter-bypass and result-expansion variants"),
        ("preg_match_subject", "exercise PHP preg_match subject leaks on search-like inputs, including proof-shaped subjects"),
        ("direct_exposure", "check likely same-origin admin, debug, config, backup, and source paths with concise body capture"),
        ("cms_exposure", "follow same-origin CMS/WordPress backup-plugin configs, logs, manifests, and backup artifacts for exposed secrets or proofs"),
        ("command_boundary", "test command-shaped inputs for benign output or timing control"),
        ("ssrf_boundary", "test URL-fetch inputs for bounded loopback/internal fetch behavior"),
        ("reflection_value_boundary", "test reflected inputs with evidence-derived values to find proof branches or slow value boundaries"),
        ("file_fetch_parser", "test file path, URL fetch, upload/parser-like inputs for read/fetch behavior"),
        ("file_read_extract", "reuse a confirmed file-read/include request template for bounded proof extraction"),
        ("xxe_boundary", "test XML/SOAP/upload parsing surfaces with bounded external-entity file-read payloads"),
        ("cookie_deserialization", "forge response-returning pickle/YAML gadgets into serialized session cookies and read back the proof"),
        ("captcha_form_state", "refresh same-origin form CSRF/captcha/code state, solve visible/weak-cookie challenges, and preserve replay templates"),
        ("api_behavior", "map API/GraphQL/options behavior and object-boundary hints"),
        ("browser_boundary", "test CORS, clickjacking frame policy, WebSocket Origin handling, and browser storage exposures"),
        ("jwt_exploit", "forge observed JWTs (alg:none, weak-secret crack, key confusion) with escalated claims and replay into protected endpoints"),
        ("graphql_exploit", "introspect the GraphQL schema, generate sensitive-field queries, alias-batch object-id traversal, and enumerate mutations"),
        ("werkzeug_console", "complete an exposed Werkzeug debugger console: extract SECRET, eval Python when unlocked, compute the PIN from leaked machine bits, or abandon"),
        ("idor_boundary", "mutate object identifiers and compare access-control boundaries with preserved request templates"),
        ("dom_execution", "render reflected inputs in a real headless browser to confirm client-side script execution (not just reflection)"),
    )


def _common_paths(session: ProbeSession) -> list[str]:
    paths: list[str] = []
    for path in (
        "/",
        "/robots.txt",
        "/sitemap.xml",
        "/favicon.ico",
        "/api",
        "/api/",
        "/api/get",
        "/name/get",
        "/healthcheck",
        "/status",
        "/script",
        "/app",
        "/app/",
    ):
        paths.append(session.absolute(path))
    return paths


def _get_many(session: ProbeSession, urls: list[str], *, limit: int) -> list[ProbeResponse]:
    responses: list[ProbeResponse] = []
    for url in urls[:limit]:
        responses.append(session.get(url))
    return responses


def _get_many_with_headers(
    session: ProbeSession,
    urls: list[str],
    *,
    headers: dict[str, str],
    limit: int,
) -> list[ProbeResponse]:
    responses: list[ProbeResponse] = []
    for url in urls[:limit]:
        responses.append(session.get(url, headers=headers))
    return responses


def _response_summaries(
    responses: list[ProbeResponse],
    *,
    body_chars: int,
) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for response in responses:
        summaries.append(response.summary(body_chars=body_chars))
    return summaries


def _extend_response_summaries(
    requests: list[dict[str, object]],
    responses: list[ProbeResponse],
    *,
    body_chars: int,
) -> None:
    for response in responses:
        requests.append(response.summary(body_chars=body_chars))


def _has_ok_response(responses: list[ProbeResponse]) -> bool:
    for response in responses:
        if response.ok:
            return True
    return False


def _response_result_markers(body: str) -> list[str]:
    lowered = body.lower()
    markers: list[str] = []
    for marker in _RESULT_MARKER_WORDS:
        if marker in lowered:
            markers.append(marker)
    return markers


def _has_new_result_marker(body: str, baseline_body: str) -> bool:
    current = set(_response_result_markers(body))
    baseline = set(_response_result_markers(baseline_body))
    return bool(current - baseline)


_RESULT_MARKER_WORDS = (
    "no results",
    "not found",
    "invalid",
    "welcome",
    "admin",
    "user",
    "password",
    "login",
    "success",
    "denied",
    "forbidden",
)


def _common_secret_paths(session: ProbeSession) -> list[str]:
    paths: list[str] = []
    for path in _COMMON_SECRET_PATHS:
        paths.append(session.absolute(path))
    return paths


_COMMON_SECRET_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/config.php",
    "/config.json",
    "/package.json",
    "/composer.json",
    "/.well-known/security.txt",
    "/backup.zip",
    "/backup.tar.gz",
    "/admin",
    "/debug",
    "/actuator/env",
    "/actuator/configprops",
)


def _direct_exposure_urls(session: ProbeSession, state: AgentState) -> list[str]:
    paths = [
        "/admin",
        "/admin/",
        "/admin.php",
        "/private",
        "/private/",
        "/private.php",
        "/private?action=list",
        "/private.php?action=list",
        "/files",
        "/files/",
        "/files.php",
        "/files?action=list",
        "/files.php?action=list",
        "/dashboard",
        "/dashboard.php",
        "/flag",
        "/flag.php",
        "/secret",
        "/secret.php",
        "/debug",
        "/debug.php",
        "/config",
        "/config.php",
        "/config.json",
        "/db.php",
        "/database.php",
        "/package.json",
        "/composer.json",
        "/backup",
        "/backup/",
        "/backup.zip",
        "/backup.tar.gz",
        "/.env",
        "/.git/HEAD",
        "/.git/config",
        "/robots.txt",
        "/sitemap.xml",
        "/phpinfo.php",
        "/info.php",
        "/actuator",
        "/actuator/env",
        "/actuator/heapdump",
        "/actuator/configprops",
        "/actuator/mappings",
        "/api/docs",
        "/api/swagger.json",
        "/openapi.json",
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/graphql",
        "/graphiql",
        "/console",
        "/_debug_toolbar/",
        "/__debugger__",
        "/static/js/main.js.map",
    ]
    for endpoint in _surface_endpoints(state):
        path = _same_origin_path(endpoint, session)
        if not path:
            continue
        paths.append(path)
        paths.extend(_backup_variants(path))

    urls: list[str] = []
    for path in _dedupe(paths):
        urls.append(session.absolute(path))
    return urls


def _backup_variants(path: str) -> list[str]:
    if not path.startswith("/"):
        path = "/" + path
    variants: list[str] = []
    for suffix in _BACKUP_SUFFIXES:
        variants.append(path + suffix)
    return variants


_BACKUP_SUFFIXES = (
    "~",
    ".bak",
    ".old",
    ".orig",
    ".save",
    ".txt",
    ".swp",
    ".backup",
    ".disabled",
)


def _same_origin_path(url: str, session: ProbeSession) -> str:
    if not url:
        return ""
    if url.startswith("/"):
        return url
    origin = session.origin.rstrip("/")
    if url.rstrip("/") == origin:
        return "/"
    if url.startswith(origin + "/"):
        path = url[len(origin) :]
        return path or "/"
    return ""


def _looks_like_baseline_404(response: ProbeResponse, baseline_404: ProbeResponse) -> bool:
    if response.status == 404:
        return True
    if response.status != baseline_404.status:
        return False
    if response.status in {200, 401, 403, 500}:
        return False
    return abs(len(response.body) - len(baseline_404.body)) < 20


def _interesting_exposure_body(body: str, url: str) -> bool:
    lowered = body.lower()
    path = url.lower()
    if not body.strip():
        return False
    if recognize_proofs(body):
        return True
    if _path_looks_static_asset(path):
        return _contains_word(lowered, ("password=", "secret=", "token=", "api_key", "private key"))
    if _looks_like_secret_material(lowered):
        return True
    if _contains_word(lowered, ("mysqli", "pdo", "traceback", "warning")):
        return True
    if _contains_word(
        path,
        (
            "admin",
            "config",
            "db",
            "debug",
            "backup",
            "flag",
            "secret",
            "actuator",
            "openapi",
            "swagger",
            "package.json",
            "composer.json",
            "graphql",
            "graphiql",
        ),
    ):
        return True
    if _contains_word(lowered, ("openapi", "swagger", "dependencies", "version", "actuator", "graphql")):
        return True
    return False


def _looks_like_secret_material(lowered_body: str) -> bool:
    secret_markers = (
        "password=",
        "password:",
        "secret=",
        "secret:",
        "token=",
        "token:",
        "api_key",
        "apikey",
        "private key",
        "database_url",
        "db_password",
        "connectionstring",
    )
    return any(marker in lowered_body for marker in secret_markers)


def _path_looks_static_asset(path: str) -> bool:
    clean_path = path.split("?", 1)[0]
    for suffix in _STATIC_ASSET_SUFFIXES:
        if clean_path.endswith(suffix):
            return True
    return False


_STATIC_ASSET_SUFFIXES = (
    ".js",
    ".css",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".map",
)


def _surface_endpoints(state: AgentState) -> list[str]:
    endpoints: list[str] = []
    for item in _surface_endpoint_items(state):
        url = str(item.get("url") or "")
        if url:
            endpoints.append(url)
    return endpoints


def _surface_endpoint_items(state: AgentState) -> list[dict[str, object]]:
    return _list_of_dicts(state.surface.get("endpoints"))


def _script_urls(state: AgentState) -> list[str]:
    scripts: list[str] = []
    for page in _list_of_dicts(state.surface.get("pages")):
        scripts.extend(_string_items(page.get("scripts")))
    return scripts


def _parameter_targets(state: AgentState, *, limit: int) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for param in _list_of_dicts(state.surface.get("parameters")):
        name = str(param.get("name") or "")
        if not name:
            continue
        locations = _string_items(param.get("locations"))
        if not locations:
            locations = [str(state.surface.get("target_url") or "")]
        for location in locations[:3]:
            targets.append(
                {
                    "name": name,
                    "url": location,
                    "sources": _string_items(param.get("sources")),
                    "hints": _string_items(param.get("hints")),
                    "priority": _int_value(param.get("priority")),
                }
            )
            seen.add((name, location))
    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "")
    signal_endpoints = [
        url
        for url in (_clean_signal_endpoint(str(value), origin=origin) for value in state.signals.get("endpoints", []))
        if url and _url_in_scope(url, origin)
    ]
    if not signal_endpoints and state.surface.get("target_url"):
        signal_endpoints = [str(state.surface.get("target_url") or "")]
    for name in state.signals.get("parameters", []):
        text = str(name)
        if not text:
            continue
        for location in signal_endpoints[:6]:
            key = (text, location)
            if key in seen:
                continue
            seen.add(key)
            targets.append(
                {
                    "name": text,
                    "url": location,
                    "sources": ["signal"],
                    "hints": ["observed_input_name"],
                    "priority": 18,
                }
            )
    targets.sort(key=_parameter_target_sort_key)
    return targets[:limit]


def _parameter_target_sort_key(target: dict[str, object]) -> tuple[int, str]:
    priority = -_int_value(target.get("priority"))
    name = str(target.get("name"))
    return priority, name


def _clean_signal_endpoint(value: str, *, origin: str) -> str:
    text = value.strip().strip("`'\"").rstrip(").,;:]}>'\"")
    if not text or text.startswith("//"):
        return ""
    if text.startswith("/"):
        if not origin:
            return text
        text = origin.rstrip("/") + text
    try:
        parts = urlsplit(text)
    except ValueError:
        return ""
    if parts.scheme and parts.scheme not in {"http", "https"}:
        return ""
    if "__debugger__" in parts.query.lower():
        return ""
    if _query_looks_probe_artifact(parts.query):
        return ""
    if _path_looks_markup_fragment(parts.path):
        return ""
    if any(char in parts.path for char in ("'", '"', "`", "[", "]", "{", "}", "<", ">")):
        return ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def _path_looks_markup_fragment(path: str) -> bool:
    lowered = path.lower().strip("/")
    if lowered in {
        "a",
        "body",
        "button",
        "div",
        "form",
        "h1",
        "h2",
        "h3",
        "head",
        "html",
        "li",
        "nav",
        "p",
        "script",
        "span",
        "table",
        "tbody",
        "td",
        "th",
        "thead",
        "title",
        "tr",
        "ul",
    }:
        return True
    return False


def _query_looks_probe_artifact(query: str) -> bool:
    if not query:
        return False
    lowered = unquote_plus(query).lower()
    return any(
        marker in lowered
        for marker in (
            "ravage_",
            "; echo ",
            "; sleep ",
            "&& echo ",
            "&& sleep ",
            "|echo ",
            "| sleep ",
            "$(echo ",
            "`echo ",
            "--host=",
            "-t custom ",
            "{{",
            "{%",
            "<script",
            "../",
            " union ",
        )
    )


def _form_targets(state: AgentState, *, limit: int) -> list[dict[str, object]]:
    forms = _list_of_dicts(state.surface.get("forms"))
    for value in state.signals.get("forms", []):
        try:
            decoded = json.loads(str(value))
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            forms.append(decoded)
    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "")
    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for form in forms:
        if not _form_in_scope(form, origin=origin):
            continue
        key = (
            str(form.get("method") or "GET").upper(),
            str(form.get("action") or ""),
            json.dumps(form.get("inputs") or [], sort_keys=True),
        )
        if key not in deduped:
            deduped[key] = form
    return list(deduped.values())[:limit]


def _form_in_scope(form: dict[str, object], *, origin: str) -> bool:
    action = str(form.get("action") or "")
    return _url_in_scope(action, origin)


def _url_in_scope(url: str, origin: str) -> bool:
    if not url or not origin:
        return True
    try:
        action_parts = urlsplit(url)
        origin_parts = urlsplit(origin)
    except ValueError:
        return False
    if not action_parts.scheme and not action_parts.netloc:
        return True
    return (action_parts.scheme, action_parts.netloc) == (origin_parts.scheme, origin_parts.netloc)


def _absolute_same_origin_url(value: object, *, base_url: str) -> str:
    """Resolve one observed URL while rejecting malformed or cross-origin targets."""
    text = str(value or "").strip()
    if not text or not base_url:
        return ""
    try:
        absolute = urljoin(base_url, text)
    except ValueError:
        return ""
    cleaned = _clean_signal_endpoint(absolute, origin=base_url)
    if not cleaned or not _url_in_scope(cleaned, base_url):
        return ""
    try:
        parsed = urlsplit(cleaned)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return ""
    return cleaned


def _url_looks_static_oauth_redirect(url: str) -> bool:
    try:
        path = urlsplit(url).path.lower().rstrip("/")
    except ValueError:
        return False
    return path.endswith("/oauth2-redirect") or path.endswith("/oauth2-redirect.html")


def _form_input_names(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        input_type = str(input_field.get("type") or "").lower()
        if name and input_type not in {"hidden", "submit", "button", "reset", "file"}:
            names.append(name)
    return names[:8]


def _form_brief(form: dict[str, object]) -> dict[str, object]:
    return {
        "id": form.get("id"),
        "method": form.get("method"),
        "action": form.get("action"),
        "categories": _string_items(form.get("categories")),
        "inputs": _form_input_names(form),
    }


def _form_text(form: dict[str, object]) -> str:
    return json.dumps(form, sort_keys=True).lower()


def _notable_response(response: ProbeResponse) -> dict[str, object]:
    return {
        "type": "notable_response",
        "url": response.url,
        "status": response.status,
        "final_url": response.final_url,
        "headers": response.headers,
        "body_len": len(response.body),
        "body_markers": _body_words(response.body, ("admin", "debug", "flag", "error", "traceback", "login", "register", "forbidden")),
    }


def _canonical_host_headers(
    session: ProbeSession,
    state: AgentState,
    responses: list[ProbeResponse] | None = None,
) -> list[dict[str, str]]:
    hosts: list[str] = []
    hosts.extend(str(value).strip() for value in state.signals.get("canonical_hosts", []) if str(value).strip())
    for response in responses or []:
        hosts.extend(_canonical_hosts_from_response(session, response))
    result: list[dict[str, str]] = []
    for host in _dedupe([host for host in hosts if _safe_host_header(host)]):
        result.append({"Host": host})
    return result[:4]


def _canonical_host_signal_findings(session: ProbeSession, responses: list[ProbeResponse]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for response in responses:
        for host in _canonical_hosts_from_response(session, response):
            if not _safe_host_header(host):
                continue
            findings.append(
                {
                    "type": "canonical_host_header_signal",
                    "host": host,
                    "headers": {"Host": host},
                    "source_url": response.url,
                    "location": response.headers.get("location", ""),
                    "detail": "same-target local redirect advertised a default host; replay same-origin probes with this Host header",
                }
            )
    deduped: dict[str, dict[str, object]] = {}
    for finding in findings:
        deduped.setdefault(str(finding.get("host") or ""), finding)
    return list(deduped.values())[:4]


def _canonical_hosts_from_response(session: ProbeSession, response: ProbeResponse) -> list[str]:
    location = str(response.headers.get("location") or "")
    if not location:
        return []
    target = urlsplit(session.target_url)
    redirected = urlsplit(session.absolute(location))
    if target.scheme not in {"http", "https"} or redirected.scheme != target.scheme:
        return []
    if not _local_hostname(str(target.hostname or "")) or not _local_hostname(str(redirected.hostname or "")):
        return []
    target_port = target.port or _default_port(target.scheme)
    redirected_port = redirected.port or _default_port(redirected.scheme)
    if target_port in {None, _default_port(target.scheme)}:
        return []
    if redirected_port != _default_port(redirected.scheme):
        return []
    host = str(redirected.hostname or "").strip()
    return [host] if host else []


def _safe_host_header(host: str) -> bool:
    if not host or any(ch in host for ch in "\r\n/:@"):
        return False
    return _local_hostname(host)


def _local_hostname(host: str) -> bool:
    lowered = host.lower().strip("[]")
    return lowered in {"localhost", "127.0.0.1", "::1"} or lowered.startswith("127.")


def _default_port(scheme: str) -> int | None:
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None


def _body_words(body: str, words: tuple[str, ...]) -> list[str]:
    lowered = body.lower()
    found: list[str] = []
    for word in words:
        if word in lowered:
            found.append(word)
    return found


def _name_looks_command(name: str) -> bool:
    lowered = name.lower()
    return _contains_word(
        lowered,
        (
            "host",
            "domain",
            "ip",
            "cmd",
            "command",
            "ping",
            "url",
            "service",
            "tool",
            "target",
            "address",
            "server",
            "lookup",
            "action",
            "name",
        ),
    )


def _marker(prefix: str) -> str:
    return f"RAVAGE_{prefix}_{secrets.token_hex(5)}"


def _contains_word(text: str, words: tuple[str, ...]) -> bool:
    for word in words:
        if word in text:
            return True
    return False


def _contains_word_in_list(values: list[str], words: tuple[str, ...]) -> bool:
    for value in values:
        if value in words:
            return True
    return False


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(dict(item))
    return items


def _dict_value(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return cast(dict[str, object], value)
    return {}


def _string_items(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        if item:
            items.append(str(item))
    return items


def _int_value(value: object, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        return int(value)
    return default
