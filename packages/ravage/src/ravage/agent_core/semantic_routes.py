from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from urllib.parse import parse_qsl, urlsplit

_FAMILY_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "path_traversal",
        (
            "path traversal",
            "directory traversal",
            "file_read_extract",
            "local file inclusion",
            " lfi",
            "../",
            "%2e",
            "/etc/passwd",
            "php://",
            "log poison",
        ),
    ),
    ("sql_injection", ("sqli", "sql injection", " union select", "sleep(", "benchmark(")),
    (
        "cross_site_scripting",
        (" xss", "dom_execution", "<script", "onerror=", "javascript:"),
    ),
    (
        "server_side_request_forgery",
        ("ssrf", "server-side request forgery", "169.254.169.254"),
    ),
    ("xml_external_entity", (" xxe", "external entity", "<!entity", "<!doctype")),
    ("template_injection", ("ssti", "template injection", "{{7*7}}", "${7*7}")),
    ("object_authorization", ("idor", "object authorization", "access control")),
    ("command_injection", ("command injection", "command_boundary", ";id", "|id", "$(id")),
    ("deserialization", ("deserial", "pickle", "unserialize", "object injection")),
    ("authentication", ("default_credentials", "login", "signin", "sign-in", "auth_session")),
    ("graphql", ("graphql", "introspectionquery", "__schema")),
    ("csrf", (" csrf", "cross-site request forgery")),
    ("file_upload", ("upload", "multipart/form-data")),
    ("exposure", ("direct_exposure", "secret_sweep", "backup", "robots.txt")),
    ("reconnaissance", ("surface_map", "recon", "crawl", "enumerat")),
)

# A run_probe action already names the specialist that will execute.  Prefer that
# structured identity when the specialist has one unambiguous vulnerability
# family; prose such as notes and fallback often mentions several later pivots.
# Multi-purpose specialists (for example file_fetch_parser) intentionally remain
# text-classified so their evidence-specific route can still be distinguished.
_PROBE_FAMILIES: dict[str, str] = {
    "surface_map": "reconnaissance",
    "secret_sweep": "exposure",
    "input_reflection": "cross_site_scripting",
    "xss_context": "cross_site_scripting",
    "dom_execution": "cross_site_scripting",
    "reflection_value_boundary": "cross_site_scripting",
    "stateful_session": "authentication",
    "csrf_session": "csrf",
    "default_credentials": "authentication",
    "jwt_exploit": "authentication",
    "server_rendering": "template_injection",
    "ssti_fingerprint": "template_injection",
    "ssti_deferred_context_closure": "template_injection",
    "data_query": "sql_injection",
    "sqli_differential": "sql_injection",
    "sqli_exploit": "sql_injection",
    "sqli_auth_transition": "sql_injection",
    "filtered_query_bypass": "sql_injection",
    "direct_exposure": "exposure",
    "cms_exposure": "exposure",
    "command_boundary": "command_injection",
    "werkzeug_console": "command_injection",
    "ssrf_boundary": "server_side_request_forgery",
    "file_read_extract": "path_traversal",
    "xxe_boundary": "xml_external_entity",
    "cookie_deserialization": "deserialization",
    "graphql_exploit": "graphql",
    "idor_boundary": "object_authorization",
}

_PAYLOAD_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("log_poisoning", ("log poison", "access.log", "<?php")),
    ("traversal_nested", ("....//", "..../")),
    ("traversal_double_encoded", ("%252e", "%25%32%65")),
    ("traversal_encoded", ("%2e", "%%32%65")),
    ("file_wrapper", ("php://", "data://", "expect://")),
    ("traversal_plain", ("../", "/etc/passwd")),
    ("sql_union", (" union ",)),
    ("sql_time", ("sleep(", "benchmark(", "pg_sleep(")),
    ("sql_boolean", (" or 1=1", " and 1=2")),
    ("xss_script", ("<script",)),
    ("xss_event", ("onerror=", "onload=")),
)

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", flags=re.IGNORECASE)
_QUOTED_PATH_RE = re.compile(r"['\"](/[^'\"\s]{1,500})['\"]")
_VARIABLE_PATH_SEGMENT_RE = re.compile(
    r"^(?:\d+|[0-9a-f]{8,}|[0-9a-f]{8}-[0-9a-f-]{27,}|[A-Za-z0-9_-]{24,})$",
    flags=re.IGNORECASE,
)


def semantic_action_route(
    action: Mapping[str, object],
    *,
    context: str = "",
) -> dict[str, object]:
    """
    Return a secret-free identity for the material route an action explores.

    Exact fingerprints distinguish byte-level changes. A semantic route groups
    attempts by vulnerability family, target, input, identity, and payload class.
    """
    kind = str(action.get("action") or "")
    body = _action_body(action)
    combined = f"{_action_metadata(action)} {body}".lower()
    endpoints = _endpoints(action, body=body)
    probe = str(action.get("probe") or "")
    return {
        "action": kind,
        "family": _action_family(action, combined=combined),
        "endpoints": endpoints,
        "method": _method(action, combined=combined, has_endpoint=bool(endpoints)),
        "inputs": _inputs(action, endpoints=endpoints),
        "identity": _identity(action, combined=combined),
        "payload_class": _payload_class(combined, probe=probe),
        "primitive": probe,
        "context": context,
    }


def semantic_action_fingerprint(
    action: Mapping[str, object],
    *,
    context: str = "",
) -> str:
    route = semantic_action_route(action, context=context)
    encoded = json.dumps(route, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]
    family = str(route.get("family") or "unknown")
    return f"{family}:{digest}"


def _action_body(action: Mapping[str, object]) -> str:
    bodies = {
        "run_command": action.get("command"),
        "run_python": action.get("code"),
        "validate_poc": json.dumps(action.get("steps") or [], sort_keys=True, default=str),
    }
    kind = str(action.get("action") or "")
    return str(bodies.get(kind) or action.get("probe") or "")


def _action_metadata(action: Mapping[str, object]) -> str:
    # fallback describes an action that is explicitly *not* being executed yet.
    # Including it makes the current route depend on an unrelated future pivot.
    keys = ("task_id", "probe", "strategy", "notes", "expected_signal")
    return " ".join(str(action.get(key) or "") for key in keys)


def _action_family(action: Mapping[str, object], *, combined: str) -> str:
    if str(action.get("action") or "") == "run_probe":
        probe = str(action.get("probe") or "").strip()
        structured_family = _PROBE_FAMILIES.get(probe)
        if structured_family:
            return structured_family
    return _first_marker_class(combined, classes=_FAMILY_MARKERS, default="unknown")


def _first_marker_class(
    text: str,
    *,
    classes: tuple[tuple[str, tuple[str, ...]], ...],
    default: str,
) -> str:
    for name, markers in classes:
        if any(marker in text for marker in markers):
            return name
    return default


def _endpoints(action: Mapping[str, object], *, body: str) -> list[str]:
    candidates = _step_endpoints(action)
    candidates.extend(match.group(0) for match in _URL_RE.finditer(body))
    if not candidates:
        candidates.extend(match.group(1) for match in _QUOTED_PATH_RE.finditer(body))
    normalized = [_normalize_endpoint(candidate) for candidate in candidates]
    return list(dict.fromkeys(item for item in normalized if item))[:4]


def _step_endpoints(action: Mapping[str, object]) -> list[str]:
    steps = action.get("steps")
    if not isinstance(steps, list):
        return []
    return [
        str(step.get("url") or step.get("path") or "").strip()
        for step in steps[:12]
        if isinstance(step, Mapping) and (step.get("url") or step.get("path"))
    ]


def _normalize_endpoint(value: str) -> str:
    cleaned = value.strip().rstrip("),;]}")
    try:
        parsed = urlsplit(cleaned)
    except ValueError:
        return ""
    path = parsed.path or "/"
    segments = [
        "{id}" if _VARIABLE_PATH_SEGMENT_RE.fullmatch(item) else item for item in path.split("/")
    ]
    normalized = "/".join(segments)
    query_names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    return normalized + ("?" + "&".join(query_names) if query_names else "")


def _method(action: Mapping[str, object], *, combined: str, has_endpoint: bool) -> str:
    explicit = str(action.get("method") or "").upper()
    if explicit:
        return explicit
    step_method = _first_step_method(action)
    if step_method:
        return step_method
    match = re.search(
        r"(?:-X|--request)\s+([A-Za-z]+)",
        combined,
        flags=re.IGNORECASE,
    )
    if match:
        return match.group(1).upper()
    inferred = next(
        (
            method
            for method in ("POST", "PUT", "PATCH", "DELETE", "GET")
            if re.search(rf"\b{method.lower()}\s*=|\.{method.lower()}\(", combined)
        ),
        "",
    )
    return inferred or ("GET" if has_endpoint else "")


def _first_step_method(action: Mapping[str, object]) -> str:
    steps = action.get("steps")
    if not isinstance(steps, list) or not steps or not isinstance(steps[0], Mapping):
        return ""
    return str(steps[0].get("method") or "GET").upper()


def _inputs(action: Mapping[str, object], *, endpoints: list[str]) -> list[str]:
    names = _explicit_inputs(action)
    names.extend(_step_inputs(action))
    names.extend(_endpoint_inputs(endpoints))
    return sorted(dict.fromkeys(name for name in names if name))[:12]


def _explicit_inputs(action: Mapping[str, object]) -> list[str]:
    return [
        str(action.get(key) or "").strip()
        for key in ("param", "parameter", "input", "field")
        if str(action.get(key) or "").strip()
    ]


def _step_inputs(action: Mapping[str, object]) -> list[str]:
    steps = action.get("steps")
    if not isinstance(steps, list):
        return []
    names: list[str] = []
    for step in steps[:12]:
        if not isinstance(step, Mapping):
            continue
        for key in ("form", "json", "params"):
            values = step.get(key)
            if isinstance(values, Mapping):
                names.extend(str(name) for name in values)
    return names


def _endpoint_inputs(endpoints: list[str]) -> list[str]:
    return [
        name
        for endpoint in endpoints
        if "?" in endpoint
        for name in endpoint.split("?", 1)[1].split("&")
    ]


def _identity(action: Mapping[str, object], *, combined: str) -> str:
    identity_keys = ("identity", "account", "role", "session_name")
    explicit = next(
        (key for key in identity_keys if str(action.get(key) or "").strip()),
        "",
    )
    if explicit:
        return explicit
    auth_markers = ("authorization", "cookie", "session", "bearer")
    return "authenticated" if any(marker in combined for marker in auth_markers) else "anonymous"


def _payload_class(text: str, *, probe: str) -> str:
    classified = _first_marker_class(text, classes=_PAYLOAD_MARKERS, default="")
    if classified:
        return classified
    if probe:
        return probe
    return "generic"
