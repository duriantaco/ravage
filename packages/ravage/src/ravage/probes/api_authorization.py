from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING
from urllib.parse import unquote_plus, urlsplit

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState

_SCHEMA = "ravage.api_authorization_inventory.v1"
_WRITE_METHODS = {"POST", "PUT", "PATCH"}
_OBSERVED_HTTP_METHODS = {"DELETE", "GET", "HEAD", "PATCH", "POST", "PUT"}
_METHOD_OVERRIDE_FIELDS = {"http_method", "method", "method_override"}
_METHOD_OVERRIDE_HEADERS = {"x_http_method_override", "x_method_override"}
_PRIVILEGED_PATH_SEGMENTS = {
    "admin",
    "audit",
    "backoffice",
    "billing",
    "export",
    "internal",
    "invite",
    "invites",
    "manage",
    "management",
    "moderator",
    "permissions",
    "roles",
    "staff",
    "superuser",
    "system",
}
_AUTHORIZATION_FIELDS = {
    "access_level",
    "account_id",
    "admin",
    "is_admin",
    "is_staff",
    "is_superuser",
    "org_id",
    "organization_id",
    "owner_id",
    "permission",
    "permissions",
    "privilege",
    "role",
    "roles",
    "scope",
    "scopes",
    "tenant_id",
    "user_id",
}
_BUSINESS_CONTROL_FIELDS = {
    "active",
    "approved",
    "balance",
    "blocked",
    "credit",
    "discount",
    "plan",
    "price",
    "status",
    "tier",
    "verified",
}
_SAFE_PROVENANCE = {
    "fetch",
    "form",
    "jquery_ajax",
    "link",
    "openapi",
    "page",
    "request_template",
    "script",
    "xhr",
}
_SAFE_ROUTE_SEGMENTS = _PRIVILEGED_PATH_SEGMENTS | {
    "account",
    "accounts",
    "api",
    "auth",
    "cart",
    "carts",
    "checkout",
    "customer",
    "customers",
    "graphql",
    "invoice",
    "invoices",
    "item",
    "items",
    "job",
    "jobs",
    "object",
    "objects",
    "order",
    "orders",
    "organization",
    "organizations",
    "orgs",
    "payment",
    "payments",
    "product",
    "products",
    "profile",
    "profiles",
    "record",
    "records",
    "resource",
    "resources",
    "session",
    "sessions",
    "setting",
    "settings",
    "tenant",
    "tenants",
    "user",
    "users",
}
_SAFE_QUERY_KEYS = {
    "account_id",
    "fields",
    "filter",
    "format",
    "id",
    "include",
    "limit",
    "offset",
    "order",
    "page",
    "q",
    "search",
    "sort",
    "tenant_id",
    "token",
    "user_id",
}


def inventory_api_authorization(
    state: AgentState,
    *,
    target_url: str = "",
) -> dict[str, object]:
    """
    Build a candidate-only API authorization inventory from saved recon state.

    This function has no HTTP/session dependency. It emits only field names,
    allowlisted provenance, and redacted route shapes: never request values,
    header values, cookies, credentials, or response bodies. Its output is an
    offline review queue, not vulnerability evidence.
    """
    scope_url = _scope_url(state, target_url)
    discovered: list[dict[str, object]] = []
    discovered.extend(_request_template_candidates(state, scope_url=scope_url))
    discovered.extend(_form_candidates(state, scope_url=scope_url))
    discovered.extend(_function_candidates(state, scope_url=scope_url))
    excluded_count = sum(
        candidate.get("scope_status") in {"out_of_scope", "unsupported_url"}
        for candidate in discovered
    )
    candidates = [
        candidate
        for candidate in discovered
        if candidate.get("scope_status") not in {"out_of_scope", "unsupported_url"}
    ]
    candidates = _prioritize_candidates(_dedupe_candidates(candidates))
    candidates = _publish_candidates(candidates)
    mass_assignment_count = sum(
        candidate.get("kind") == "mass_assignment_review" for candidate in candidates
    )
    function_count = sum(
        candidate.get("kind") == "function_authorization_review" for candidate in candidates
    )
    scope = {
        "policy": "same_origin_for_absolute_urls",
        "target_origin_available": bool(_origin(scope_url)),
        "excluded_candidate_count": excluded_count,
    }
    summary = {
        "candidate_count": len(candidates),
        "mass_assignment_review_count": mass_assignment_count,
        "function_authorization_review_count": function_count,
    }
    inventory: dict[str, object] = {
        "schema": _SCHEMA,
        "analysis_mode": "passive_saved_state",
        "candidate_only": True,
        "network_requests": 0,
        "mutation_attempts": 0,
        "confirmed_vulnerabilities": 0,
        "scope": scope,
        "summary": summary,
        "candidates": candidates,
    }
    return inventory


def _request_template_candidates(
    state: AgentState,
    *,
    scope_url: str,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for template in _request_templates(state):
        method = str(template.get("method") or "GET").upper()
        if method not in _WRITE_METHODS:
            continue
        url = str(template.get("url") or "")
        if not _looks_api_shaped(template, url):
            continue
        fields = template.get("fields")
        if not isinstance(fields, dict):
            continue
        field_names = _mapping_field_names(fields)
        candidate = _mass_assignment_candidate(
            method=method,
            url=url,
            field_names=field_names,
            sources=_safe_sources([str(template.get("source") or "request_template")]),
            scope_status=_scope_status(url, scope_url),
            method_override_signal=_method_override_signal(template, field_names),
        )
        if candidate:
            candidates.append(candidate)
    return candidates


def _request_templates(state: AgentState) -> list[dict[str, object]]:
    templates = _list_of_dicts(state.surface.get("request_templates"))
    for value in state.signals.get("request_templates", []):
        parsed = _json_mapping(value)
        if parsed:
            templates.append(parsed)
    return templates


def _form_candidates(state: AgentState, *, scope_url: str) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for form in _forms(state):
        method = str(form.get("method") or "GET").upper()
        if method not in _WRITE_METHODS:
            continue
        url = str(form.get("action") or "")
        if not _looks_api_shaped(form, url):
            continue
        field_names = _form_field_names(form)
        sources = _form_sources(form)
        candidate = _mass_assignment_candidate(
            method=method,
            url=url,
            field_names=field_names,
            sources=sources,
            scope_status=_scope_status(url, scope_url),
            method_override_signal=_method_override_signal(form, field_names),
        )
        if candidate:
            candidates.append(candidate)
    return candidates


def _forms(state: AgentState) -> list[dict[str, object]]:
    forms = _list_of_dicts(state.surface.get("forms"))
    for value in state.signals.get("forms", []):
        parsed = _json_mapping(value)
        if parsed:
            forms.append(parsed)
    return forms


def _mass_assignment_candidate(  # noqa: PLR0913
    *,
    method: str,
    url: str,
    field_names: list[str],
    sources: list[str],
    scope_status: str,
    method_override_signal: str,
) -> dict[str, object] | None:
    authorization_fields = sorted(
        {
            name
            for raw_name in field_names
            if (name := _canonical_field_leaf(raw_name)) in _AUTHORIZATION_FIELDS
        }
    )
    business_fields = sorted(
        {
            name
            for raw_name in field_names
            if (name := _canonical_field_leaf(raw_name)) in _BUSINESS_CONTROL_FIELDS
        }
    )
    if not authorization_fields and not business_fields:
        return None
    review_priority = _mass_assignment_review_priority(authorization_fields)
    override_signals = _method_override_signals(method_override_signal)
    candidate: dict[str, object] = {
        "kind": "mass_assignment_review",
        "verification_status": "unverified_candidate",
        "access_context": "unknown",
        "method": method,
        "route": _safe_route_metadata(url),
        "_route_identity": _route_identity(url),
        "scope_status": scope_status,
        "authorization_fields": authorization_fields,
        "business_control_fields": business_fields,
        "sources": sources,
        "review_priority": review_priority,
        "evidence_status": "request_shape_names_only",
        "method_override_signals": override_signals,
        "review_requirement": (
            "Use an explicitly disposable owned object and reversible mutation; compare "
            "two principals before reporting a vulnerability."
        ),
    }
    return candidate


def _function_candidates(state: AgentState, *, scope_url: str) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    candidates.extend(_endpoint_function_candidates(state, scope_url=scope_url))
    candidates.extend(_template_function_candidates(state, scope_url=scope_url))
    candidates.extend(_form_function_candidates(state, scope_url=scope_url))
    return candidates


def _endpoint_function_candidates(
    state: AgentState,
    *,
    scope_url: str,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for endpoint in _list_of_dicts(state.surface.get("endpoints")):
        url = str(endpoint.get("url") or "")
        raw_sources = _string_items(endpoint.get("sources"))
        if not _observed_get_source(raw_sources) or not _looks_api_shaped(endpoint, url):
            continue
        candidate = _function_candidate(
            method="GET",
            url=url,
            sources=_safe_sources(raw_sources),
            scope_status=_scope_status(url, scope_url),
            method_override_signal="none",
        )
        if candidate:
            candidates.append(candidate)
    return candidates


def _template_function_candidates(
    state: AgentState,
    *,
    scope_url: str,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for template in _request_templates(state):
        method = str(template.get("method") or "GET").upper()
        url = str(template.get("url") or "")
        if method not in _OBSERVED_HTTP_METHODS or not _looks_api_shaped(template, url):
            continue
        fields = template.get("fields")
        field_names: list[str] = []
        if isinstance(fields, dict):
            field_names = _mapping_field_names(fields)
        candidate = _function_candidate(
            method=method,
            url=url,
            sources=_safe_sources([str(template.get("source") or "request_template")]),
            scope_status=_scope_status(url, scope_url),
            method_override_signal=_method_override_signal(template, field_names),
        )
        if candidate:
            candidates.append(candidate)
    return candidates


def _form_function_candidates(
    state: AgentState,
    *,
    scope_url: str,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for form in _forms(state):
        method = str(form.get("method") or "GET").upper()
        url = str(form.get("action") or "")
        if method not in _OBSERVED_HTTP_METHODS or not _looks_api_shaped(form, url):
            continue
        field_names = _form_field_names(form)
        sources = _form_sources(form)
        candidate = _function_candidate(
            method=method,
            url=url,
            sources=sources,
            scope_status=_scope_status(url, scope_url),
            method_override_signal=_method_override_signal(form, field_names),
        )
        if candidate:
            candidates.append(candidate)
    return candidates


def _function_candidate(
    *,
    method: str,
    url: str,
    sources: list[str],
    scope_status: str,
    method_override_signal: str,
) -> dict[str, object] | None:
    privileged_segments = _privileged_segments(url)
    function_signals: list[str] = []
    if privileged_segments:
        function_signals.append("privileged_route_name")
    if method == "DELETE":
        function_signals.append("destructive_method")
    if method_override_signal != "none":
        function_signals.append("method_override_name")
    if not function_signals:
        return None
    review_priority = _function_review_priority(function_signals)
    override_signals = _method_override_signals(method_override_signal)
    candidate: dict[str, object] = {
        "kind": "function_authorization_review",
        "verification_status": "unverified_candidate",
        "access_context": "unknown",
        "method": method,
        "route": _safe_route_metadata(url),
        "_route_identity": _route_identity(url),
        "scope_status": scope_status,
        "privileged_path_segments": privileged_segments,
        "function_signals": function_signals,
        "sources": sources,
        "review_priority": review_priority,
        "evidence_status": "request_method_and_route_names_only",
        "method_override_signals": override_signals,
        "review_requirement": _function_review_requirement(method),
    }
    return candidate


def _function_review_requirement(method: str) -> str:
    if method in {"GET", "HEAD"}:
        return (
            "Compare anonymous, low-privilege, and authorized-role responses under an "
            "explicit side-effect-free policy before reporting a vulnerability."
        )
    return (
        "Use an explicitly authorized disposable or reversible workflow when comparing "
        "roles; the observed route and method are not vulnerability evidence."
    )


def _mass_assignment_review_priority(authorization_fields: list[str]) -> str:
    if authorization_fields:
        return "medium"
    return "low"


def _function_review_priority(function_signals: list[str]) -> str:
    elevated_signals = {"destructive_method", "method_override_name"}
    if set(function_signals) & elevated_signals:
        return "medium"
    return "low"


def _method_override_signals(signal: str) -> list[str]:
    if signal == "none":
        return []
    return [signal]


def _method_override_signal(item: dict[str, object], field_names: list[str]) -> str:
    if any(_canonical_field_leaf(name) in _METHOD_OVERRIDE_FIELDS for name in field_names):
        return "field_name_present"
    headers = item.get("headers")
    if isinstance(headers, dict) and any(
        _canonical_field_name(str(name)) in _METHOD_OVERRIDE_HEADERS for name in headers
    ):
        return "header_name_present"
    return "none"


def _observed_get_source(sources: list[str]) -> bool:
    observed_sources = set(_safe_sources(sources))
    has_get_source = bool(observed_sources & {"link", "page"})
    return has_get_source  # noqa: RET504 - named decision keeps returns simple.


def _privileged_segments(url: str) -> list[str]:
    try:
        path = urlsplit(url).path
    except ValueError:
        return []
    privileged: set[str] = set()
    for segment in path.split("/"):
        canonical = _canonical_field_name(unquote_plus(segment))
        if canonical in _PRIVILEGED_PATH_SEGMENTS:
            privileged.add(canonical)
    ordered = sorted(privileged)
    return ordered  # noqa: RET504 - named ordering keeps return statements simple.


def _looks_api_shaped(item: dict[str, object], url: str) -> bool:
    categories = {value.lower() for value in _string_items(item.get("categories"))}
    hints = {value.lower() for value in _string_items(item.get("hints"))}
    content_types = {
        str(item.get("enctype") or "").lower(),
        str(item.get("content_type") or "").lower(),
        _header_content_type(item.get("headers")),
    }
    source = _canonical_field_name(str(item.get("source") or ""))
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        path = ""
    looks_like_api = (
        path == "/api"
        or path.startswith("/api/")
        or bool(re.match(r"^/v\d+(?:/|$)", path))
        or bool(categories & {"api", "openapi"})
        or bool(hints & {"api", "graphql", "openapi"})
        or source == "openapi"
        or any("json" in content_type for content_type in content_types)
    )
    return looks_like_api  # noqa: RET504 - named decision keeps return statements simple.


def _header_content_type(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    for name, header_value in value.items():
        if str(name).lower() == "content-type":
            return str(header_value).lower()
    return ""


def _is_openapi_form(form: dict[str, object]) -> bool:
    categories = {value.lower() for value in _string_items(form.get("categories"))}
    is_openapi = "openapi" in categories
    return is_openapi  # noqa: RET504 - named decision keeps returns simple.


def _form_field_names(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    for field in _list_of_dicts(form.get("inputs")):
        name = str(field.get("name") or "")
        if name:
            names.append(name)
    return names


def _form_sources(form: dict[str, object]) -> list[str]:
    if _is_openapi_form(form):
        return ["openapi"]
    return ["form"]


def _scope_url(state: AgentState, target_url: str) -> str:
    scope_url = target_url
    if not scope_url:
        state_origin = state.surface.get("origin")
        if state_origin:
            scope_url = str(state_origin)
    if not scope_url:
        state_target = state.surface.get("target_url")
        if state_target:
            scope_url = str(state_target)
    return scope_url


def _scope_status(url: str, scope_url: str) -> str:
    status = "unsupported_url"
    try:
        parsed = urlsplit(url)
    except ValueError:
        parsed = None
    if parsed is None:
        return status
    if not parsed.scheme and not parsed.netloc:
        status = "relative_to_target"
    elif parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        status = "unsupported_url"
    else:
        status = _absolute_scope_status(url, scope_url)
    return status


def _absolute_scope_status(url: str, scope_url: str) -> str:
    target_origin = _origin(scope_url)
    fallback_scheme = ""
    if target_origin is not None:
        fallback_scheme = target_origin[0]
    candidate_origin = _origin(url, fallback_scheme=fallback_scheme)
    if candidate_origin is None:
        return "unsupported_url"
    if target_origin is None:
        return "absolute_origin_unverified"
    if candidate_origin == target_origin:
        return "same_origin"
    return "out_of_scope"


def _origin(url: str, *, fallback_scheme: str = "") -> tuple[str, str, int | None] | None:
    if not url:
        return None
    try:
        parsed = urlsplit(url)
        scheme = (parsed.scheme or fallback_scheme).lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return None
    if scheme not in {"http", "https"} or not hostname:
        return None
    default_port = 80
    if scheme == "https":
        default_port = 443
    resolved_port = port or default_port
    origin = (scheme, hostname, resolved_port)
    return origin  # noqa: RET504 - named origin keeps return statements simple.


def _safe_route_metadata(url: str) -> dict[str, object]:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return {"path_shape": "/", "query_keys": []}
    path_segments = [_safe_path_segment(segment) for segment in parsed.path.split("/") if segment]
    query_keys = sorted(
        {
            safe_key
            for part in parsed.query.split("&")
            if (safe_key := _safe_query_key(part.split("=", 1)[0]))
        }
    )
    path_shape = "/"
    if path_segments:
        path_shape = "/" + "/".join(path_segments)
    metadata: dict[str, object] = {
        "path_shape": path_shape,
        "query_keys": query_keys,
    }
    return metadata


def _safe_path_segment(segment: str) -> str:
    canonical = _canonical_field_name(unquote_plus(segment))
    if canonical in _SAFE_ROUTE_SEGMENTS or re.fullmatch(r"v\d{1,2}", canonical):
        return canonical
    return "{dynamic}"


def _route_identity(url: str) -> str:
    try:
        path = urlsplit(url).path
    except ValueError:
        path = ""
    payload = f"{_SCHEMA}\0{path}".encode()
    return hashlib.sha256(payload, usedforsecurity=False).hexdigest()


def _safe_query_key(raw_key: str) -> str:
    canonical = _canonical_field_name(unquote_plus(raw_key))
    if not canonical:
        return ""
    if canonical in _SAFE_QUERY_KEYS:
        return canonical
    return "{key}"


def _safe_sources(sources: list[str]) -> list[str]:
    safe: set[str] = set()
    for source in sources:
        canonical = _canonical_field_name(source)
        if not canonical:
            continue
        if canonical in _SAFE_PROVENANCE:
            safe.add(canonical)
        else:
            safe.add("observed")
    if not safe:
        safe.add("observed")
    ordered = sorted(safe)
    return ordered  # noqa: RET504 - named ordering keeps return statements simple.


def _canonical_field_leaf(name: str) -> str:
    parts = [part for part in re.split(r"\]\[|[\[\]./]", str(name)) if part]
    leaf = str(name)
    if parts:
        leaf = parts[-1]
    canonical = _canonical_field_name(leaf)
    return canonical  # noqa: RET504 - named value keeps return statements simple.


def _canonical_field_name(name: str) -> str:
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", str(name))
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _json_mapping(value: object) -> dict[str, object]:
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return dict(parsed)


def _mapping_field_names(value: dict[object, object], *, limit: int = 200) -> list[str]:
    names: list[str] = []
    pending: list[dict[object, object]] = [value]
    seen: set[int] = set()
    while pending and len(names) < limit:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        for key, nested in current.items():
            name = str(key)
            if name:
                names.append(name)
            if isinstance(nested, dict):
                pending.append(nested)
            elif isinstance(nested, list):
                pending.extend(item for item in nested if isinstance(item, dict))
    return names[:limit]


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(dict(item))  # noqa: PERF401 - explicit filtering is clearer.
    return items


def _string_items(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        if item:
            items.append(str(item))  # noqa: PERF401 - explicit filtering is clearer.
    return items


def _dedupe_candidates(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: dict[str, dict[str, object]] = {}
    for candidate in candidates:
        key = json.dumps(
            {
                "kind": candidate.get("kind"),
                "method": candidate.get("method"),
                "route": candidate.get("route"),
                "route_identity": candidate.get("_route_identity"),
                "authorization_fields": candidate.get("authorization_fields"),
                "business_control_fields": candidate.get("business_control_fields"),
                "privileged_path_segments": candidate.get("privileged_path_segments"),
                "function_signals": candidate.get("function_signals"),
            },
            sort_keys=True,
        )
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = candidate
            continue
        existing["sources"] = sorted(
            set(_string_items(existing.get("sources")))
            | set(_string_items(candidate.get("sources")))
        )
        existing["method_override_signals"] = sorted(
            set(_string_items(existing.get("method_override_signals")))
            | set(_string_items(candidate.get("method_override_signals")))
        )
        existing["scope_status"] = min(
            {str(existing.get("scope_status")), str(candidate.get("scope_status"))},
            key=_scope_status_priority,
        )
    unique_candidates = list(deduped.values())
    return unique_candidates  # noqa: RET504 - named collection keeps returns simple.


def _prioritize_candidates(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    prioritized = sorted(candidates, key=_candidate_sort_key)
    return prioritized  # noqa: RET504 - named ordering keeps return statements simple.


def _candidate_sort_key(candidate: dict[str, object]) -> tuple[object, ...]:
    priority = _candidate_priority(candidate)
    method = str(candidate.get("method"))
    route = json.dumps(candidate.get("route"), sort_keys=True)
    authorization_fields = json.dumps(candidate.get("authorization_fields"), sort_keys=True)
    business_fields = json.dumps(candidate.get("business_control_fields"), sort_keys=True)
    privileged_segments = json.dumps(candidate.get("privileged_path_segments"), sort_keys=True)
    function_signals = json.dumps(candidate.get("function_signals"), sort_keys=True)
    sources = json.dumps(candidate.get("sources"), sort_keys=True)
    override_signals = json.dumps(candidate.get("method_override_signals"), sort_keys=True)
    route_identity = str(candidate.get("_route_identity"))
    sort_key = (
        priority,
        method,
        route,
        authorization_fields,
        business_fields,
        privileged_segments,
        function_signals,
        sources,
        override_signals,
        route_identity,
    )
    return sort_key  # noqa: RET504 - named tuple keeps return statements simple.


def _publish_candidates(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    route_references: dict[str, str] = {}
    published: list[dict[str, object]] = []
    for candidate in candidates:
        identity = str(candidate.get("_route_identity") or "")
        if identity not in route_references:
            route_references[identity] = f"route-{len(route_references) + 1:04d}"
        public_candidate = {
            key: value for key, value in candidate.items() if not key.startswith("_")
        }
        route = public_candidate.get("route")
        if isinstance(route, dict):
            public_candidate["route"] = {
                **route,
                "route_ref": route_references[identity],
            }
        published.append(public_candidate)
    return published


def _candidate_priority(candidate: dict[str, object]) -> int:
    if candidate.get("kind") == "mass_assignment_review" and candidate.get("authorization_fields"):
        return 0
    if candidate.get("kind") == "function_authorization_review":
        return 1
    if candidate.get("kind") == "mass_assignment_review":
        return 2
    return 20


def _scope_status_priority(status: str) -> int:
    priorities = {
        "same_origin": 0,
        "relative_to_target": 1,
        "absolute_origin_unverified": 2,
    }
    priority = priorities.get(status, 20)
    return priority  # noqa: RET504 - named value keeps return statements simple.


__all__ = ["inventory_api_authorization"]
