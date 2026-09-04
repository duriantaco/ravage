from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.probe_suite_parts.sqli.sqli_forms import _sqli_skip_form_field
from ravage.probe_suite_parts.sqli.sqli_replay import (
    _confirmed_sqli_input_keys,
    _confirmed_sqli_replay_targets,
)
from ravage.probe_suite_parts.sqli.sqli_values import _form_input_value, _query_param_value
from ravage.probe_suite_parts.support import (
    _contains_word,
    _dedupe,
    _dict_value,
    _form_input_names,
    _form_targets,
    _int_value,
    _list_of_dicts,
    _parameter_targets,
    _string_items,
    _surface_endpoint_items,
    _url_in_scope,
    _url_looks_static_oauth_redirect,
)

_SOURCE_QUERY_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:\[\]-]{0,127}$")
_SOURCE_QUERY_VALUE_KINDS = frozenset({"boolean", "integer", "number", "string", "uuid"})
_SOURCE_QUERY_PLACEHOLDERS = {
    "boolean": "false",
    "integer": "1",
    "number": "1",
    "string": "ravage",
    "uuid": "00000000-0000-0000-0000-000000000001",
}


def _sqli_targets(state: AgentState) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    confirmed = _confirmed_sqli_input_keys(state)
    origin = str(
        state.surface.get("origin")
        or state.surface.get("target_url")
        or state.surface_graph.target_origin
        or ""
    )
    # Source ingest binds the graph to the live attack target.  Never recover
    # this egress authority from the mutable legacy surface projection.
    source_origin = str(state.surface_graph.target_origin or "")
    source_targets = _source_sqli_targets(
        state,
        origin=source_origin,
        confirmed=confirmed,
    )
    if state.surface.get("source_validation_probe") == "sqli_differential":
        return source_targets[:8]
    targets.extend(source_targets)
    targets.extend(_confirmed_sqli_replay_targets(state))
    targets.extend(_request_template_targets(state, origin=origin, confirmed=confirmed))
    for target in _parameter_targets(state, limit=18):
        url = str(target.get("url") or "")
        if not _url_in_scope(url, origin) or _url_looks_static_oauth_redirect(url):
            continue
        name = str(target.get("name") or "")
        targets.append(
            {
                "kind": "query_param",
                "url": url,
                "input": name,
                "baseline": _query_param_value(url, name),
                "hints": _string_items(target.get("hints")),
                "priority": _sqli_priority(
                    "query_param",
                    str(target.get("url") or ""),
                    str(target.get("name") or ""),
                    confirmed,
                    _int_value(target.get("priority")) + 30,
                ),
            }
        )
    for form in _form_targets(state, limit=10):
        action = str(form.get("action") or state.surface.get("target_url") or "")
        if not action:
            continue
        for name in _form_input_names(form):
            if _sqli_skip_form_field(name, form):
                continue
            targets.append(
                {
                    "kind": "form",
                    "url": action,
                    "input": name,
                    "form": form,
                    "baseline": _form_input_value(form, name),
                    "hints": _string_items(form.get("categories")),
                    "priority": _sqli_priority(
                        "form",
                        action,
                        name,
                        confirmed,
                        _form_sqli_base_priority(form) + _sqli_name_priority(name),
                    ),
                }
            )
    for endpoint in _query_like_urls(state):
        for name in _common_sqli_param_names(endpoint):
            targets.append(
                {
                    "kind": "heuristic_get",
                    "url": endpoint,
                    "input": name,
                    "hints": ["heuristic_query_input"],
                    "priority": _sqli_priority(
                        "heuristic_get",
                        endpoint,
                        name,
                        confirmed,
                        20 + _sqli_name_priority(name),
                    ),
                }
            )
        if _path_looks_login_or_search(endpoint):
            for name in _common_sqli_param_names(endpoint)[:8]:
                targets.append(
                    {
                        "kind": "heuristic_post",
                        "url": endpoint,
                        "input": name,
                        "hints": ["heuristic_post_input"],
                        "priority": _sqli_priority(
                            "heuristic_post",
                            endpoint,
                            name,
                            confirmed,
                            18 + _sqli_name_priority(name),
                        ),
                    }
                )
    for endpoint in _signal_endpoints(state):
        kind = _heuristic_kind_for_endpoint(endpoint)
        names = _names_for_signal_endpoint(state, endpoint)
        base_priority = 34
        if kind == "json_post":
            base_priority = 72
        if kind == "graphql_post":
            base_priority = 86
        if kind == "graphql_post":
            for spec in _graphql_field_specs(state)[:8]:
                spec_names = _dedupe([str(spec.get("input") or ""), *names])[:8]
                for name in spec_names:
                    field_name = str(spec.get("field") or "")
                    priority = (
                        base_priority
                        + _sqli_name_priority(name)
                        + _graphql_field_priority(field_name)
                    )
                    targets.append(
                        {
                            "kind": kind,
                            "url": endpoint,
                            "input": name,
                            "graphql_field": spec.get("field"),
                            "graphql_selection": spec.get("selection"),
                            "hints": ["observed_graphql_input"],
                            "priority": _sqli_priority(
                                kind,
                                endpoint,
                                name,
                                confirmed,
                                priority,
                            ),
                        }
                    )
            continue
        for name in names[:12]:
            targets.append(
                {
                    "kind": kind,
                    "url": endpoint,
                    "input": name,
                    "hints": ["observed_input_name"],
                    "priority": _sqli_priority(
                        kind,
                        endpoint,
                        name,
                        confirmed,
                        base_priority + _sqli_name_priority(name),
                    ),
                }
            )
    ordered = _dedupe_sqli_targets(targets)
    ordered.sort(key=_sqli_target_sort_key)
    return ordered[:20]


def _source_sqli_targets(
    state: AgentState,
    *,
    origin: str,
    confirmed: set[tuple[str, str, str]],
) -> list[dict[str, object]]:
    """Build value-free replay targets from trusted, locally derived candidates."""
    raw_candidates = state.surface.get("source_candidates")
    if not isinstance(raw_candidates, list) or not origin:
        return []
    validation_mode = state.surface.get("source_validation_probe") == "sqli_differential"
    raw_candidate_ids = state.surface.get("source_validation_candidate_ids")
    active_candidate_ids = (
        {str(item) for item in raw_candidate_ids if str(item)}
        if isinstance(raw_candidate_ids, list)
        else set()
    )
    if validation_mode and not active_candidate_ids:
        return []
    targets_by_shape: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for candidate in raw_candidates[:64]:
        if not isinstance(candidate, dict):
            continue
        candidate_id = str(candidate.get("candidate_id") or "")
        if validation_mode and candidate_id not in active_candidate_ids:
            continue
        family = str(candidate.get("family") or "").strip().lower().replace("-", "_")
        if family not in {"sql_injection", "sqli"}:
            continue
        method = str(candidate.get("method") or "GET").strip().upper()
        if (
            method != "GET"
            or candidate.get("live_validation") != "automatic_get_query"
            or candidate.get("route_binding") not in {"direct", "mounted"}
        ):
            continue
        route = str(candidate.get("route") or "").strip()
        input_name = str(candidate.get("input_name") or "").strip()
        location = str(candidate.get("input_location") or "").strip().lower()
        if (
            not route.startswith("/")
            or "{" in route
            or "}" in route
            or not input_name
            or location != "query"
        ):
            continue
        query_fields = _source_query_fields(candidate.get("query_fields"))
        target_field = next(
            (field for field in query_fields if field[0] == input_name),
            None,
        )
        if target_field is None or target_field[1] != "string":
            continue
        url = urljoin(origin.rstrip("/") + "/", route.lstrip("/"))
        if not _url_in_scope(url, origin):
            continue
        for field_name, value_kind, required in query_fields:
            if required and field_name != input_name:
                url = _url_with_query_field(
                    url,
                    name=field_name,
                    value=_SOURCE_QUERY_PLACEHOLDERS[value_kind],
                )
        shape = (method, url, location, input_name)
        previous = targets_by_shape.get(shape)
        if previous is not None:
            source_candidate_ids = previous.get("source_candidate_ids")
            if (
                isinstance(source_candidate_ids, list)
                and candidate_id
                and candidate_id not in source_candidate_ids
            ):
                source_candidate_ids.append(candidate_id)
            continue
        target: dict[str, object] = {
            "kind": "replay",
            "url": url,
            "input": input_name,
            "payload_field": input_name,
            "input_location": location,
            "method": method,
            "encoding": "application/x-www-form-urlencoded",
            "required_fields": sorted(
                field_name
                for field_name, _value_kind, required in query_fields
                if required or field_name == input_name
            ),
            "hints": ["source_code", "source_family:sql_injection"],
            "source_candidate_ids": [candidate_id] if candidate_id else [],
            "priority": _sqli_priority(
                "replay",
                url,
                input_name,
                confirmed,
                360,
            ),
        }
        targets_by_shape[shape] = target
    return list(targets_by_shape.values())


def _source_query_fields(value: object) -> tuple[tuple[str, str, bool], ...]:
    if not isinstance(value, list) or not value or len(value) > 32:
        return ()
    fields: list[tuple[str, str, bool]] = []
    names: set[str] = set()
    for raw_field in value:
        if not isinstance(raw_field, dict) or set(raw_field) != {
            "name",
            "required",
            "value_kind",
        }:
            return ()
        name = str(raw_field.get("name") or "")
        value_kind = str(raw_field.get("value_kind") or "")
        required = raw_field.get("required")
        if (
            not _SOURCE_QUERY_NAME_RE.fullmatch(name)
            or name in names
            or value_kind not in _SOURCE_QUERY_VALUE_KINDS
            or not isinstance(required, bool)
        ):
            return ()
        names.add(name)
        fields.append((name, value_kind, required))
    return tuple(fields)


def _url_with_query_field(url: str, *, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = [
        (key, raw_value)
        for key, raw_value in parse_qsl(parts.query, keep_blank_values=True)
        if key != name
    ]
    query.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

def _sqli_target_brief(target: dict[str, object]) -> dict[str, object]:
    brief = {
        "kind": target.get("kind"),
        "url": target.get("url"),
        "input": target.get("input"),
        "hints": _string_items(target.get("hints")),
    }
    if target.get("kind") == "replay":
        brief["method"] = target.get("method")
        brief["required_fields"] = target.get("required_fields", [])
        if target.get("input_location"):
            brief["input_location"] = target.get("input_location")
        if target.get("source_candidate_ids"):
            brief["source_candidate_ids"] = target.get("source_candidate_ids")
    if target.get("kind") == "graphql_post":
        brief["graphql_field"] = target.get("graphql_field")
        brief["graphql_selection"] = target.get("graphql_selection")
    return brief

def _accept_all_targets(_target: dict[str, object]) -> bool:
    return True

def _heuristic_kind_for_endpoint(endpoint: str) -> str:
    if _path_looks_graphql_endpoint(endpoint):
        return "graphql_post"
    if _path_looks_json_query_endpoint(endpoint):
        return "json_post"
    if _path_looks_login_or_search(endpoint):
        return "heuristic_post"
    return "heuristic_get"

def _dedupe_sqli_targets(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: dict[tuple[str, str, str, str, str], dict[str, object]] = {}
    for target in targets:
        key = _sqli_target_key(target)
        previous = deduped.get(key)
        if previous is None:
            deduped[key] = target
            continue
        if _int_value(target.get("priority")) > _int_value(previous.get("priority")):
            deduped[key] = target
    return list(deduped.values())

def _sqli_target_key(target: dict[str, object]) -> tuple[str, str, str, str, str]:
    return (
        str(target.get("kind")),
        str(target.get("url")),
        str(target.get("input")),
        str(target.get("method")),
        str(target.get("input_location")),
    )

def _sqli_target_sort_key(target: dict[str, object]) -> tuple[int, int, int, int, str, str]:
    priority = _int_value(target.get("priority"))
    confirmed_rank = 1
    if priority >= 400:
        confirmed_rank = 0
    surface_rank = _sqli_target_surface_rank(target)
    kind_rank = _sqli_target_kind_rank(str(target.get("kind") or ""))
    url = str(target.get("url"))
    input_name = str(target.get("input"))
    return confirmed_rank, surface_rank, kind_rank, -priority, url, input_name

def _sqli_target_surface_rank(target: dict[str, object]) -> int:
    kind = str(target.get("kind") or "")
    url = str(target.get("url") or "")
    if kind == "replay":
        # Confirmed replays are already promoted by ``confirmed_rank``.  An
        # unconfirmed authentication template has already received a bounded,
        # field-interleaved auth-bypass pass before the main differential
        # sweep. Demote only the credential fields exercised by that pass;
        # tenant and other adjacent inputs remain high-fidelity replay targets.
        if _sqli_replay_template_received_auth_prepass(target):
            return 4
        # Preserve the historical preference for all other high-fidelity
        # observed replays, including JSON bodies with domain-specific keys.
        return 0
    if kind == "form" and _sqli_target_looks_contact_or_content_form(target):
        return 1
    if _sqli_target_looks_auth_surface(target):
        return 4
    if kind == "query_param" and _path_looks_json_query_endpoint(url) and not urlsplit(url).query:
        return 3
    if kind in {"heuristic_get", "heuristic_post"} and _path_looks_json_query_endpoint(url) and not urlsplit(url).query:
        return 3
    if _sqli_target_looks_visible_query_surface(target):
        return 1
    if kind == "json_post":
        return 1
    if kind == "query_param":
        if urlsplit(url).query:
            return 2
        return 6
    if kind == "form":
        return 1
    if kind == "heuristic_get":
        if _url_looks_query_related(url):
            return 3
        return 6
    if kind == "heuristic_post":
        return 4
    if kind == "graphql_post":
        return 5
    if _path_looks_json_query_endpoint(url):
        return 3
    return 6

def _sqli_target_looks_auth_surface(target: dict[str, object]) -> bool:
    text = _sqli_target_surface_text(target)
    return _contains_word(text, ("login", "signin", "auth", "password", "credential", "session"))


def _sqli_replay_template_received_auth_prepass(target: dict[str, object]) -> bool:
    if str(target.get("kind") or "") != "replay":
        return False
    input_name = str(target.get("input") or "").lower()
    credential_input = "pass" in input_name or (
        input_name in {"username", "user", "login", "log", "email"}
        or _contains_word(input_name, ("user", "login", "email"))
    )
    if not credential_input:
        return False
    form = _dict_value(target.get("form"))
    field_names = [str(name).lower() for name in form]
    has_username_candidate = any(
        name in {"username", "user", "login", "log", "email"}
        or _contains_word(name, ("user", "login", "email"))
        for name in field_names
    )
    if not has_username_candidate:
        return False
    return bool(
        _contains_word(
            _sqli_target_surface_text(target),
            ("password", "passwd", "pwd", "login", "signin", "admin", "auth"),
        )
    )

def _sqli_target_looks_contact_or_content_form(target: dict[str, object]) -> bool:
    if str(target.get("kind") or "") != "form":
        return False
    text = _sqli_target_surface_text(target)
    markers = (
        "contact",
        "content",
        "message",
        "comment",
        "feedback",
        "support",
        "send.php",
    )
    return _contains_word(text, markers)

def _sqli_target_looks_visible_query_surface(target: dict[str, object]) -> bool:
    text = _sqli_target_visible_context_text(target)
    if _contains_word(
        text,
        (
            "search",
            "query",
            "catalog",
            "product",
            "category",
            "filter",
            "lookup",
            "item",
            "job",
            "jobs",
        ),
    ):
        return True
    return bool(urlsplit(str(target.get("url") or "")).query)

def _sqli_target_surface_text(target: dict[str, object]) -> str:
    parts = [
        str(target.get("kind") or ""),
        str(target.get("url") or ""),
        str(target.get("input") or ""),
        " ".join(_string_items(target.get("hints"))),
    ]
    form = _dict_value(target.get("form"))
    if form:
        parts.append(str(form.get("id") or ""))
        parts.append(" ".join(_string_items(form.get("categories"))))
        # Replay templates store a value-free field mapping rather than the
        # richer ``inputs`` list used by recon forms.  Field names are enough
        # to identify an authentication surface without retaining values.
        parts.append(" ".join(str(name) for name in form))
    return " ".join(parts).lower()

def _sqli_target_visible_context_text(target: dict[str, object]) -> str:
    kind = str(target.get("kind") or "")
    parts = [
        kind,
        str(target.get("url") or ""),
    ]
    if not kind.startswith("heuristic_"):
        parts.append(" ".join(_string_items(target.get("hints"))))
    form = _dict_value(target.get("form"))
    if form:
        parts.append(str(form.get("id") or ""))
        parts.append(" ".join(_string_items(form.get("categories"))))
    return " ".join(parts).lower()

def _sqli_target_kind_rank(kind: str) -> int:
    return {
        "replay": 0,
        "form": 1,
        "query_param": 1,
        "heuristic_get": 2,
        "heuristic_post": 3,
        "json_post": 4,
        "graphql_post": 5,
    }.get(kind, 6)

def _filtered_query_targets(state: AgentState) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for target in _sqli_targets(state):
        url = str(target.get("url") or "")
        if _url_looks_static_oauth_redirect(url):
            continue
        if _path_looks_search_or_auth(url) or _path_looks_json_query_endpoint(url):
            targets.append(target)
    targets.sort(key=_filtered_query_sort_key)
    return targets[:12]

def _filtered_query_sort_key(target: dict[str, object]) -> tuple[int, int, int, int, str, str]:
    form_rank = 1
    if "form" in str(target.get("kind") or ""):
        form_rank = 0
    search_rank = 1
    if "search" in str(target.get("url") or "").lower():
        search_rank = 0
    input_rank = _filtered_query_input_rank(str(target.get("input") or ""))
    priority = -_int_value(target.get("priority"))
    url = str(target.get("url"))
    input_name = str(target.get("input"))
    return form_rank, search_rank, input_rank, priority, url, input_name

def _filtered_query_input_rank(name: str) -> int:
    lowered = name.lower()
    if lowered in {"username", "user", "login", "email", "q", "search", "query", "term", "keyword", "name", "id"}:
        return 0
    if _contains_word(lowered, ("user", "login", "email", "search", "query", "name", "id")):
        return 1
    if lowered in {"action", "wsdl", "submit", "button", "csrf", "token", "_token"}:
        return 3
    return 2

def _preg_match_targets(state: AgentState) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for target in _filtered_query_targets(state):
        input_name = str(target.get("input") or "").lower()
        url = str(target.get("url") or "")
        if input_name in {"username", "user", "name", "search", "q", "query"} and _path_looks_search_or_auth(url):
            targets.append(target)
    return targets[:10]

def _sqli_priority(kind: str, url: str, input_name: str, confirmed: set[tuple[str, str, str]], base: int) -> int:
    if (kind, url, input_name) in confirmed:
        return base + 500
    if _confirmed_input_matches(confirmed, url=url, input_name=input_name):
        return base + 400
    return base

def _confirmed_input_matches(
    confirmed: set[tuple[str, str, str]],
    *,
    url: str,
    input_name: str,
) -> bool:
    for _key_kind, key_url, key_input in confirmed:
        if key_url == url and key_input == input_name:
            return True
    return False

def _signal_parameter_names(state: AgentState) -> list[str]:
    names: list[str] = []
    for name in state.signals.get("parameters", []):
        text = str(name)
        if text:
            names.append(text)
    return _dedupe(names)

def _request_template_targets(
    state: AgentState,
    *,
    origin: str,
    confirmed: set[tuple[str, str, str]],
) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for template in _request_templates_from_state(state):
        # Source-only graph operations can omit companion request fields. The
        # exact, analyzer-approved GET shape is handled by _source_sqli_targets;
        # never turn a hint-only source operation into an invented POST replay.
        if str(template.get("source") or "") == "source_code":
            continue
        method = _request_template_method(template)
        if method != "POST":
            continue
        url = _request_template_url(template, origin=origin)
        if not url or not _url_in_scope(url, origin):
            continue
        fields = _request_template_fields(template)
        if not fields:
            continue
        headers = _request_template_headers(template)
        encoding = _request_template_encoding(template, url=url, headers=headers)
        required_fields = sorted(fields)
        hints = _request_template_hints(template, encoding=encoding)
        for name, baseline in fields.items():
            if _request_template_field_looks_control(name):
                continue
            targets.append(
                {
                    "kind": "replay",
                    "url": url,
                    "input": name,
                    "payload_field": name,
                    "method": method,
                    "form": fields,
                    "headers": headers,
                    "encoding": encoding,
                    "required_fields": required_fields,
                    "baseline": baseline,
                    "hints": hints,
                    "priority": _sqli_priority(
                        "replay",
                        url,
                        name,
                        confirmed,
                        260 + _sqli_name_priority(name),
                    ),
                }
            )
    return targets[:16]

def _request_templates_from_state(state: AgentState) -> list[dict[str, object]]:
    templates: list[dict[str, object]] = []
    seen: set[str] = set()
    raw_surface_templates = state.surface.get("request_templates", [])
    surface_templates = (
        raw_surface_templates if isinstance(raw_surface_templates, list) else []
    )
    raw_signal_templates = state.signals.get("request_templates", [])
    signal_templates = raw_signal_templates if isinstance(raw_signal_templates, list) else []
    for raw_template in [*surface_templates, *signal_templates]:
        if isinstance(raw_template, dict):
            parsed = dict(raw_template)
        else:
            try:
                parsed = json.loads(str(raw_template))
            except (TypeError, ValueError):
                continue
            if not isinstance(parsed, dict):
                continue
        key = json.dumps(parsed, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        templates.append(dict(parsed))
    return templates[:20]

def _request_template_method(template: dict[str, object]) -> str:
    method = str(template.get("method") or "GET").upper()
    if method in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        return method
    return "GET"

def _request_template_url(template: dict[str, object], *, origin: str) -> str:
    raw_url = str(template.get("url") or template.get("endpoint") or template.get("path") or "")
    url = _clean_signal_endpoint(raw_url, origin=origin)
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if origin and not parts.scheme and not parts.netloc:
        return _clean_signal_endpoint(f"{origin.rstrip('/')}/{url.lstrip('/')}", origin=origin)
    return url

def _request_template_fields(template: dict[str, object]) -> dict[str, str]:
    raw_fields = template.get("fields")
    if not isinstance(raw_fields, dict):
        return {}

    fields: dict[str, str] = {}
    for raw_name, raw_value in raw_fields.items():
        name = str(raw_name).strip()
        if not name:
            continue
        fields[name] = str(raw_value).strip()
    return fields

def _request_template_headers(template: dict[str, object]) -> dict[str, str]:
    raw_headers = template.get("headers")
    if not isinstance(raw_headers, dict):
        return {}

    headers: dict[str, str] = {}
    for raw_name, raw_value in raw_headers.items():
        name = str(raw_name).strip()
        value = str(raw_value).strip()
        if not name or not value:
            continue
        if any(char in name for char in "\r\n:") or any(char in value for char in "\r\n"):
            continue
        headers[name] = value
    return headers

def _request_template_encoding(
    template: dict[str, object],
    *,
    url: str,
    headers: dict[str, str],
) -> str:
    explicit = str(template.get("encoding") or template.get("content_type") or "")
    content_types = [explicit.lower()]
    for name, value in headers.items():
        if name.lower() == "content-type":
            content_types.append(value.lower())
    if any("json" in item for item in content_types):
        return "application/json"
    if (
        str(template.get("source") or "").lower() == "fetch"
        and _path_looks_json_query_endpoint(url)
    ):
        return "application/json"
    return "application/x-www-form-urlencoded"

def _request_template_hints(template: dict[str, object], *, encoding: str) -> list[str]:
    hints = ["observed_request_template"]
    source = str(template.get("source") or "").strip()
    if source:
        hints.append(source)
    if "json" in encoding.lower():
        hints.append("observed_json_body")
    return _dedupe(hints)

def _request_template_field_looks_control(name: str) -> bool:
    lowered = name.lower()
    return lowered in {"csrf", "_csrf", "token", "_token", "authenticity_token", "submit", "button"}

def _names_for_signal_endpoint(state: AgentState, endpoint: str) -> list[str]:
    signal_names = _signal_parameter_names(state)
    common_names = _common_sqli_param_names(endpoint)
    if _path_looks_login_or_search(endpoint):
        return _dedupe(common_names + signal_names)
    if _path_looks_graphql_endpoint(endpoint):
        graphql_names = [
            "jobType",
            "job_type",
            "type",
            "category",
            "filter",
            "query",
            "search",
            "name",
        ]
        graphql_names.extend(common_names)
        graphql_names.extend(signal_names)
        return _dedupe(graphql_names)
    if _path_looks_json_query_endpoint(endpoint):
        return _dedupe(common_names + signal_names)
    return signal_names or common_names

def _signal_endpoints(state: AgentState) -> list[str]:
    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "")
    endpoints = []
    for url in state.signals.get("endpoints", []):
        text = _clean_signal_endpoint(str(url), origin=origin)
        if not text:
            continue
        if _url_looks_static_oauth_redirect(text):
            continue
        if origin and not text.startswith(origin.rstrip("/") + "/") and text.rstrip("/") != origin.rstrip("/"):
            continue
        if (
            _path_looks_graphql_endpoint(text)
            or _path_looks_login_or_search(text)
            or _path_looks_json_query_endpoint(text)
            or text.lower().endswith(".php")
        ):
            endpoints.append(text)
    return _dedupe(endpoints)[:12]

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
    invalid_path_chars = ("'", '"', "`", "[", "]", "{", "}", "<", ">")
    for char in invalid_path_chars:
        if char in parts.path:
            return ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))

def _query_like_urls(state: AgentState) -> list[str]:
    urls: list[str] = []
    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "")
    for item in _surface_endpoint_items(state):
        url = str(item.get("url") or "")
        if url:
            urls.append(url)
    for page in _list_of_dicts(state.surface.get("pages")):
        url = str(page.get("url") or "")
        if url:
            urls.append(url)
        urls.extend(_string_items(page.get("links")))
    target = str(state.surface.get("target_url") or "")
    if target:
        urls.append(target)
    same_origin = _same_origin_urls(urls, origin)
    filtered = _query_candidate_urls(same_origin)
    return filtered[:12] or same_origin[:8]

def _same_origin_urls(urls: list[str], origin: str) -> list[str]:
    same_origin: list[str] = []
    base = origin.rstrip("/")
    for url in _dedupe(urls):
        if not origin:
            same_origin.append(url)
            continue
        if url.startswith(base + "/") or url.rstrip("/") == base:
            same_origin.append(url)
    return same_origin

def _query_candidate_urls(urls: list[str]) -> list[str]:
    filtered: list[str] = []
    for url in urls:
        if _url_looks_static_oauth_redirect(url):
            continue
        if _url_looks_query_related(url):
            filtered.append(url)
    return filtered

def _url_looks_query_related(url: str) -> bool:
    if _path_looks_login_or_search(url):
        return True
    if _path_looks_json_query_endpoint(url):
        return True
    return _contains_word(url.lower(), (".php", "/api", "user", "item", "product"))

def _common_sqli_param_names(url: str) -> list[str]:
    lowered = url.lower()
    names = ["q", "search", "query", "id", "name", "username", "user", "email", "title", "filter", "sort", "page"]
    if "graphql" in lowered or "/gql" in lowered:
        names = ["jobType", "job_type", "type", "category", "filter", "query", "search", "name", *names]
    if "login" in lowered or "signin" in lowered:
        names = ["username", "user", "email", "login", "password", "pass", *names]
    if "search" in lowered:
        names = ["search", "q", "query", "term", "keyword", "name", "username", "email", *names]
    if "user" in lowered:
        names = ["id", "user", "username", "email", "name", *names]
    if "job" in lowered:
        names = ["job_type", "type", "category", "filter", "name", *names]
    return _dedupe(names)[:12]

def _path_looks_login_or_search(url: str) -> bool:
    lowered = url.lower()
    return _contains_word(lowered, ("search", "login", "signin", "user", "lookup", "filter", "admin", "auth"))

def _path_looks_search_or_auth(url: str) -> bool:
    lowered = url.lower()
    return _contains_word(lowered, ("search", "login", "signin", "lookup", "filter", "auth", "user", "admin"))

def _path_looks_json_query_endpoint(url: str) -> bool:
    lowered = url.lower()
    return _contains_word(lowered, ("/api", "job", "jobs", "filter"))

def _path_looks_graphql_endpoint(url: str) -> bool:
    lowered = url.lower()
    return _contains_word(lowered, ("graphql", "graphiql", "/gql"))

def _graphql_field_specs(state: AgentState) -> list[dict[str, str]]:
    corpus = _graphql_text_corpus(state)
    specs: list[dict[str, str]] = []
    for match in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[^)]{0,200}\)\s*(\{[^{}]{1,400}\})",
        corpus,
    ):
        field = _safe_graphql_identifier(match.group(1))
        input_name = _safe_graphql_identifier(match.group(2))
        selection = _clean_graphql_selection(match.group(3))
        if field and input_name and selection:
            specs.append({"field": field, "input": input_name, "selection": selection})
    if "job" in corpus.lower():
        specs.append({"field": "jobs", "input": "jobType", "selection": "{ id name type description }"})
    specs.extend(
        [
            {"field": "jobs", "input": "jobType", "selection": "{ id name type description }"},
            {"field": "items", "input": "type", "selection": "{ id name title description }"},
            {"field": "products", "input": "category", "selection": "{ id name title description }"},
            {"field": "notes", "input": "search", "selection": "{ id title body content }"},
            {"field": "users", "input": "search", "selection": "{ id username email }"},
        ]
    )
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for spec in specs:
        key = (spec["field"], spec["input"], spec["selection"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(spec)
    return deduped

def _graphql_text_corpus(state: AgentState) -> str:
    parts: list[str] = []
    parts.append(state.summary)
    parts.extend(state.facts)
    parts.extend(state.hypotheses)
    for values in state.signals.values():
        for value in values:
            parts.append(str(value))
    try:
        parts.append(json.dumps(state.surface, sort_keys=True))
        parts.append(json.dumps(state.last_observation, sort_keys=True))
    except (TypeError, ValueError):
        pass
    corpus_parts: list[str] = []
    for part in parts:
        if part:
            corpus_parts.append(part)
    return "\n".join(corpus_parts)

def _graphql_sqli_query(target: dict[str, object], value: str) -> str:
    field = _safe_graphql_identifier(str(target.get("graphql_field") or "")) or "jobs"
    input_name = _safe_graphql_identifier(str(target.get("input") or "")) or "query"
    raw_selection = str(target.get("graphql_selection") or "")
    selection = _clean_graphql_selection(raw_selection)
    if not selection:
        selection = _default_graphql_selection(field)
    return f"query {{ {field}({input_name}: {json.dumps(value)}) {selection} }}".strip()

def _clean_graphql_selection(raw: str) -> str:
    names = []
    for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", raw):
        if token in {"query", "mutation", "subscription", "fragment", "on", "true", "false", "null"}:
            continue
        names.append(token)
    names = _dedupe(names)[:10]
    if not names:
        return ""
    return "{ " + " ".join(names) + " }"

def _default_graphql_selection(field: str) -> str:
    lowered = field.lower()
    if lowered in {"flag", "flags", "secret", "secrets", "token", "tokens"}:
        return ""
    if lowered in {"job", "jobs"}:
        return "{ id name type description }"
    if lowered in {"user", "users", "account", "accounts"}:
        return "{ id username email }"
    if lowered in {"note", "notes"}:
        return "{ id title body content }"
    return "{ id name title description }"

def _safe_graphql_identifier(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        return value
    return ""

def _graphql_field_priority(field: str) -> int:
    lowered = field.lower()
    if lowered in {"jobs", "users", "items", "products", "notes"}:
        return 12
    if _contains_word(lowered, ("job", "user", "item", "product", "note", "search")):
        return 8
    return 0

def _sqli_name_priority(name: str) -> int:
    lowered = name.lower()
    if lowered == "jobtype":
        return 28
    if lowered == "job_type":
        return 24
    if lowered in {"type", "category", "filter"}:
        return 18
    if lowered in {
        "q",
        "search",
        "query",
        "id",
        "username",
        "user",
        "email",
        "name",
        "title",
        "term",
        "keyword",
    }:
        return 12
    if _contains_word(
        lowered,
        ("search", "query", "user", "id", "email", "name", "title", "type", "category", "filter", "sort"),
    ):
        return 8
    return 0

def _form_sqli_base_priority(form: dict[str, object]) -> int:
    categories = set(_string_items(form.get("categories")))
    text = json.dumps(form, sort_keys=True).lower()
    if _form_looks_contact_or_content(form, text=text):
        return 84

    has_auth_marker = "auth" in categories
    for marker in ("login", "signin", "password"):
        if marker in text:
            has_auth_marker = True
            break
    if has_auth_marker:
        return 76

    has_query_marker = bool(categories & {"query", "search"})
    for marker in ("search", "query", "filter", "lookup"):
        if marker in text:
            has_query_marker = True
            break
    if has_query_marker:
        return 60
    return 45

def _form_looks_contact_or_content(form: dict[str, object], *, text: str) -> bool:
    method = str(form.get("method") or "GET").upper()
    if method != "POST":
        return False
    markers = (
        "contact",
        "content",
        "message",
        "comment",
        "feedback",
        "support",
        "send.php",
    )
    return _contains_word(text, markers)
