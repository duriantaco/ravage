from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import cast
from urllib.parse import parse_qsl, quote, urljoin, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    form_defaults,
    inject_query_param,
)

_SLOW_RESPONSE_MS = 2_000

_MONGO_OBJECT_ID_RE = re.compile(r"(?i)\b[a-f0-9]{24}\b")


def _generic_input_targets(state: AgentState, *, limit: int) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    reflected = _reflected_input_names(state)
    for target in _parameter_targets(state, limit=limit):
        input_name = str(target.get("name") or "")
        priority = _int_value(target.get("priority"))
        priority += _input_name_priority(input_name)
        priority += _rendered_text_input_bonus(input_name)
        priority += _reflected_priority_bonus(input_name, reflected)
        targets.append(
            {
                "kind": "query_param",
                "url": target.get("url"),
                "input": input_name,
                "hints": _string_items(target.get("hints")),
                "priority": priority,
            }
        )
    for form in _form_targets(state, limit=limit):
        action = str(form.get("action") or state.surface.get("target_url") or "")
        if not action:
            continue
        for name in _form_input_names(form):
            priority = 40
            priority += _input_name_priority(name)
            priority += _rendered_text_input_bonus(name)
            priority += _reflected_priority_bonus(name, reflected)
            priority += _api_discovered_form_bonus(form)
            targets.append(
                {
                    "kind": "form",
                    "url": action,
                    "input": name,
                    "form": form,
                    "hints": _string_items(form.get("categories")),
                    "priority": priority,
                }
            )
    for target in _signal_parameter_targets(state, reflected=reflected, limit=limit):
        targets.append(target)
    for endpoint in _signal_endpoints(state):
        endpoint_query_names = _query_param_names_from_url(endpoint)
        names = endpoint_query_names or _common_param_names(endpoint)
        endpoint_priority = _endpoint_input_priority(endpoint)
        endpoint_priority += _endpoint_query_bonus(endpoint_query_names)
        for name in names:
            if _parameter_name_looks_protocol_noise(name):
                continue
            targets.append(
                {
                    "kind": _endpoint_target_kind(endpoint),
                    "url": endpoint,
                    "input": name,
                    "hints": ["observed_input_name"],
                    "priority": 24
                    + endpoint_priority
                    + _input_name_priority(name)
                    + _rendered_text_input_bonus(name),
                }
            )
    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for target in targets:
        key = _target_dedupe_key(target)
        previous = deduped.get(key)
        if _target_should_replace_previous(target, previous):
            deduped[key] = target
    ordered = list(deduped.values())
    ordered.sort(key=_target_sort_key)
    return ordered[:limit]


def _reflected_priority_bonus(input_name: str, reflected: set[str]) -> int:
    if input_name in reflected:
        return 90
    return 0


def _endpoint_query_bonus(endpoint_query_names: list[str]) -> int:
    if endpoint_query_names:
        return 28
    return 0


def _endpoint_target_kind(endpoint: str) -> str:
    if _path_looks_login_or_search(endpoint):
        return "heuristic_post"
    return "query_param"


def _api_discovered_form_bonus(form: dict[str, object]) -> int:
    text = json.dumps(form, sort_keys=True).lower()
    if not any(marker in text for marker in ("openapi", "swagger", "api")):
        return 0
    if str(form.get("method") or "GET").upper() == "GET":
        return 80
    return 28


def _rendered_text_input_bonus(name: str) -> int:
    lowered = name.lower()
    if lowered in {"username", "user", "name", "display_name", "nickname", "handle"}:
        return 18
    if _contains_marker(
        lowered,
        (
            "comment",
            "message",
            "title",
            "body",
            "content",
            "description",
            "note",
            "bio",
            "text",
            "author",
        ),
    ):
        return 16
    return 0


def _target_dedupe_key(target: dict[str, object]) -> tuple[str, str, str]:
    kind = str(target.get("kind"))
    url = str(target.get("url"))
    input_name = str(target.get("input"))
    return kind, url, input_name


def _target_should_replace_previous(
    target: dict[str, object],
    previous: dict[str, object] | None,
) -> bool:
    if previous is None:
        return True
    return _int_value(target.get("priority")) > _int_value(previous.get("priority"))


def _target_sort_key(item: dict[str, object]) -> tuple[int, str, str]:
    priority = -_int_value(item.get("priority"))
    url = str(item.get("url"))
    input_name = str(item.get("input"))
    return priority, url, input_name


def _send_target(session: ProbeSession, target: dict[str, object], value: str) -> ProbeResponse:
    kind = str(target.get("kind") or "")
    url = str(target.get("url") or session.target_url)
    input_name = str(target.get("input") or "")
    headers = _target_headers(target)
    if kind == "form" and isinstance(target.get("form"), dict):
        form = _fresh_form_for_submission(session, _dict_value(target.get("form")), headers=headers)
        fields = form_defaults(form, marker_name=input_name, marker=value)
        return _submit_form(session, form, fields, headers=headers)
    if kind == "heuristic_post":
        return session.post_form(
            url, _heuristic_post_fields(url, input_name, value), headers=headers or None
        )
    if kind == "path_segment":
        return session.get(
            _replace_path_segment(url, _int_value(target.get("path_index")), value),
            headers=headers or None,
        )
    return session.get(inject_query_param(url, input_name, value), headers=headers or None)


def _replace_path_segment(url: str, index: int, value: str) -> str:
    parts = urlsplit(url)
    segments = parts.path.split("/")
    if 0 <= index < len(segments):
        segments[index] = quote(value, safe="")
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), parts.query, parts.fragment))


def _target_replay(target: dict[str, object], value: str) -> dict[str, object]:
    kind = str(target.get("kind") or "")
    url = str(target.get("url") or "")
    input_name = str(target.get("input") or "")
    headers = _target_headers(target)
    if kind == "form" and isinstance(target.get("form"), dict):
        form = _dict_value(target.get("form"))
        fields = form_defaults(form, marker_name=input_name, marker=value)
        replay: dict[str, object] = {
            "method": str(form.get("method") or "GET").upper(),
            "url": str(form.get("action") or url),
            "payload_field": input_name,
            "form": fields,
            "required_fields": sorted(fields),
            "encoding": "application/x-www-form-urlencoded",
            "replay_hint": "Preserve submit, hidden, and unchanged fields exactly.",
        }
        if headers:
            replay["headers"] = headers
        return replay
    if kind == "heuristic_post":
        fields = _heuristic_post_fields(url, input_name, value)
        replay = {
            "method": "POST",
            "url": url,
            "payload_field": input_name,
            "form": fields,
            "required_fields": sorted(fields),
            "encoding": "application/x-www-form-urlencoded",
        }
        if headers:
            replay["headers"] = headers
        return replay
    if kind == "path_segment":
        replay = {
            "method": "GET",
            "url": _replace_path_segment(url, _int_value(target.get("path_index")), value),
            "payload_field": f"path[{_int_value(target.get('path_index'))}]",
        }
        if headers:
            replay["headers"] = headers
        return replay
    replay = {
        "method": "GET",
        "url": inject_query_param(url, input_name, value),
        "payload_field": input_name,
    }
    if headers:
        replay["headers"] = headers
    return replay


def _target_brief(target: dict[str, object]) -> dict[str, object]:
    brief = {
        "kind": target.get("kind"),
        "url": target.get("url"),
        "input": target.get("input"),
        "hints": _string_items(target.get("hints")),
    }
    if _target_headers(target):
        brief["authenticated"] = True
    return brief


def _target_headers(target: dict[str, object]) -> dict[str, str]:
    raw_headers = target.get("auth_headers") or target.get("headers")
    if raw_headers is None and isinstance(target.get("form"), dict):
        form = _dict_value(target.get("form"))
        raw_headers = form.get("auth_headers") or form.get("headers")
    if isinstance(raw_headers, dict):
        return _headers_from_mapping(raw_headers)
    headers: dict[str, str] = {}
    if isinstance(raw_headers, list):
        for item in raw_headers:
            if not isinstance(item, str) or ":" not in item:
                continue
            name, value = item.split(":", 1)
            if name.strip() and value.strip():
                headers[name.strip()] = value.strip()
    return headers


def _headers_from_mapping(raw_headers: dict[object, object]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in raw_headers.items():
        header_name = str(name)
        header_value = str(value)
        if header_name and header_value:
            headers[header_name] = header_value
    return headers


def _submit_form(
    session: ProbeSession,
    form: dict[str, object],
    fields: dict[str, str],
    *,
    headers: dict[str, str] | None = None,
) -> ProbeResponse:
    method = str(form.get("method") or "GET").upper()
    action = str(form.get("action") or session.target_url)
    if method == "POST":
        return session.post_form(action, fields, headers=headers)
    query_url = action
    for name, value in fields.items():
        query_url = inject_query_param(query_url, name, value)
    return session.get(query_url, headers=headers)


def _fresh_form_for_submission(
    session: ProbeSession,
    form: dict[str, object],
    *,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    action = str(form.get("action") or session.target_url)
    page = session.get(action, headers=headers)
    if page.status not in {200, 201, 202}:
        return form
    candidates = _forms_from_html(page.final_url, page.body)
    match = _matching_live_form(form, candidates)
    if match is None:
        return form
    match = _preserve_form_input_values(match, form)
    categories = _string_items(form.get("categories"))
    if categories:
        current = _string_items(match.get("categories"))
        match["categories"] = _dedupe(current + categories)
    auth_headers = _target_headers({"form": form})
    if auth_headers:
        match["auth_headers"] = auth_headers
    return match


def _preserve_form_input_values(
    live_form: dict[str, object], original_form: dict[str, object]
) -> dict[str, object]:
    original_values: dict[str, str] = {}
    for input_field in _list_of_dicts(original_form.get("inputs")):
        name = str(input_field.get("name") or "")
        value = str(input_field.get("value") or "")
        if name and value:
            original_values[name] = value
    if not original_values:
        return live_form
    copied = dict(live_form)
    inputs: list[dict[str, object]] = []
    changed = False
    for input_field in _list_of_dicts(live_form.get("inputs")):
        field = dict(input_field)
        name = str(field.get("name") or "")
        if name and not str(field.get("value") or "") and name in original_values:
            field["value"] = original_values[name]
            changed = True
        inputs.append(field)
    if changed:
        copied["inputs"] = inputs
    return copied


def _forms_from_html(final_url: str, body: str) -> list[dict[str, object]]:
    parser = _SpecialistFormParser(final_url)
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed target HTML should not block probing.
        return []
    return parser.forms[:8]


class _SpecialistFormParser(HTMLParser):
    def __init__(self, final_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.final_url = final_url
        self.forms: list[dict[str, object]] = []
        self._current: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = _attributes_from_html_attrs(attrs)
        lowered = tag.lower()
        if lowered == "form":
            action = attributes.get("action") or self.final_url
            self._current = {
                "id": attributes.get("id") or f"specialist-form-{len(self.forms)}",
                "action": urljoin(self.final_url, action),
                "method": (attributes.get("method") or "GET").upper(),
                "enctype": attributes.get("enctype") or "",
                "inputs": [],
                "categories": [],
            }
            return
        if self._current is None or lowered not in {"input", "textarea", "select", "button"}:
            return
        inputs = self._current.setdefault("inputs", [])
        if isinstance(inputs, list):
            inputs.append(
                {
                    "name": attributes.get("name") or "",
                    "type": _input_type_from_attributes(lowered, attributes),
                    "value": attributes.get("value") or "",
                    "disabled": "disabled" in attributes,
                    "required": "required" in attributes,
                    "minlength": attributes.get("minlength") or "",
                    "maxlength": attributes.get("maxlength") or "",
                    "pattern": attributes.get("pattern") or "",
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current is None:
            return
        self.forms.append(self._current)
        self._current = None


def _attributes_from_html_attrs(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for name, value in attrs:
        attributes[name.lower()] = value or ""
    return attributes


def _input_type_from_attributes(tag_name: str, attributes: dict[str, str]) -> str:
    if "hidden" in attributes:
        return "hidden"
    field_type = attributes.get("type")
    if field_type:
        return field_type
    return tag_name


def _matching_live_form(
    form: dict[str, object], candidates: list[dict[str, object]]
) -> dict[str, object] | None:
    original_names = _form_input_name_set(form)
    original_action = str(form.get("action") or "").rstrip("/")
    original_method = str(form.get("method") or "GET").upper()
    best: tuple[int, dict[str, object]] | None = None
    for candidate in candidates:
        if str(candidate.get("method") or "GET").upper() != original_method:
            continue
        candidate_names = _form_input_name_set(candidate)
        overlap = len(original_names & candidate_names)
        if original_action and str(candidate.get("action") or "").rstrip("/") == original_action:
            overlap += 2
        if overlap <= 0:
            continue
        if best is None or overlap > best[0]:
            best = (overlap, candidate)
    return _matching_live_form_result(best)


def _form_input_name_set(form: dict[str, object]) -> set[str]:
    names: set[str] = set()
    for item in _list_of_dicts(form.get("inputs")):
        name = str(item.get("name") or "")
        if name:
            names.add(name)
    return names


def _matching_live_form_result(
    best: tuple[int, dict[str, object]] | None,
) -> dict[str, object] | None:
    if best is None:
        return None
    return dict(best[1])


def _heuristic_post_fields(url: str, input_name: str, value: str) -> dict[str, str]:
    lowered = url.lower()
    if "login" in lowered or "signin" in lowered:
        fields = {
            "username": "ravage",
            "user": "ravage",
            "email": "ravage@example.test",
            "password": "RavagePass123!",
        }
    elif "search" in lowered:
        fields = {"q": "ravage", "search": "ravage", "query": "ravage"}
    else:
        fields = {"id": "1", "q": "ravage", "search": "ravage"}
    fields[input_name] = value
    return fields


def _baseline_value(name: str) -> str:
    lowered = name.lower()
    if lowered in {"id", "page", "limit", "offset"} or lowered.endswith("id"):
        return "1"
    if "email" in lowered:
        return "ravage@example.test"
    if "pass" in lowered:
        return "RavagePass123!"
    return "ravage"


def _slow_response(response: ProbeResponse) -> bool:
    return response.elapsed_ms >= _SLOW_RESPONSE_MS


def _auth_headers_from_state(state: AgentState) -> dict[str, str]:
    for form in _signal_form_targets(state):
        headers = _target_headers({"form": form})
        if headers:
            return headers
    for value in state.signals.get("auth_headers", []):
        text = str(value)
        if ":" not in text:
            continue
        name, raw = text.split(":", 1)
        if name.strip() and raw.strip():
            return {name.strip(): raw.strip()}
    cookies = _cookie_signal_values(state)
    if cookies:
        return {"Cookie": "; ".join(_dedupe(cookies)[:6])}
    return {}


def _cookie_signal_values(state: AgentState) -> list[str]:
    cookies: list[str] = []
    for value in state.signals.get("cookies", []):
        text = str(value).strip()
        if "=" in text:
            cookies.append(text)
    return cookies


def _name_looks_expression_context(name: str, url: str) -> bool:
    text = f"{name} {url}".lower()
    return _contains_marker(
        text,
        (
            "term",
            "amount",
            "principal",
            "payment",
            "rate",
            "months",
            "years",
            "value",
            "expression",
            "calc",
            "amort",
            "total",
            "date",
            "time",
            "remind",
            "reminder",
            "notify",
            "schedule",
        ),
    )


def _target_current_value(target: dict[str, object]) -> str:
    input_name = str(target.get("input") or "")
    url = str(target.get("url") or "")
    for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if key == input_name and value:
            return value
    form = target.get("form")
    if isinstance(form, dict):
        defaults = form_defaults(form)
        if defaults.get(input_name):
            return defaults[input_name]
    return ""


def _name_looks_idor(name: str, url: str) -> bool:
    lowered = f"{name} {url}".lower()
    return _contains_marker(
        lowered,
        (
            "id",
            "user",
            "account",
            "profile",
            "order",
            "invoice",
            "file",
            "doc",
            "message",
            "post",
            "item",
            "resource",
            "email",
            "company",
            "tenant",
            "org",
            "organization",
            "workspace",
            "job",
        ),
    )


def _value_looks_idor_id(value: str) -> bool:
    return _idor_id_format(value) in {"numeric", "uuid", "hash", "objectid", "email", "username"}


def _idor_id_format(value: str) -> str:
    if re.fullmatch(r"\d+", value or ""):
        return "numeric"
    if re.fullmatch(
        r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}", value or ""
    ):
        return "uuid"
    if _looks_mongo_object_id(value):
        return "objectid"
    if re.fullmatch(r"[a-fA-F0-9]{32,64}", value or ""):
        return "hash"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value or ""):
        return "email"
    if re.fullmatch(r"[a-zA-Z0-9_-]{3,40}", value or ""):
        return "username"
    return "custom"


def _looks_mongo_object_id(value: str) -> bool:
    return bool(_MONGO_OBJECT_ID_RE.fullmatch(value or ""))


def _parameter_targets(state: AgentState, *, limit: int) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
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
    targets.sort(key=_parameter_target_sort_key)
    return targets[:limit]


def _parameter_target_sort_key(item: dict[str, object]) -> tuple[int, str]:
    priority = -_int_value(item.get("priority"))
    name = str(item.get("name"))
    return priority, name


def _form_targets(state: AgentState, *, limit: int) -> list[dict[str, object]]:
    forms = _list_of_dicts(state.surface.get("forms"))
    forms.extend(_signal_form_targets(state))
    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for form in forms:
        action = str(form.get("action") or "")
        method = str(form.get("method") or "GET").upper()
        names = ",".join(_form_input_names(form))
        key = (method, action, names)
        previous = deduped.get(key)
        if previous is None or _form_priority(form) > _form_priority(previous):
            deduped[key] = form
    ordered = list(deduped.values())
    ordered.sort(key=_form_target_sort_key)
    return ordered[:limit]


def _form_target_sort_key(item: dict[str, object]) -> tuple[int, str]:
    priority = -_form_priority(item)
    action = str(item.get("action") or "")
    return priority, action


def _signal_form_targets(state: AgentState) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for value in state.signals.get("forms", []):
        text = str(value).strip()
        if not text.startswith("{"):
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        inputs = _list_of_dicts(parsed.get("inputs"))
        action = str(parsed.get("action") or "")
        if not action or not inputs:
            continue
        form = dict(parsed)
        form["inputs"] = inputs
        forms.append(form)
    return forms[:16]


def _form_priority(form: dict[str, object]) -> int:
    text = json.dumps(form, sort_keys=True).lower()
    score = 0
    if form.get("auth_headers"):
        score += 40
    if "multipart/form-data" in text or '"type": "file"' in text:
        score += 24
    if _contains_marker(
        text, ("template", "include", "error_type", "page", "view", "profile", "name")
    ):
        score += 16
    if _contains_marker(text, ("csrf", "_token")):
        score += 4
    return score


def _form_input_names(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        input_type = str(input_field.get("type") or "").lower()
        if name and input_type not in {"hidden", "submit", "button", "reset", "file"}:
            names.append(name)
    return names[:8]


def _signal_parameter_names(state: AgentState) -> list[str]:
    names: list[str] = []
    for name in state.signals.get("parameters", []):
        text = str(name)
        if text:
            names.append(text)
    return _dedupe(names)


def _signal_parameter_targets(
    state: AgentState,
    *,
    reflected: set[str],
    limit: int,
) -> list[dict[str, object]]:
    names = [
        name
        for name in _signal_parameter_names(state)
        if not _parameter_name_looks_protocol_noise(name)
    ][: limit * 2]
    if not names:
        return []

    targets: list[dict[str, object]] = []
    for url in _signal_parameter_base_urls(state)[:4]:
        for name in names:
            priority = 28
            priority += _input_name_priority(name)
            priority += _rendered_text_input_bonus(name)
            priority += _reflected_priority_bonus(name, reflected)
            targets.append(
                {
                    "kind": "query_param",
                    "url": url,
                    "input": name,
                    "hints": ["observed_parameter_name"],
                    "priority": priority,
                }
            )
    targets.sort(key=_target_sort_key)
    return targets[:limit]


def _signal_parameter_base_urls(state: AgentState) -> list[str]:
    candidates: list[str] = []
    target_url = str(state.surface.get("target_url") or "")
    origin = str(state.surface.get("origin") or target_url)
    if target_url:
        candidates.append(target_url)
    if origin:
        candidates.append(origin.rstrip("/") + "/")
    for endpoint in _surface_endpoints(state):
        if endpoint:
            candidates.append(endpoint)

    cleaned: list[str] = []
    for candidate in candidates:
        clean = _queryless_url(candidate)
        if not clean:
            continue
        if _endpoint_text_looks_malformed(clean) or _path_looks_static_or_markup_fragment(clean):
            continue
        cleaned.append(clean)
    return _dedupe(cleaned)


def _queryless_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return ""
    if not parsed.scheme or not parsed.netloc:
        return ""
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _parameter_name_looks_protocol_noise(name: str) -> bool:
    lowered = name.lower()
    return lowered in {"eio", "transport", "sid", "t"} or lowered.startswith("utm_")


def _signal_endpoints(state: AgentState) -> list[str]:
    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "")
    endpoints: list[str] = []
    for url in state.signals.get("endpoints", []):
        text = str(url)
        if not text:
            continue
        if text.startswith("/"):
            text = origin.rstrip("/") + text
        if (
            origin
            and not text.startswith(origin.rstrip("/") + "/")
            and text.rstrip("/") != origin.rstrip("/")
        ):
            continue
        if _endpoint_text_looks_malformed(text):
            continue
        if _url_looks_generated_probe_payload(text):
            continue
        if _path_looks_static_or_markup_fragment(text):
            continue
        endpoints.append(text)
    ordered = _dedupe(endpoints)
    ordered.sort(key=_endpoint_sort_key)
    return ordered[:12]


def _endpoint_text_looks_malformed(url: str) -> bool:
    return any(marker in url for marker in ("\\n", "\n", "\r", "[", "]", '"', "'"))


def _endpoint_sort_key(url: str) -> tuple[int, str]:
    priority = -_endpoint_input_priority(url)
    return priority, str(url)


def _query_param_names_from_url(url: str) -> list[str]:
    try:
        query = urlsplit(url).query
    except ValueError:
        return []
    names: list[str] = []
    for name, _value in parse_qsl(query, keep_blank_values=True):
        if name:
            names.append(name)
    return _dedupe(names)


def _endpoint_input_priority(url: str) -> int:
    lowered = url.lower()
    score = 0
    try:
        if urlsplit(url).query:
            score += 16
    except ValueError:
        return score
    if _contains_marker(
        lowered,
        (
            "template",
            "render",
            "preview",
            "message",
            "notify",
            "schedule",
            "remind",
            "reminder",
        ),
    ):
        score += 36
    if _contains_marker(
        lowered, ("calc", "loan", "amort", "payment", "quote", "price", "total")
    ):
        score += 24
    if _contains_marker(lowered, ("login", "logout", "static", "asset")):
        score -= 12
    if _url_looks_generated_probe_payload(url):
        score -= 80
    return score


def _url_looks_generated_probe_payload(url: str) -> bool:
    try:
        query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return False
    for _name, value in query:
        if _query_value_looks_generated_probe_payload(value):
            return True
    return False


def _query_value_looks_generated_probe_payload(value: str) -> bool:
    lowered = value.lower()
    if re.search(r"\bxss[0-9a-f_-]{4,}\b", lowered):
        return True
    if "xss" in lowered and any(marker in lowered for marker in ("<", "on", "alert", "prompt", "confirm")):
        return True
    return _contains_marker(
        lowered,
        (
            "<script",
            "<svg",
            "<details",
            "<input",
            "<source",
            "onload",
            "onerror",
            "onfocus",
            "ontoggle",
            "autofocus",
            "alert(",
            "prompt(",
            "confirm(",
            "{{",
            "}}",
            "{%",
            "%}",
            "${",
            "#{",
        ),
    )


def _reflected_input_names(state: AgentState) -> set[str]:
    names: set[str] = set()
    for reflection in _list_of_dicts(state.surface.get("reflections")):
        for key in ("name", "parameter", "input"):
            value = str(reflection.get(key) or "")
            if value:
                names.add(value)
    for raw in state.signals.get("reflections", []):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            reflection = cast(dict[str, object], payload)
            for key in ("name", "parameter", "input"):
                value = str(reflection.get(key) or "")
                if value:
                    names.add(value)
    return names


def _path_looks_static_or_markup_fragment(url: str) -> bool:
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return True
    if path in {"/html", "/head", "/body", "/title", "/script", "/css"}:
        return True
    return _endswith_marker(
        path,
        (
            ".css",
            ".js",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".ico",
            ".woff",
            ".woff2",
        ),
    )


def _surface_endpoints(state: AgentState) -> list[str]:
    endpoints: list[str] = []
    for item in _list_of_dicts(state.surface.get("endpoints")):
        url = str(item.get("url") or "")
        if url:
            endpoints.append(url)
    for page in _list_of_dicts(state.surface.get("pages")):
        for key in ("final_url", "url"):
            url = str(page.get(key) or "")
            if url:
                endpoints.append(url)
        endpoints.extend(_string_items(page.get("links")))
    endpoints.extend(_signal_endpoints(state))
    return _dedupe(endpoints)


def _common_param_names(url: str) -> list[str]:
    lowered = url.lower()
    names = [
        "q",
        "search",
        "query",
        "id",
        "name",
        "username",
        "user",
        "email",
        "title",
        "filter",
        "sort",
        "page",
    ]
    if _contains_marker(
        lowered,
        ("template", "include", "render", "view", "page", "error", "file"),
    ):
        names = [
            "template",
            "page",
            "view",
            "file",
            "path",
            "filename",
            "error_type",
            "type",
            "message",
            *names,
        ]
    if _contains_marker(
        lowered,
        ("calc", "loan", "amort", "payment", "quote", "price", "total"),
    ):
        names = [
            "term",
            "amount",
            "principal",
            "payment",
            "rate",
            "months",
            "years",
            "value",
            "expression",
            *names,
        ]
    if _contains_marker(
        lowered,
        ("remind", "reminder", "notify", "schedule", "date", "time"),
    ):
        names = ["date", "time", "message", "template", "value", "text", *names]
    if "login" in lowered or "signin" in lowered:
        names = ["username", "user", "email", "login", "password", "pass", *names]
    if "search" in lowered:
        names = ["search", "q", "query", "term", "keyword", "name", "username", "email", *names]
    if "user" in lowered:
        names = ["id", "user", "username", "email", "name", *names]
    return _dedupe(names)[:12]


def _path_looks_login_or_search(url: str) -> bool:
    try:
        lowered = urlsplit(url).path.lower()
    except ValueError:
        lowered = url.lower()
    return _contains_marker(
        lowered,
        ("search", "login", "signin", "user", "lookup", "filter", "admin", "auth"),
    )


def _input_name_priority(name: str) -> int:
    lowered = name.lower()
    if _contains_marker(
        lowered,
        (
            "template",
            "include",
            "view",
            "page",
            "file",
            "path",
            "error_type",
            "filename",
        ),
    ):
        return 22
    if _contains_marker(
        lowered,
        ("term", "amount", "principal", "payment", "rate", "expression", "calc"),
    ):
        return 18
    if _contains_marker(lowered, ("date", "time", "remind", "message", "value", "text")):
        return 14
    if _contains_marker(
        lowered,
        ("search", "query", "q", "comment", "message", "name", "title", "body"),
    ):
        return 12
    if _name_looks_idor(lowered, ""):
        return 10
    if lowered in {"q", "search", "query", "id", "username", "user", "email", "name", "title"}:
        return 12
    if _contains_marker(
        lowered,
        ("search", "query", "user", "id", "email", "name", "title", "filter", "sort"),
    ):
        return 8
    return 0


def _looks_filtered_response(body: str) -> bool:
    lowered = body.lower()
    return _contains_marker(
        lowered,
        (
            "filtered",
            "blocked",
            "blacklist",
            "forbidden keyword",
            "not allowed",
            "waf",
            "invalid character",
        ),
    )


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
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


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False


def _endswith_marker(text: str, suffixes: tuple[str, ...]) -> bool:
    for suffix in suffixes:
        if text.endswith(suffix):
            return True
    return False
