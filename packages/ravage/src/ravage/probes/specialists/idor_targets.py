from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.probes.specialists.shared import (
    _auth_headers_from_state,
    _baseline_value,
    _dedupe,
    _form_targets,
    _generic_input_targets,
    _idor_id_format,
    _input_name_priority,
    _int_value,
    _list_of_dicts,
    _looks_mongo_object_id,
    _name_looks_expression_context,
    _name_looks_idor,
    _string_items,
    _surface_endpoints,
    _target_current_value,
    _target_headers,
    _value_looks_idor_id,
)
from ravage.web_core.http_probe import form_defaults


def _idor_path_targets(state: AgentState) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()
    auth_headers = _auth_headers_from_state(state)
    for endpoint in _surface_endpoints(state):
        parts = urlsplit(endpoint)
        segments = parts.path.split("/")
        for index, segment in enumerate(segments):
            if not segment or "." in segment:
                continue
            id_format = _idor_id_format(segment)
            if id_format not in {"numeric", "uuid", "hash", "objectid"}:
                continue
            base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            key = (base, index)
            if key in seen:
                continue
            seen.add(key)
            preceding = _preceding_path_segment(segments, index)
            target: dict[str, object] = {
                "kind": "path_segment",
                "url": base,
                "input": preceding or "path",
                "path_index": index,
                "baseline_id": segment,
                "id_format": id_format,
                "object_type": _idor_object_type(preceding, parts.path),
                "hints": ["path_id"],
                "priority": 78,
            }
            if auth_headers:
                target["auth_headers"] = auth_headers
                target["priority"] = 168
            targets.append(target)
    return targets


def _idor_targets(state: AgentState) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    targets.extend(_idor_path_targets(state))
    targets.extend(_idor_form_targets(state))
    for target in _generic_input_targets(state, limit=24):
        input_name = str(target.get("input") or "")
        url = str(target.get("url") or "")
        if _target_is_auth_identity_field(target):
            continue
        current_value = _target_current_value(target)
        baseline_id = current_value or _baseline_value(input_name)
        name_looks_idor = _name_looks_idor(input_name, url)
        if _name_looks_credential_secret(input_name) and not name_looks_idor:
            continue
        if _looks_expression_only_idor_candidate(input_name, url):
            continue
        if not name_looks_idor and not _value_is_structured_idor_id(current_value):
            continue
        targets.append(
            target
            | {
                "baseline_id": baseline_id,
                "id_format": _idor_id_format(baseline_id),
                "object_type": _idor_object_type(input_name, url),
                "priority": _int_value(target.get("priority")) + 30,
            }
        )
    for endpoint in _surface_endpoints(state):
        for param_name, value in parse_qsl(urlsplit(endpoint).query, keep_blank_values=True):
            if _looks_expression_only_idor_candidate(param_name, endpoint):
                continue
            if not (
                _name_looks_idor(param_name, endpoint)
                or _value_is_structured_idor_id(value)
            ):
                continue
            baseline_id = value or _baseline_value(param_name)
            targets.append(
                {
                    "kind": "query_param",
                    "url": endpoint,
                    "input": param_name,
                    "baseline_id": baseline_id,
                    "hints": ["endpoint_query_id"],
                    "id_format": _idor_id_format(baseline_id),
                    "object_type": _idor_object_type(param_name, endpoint),
                    "priority": 70,
                }
            )
    if _targets_include_authenticated_context(targets):
        targets = _authenticated_or_path_id_targets(targets)
    deduped: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for target in targets:
        dedupe_key = _idor_target_dedupe_key(target)
        previous = deduped.get(dedupe_key)
        if _target_has_higher_priority(target, previous):
            deduped[dedupe_key] = target
    ordered = list(deduped.values())
    ordered.sort(key=_idor_target_sort_key)
    return ordered[:16]


def _preceding_path_segment(segments: list[str], index: int) -> str:
    if index <= 0:
        return ""
    return segments[index - 1]


def _targets_include_authenticated_context(targets: list[dict[str, object]]) -> bool:
    for target in targets:
        if _target_headers(target):
            return True
    return False


def _authenticated_or_path_id_targets(
    targets: list[dict[str, object]],
) -> list[dict[str, object]]:
    filtered: list[dict[str, object]] = []
    for target in targets:
        if _target_headers(target):
            filtered.append(target)
            continue
        if "path_id" in _string_items(target.get("hints")):
            filtered.append(target)
    return filtered


def _idor_target_dedupe_key(target: dict[str, object]) -> tuple[str, str, str, str]:
    kind = str(target.get("kind"))
    url = str(target.get("url"))
    input_name = str(target.get("input"))
    baseline_id = str(target.get("baseline_id"))
    return kind, url, input_name, baseline_id


def _target_has_higher_priority(
    target: dict[str, object],
    previous: dict[str, object] | None,
) -> bool:
    if previous is None:
        return True
    return _int_value(target.get("priority")) > _int_value(previous.get("priority"))


def _idor_target_sort_key(item: dict[str, object]) -> tuple[int, str, str]:
    priority = -_int_value(item.get("priority"))
    url = str(item.get("url"))
    input_name = str(item.get("input"))
    return priority, url, input_name


def _idor_form_targets(state: AgentState) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for form in _form_targets(state, limit=24):
        action = str(form.get("action") or state.surface.get("target_url") or "")
        if not action:
            continue
        defaults = form_defaults(form)
        auth_bonus = _form_auth_bonus(form)
        for input_field in _list_of_dicts(form.get("inputs")):
            name = str(input_field.get("name") or "")
            if not name or input_field.get("disabled"):
                continue
            input_type = str(input_field.get("type") or "text").lower()
            if input_type in {"button", "file", "image", "reset", "submit"}:
                continue
            if _auth_form_identity_field(name, form, action):
                continue
            value = defaults.get(name) or str(input_field.get("value") or "")
            name_looks_idor = _name_looks_idor(name, action)
            if _name_looks_credential_secret(name) and not name_looks_idor:
                continue
            if _looks_expression_only_idor_candidate(name, action):
                continue
            if not name_looks_idor and not _value_is_structured_idor_id(value):
                continue
            baseline_id = value or _baseline_value(name)
            priority = 55 + auth_bonus + _input_name_priority(name)
            lowered_name = name.lower().replace("-", "_")
            if lowered_name == "id" or lowered_name.endswith("_id") or lowered_name.endswith("id"):
                priority += 25
            if input_type == "hidden":
                priority += 35
            if value:
                priority += 20
            if _value_looks_idor_id(value):
                priority += 20
            targets.append(
                {
                    "kind": "form",
                    "url": action,
                    "input": name,
                    "form": form,
                    "baseline_id": baseline_id,
                    "hints": _dedupe([*_string_items(form.get("categories")), "form_object_id"]),
                    "id_format": _idor_id_format(baseline_id),
                    "object_type": _idor_object_type(name, action),
                    "priority": priority,
                }
            )
    return targets


def _value_is_structured_idor_id(value: str) -> bool:
    return _idor_id_format(value) in {"numeric", "uuid", "hash", "objectid"}


def _form_auth_bonus(form: dict[str, object]) -> int:
    if _target_headers({"form": form}):
        return 90
    return 0


def _name_looks_credential_secret(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return _contains_marker(
        lowered,
        (
            "access_token",
            "api_key",
            "auth_token",
            "csrf",
            "pass",
            "password",
            "pwd",
            "secret",
            "session_token",
        ),
    )


def _target_is_auth_identity_field(target: dict[str, object]) -> bool:
    form = target.get("form")
    return isinstance(form, dict) and _auth_form_identity_field(
        str(target.get("input") or ""),
        form,
        str(target.get("url") or form.get("action") or ""),
    )


def _auth_form_identity_field(name: str, form: dict[str, object], action: str) -> bool:
    lowered = name.lower().replace("-", "_")
    if lowered not in {"username", "user", "email", "login", "account"}:
        return False
    if lowered.endswith("_id") or lowered == "user_id":
        return False
    categories = " ".join(_string_items(form.get("categories"))).lower()
    if "auth" in categories or "login" in categories or "signin" in categories:
        return True
    if (
        str(form.get("method") or "GET").upper() == "POST"
        and _path_is_root(action)
        and _form_has_only_auth_identity_fields(form)
    ):
        return True
    return _path_looks_auth_flow(action)


def _form_has_only_auth_identity_fields(form: dict[str, object]) -> bool:
    names = []
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "").lower().replace("-", "_")
        input_type = str(input_field.get("type") or "text").lower()
        if not name or input_type in {"button", "submit", "reset", "image", "file"}:
            continue
        names.append(name)
    if not names:
        return False
    allowed = {"username", "user", "email", "login", "account", "password", "pass", "pwd"}
    return _all_names_allowed(names, allowed)


def _all_names_allowed(names: list[str], allowed: set[str]) -> bool:
    for name in names:
        if name not in allowed:
            return False
    return True


def _path_is_root(url: str) -> bool:
    try:
        path = urlsplit(url).path.rstrip("/") or "/"
    except ValueError:
        return False
    return path == "/"


def _path_looks_auth_flow(url: str) -> bool:
    try:
        path = urlsplit(url).path.lower().rstrip("/") or "/"
    except ValueError:
        return False
    if path in {"/login", "/signin", "/sign-in", "/auth"}:
        return True
    return _contains_marker(path, ("login", "signin", "sign-in", "authenticate", "password"))


def _looks_expression_only_idor_candidate(name: str, url: str) -> bool:
    return _name_looks_expression_context(name, url) and not _name_looks_idor(name, url)


def _idor_object_type(name: str, url: str) -> str:
    lowered = f"{name} {url}".lower()
    for object_type, tokens in {
        "user": ("user", "account", "profile", "member", "email"),
        "company": ("company", "tenant", "org", "organization", "workspace"),
        "order": ("order", "purchase", "cart", "invoice"),
        "file": ("file", "document", "doc", "download"),
        "message": ("message", "mail", "chat"),
        "post": ("post", "article", "blog"),
        "job": ("job", "jobs", "posting"),
        "resource": ("resource", "item", "object"),
    }.items():
        if _contains_marker(lowered, tokens):
            return object_type
    return "resource"


def _idor_candidate_values(current_id: str, id_format: str) -> list[str]:
    candidates: list[str] = []
    if id_format == "numeric":
        current = int(current_id or "1")
        for offset in (
            1,
            -1,
            2,
            -2,
            3,
            -3,
            5,
            -5,
            8,
            -8,
            10,
            -10,
            13,
            -13,
            16,
            -16,
            20,
            -20,
            25,
            -25,
            32,
            -32,
        ):
            candidate = current + offset
            if candidate >= 0:
                candidates.append(str(candidate))
        if current >= 100:
            boundaries = _numeric_id_boundaries(current)
            for boundary in boundaries:
                for offset in (0, 1, 2, 3, 5, 8, 10, 13, 16, 20, 25, 32, 50, 100):
                    candidate = boundary + offset
                    if candidate >= 0:
                        candidates.append(str(candidate))
        candidates.extend(["0", "1", "2", "3", "4", "5", "10", "100", "1000"])
    elif id_format == "uuid":
        candidates.extend(
            ["00000000-0000-0000-0000-000000000000", "11111111-1111-1111-1111-111111111111"]
        )
    elif id_format == "objectid":
        candidates.extend(_object_id_counter_candidates(current_id))
    elif id_format == "email":
        candidates.extend(
            ["admin@example.com", "admin@localhost", "user@example.com", "test@example.com"]
        )
    elif id_format == "username":
        candidates.extend(["admin", "administrator", "root", "user", "test", "guest", "support"])
    else:
        candidates.extend(["1", "2", "admin", "test", "flag"])
    limit = _candidate_limit_for_format(id_format)
    return _candidate_values_without_current(candidates, current_id)[:limit]


def _candidate_limit_for_format(id_format: str) -> int:
    if id_format in {"numeric", "objectid"}:
        return 48
    return 10


def _candidate_values_without_current(candidates: list[str], current_id: str) -> list[str]:
    filtered: list[str] = []
    for candidate in _dedupe(candidates):
        if candidate != current_id:
            filtered.append(candidate)
    return filtered


def _numeric_id_boundaries(current: int) -> list[int]:
    boundaries: list[int] = []
    for magnitude in (10, 100, 1000, 10_000, 100_000, 1_000_000):
        if current < magnitude:
            continue
        boundaries.append((current // magnitude) * magnitude)
    unique_boundaries: list[int] = []
    boundary_strings: list[str] = []
    for value in boundaries:
        boundary_strings.append(str(value))
    for value in _dedupe(boundary_strings):
        unique_boundaries.append(int(value))
    return unique_boundaries


def _object_id_counter_candidates(current_id: str) -> list[str]:
    if not _looks_mongo_object_id(current_id):
        return []
    prefix = current_id[:18].lower()
    counter = int(current_id[-6:], 16)
    candidates: list[str] = []
    for offset in (
        1,
        -1,
        2,
        -2,
        3,
        -3,
        4,
        -4,
        5,
        -5,
        8,
        -8,
        10,
        -10,
        16,
        -16,
        20,
        -20,
        32,
        -32,
        50,
        -50,
        100,
        -100,
    ):
        candidate_counter = counter + offset
        if 0 <= candidate_counter <= 0xFFFFFF:
            candidates.append(f"{prefix}{candidate_counter:06x}")
    return candidates


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False
