from __future__ import annotations

from urllib.parse import urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.probes.cookie.cookie_deserialization_discovery import _cookie_harvest_forms
from ravage.probes.cookie.cookie_deserialization_shared import (
    _dedupe_urls,
    _in_scope,
    _list_of_dicts,
)
from ravage.web_core.http_probe import ProbeSession

_DESER_FIELD_MARKERS = (
    "payload",
    "data",
    "state",
    "session",
    "cookie",
    "profile",
    "cart",
    "object",
    "config",
    "yaml",
    "pickle",
    "serialized",
    "serialize",
    "token",
    "bookmark",
    "bookmarks",
    "links",
    "url",
    "sku",
)

_BODY_DESER_ENDPOINT_MARKERS = (
    "deserialize",
    "unserialize",
    "import",
    "restore",
    "load",
    "state",
    "session",
    "profile",
    "cart",
    "api",
)


def _body_deserialization_targets(
    session: ProbeSession, state: AgentState
) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    targets.extend(_form_body_deserialization_targets(session, state))
    targets.extend(_surface_parameter_deserialization_targets(session, state))
    targets.extend(_signal_endpoint_deserialization_targets(session, state))
    return _dedupe_body_deserialization_targets(targets)


def _form_body_deserialization_targets(
    session: ProbeSession,
    state: AgentState,
) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for form in _cookie_harvest_forms(state):
        action = str(form.get("action") or session.target_url)
        if not action or not _in_scope(session, action):
            continue
        for name in _form_input_names(form):
            if not _looks_deserialization_field(name):
                continue
            targets.append(
                {
                    "kind": "form",
                    "url": action,
                    "input": name,
                    "form": form,
                    "priority": 80,
                }
            )
    return targets


def _surface_parameter_deserialization_targets(
    session: ProbeSession,
    state: AgentState,
) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for param in _list_of_dicts(state.surface.get("parameters")):
        name = str(param.get("name") or "")
        if not _looks_deserialization_field(name):
            continue
        for location in _parameter_locations(session, state, param):
            if _in_scope(session, location):
                targets.append(
                    {
                        "kind": "query_param",
                        "url": location,
                        "input": name,
                        "priority": 55,
                    }
                )
    return targets


def _parameter_locations(
    session: ProbeSession,
    state: AgentState,
    param: dict[str, object],
) -> list[str]:
    raw_locations = param.get("locations")
    locations: list[str] = []
    if isinstance(raw_locations, list):
        for item in raw_locations:
            if item:
                locations.append(str(item))
    if locations:
        return locations
    return [str(state.surface.get("target_url") or session.target_url)]


def _signal_endpoint_deserialization_targets(
    session: ProbeSession,
    state: AgentState,
) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    signal_params = _deserialization_signal_parameters(state)
    for endpoint in _state_endpoint_urls(session, state):
        if not _in_scope(session, endpoint):
            continue
        for name in signal_params[:4]:
            targets.append(
                {
                    "kind": "query_param",
                    "url": endpoint,
                    "input": name,
                    "priority": 45,
                }
            )
        if _endpoint_looks_body_deserialization_candidate(endpoint):
            for name in ("payload", "data", "state"):
                targets.append(
                    {
                        "kind": "json_post",
                        "url": endpoint,
                        "input": name,
                        "priority": 40,
                    }
                )
    return targets


def _deserialization_signal_parameters(state: AgentState) -> list[str]:
    params: list[str] = []
    for value in state.signals.get("parameters", []):
        name = str(value)
        if _looks_deserialization_field(name):
            params.append(name)
    return params


def _dedupe_body_deserialization_targets(
    targets: list[dict[str, object]],
) -> list[dict[str, object]]:
    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for target in targets:
        key = (str(target.get("kind")), str(target.get("url")), str(target.get("input")))
        previous = deduped.get(key)
        if previous is None:
            deduped[key] = target
            continue
        if _target_priority(target) > _target_priority(previous):
            deduped[key] = target
    ordered = list(deduped.values())
    ordered.sort(key=_body_deserialization_target_sort_key)
    return ordered


def _body_deserialization_target_sort_key(target: dict[str, object]) -> tuple[int, str, str]:
    priority = _target_priority(target)
    url = str(target.get("url") or "")
    input_name = str(target.get("input") or "")
    return -priority, url, input_name


def _target_priority(target: dict[str, object]) -> int:
    raw_priority = target.get("priority")
    if isinstance(raw_priority, int):
        return raw_priority
    if isinstance(raw_priority, str):
        try:
            return int(raw_priority)
        except ValueError:
            return 0
    return 0


def _body_deserialization_target_brief(target: dict[str, object]) -> dict[str, object]:
    return {
        "kind": str(target.get("kind") or ""),
        "url": str(target.get("url") or ""),
        "input": str(target.get("input") or ""),
    }


def _looks_deserialization_field(name: str) -> bool:
    lowered = name.lower()
    for marker in _DESER_FIELD_MARKERS:
        if marker in lowered:
            return True
    return False


def _form_input_names(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        if name:
            names.append(name)
    return names


def _form_auth_headers(form: dict[str, object]) -> dict[str, str]:
    raw = form.get("auth_headers")
    if not isinstance(raw, dict):
        return {}
    headers: dict[str, str] = {}
    for name, value in raw.items():
        if name:
            headers[str(name)] = str(value)
    return headers


def _state_endpoint_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls = [str(state.surface.get("target_url") or session.target_url)]
    for endpoint in _list_of_dicts(state.surface.get("endpoints")):
        url = str(endpoint.get("url") or "")
        if url:
            urls.append(url)
    for value in state.signals.get("endpoints", []):
        if value:
            urls.append(str(value))
    return _dedupe_urls(urls)[:18]


def _endpoint_looks_body_deserialization_candidate(url: str) -> bool:
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return False
    for marker in _BODY_DESER_ENDPOINT_MARKERS:
        if marker in path:
            return True
    return False
