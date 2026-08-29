from __future__ import annotations

import json
from urllib.parse import urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.auth_forms import _form_has_password_input, _forms_from_html
from ravage.probe_suite_parts.support import (
    _contains_word,
    _dedupe,
    _form_targets,
    _form_text,
    _list_of_dicts,
    _string_items,
    _surface_endpoints,
)
from ravage.web_core.http_probe import ProbeSession

__all__ = [
    "_auth_forms",
    "_discover_auth_forms",
    "_form_looks_auth_related",
    "_form_looks_login_related",
    "_form_looks_registration_related",
    "_ordered_auth_forms",
]

_AUTH_DISCOVERY_PATHS = (
    "/",
    "/wp-login.php",
    "/wp-admin/",
    "/login",
    "/signin",
    "/register",
    "/signup",
    "/sign-up",
    "/accounts/register/",
)
_AUTH_DISCOVERY_ENDPOINT_MARKERS = (
    "login",
    "signin",
    "sign-in",
    "register",
    "signup",
    "sign-up",
    "account",
    "admin",
)
_AUTH_CONTEXT_MARKERS = (
    "login",
    "signin",
    "sign-in",
    "register",
    "signup",
    "sign-up",
    "auth",
    "session",
    "password",
    "account",
)
_REGISTRATION_MARKERS = (
    "register",
    "signup",
    "sign-up",
    "create account",
    "new account",
    "accounts/register",
)


def _auth_forms(state: AgentState) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "")

    for form in _form_targets(state, limit=12):
        if _form_looks_auth_related(form):
            forms.append(form)

    for form in _signal_forms(state):
        if not _form_action_in_scope_for_origin(form, origin):
            continue
        if _form_looks_auth_related(form):
            forms.append(form)

    return _dedupe_forms(forms)


def _discover_auth_forms(
    session: ProbeSession,
    state: AgentState,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    requests: list[dict[str, object]] = []
    forms: list[dict[str, object]] = []

    for url in _auth_discovery_urls(session, state):
        if not session.in_scope(url):
            continue

        response = session.get(url)
        requests.append(response.summary(body_chars=360) | {"probe_kind": "auth_form_discovery"})
        if response.status not in {200, 201, 202}:
            continue

        for form in _forms_from_html(response.final_url, response.body, auth_headers={}, base_categories=()):
            if _form_looks_auth_related(form):
                forms.append(form)

    if not forms:
        forms.extend(_heuristic_signal_auth_forms(session, state))

    return _ordered_auth_forms(forms), requests


def _auth_discovery_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls = [session.target_url]
    for path in _AUTH_DISCOVERY_PATHS:
        urls.append(session.absolute(path))

    for endpoint in _surface_endpoints(state):
        lowered = endpoint.lower()
        for marker in _AUTH_DISCOVERY_ENDPOINT_MARKERS:
            if marker in lowered:
                urls.append(endpoint)
                break

    return _dedupe(urls)


def _form_action_in_scope_for_origin(form: dict[str, object], origin: str) -> bool:
    action = str(form.get("action") or "")
    if not action or not origin:
        return True

    try:
        action_parts = urlsplit(action)
        origin_parts = urlsplit(origin)
    except ValueError:
        return False

    if not action_parts.scheme and not action_parts.netloc:
        return True

    return (action_parts.scheme, action_parts.netloc) == (origin_parts.scheme, origin_parts.netloc)


def _signal_forms(state: AgentState) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for value in state.signals.get("forms", []):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            forms.append(decoded)
    return forms


def _heuristic_signal_auth_forms(session: ProbeSession, state: AgentState) -> list[dict[str, object]]:
    names = _signal_values(state, "parameters")
    endpoints = _signal_values(state, "endpoints")
    text = _signal_context_text(names, endpoints)

    if not _contains_word(text, ("login", "signin", "sign-in", "register", "signup", "auth", "password", "session")):
        return []
    if not _has_auth_parameter_name(names):
        return []

    inputs = []
    for name in names:
        if name:
            inputs.append({"name": name, "type": "text", "value": ""})

    return [
        {
            "id": "signal-auth-form",
            "action": session.target_url,
            "method": "POST",
            "inputs": inputs[:6],
            "categories": ["auth", "signal"],
        }
    ]


def _has_auth_parameter_name(names: list[str]) -> bool:
    for name in names:
        lowered = name.lower()
        if "user" in lowered or "email" in lowered or "login" in lowered or "pass" in lowered:
            return True
    return False


def _signal_values(state: AgentState, key: str) -> list[str]:
    values: list[str] = []
    for value in state.signals.get(key, []):
        values.append(str(value))
    return values


def _signal_context_text(names: list[str], endpoints: list[str]) -> str:
    values: list[str] = []
    values.extend(names)
    values.extend(endpoints)
    return " ".join(values).lower()


def _form_looks_auth_related(form: dict[str, object]) -> bool:
    categories = _string_items(form.get("categories"))
    if "auth" in categories:
        return True

    text = _form_text(form)
    if _contains_word(text, ("login", "signin", "sign-in", "auth", "session")):
        return True
    if _contains_word(text, ("register", "signup", "sign-up", "create account", "new account")):
        return True

    input_names = _input_names(form)
    input_types = _input_types(form)
    if "password" in input_types:
        return True
    if _input_names_contain_password(input_names):
        return True
    if input_names & {"username", "user", "login", "email"}:
        return _form_has_auth_context(form)

    return False


def _form_looks_login_related(form: dict[str, object]) -> bool:
    text = _form_text(form)
    if _contains_word(text, _REGISTRATION_MARKERS):
        return False
    if _form_has_password_input(form):
        return True
    if _contains_word(text, ("login", "signin", "sign-in", "auth", "session")):
        return True

    categories = _string_items(form.get("categories"))
    input_names = _input_names(form)
    if "auth" in categories and input_names & {"username", "user", "login", "email"}:
        return True

    return False


def _form_has_auth_context(form: dict[str, object]) -> bool:
    text = _form_text(form)
    return _contains_word(text, _AUTH_CONTEXT_MARKERS)


def _ordered_auth_forms(forms: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(forms, key=_auth_form_sort_key)


def _auth_form_sort_key(form: dict[str, object]) -> tuple[int, str]:
    return (-_auth_form_priority(form), str(form.get("action") or ""))


def _auth_form_priority(form: dict[str, object]) -> int:
    text = _form_text(form)
    score = 0

    if _form_looks_registration_related(form):
        score += 80
    if _text_contains_any(text, ("step", "next", "continue", "complete")):
        score += 30
    if _text_contains_any(text, ("premium", "admin", "staff", "role", "account_type", "is_")):
        score += 20
    if _form_has_password_input(form):
        score += 10

    return score


def _form_looks_registration_related(form: dict[str, object]) -> bool:
    text = _form_text(form)
    return _text_contains_any(text, _REGISTRATION_MARKERS)


def _input_names_contain_password(input_names: set[str]) -> bool:
    for name in input_names:
        if "pass" in name:
            return True
    return False


def _text_contains_any(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False


def _dedupe_forms(forms: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for form in forms:
        key = (
            str(form.get("method") or "GET").upper(),
            str(form.get("action") or ""),
            json.dumps(form.get("inputs") or [], sort_keys=True),
        )
        deduped.setdefault(key, form)
    return list(deduped.values())


def _input_names(form: dict[str, object]) -> set[str]:
    names: set[str] = set()
    for item in _list_of_dicts(form.get("inputs")):
        name = str(item.get("name") or "").lower()
        if name:
            names.add(name)
    return names


def _input_types(form: dict[str, object]) -> set[str]:
    input_types: set[str] = set()
    for item in _list_of_dicts(form.get("inputs")):
        input_type = str(item.get("type") or "").lower()
        if input_type:
            input_types.add(input_type)
    return input_types
