from __future__ import annotations

import json
import re
import secrets
import time

from ravage.agent_core.agent_state import AgentState
from ravage.probes.cookie.cookie_deserialization_shared import (
    _dedupe_urls,
    _in_scope,
    _list_of_dicts,
    _request_summary,
)
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    form_defaults,
    inject_query_param,
)

_COOKIE_DISCOVERY_PATHS = (
    "/",
    "/list",
    "/home",
    "/index",
    "/index.php",
    "/profile",
    "/profile.php",
    "/dashboard",
    "/account",
)

_FORM_COOKIE_HARVEST_LIMIT = 8
_AUTH_BACKEND_RETRY_DELAYS = (0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.0, 3.0, 3.0, 3.0)

# --- cookie discovery ---------------------------------------------------------


def _candidate_cookies(
    session: ProbeSession, state: AgentState, requests: list[dict[str, object]]
) -> list[tuple[str, str]]:
    seen: dict[str, str] = {}
    for url in _cookie_discovery_urls(session, state):
        response = session.get(url)
        requests.append(_request_summary(response, url=url, cookie="", gadget="cookie_discovery"))
        _remember_response_cookies(seen, response)
        _remember_session_cookies(seen, session)
        location = response.headers.get("location", "")
        if location and _in_scope(session, location):
            redirected = session.get(location)
            requests.append(
                _request_summary(
                    redirected, url=location, cookie="", gadget="cookie_redirect_discovery"
                )
            )
            _remember_response_cookies(seen, redirected)
            _remember_session_cookies(seen, session)
    for form in _cookie_harvest_forms(state):
        response = _submit_cookie_harvest_form(session, form)
        if response is None:
            continue
        requests.append(
            _request_summary(
                response,
                url=str(form.get("action") or session.target_url),
                cookie="",
                gadget="form_cookie_harvest",
            )
        )
        _remember_response_cookies(seen, response)
        _remember_session_cookies(seen, session)
    for response in _auth_cookie_harvest_flows(session, state):
        requests.append(
            _request_summary(
                response,
                url=response.url,
                cookie="",
                gadget="auth_cookie_harvest",
            )
        )
        _remember_response_cookies(seen, response)
        _remember_session_cookies(seen, session)
    for raw in state.signals.get("cookies", []):
        for name, value in _parse_set_cookie(str(raw)):
            seen.setdefault(name, value)
    candidates: list[tuple[str, str]] = []
    for name, value in seen.items():
        if value:
            candidates.append((name, value))
    return candidates


def _parse_set_cookie(raw: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for chunk in re.split(r"\n|,(?=[^;]+=)", raw):
        head = chunk.split(";", 1)[0].strip()
        if "=" not in head:
            continue
        name, value = head.split("=", 1)
        name = name.strip()
        value = value.strip()
        if (
            name
            and value
            and name.lower()
            not in {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly"}
        ):
            pairs.append((name, value))
    return pairs


def _remember_response_cookies(seen: dict[str, str], response: ProbeResponse) -> None:
    for name, value in _parse_set_cookie(response.headers.get("set-cookie", "")):
        seen.setdefault(name, value)


def _remember_session_cookies(seen: dict[str, str], session: ProbeSession) -> None:
    for cookie in getattr(session, "cookies", ()):
        if cookie.name and cookie.value:
            seen.setdefault(cookie.name, cookie.value)


def _cookie_discovery_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls = [session.target_url]
    for path in _COOKIE_DISCOVERY_PATHS:
        urls.append(session.absolute(path))
    for form in _cookie_harvest_forms(state):
        page = str(form.get("page") or "")
        action = str(form.get("action") or "")
        if page:
            urls.append(page)
        if action:
            urls.append(action)
    scoped_urls: list[str] = []
    for url in urls:
        if _in_scope(session, url):
            scoped_urls.append(url)
    return _dedupe_urls(scoped_urls)[:16]


def _cookie_harvest_forms(state: AgentState) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for form in _list_of_dicts(state.surface.get("forms")):
        forms.append(form)
    for value in state.signals.get("forms", []):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            forms.append(decoded)
    forms.sort(key=_form_cookie_harvest_key)
    return _dedupe_forms(forms)[:_FORM_COOKIE_HARVEST_LIMIT]


def _submit_cookie_harvest_form(
    session: ProbeSession, form: dict[str, object]
) -> ProbeResponse | None:
    fields = form_defaults(form)
    if not fields:
        return None
    method = str(form.get("method") or "GET").upper()
    action = str(form.get("action") or session.target_url)
    if not _in_scope(session, action):
        return None
    if method == "POST":
        return session.post_form(action, fields)
    url = action
    for name, value in fields.items():
        url = inject_query_param(url, name, value)
    return session.get(url)


def _auth_cookie_harvest_flows(session: ProbeSession, state: AgentState) -> list[ProbeResponse]:
    forms = _cookie_harvest_forms(state)
    register_forms = [form for form in forms if _auth_form_role(form) == "register"]
    login_forms = [form for form in forms if _auth_form_role(form) == "login"]
    if not register_forms or not login_forms:
        return []

    responses: list[ProbeResponse] = []
    attempts = 0
    for register_form in register_forms[:3]:
        for login_form in login_forms[:3]:
            if attempts >= 4:
                return responses
            attempts += 1
            username = "ravage_" + secrets.token_hex(4)
            password = "Ravage!" + secrets.token_hex(5)
            register = _submit_auth_form(
                session,
                register_form,
                username=username,
                password=password,
            )
            if register is not None:
                responses.append(register)
            login = _submit_auth_form(
                session,
                login_form,
                username=username,
                password=password,
            )
            if login is not None:
                responses.append(login)
                location = login.headers.get("location", "")
                if location and _in_scope(session, location):
                    follow = session.get(location)
                    responses.append(follow)
    return responses


def _submit_auth_form(
    session: ProbeSession,
    form: dict[str, object],
    *,
    username: str,
    password: str,
) -> ProbeResponse | None:
    response = _submit_auth_form_once(
        session,
        form,
        username=username,
        password=password,
    )
    if response is None:
        return None
    for delay in _AUTH_BACKEND_RETRY_DELAYS:
        if not _response_has_transient_auth_backend_error(response):
            return response
        time.sleep(delay)
        retry = _submit_auth_form_once(
            session,
            form,
            username=username,
            password=password,
        )
        if retry is None:
            return response
        response = retry
    return response


def _submit_auth_form_once(
    session: ProbeSession,
    form: dict[str, object],
    *,
    username: str,
    password: str,
) -> ProbeResponse | None:
    fields = form_defaults(form)
    if not fields:
        return None
    username_field = _named_auth_field(form, ("username", "user", "login", "email"))
    password_field = _named_auth_field(form, ("password", "passwd", "pass", "pwd"))
    if not username_field or not password_field:
        return None
    fields[username_field] = username
    fields[password_field] = password
    action = str(form.get("action") or session.target_url)
    if not _in_scope(session, action):
        return None
    method = str(form.get("method") or "GET").upper()
    if method == "POST":
        return session.post_form(action, fields)
    url = action
    for name, value in fields.items():
        url = inject_query_param(url, name, value)
    return session.get(url)


def _response_has_transient_auth_backend_error(response: ProbeResponse) -> bool:
    body = response.body.lower()
    if "connection refused" not in body:
        return False
    return any(marker in body for marker in ("mysqli", "mysql", "pdo", "sqlstate", "connection failed"))


def _auth_form_role(form: dict[str, object]) -> str:
    if not _form_has_fields(form, ("username", "user", "login", "email"), ("password", "passwd", "pass", "pwd")):
        return ""
    text = " ".join(
        [
            str(form.get("action") or ""),
            str(form.get("page") or ""),
            repr(form.get("inputs") or ""),
            " ".join(str(item.get("value") or "") for item in _list_of_dicts(form.get("inputs"))),
        ]
    ).lower()
    if _contains_marker(text, ("register", "signup", "sign-up", "create a new account")):
        return "register"
    if _contains_marker(text, ("login", "signin", "sign-in")):
        return "login"
    return ""


def _form_has_fields(
    form: dict[str, object],
    username_names: tuple[str, ...],
    password_names: tuple[str, ...],
) -> bool:
    return bool(_named_auth_field(form, username_names) and _named_auth_field(form, password_names))


def _named_auth_field(form: dict[str, object], names: tuple[str, ...]) -> str:
    lowered_names = {name.lower() for name in names}
    for item in _list_of_dicts(form.get("inputs")):
        name = str(item.get("name") or "")
        input_type = str(item.get("type") or "").lower()
        lowered = name.lower()
        if lowered in lowered_names or (input_type == "password" and "password" in lowered_names):
            return name
    return ""


def _form_cookie_harvest_key(form: dict[str, object]) -> tuple[int, str]:
    text = repr(form).lower()
    mutates_state = str(form.get("method") or "GET").upper() == "POST"
    priority = _form_cookie_harvest_priority(text, mutates_state)
    return priority, str(form.get("action") or "")


def _form_cookie_harvest_priority(text: str, mutates_state: bool) -> int:
    has_stateful_fields = _contains_marker(
        text,
        (
            "url",
            "bookmark",
            "note",
            "title",
            "content",
            "comment",
            "name",
            "profile",
            "settings",
        ),
    )
    is_auth = _contains_marker(
        text,
        ("password", "login", "signin", "sign-in", "register", "signup", "sign-up"),
    )
    if mutates_state and has_stateful_fields and not is_auth:
        return 0
    if mutates_state:
        return 1
    return 2


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False


def _dedupe_forms(forms: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    deduped: list[dict[str, object]] = []
    for form in forms:
        key = json.dumps(
            {
                "method": str(form.get("method") or "GET").upper(),
                "action": str(form.get("action") or ""),
                "inputs": _form_input_names_for_key(form),
            },
            sort_keys=True,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(form)
    return deduped


def _form_input_names_for_key(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    for item in _list_of_dicts(form.get("inputs")):
        names.append(str(item.get("name") or ""))
    return names


def _replay_urls(session: ProbeSession) -> list[str]:
    urls = [session.target_url]
    for path in (
        "/list",
        "/bookmarks",
        "/bookmark",
        "/cart",
        "/items",
        "/urls",
        "/links",
        "/",
        "/home",
        "/profile",
        "/dashboard",
        "/account",
    ):
        absolute = session.absolute(path)
        if absolute not in urls:
            urls.append(absolute)
    return urls[:8]


def _php_replay_urls(session: ProbeSession) -> list[str]:
    urls = [session.target_url]
    for path in (
        "/",
        "/index.php",
        "/profile",
        "/profile.php",
        "/dashboard",
        "/account",
        "/admin",
        "/admin.php",
    ):
        absolute = session.absolute(path)
        if absolute not in urls:
            urls.append(absolute)
    return urls[:8]
