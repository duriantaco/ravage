from __future__ import annotations

import json
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeSession
from ravage.probe_suite_parts.support import (
    _contains_word,
    _contains_word_in_list,
    _dedupe,
    _form_brief,
    _form_targets,
    _name_looks_command,
    _parameter_targets,
    _path_looks_static_asset,
    _string_items,
    _surface_endpoint_items,
)


def _command_state_followup_urls(session: ProbeSession, target: dict[str, object]) -> list[str]:
    url = str(target.get("url") or "")
    name = str(target.get("name") or "").lower()
    path = urlsplit(url).path.lower()
    if not _target_can_have_state_followup(path, name):
        return []
    candidates = [
        "/api/get",
        "/name/get",
        "/app/",
        "/app",
        "/script",
        "/healthcheck",
        "/status",
    ]
    urls: list[str] = []
    for candidate in candidates:
        absolute_url = session.absolute(candidate)
        if session.in_scope(absolute_url):
            urls.append(absolute_url)
    return _dedupe(urls)


def _target_can_have_state_followup(path: str, name: str) -> bool:
    if _contains_word(path, ("set", "update", "save", "config")):
        return True
    return name in {"url", "uri", "endpoint", "target", "service"}


def _command_text_getter_urls(session: ProbeSession, setter: dict[str, object]) -> list[str]:
    urls = list(_command_state_followup_urls(session, setter))
    path = urlsplit(str(setter.get("url") or "")).path
    if "/set" in path:
        urls.append(session.absolute(path.replace("/set", "/get", 1)))
        urls.append(session.absolute(path.replace("/set", "", 1) or "/"))
    name = str(setter.get("name") or "").lower()
    if name:
        urls.append(session.absolute(f"/{name}/get"))
        urls.append(session.absolute(f"/{name}"))
    scoped_urls: list[str] = []
    for url in urls:
        if session.in_scope(url):
            scoped_urls.append(url)
    return _dedupe(scoped_urls)


def _command_reachable_getter_urls(
    session: ProbeSession,
    state: AgentState,
    url_setter: dict[str, object],
    getter_url: str,
) -> list[str]:
    parsed = urlsplit(getter_url)
    path = parsed.path or "/"
    query = ""
    if parsed.query:
        query = f"?{parsed.query}"
    urls: list[str] = []
    for origin in _prioritized_internal_origins(session, state, url_setter):
        urls.append(origin.rstrip("/") + path + query)
    urls.extend([getter_url, session.absolute(path + query)])
    return _dedupe(urls)


def _prioritized_internal_origins(session: ProbeSession, state: AgentState, url_setter: dict[str, object]) -> list[str]:
    origins = _command_internal_origins(session, state, url_setter)

    def priority(origin: str) -> tuple[int, str]:
        netloc = urlsplit(origin).netloc.lower()
        if netloc in {"nginx", "nginx:80"}:
            return (0, origin)
        if netloc and not netloc.startswith(("localhost", "127.", "0.0.0.0")):
            return (1, origin)
        return (2, origin)

    return sorted(origins, key=priority)


def _command_internal_origins(session: ProbeSession, state: AgentState, url_setter: dict[str, object]) -> list[str]:
    text = _command_state_text(state) + " " + str(url_setter.get("url") or "")
    origins: list[str] = []
    for raw in re.findall(r"https?://[^\s\"'<>),]+", text):
        raw = unquote(raw.rstrip(".,;]})"))
        parts = urlsplit(raw)
        if parts.scheme and parts.netloc:
            origins.append(urlunsplit((parts.scheme, parts.netloc, "", "", "")))
    target = urlsplit(session.target_url)
    if target.scheme and target.netloc:
        origins.append(urlunsplit((target.scheme, target.netloc, "", "", "")))
    if _command_state_suggests_nginx_gateway(state):
        origins.extend(["http://nginx", "http://nginx:80"])
    return _dedupe(origins)


def _command_state_text(state: AgentState) -> str:
    try:
        payload = {
            "summary": state.summary,
            "facts": state.facts[-30:],
            "hypotheses": state.hypotheses[-20:],
            "actions": state.actions[-20:],
            "signals": state.signals,
            "surface": state.surface,
            "tasks": state.tasks[-20:],
            "last_observation": state.last_observation,
        }
        return json.dumps(payload, sort_keys=True)
    except TypeError:
        return " ".join([state.summary, " ".join(state.facts), " ".join(state.hypotheses)])


def _command_state_suggests_nginx_gateway(state: AgentState) -> bool:
    text = _command_state_text(state).lower()
    if "nginx" not in text:
        return False
    if "server" in text:
        return True
    return _contains_word(text, ("proxy", "mapping", "upstream"))


def _command_consumer_urls(session: ProbeSession, state: AgentState, url_setter: dict[str, object]) -> list[str]:
    candidates = [
        session.absolute("/app"),
        session.absolute("/app/"),
        session.absolute("/dashboard"),
        session.absolute("/"),
        *_command_state_followup_urls(session, url_setter),
    ]
    for item in _surface_endpoint_items(state):
        url = str(item.get("url") or "")
        if not url or not session.in_scope(url):
            continue
        path = urlsplit(url).path.lower()
        if _path_looks_static_asset(path):
            continue
        if _contains_word(path, ("app", "dashboard", "admin", "status", "health", "service")):
            candidates.append(url)
    return _dedupe(candidates)


def _command_target_is_url_setter(target: dict[str, object]) -> bool:
    name = str(target.get("name") or "").lower()
    path = urlsplit(str(target.get("url") or "")).path.lower()
    hints = " ".join(_string_items(target.get("hints"))).lower()
    return name in {"url", "uri", "endpoint", "target", "service"} and (
        _contains_word(path, ("set", "update", "save", "config")) or "url" in hints
    )


def _command_target_is_text_setter(target: dict[str, object]) -> bool:
    if _command_target_is_url_setter(target):
        return False
    name = str(target.get("name") or "").lower()
    path = urlsplit(str(target.get("url") or "")).path.lower()
    if not _contains_word(path, ("set", "update", "save", "config")):
        return False
    return name in {"name", "text", "value", "payload", "data", "body", "content", "script", "template"}


def _command_context_parameter_targets(
    state: AgentState,
    existing: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not _state_has_command_boundary_context(state):
        return []
    seen: set[tuple[str, str]] = set()
    for target in existing:
        seen.add(_command_target_identity(target))
    targets: list[dict[str, object]] = []
    for target in _parameter_targets(state, limit=80):
        key = _command_target_identity(target)
        if key in seen:
            continue
        if not _command_context_allows_target(target):
            continue
        seen.add(key)
        boosted = dict(target)
        boosted["hints"] = _dedupe([*_string_items(boosted.get("hints")), "command_boundary"])
        targets.append(boosted)
    return targets


def _command_target_identity(target: dict[str, object]) -> tuple[str, str]:
    return str(target.get("name") or ""), str(target.get("url") or "")


def _state_has_command_boundary_context(state: AgentState) -> bool:
    parts = [
        json.dumps(state.surface.get("candidate_workflows", []), sort_keys=True),
        json.dumps(state.surface.get("markers", []), sort_keys=True),
        _recent_facts_text(state),
        _recent_signal_text(state),
    ]
    text = " ".join(parts).lower()
    return _contains_word(
        text,
        (
            "command boundary",
            "command execution",
            "code execution",
            "execute code",
            "shell",
            "rce",
            "ognl",
            "struts",
        ),
    )


def _state_has_ognl_action_context(state: AgentState) -> bool:
    parts = [
        json.dumps(state.surface.get("technologies", []), sort_keys=True),
        json.dumps(state.surface.get("candidate_workflows", []), sort_keys=True),
        json.dumps(state.surface.get("markers", []), sort_keys=True),
        json.dumps(_recent_form_briefs(state), sort_keys=True),
        _recent_facts_text(state),
        _recent_signal_text(state),
    ]
    text = " ".join(parts).lower()
    return _contains_word(text, ("ognl", "struts", "jsessionid")) or ".action" in text


def _recent_facts_text(state: AgentState) -> str:
    facts: list[str] = []
    for fact in state.facts[-80:]:
        facts.append(str(fact))
    return " ".join(facts)


def _recent_signal_text(state: AgentState) -> str:
    values: list[str] = []
    for signal_values in state.signals.values():
        for value in signal_values[-30:]:
            values.append(str(value))
    return " ".join(values)


def _recent_form_briefs(state: AgentState) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for form in _form_targets(state, limit=12):
        forms.append(_form_brief(form))
    return forms


def _command_context_allows_target(target: dict[str, object]) -> bool:
    name = str(target.get("name") or "").lower()
    url = str(target.get("url") or "").lower()
    hints = " ".join(_string_items(target.get("hints"))).lower()
    text = " ".join((name, url, hints))
    if _command_context_name_allowed(name):
        return True
    return _contains_word(
        text,
        (
            "add_url",
            "validate",
            "validator",
            "check",
            "health",
            "status",
            "script",
            "service",
            "api/set",
            "name/set",
            "proxy",
            "mapping",
        ),
    )


def _command_context_name_allowed(name: str) -> bool:
    allowed_names = {
        "url",
        "uri",
        "endpoint",
        "target",
        "host",
        "domain",
        "ip",
        "q",
        "query",
        "input",
        "payload",
        "cmd",
        "command",
        "name",
    }
    return name in allowed_names


def _command_target_filter(target: dict[str, object]) -> bool:
    hints = _string_items(target.get("hints"))
    if _contains_word_in_list(hints, ("command_boundary",)):
        return True
    name = str(target.get("name") or "")
    path = urlsplit(str(target.get("url") or "")).path.lower()
    if path.endswith("/api/set") and name.lower() not in {"url", "uri", "endpoint", "target", "service"}:
        return False
    if path.endswith("/name/set") and name.lower() != "name":
        return False
    weak_command_names = {"action", "name", "username", "user"}
    if _name_looks_command(name) and name.lower() not in weak_command_names:
        return True
    context = " ".join(
        [
            name,
            str(target.get("url") or ""),
            str(target.get("context") or ""),
            " ".join(hints),
            " ".join(_string_items(target.get("sources"))),
        ]
    ).lower()
    command_context = _contains_word(
        context,
        (
            "remind",
            "reminder",
            "notify",
            "schedule",
            "scheduler",
            "cron",
            "job",
            "task",
            "command",
            "cmd",
            "shell",
            "exec",
            "execution",
            "script",
            "healthcheck",
            "validate",
            "validator",
            "availability",
            "status",
            "service",
            "proxy",
            "mapping",
            "api/set",
            "name/set",
        ),
    )
    if "url" in hints and command_context:
        return True
    if command_context and name.lower() in {"q", "url", "uri", "endpoint", "input", "payload", "name"}:
        return True
    if not command_context:
        return False
    return _contains_word(
        name.lower(),
        (
            "date",
            "time",
            "message",
            "text",
            "value",
            "target",
            "query",
            "input",
            "payload",
            "path",
            "url",
            "service",
        ),
    )


def _command_target_sort_key(target: dict[str, object]) -> tuple[int, str, str]:
    name = str(target.get("name") or "").lower()
    url = str(target.get("url") or "").lower()
    path = urlsplit(str(target.get("url") or "")).path.lower()
    hints = " ".join(_string_items(target.get("hints"))).lower()
    text = " ".join((name, url, hints))
    priority = 0
    if _contains_word(text, ("remind", "reminder", "notify", "schedule", "scheduler", "cron", "job", "task")):
        priority += 60
    if _contains_word(text, ("exec", "command", "cmd", "shell", "script", "healthcheck", "validate", "status")):
        priority += 48
    if _is_api_url_setter(path, name):
        priority += 80
    if path.endswith("/api/set") and not _is_api_url_setter(path, name):
        priority -= 80
    if path.endswith("/name/set") and name == "name":
        priority += 48
    if _contains_word(name, ("date", "time", "message", "text", "value", "target", "url", "endpoint", "name")):
        priority += 24
    if "?" in url:
        priority += 12
    if _contains_word_in_list(_string_items(target.get("sources")), ("signal",)):
        priority += 8
    return (-priority, str(target.get("url") or ""), str(target.get("name") or ""))


def _is_api_url_setter(path: str, name: str) -> bool:
    if not path.endswith("/api/set"):
        return False
    return name in {"url", "uri", "endpoint", "target", "service"}
