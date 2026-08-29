from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ravage.web_core.http_probe import ProbeResponse, ProbeSession, form_defaults, inject_query_param
from ravage.probe_suite_parts.general import safe_get, submit_form
from ravage.probe_suite_parts.sqli.sqli_forms import _form_requires_state_refresh, _source_form_for_sqli_replay
from ravage.probe_suite_parts.sqli.sqli_replay import _replay_headers
from ravage.probe_suite_parts.sqli.sqli_targets import _graphql_sqli_query
from ravage.probe_suite_parts.sqli.sqli_values import _sqli_baseline_value
from ravage.probe_suite_parts.support import _dict_value
from ravage.probes.captcha_form_state import prepare_stateful_form_fields

def _send_sqli_target(session: ProbeSession, target: dict[str, object], value: str) -> ProbeResponse:
    kind = str(target.get("kind") or "")
    url = str(target.get("url") or session.target_url)
    input_name = str(target.get("input") or "")
    if kind == "replay":
        return _send_replay_target(session, target, value)
    if kind == "form" and isinstance(target.get("form"), dict):
        prepared = prepare_stateful_form_fields(
            session,
            _dict_value(target.get("form")),
            marker_name=input_name,
            marker=value,
        )
        return submit_form(session, prepared.form, prepared.fields)
    if kind == "heuristic_post":
        fields = _heuristic_post_fields(url, input_name, value)
        return session.post_form(url, fields)
    if kind == "json_post":
        body = json.dumps({input_name: value}).encode("utf-8")
        return session.request("POST", url, data=body, headers={"Content-Type": "application/json"})
    if kind == "graphql_post":
        return _send_graphql_sqli_target(session, target, value)
    return safe_get(session, inject_query_param(url, input_name, value))

def _send_graphql_sqli_target(session: ProbeSession, target: dict[str, object], value: str) -> ProbeResponse:
    url = str(target.get("url") or session.target_url)
    query = _graphql_sqli_query(target, value)
    body = json.dumps({"query": query}).encode("utf-8")
    response = session.request("POST", url, data=body, headers={"Content-Type": "application/json"})
    redirect_url = _same_origin_redirect_location(session, response)
    if redirect_url:
        return session.request("POST", redirect_url, data=body, headers={"Content-Type": "application/json"})
    return response

def _send_array_subject_target(
    session: ProbeSession,
    target: dict[str, object],
    input_name: str,
    values: list[str],
) -> ProbeResponse:
    kind = str(target.get("kind") or "")
    url = str(target.get("url") or session.target_url)
    if kind == "form" and isinstance(target.get("form"), dict):
        prepared = prepare_stateful_form_fields(
            session,
            _dict_value(target.get("form")),
            marker_name=input_name,
            marker=_sqli_baseline_value(input_name),
        )
        form = prepared.form
        url = str(form.get("action") or url)
        method = str(form.get("method") or "GET").upper()
        defaults = prepared.fields
        pairs = _array_subject_pairs(defaults, input_name=input_name, values=values)
        if method == "GET":
            return safe_get(session, _url_with_query_pairs(url, pairs))
        body = urlencode(pairs).encode("utf-8")
        return session.request(method, url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    if kind == "heuristic_post":
        fields = _heuristic_post_fields(url, input_name, _sqli_baseline_value(input_name))
        pairs = _array_subject_pairs(fields, input_name=input_name, values=values)
        body = urlencode(pairs).encode("utf-8")
        return session.request("POST", url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    pairs = _array_only_pairs(input_name, values)
    return safe_get(session, _url_with_query_pairs(url, pairs))

def _send_replay_target(session: ProbeSession, target: dict[str, object], value: str) -> ProbeResponse:
    method = str(target.get("method") or "GET").upper()
    url = str(target.get("url") or session.target_url)
    payload_field = str(target.get("input") or target.get("payload_field") or "")
    headers = _replay_headers(target)
    if isinstance(target.get("form"), dict):
        fields: dict[str, str] = {}
        for key, raw_value in _dict_value(target.get("form")).items():
            fields[str(key)] = str(raw_value)
        if payload_field:
            fields[payload_field] = value
        source_form = _dict_value(target.get("source_form"))
        if source_form:
            prepared = prepare_stateful_form_fields(
                session,
                source_form,
                marker_name=payload_field,
                marker=value,
                seed_fields=fields,
            )
            fields = prepared.fields
            method = str(prepared.form.get("method") or method).upper()
            url = str(prepared.form.get("action") or url)
        if method == "GET":
            query_url = url
            for name, field_value in fields.items():
                query_url = inject_query_param(query_url, name, field_value)
            return safe_get(session, query_url)
        if "json" in str(target.get("encoding") or "").lower():
            body = json.dumps(fields).encode("utf-8")
            replay_headers = dict(headers)
            replay_headers["Content-Type"] = "application/json"
            return session.request(method, url, data=body, headers=replay_headers)
        return session.post_form(url, fields, headers=headers or None)
    if method == "POST":
        fields: dict[str, str] = {}
        if payload_field:
            fields[payload_field] = value
        if "json" in str(target.get("encoding") or "").lower():
            body = json.dumps(fields).encode("utf-8")
            replay_headers = dict(headers)
            replay_headers["Content-Type"] = "application/json"
            return session.request("POST", url, data=body, headers=replay_headers)
        return session.post_form(url, fields, headers=headers or None)
    return safe_get(session, inject_query_param(url, payload_field, value))

def _sqli_replay(target: dict[str, object], value: str) -> dict[str, object]:
    kind = str(target.get("kind") or "")
    url = str(target.get("url") or "")
    input_name = str(target.get("input") or "")
    if kind == "replay":
        replay: dict[str, object] = {
            "method": str(target.get("method") or "GET").upper(),
            "url": url,
            "payload_field": input_name,
            "replay_hint": "Replay this confirmed request template verbatim; change only payload_field.",
        }
        form = _dict_value(target.get("form"))
        if form:
            fields: dict[str, str] = {}
            for key, raw_value in form.items():
                fields[str(key)] = str(raw_value)
            fields[input_name] = value
            replay["form"] = fields
            replay["required_fields"] = sorted(fields)
            replay["encoding"] = str(target.get("encoding") or "application/x-www-form-urlencoded")
            source_form = _dict_value(target.get("source_form"))
            if source_form:
                replay["source_form"] = _source_form_for_sqli_replay(source_form)
                replay["refresh_state"] = True
        headers = _replay_headers(target)
        if headers:
            replay["headers"] = headers
        if not form and input_name:
            replay["url"] = inject_query_param(url, input_name, value)
        return replay
    if kind == "form" and isinstance(target.get("form"), dict):
        form = _dict_value(target.get("form"))
        fields = form_defaults(form, marker_name=input_name, marker=value)
        replay = {
            "method": str(form.get("method") or "GET").upper(),
            "url": str(form.get("action") or url),
            "payload_field": input_name,
            "form": fields,
            "source_form": _source_form_for_sqli_replay(form),
            "required_fields": sorted(fields),
            "encoding": "application/x-www-form-urlencoded",
            "replay_hint": (
                "Use this form dict verbatim with Python urllib.parse.urlencode(fields) "
                "or curl --data-urlencode per field; "
                "do not drop submit, hidden, or unchanged fields."
            ),
        }
        if _form_requires_state_refresh(form):
            replay["refresh_state"] = True
            replay["replay_hint"] = (
                "Refresh the source form before replay, preserve hidden/submit fields, "
                "solve visible captcha/code state, "
                "and change only payload_field."
            )
        return replay
    if kind == "heuristic_post":
        fields = _heuristic_post_fields(url, input_name, value)
        return {
            "method": "POST",
            "url": url,
            "payload_field": input_name,
            "form": fields,
            "required_fields": sorted(fields),
            "encoding": "application/x-www-form-urlencoded",
            "replay_hint": (
                "Use this form dict verbatim with Python urllib.parse.urlencode(fields) to avoid shell quoting bugs; "
                "do not drop unchanged fields."
            ),
        }
    if kind == "json_post":
        return {
            "method": "POST",
            "url": url,
            "payload_field": input_name,
            "form": {input_name: value},
            "required_fields": [input_name],
            "encoding": "application/json",
            "headers": {"Content-Type": "application/json"},
            "replay_hint": "POST this JSON body verbatim; change only payload_field.",
        }
    if kind == "graphql_post":
        query = _graphql_sqli_query(target, value)
        return {
            "method": "POST",
            "url": url,
            "payload_field": input_name,
            "graphql_field": target.get("graphql_field"),
            "graphql_query": query,
            "form": {"query": query},
            "required_fields": ["query"],
            "encoding": "application/json",
            "headers": {"Content-Type": "application/json"},
            "replay_hint": "POST this GraphQL JSON body verbatim; change only payload_field inside graphql_query.",
        }
    return {
        "method": "GET",
        "url": inject_query_param(url, input_name, value),
        "payload_field": input_name,
        "replay_hint": "GET request is fully encoded in url.",
    }

def _same_origin_redirect_location(session: ProbeSession, response: ProbeResponse) -> str:
    if response.status not in {301, 302, 303, 307, 308}:
        return ""
    location = response.headers.get("location", "")
    if not location:
        return ""
    absolute = session.absolute(location)
    if absolute == response.url or not session.in_scope(absolute):
        return ""
    return absolute

def _array_subject_pairs(
    fields: dict[str, str],
    *,
    input_name: str,
    values: list[str],
) -> list[tuple[str, str]]:
    pairs = _pairs_without_field(fields, input_name)
    pairs.extend(_array_only_pairs(input_name, values))
    return pairs

def _pairs_without_field(fields: dict[str, str], input_name: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for key, value in fields.items():
        if key != input_name:
            pairs.append((key, value))
    return pairs

def _array_only_pairs(input_name: str, values: list[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for value in values:
        pairs.append((f"{input_name}[]", value))
    return pairs

def _url_with_query_pairs(url: str, pairs: list[tuple[str, str]]) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.extend(pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

def _heuristic_post_fields(url: str, input_name: str, value: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    lowered = url.lower()
    if "login" in lowered or "signin" in lowered:
        fields = {"username": "ravage", "user": "ravage", "email": "ravage@example.test", "password": "RavagePass123!"}
    elif "search" in lowered:
        fields = {"q": "ravage", "search": "ravage", "query": "ravage"}
    else:
        fields = {"id": "1", "q": "ravage", "search": "ravage"}
    fields[input_name] = value
    return fields
