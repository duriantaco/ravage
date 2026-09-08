from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from ravage.agent_core.agent_state import AgentState, append_unique, merge_signals

MAX_SURFACE_ITEMS = 40


@dataclass
class _EndpointAccumulator:
    url: str
    sources: set[str] = field(default_factory=set)
    hints: set[str] = field(default_factory=set)


def surface_from_recon(
    *,
    target_url: str,
    description: str,
    recon_payload: dict[str, object],
) -> dict[str, object]:
    pages = _list_of_dicts(recon_payload.get("pages"))
    forms = _forms_from_pages(pages)
    parameters = _parameters_from_pages(pages)
    cookies = _cookies_from_pages(pages)
    endpoints = _endpoints_from_pages(pages)
    request_templates = _request_templates_from_pages(pages)
    reflected = _reflections_from_pages(pages)
    markers = _markers_from_pages(pages, recon_payload)
    technologies = _technologies_from_pages(pages, description)
    workflows = _candidate_workflows(
        description=description,
        forms=forms,
        parameters=parameters,
        endpoints=endpoints,
        cookies=cookies,
        markers=markers,
        reflected=reflected,
    )
    return {
        "target_url": target_url,
        "origin": str(recon_payload.get("origin") or ""),
        "counts": {
            "pages": len(pages),
            "forms": len(forms),
            "parameters": len(parameters),
            "cookies": len(cookies),
            "endpoints": len(endpoints),
            "request_templates": len(request_templates),
            "reflections": len(reflected),
            "workflows": len(workflows),
        },
        "pages": pages[:MAX_SURFACE_ITEMS],
        "forms": forms[:MAX_SURFACE_ITEMS],
        "parameters": parameters[:MAX_SURFACE_ITEMS],
        "cookies": cookies[:MAX_SURFACE_ITEMS],
        "endpoints": endpoints[:MAX_SURFACE_ITEMS],
        "request_templates": request_templates[:MAX_SURFACE_ITEMS],
        "reflections": reflected[:MAX_SURFACE_ITEMS],
        "markers": markers[:MAX_SURFACE_ITEMS],
        "technologies": technologies[:MAX_SURFACE_ITEMS],
        "candidate_workflows": workflows[:MAX_SURFACE_ITEMS],
    }


def merge_surface_state(state: AgentState, surface: dict[str, object]) -> None:
    state.surface = surface
    workflow_names = _workflow_names_for_surface(surface)
    if workflow_names:
        append_unique(
            state.facts,
            "candidate workflows from evidence: " + ", ".join(workflow_names[:12]),
            limit=80,
        )
    endpoints = _endpoint_urls_for_surface(surface)
    if endpoints:
        merge_signals(state, {"endpoints": endpoints[:20]})
    request_templates = _request_template_signals_for_surface(surface)
    if request_templates:
        merge_signals(state, {"request_templates": request_templates[:20]})
    parameters = _parameter_names_for_surface(surface)
    if parameters:
        merge_signals(state, {"parameters": parameters[:40]})


def compact_surface_for_prompt(surface: dict[str, object]) -> dict[str, object]:
    return {
        "counts": surface.get("counts", {}),
        "technologies": _string_list(surface.get("technologies"))[:20],
        "candidate_workflows": _list_of_dicts(surface.get("candidate_workflows"))[:20],
        "high_value_forms": _ranked_forms(surface)[:10],
        "high_value_parameters": _ranked_parameters(surface)[:16],
        "reflections": _list_of_dicts(surface.get("reflections"))[:20],
        "markers": _string_list(surface.get("markers"))[:20],
        "notable_endpoints": _ranked_endpoints(surface)[:16],
        "request_templates": _ranked_request_templates(surface)[:10],
        "source_analysis": _compact_source_analysis(surface.get("source_analysis")),
        "source_candidates": _compact_source_candidates(
            surface.get("source_candidates"),
            limit=8,
        ),
    }


def _compact_source_analysis(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    allowed = (
        "schema",
        "analyzer_contract",
        "source_digest",
        "candidate_digest",
        "files_scanned",
        "files_parsed",
        "parse_failures",
        "symlinks_skipped",
        "directories_scanned",
        "directory_entries_scanned",
        "excluded_directories",
        "analysis_complete",
        "routes_discovered",
        "route_patterns_skipped",
        "flow_patterns_skipped",
        "candidates_found",
        "candidates_ingested",
        "artifact",
    )
    return {key: value[key] for key in allowed if key in value}


def _compact_source_candidates(value: object, *, limit: int) -> list[dict[str, object]]:
    allowed = (
        "candidate_id",
        "family",
        "method",
        "route",
        "input_name",
        "input_location",
        "framework",
        "route_binding",
        "relative_file",
        "line",
        "sink_kind",
        "live_validation",
        "query_fields",
        "status",
    )
    candidates = _list_of_dicts(value)
    selected: list[dict[str, object]] = []
    selected_ids: set[int] = set()
    represented_families: set[str] = set()
    for index, item in enumerate(candidates):
        family = str(item.get("family") or "").strip().casefold()
        if not family or family in represented_families:
            continue
        selected.append(item)
        selected_ids.add(index)
        represented_families.add(family)
        if len(selected) == limit:
            break
    if len(selected) < limit:
        for index, item in enumerate(candidates):
            if index in selected_ids:
                continue
            selected.append(item)
            if len(selected) == limit:
                break
    return [{key: item[key] for key in allowed if key in item} for item in selected]


def _workflow_names_for_surface(surface: dict[str, object]) -> list[str]:
    names: list[str] = []
    for item in _list_of_dicts(surface.get("candidate_workflows")):
        name = str(item.get("name") or "")
        if name:
            names.append(name)
    return names


def _endpoint_urls_for_surface(surface: dict[str, object]) -> list[str]:
    urls: list[str] = []
    for item in _list_of_dicts(surface.get("endpoints")):
        url = str(item.get("url") or "")
        if url:
            urls.append(url)
    return urls


def _request_template_signals_for_surface(surface: dict[str, object]) -> list[str]:
    return [
        json.dumps(item, sort_keys=True)
        for item in _list_of_dicts(surface.get("request_templates"))
        if item.get("url")
    ]


def _parameter_names_for_surface(surface: dict[str, object]) -> list[str]:
    names: list[str] = []
    for item in _list_of_dicts(surface.get("parameters")):
        name = str(item.get("name") or "")
        if name:
            names.append(name)
    return names


def _forms_from_pages(pages: list[dict[str, object]]) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    seen: set[str] = set()
    for page in pages:
        page_url = str(page.get("final_url") or page.get("url") or "")
        for index, form in enumerate(_list_of_dicts(page.get("forms"))):
            action = str(form.get("action") or page_url)
            method = str(form.get("method") or "GET").upper()
            inputs = _list_of_dicts(form.get("inputs"))
            names = _input_names(inputs)
            input_types = _input_types(inputs)
            form_id = _stable_id(f"{method}:{action}:{','.join(names)}:{index}")
            if form_id in seen:
                continue
            seen.add(form_id)
            categories = _form_categories(action=action, names=names, input_types=input_types)
            forms.append(
                {
                    "id": form_id,
                    "page": page_url,
                    "action": action,
                    "method": method,
                    "enctype": str(form.get("enctype") or ""),
                    "categories": categories,
                    "inputs": _input_payloads(inputs, limit=20),
                    "csrf_fields": _csrf_fields(names),
                    "file_fields": _file_fields(inputs),
                }
            )
    return forms


def _input_names(inputs: list[dict[str, object]]) -> list[str]:
    names: list[str] = []
    for item in inputs:
        name = str(item.get("name") or "")
        if name:
            names.append(name)
    return names


def _input_types(inputs: list[dict[str, object]]) -> list[str]:
    input_types: list[str] = []
    for item in inputs:
        input_types.append(str(item.get("type") or "").lower())
    return input_types


def _input_payloads(inputs: list[dict[str, object]], *, limit: int) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for item in inputs[:limit]:
        payload = {
            "name": str(item.get("name") or ""),
            "type": str(item.get("type") or ""),
            "value": str(item.get("value") or ""),
            "required": bool(item.get("required")),
            "disabled": bool(item.get("disabled")),
        }
        for key in ("minlength", "maxlength", "pattern"):
            value = str(item.get(key) or "")
            if value:
                payload[key] = value
        payloads.append(payload)
    return payloads


def _csrf_fields(names: list[str]) -> list[str]:
    fields: list[str] = []
    for name in names:
        if _looks_like_csrf(name):
            fields.append(name)
    return fields


def _file_fields(inputs: list[dict[str, object]]) -> list[str]:
    fields: list[str] = []
    for item in inputs:
        input_type = str(item.get("type") or "").lower()
        if input_type != "file":
            continue
        fields.append(str(item.get("name") or ""))
    return fields


def _parameters_from_pages(pages: list[dict[str, object]]) -> list[dict[str, object]]:
    locations: dict[str, set[str]] = defaultdict(set)
    sources: dict[str, set[str]] = defaultdict(set)
    for page in pages:
        page_url = str(page.get("final_url") or page.get("url") or "")
        for name in _string_list(page.get("query_parameter_names")):
            locations[name].add(page_url)
            sources[name].add("query")
        for reflected in _list_of_dicts(page.get("reflected_parameters")):
            name = str(reflected.get("name") or "")
            if name:
                locations[name].add(str(reflected.get("url") or page_url))
                sources[name].add("reflection")
        for form in _list_of_dicts(page.get("forms")):
            method = str(form.get("method") or "GET").lower()
            action = str(form.get("action") or page_url)
            for input_field in _list_of_dicts(form.get("inputs")):
                name = str(input_field.get("name") or "")
                if name:
                    locations[name].add(action)
                    sources[name].add(f"form:{method}")
        _add_request_template_parameters(locations, sources, page, page_url)
    parameters = []
    for name in sorted(locations):
        hints = _parameter_hints(name)
        parameters.append(
            {
                "name": name,
                "sources": sorted(sources[name]),
                "locations": sorted(locations[name])[:8],
                "hints": hints,
                "priority": _parameter_priority(name, hints, sources[name]),
            }
        )
    parameters.sort(key=_parameter_sort_key)
    return parameters


def _add_request_template_parameters(
    locations: dict[str, set[str]],
    sources: dict[str, set[str]],
    page: dict[str, object],
    page_url: str,
) -> None:
    for template in _list_of_dicts(page.get("request_templates")):
        method = str(template.get("method") or "GET").lower()
        template_url = _absolute_template_url(template, page_url)
        fields = template.get("fields")
        if not isinstance(fields, dict):
            continue
        for name in fields:
            field_name = str(name)
            if field_name:
                locations[field_name].add(template_url or page_url)
                sources[field_name].add(f"request_template:{method}")


def _cookies_from_pages(pages: list[dict[str, object]]) -> list[dict[str, object]]:
    by_name: dict[str, dict[str, object]] = {}
    for page in pages:
        for cookie in _list_of_dicts(page.get("cookies")):
            name = str(cookie.get("name") or "")
            if not name:
                continue
            if name not in by_name:
                by_name[name] = _cookie_payload(name, cookie)
    return list(by_name.values())


def _cookie_payload(name: str, cookie: dict[str, object]) -> dict[str, object]:
    value = str(cookie.get("value") or "")
    return {
        "name": name,
        "path": str(cookie.get("path") or ""),
        "secure": bool(cookie.get("secure")),
        "httponly": bool(cookie.get("httponly")),
        "samesite": str(cookie.get("samesite") or ""),
        "hints": _cookie_hints(name, value),
    }


def _endpoints_from_pages(pages: list[dict[str, object]]) -> list[dict[str, object]]:
    endpoints: dict[str, _EndpointAccumulator] = {}
    for page in pages:
        page_url = str(page.get("final_url") or page.get("url") or "")
        if page_url:
            _endpoint_record(endpoints, page_url).sources.add("page")
        for key, source in (("links", "link"), ("scripts", "script")):
            for url in _string_list(page.get(key)):
                _endpoint_record(endpoints, url).sources.add(source)
        for form in _list_of_dicts(page.get("forms")):
            action = str(form.get("action") or "")
            if action:
                _endpoint_record(endpoints, action).sources.add("form")
        for template in _list_of_dicts(page.get("request_templates")):
            template_url = _absolute_template_url(template, page_url)
            if template_url:
                record = _endpoint_record(endpoints, template_url)
                record.sources.add("request_template")
                record.hints.add("api")
    results: list[dict[str, object]] = []
    for endpoint in endpoints.values():
        results.append(_endpoint_payload(endpoint))
    results.sort(key=_endpoint_sort_key)
    return results


def _request_templates_from_pages(pages: list[dict[str, object]]) -> list[dict[str, object]]:
    templates: list[dict[str, object]] = []
    seen: set[str] = set()
    for page in pages:
        page_url = str(page.get("final_url") or page.get("url") or "")
        for template in _list_of_dicts(page.get("request_templates")):
            payload = _request_template_payload(template, page_url)
            if not payload:
                continue
            key = json.dumps(payload, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            templates.append(payload)
    return templates


def _request_template_payload(template: dict[str, object], page_url: str) -> dict[str, object]:
    url = _absolute_template_url(template, page_url)
    if not url:
        return {}
    method = str(template.get("method") or "GET").upper()
    payload: dict[str, object] = {
        "source": str(template.get("source") or "request_template"),
        "method": method,
        "url": url,
    }
    fields = template.get("fields")
    if isinstance(fields, dict):
        payload["fields"] = {str(key): str(value) for key, value in fields.items() if str(key)}
    headers = template.get("headers")
    if isinstance(headers, dict):
        payload["headers"] = {str(key): str(value) for key, value in headers.items() if str(key)}
    return payload


def _absolute_template_url(template: dict[str, object], page_url: str) -> str:
    raw_url = str(template.get("url") or "").strip()
    if not raw_url:
        return ""
    if raw_url.startswith(("http://", "https://")):
        return raw_url
    if page_url:
        return urljoin(page_url, raw_url)
    return raw_url


def _endpoint_record(
    endpoints: dict[str, _EndpointAccumulator],
    url: str,
) -> _EndpointAccumulator:
    endpoint = endpoints.get(url)
    if endpoint is None:
        endpoint = _EndpointAccumulator(url=url)
        endpoints[url] = endpoint
    return endpoint


def _endpoint_payload(endpoint: _EndpointAccumulator) -> dict[str, object]:
    hints = _endpoint_hints(endpoint.url)
    for value in endpoint.hints:
        hints.append(str(value))
    return {
        "url": endpoint.url,
        "sources": sorted(endpoint.sources),
        "hints": sorted(set(hints)),
        "priority": _endpoint_priority(endpoint.url, hints, endpoint.sources),
    }


def _reflections_from_pages(pages: list[dict[str, object]]) -> list[dict[str, object]]:
    reflected: list[dict[str, object]] = []
    for page in pages:
        page_url = str(page.get("final_url") or page.get("url") or "")
        for item in _list_of_dicts(page.get("reflected_parameters")):
            reflected.append(
                {
                    "page": page_url,
                    "source": str(item.get("source") or ""),
                    "name": str(item.get("name") or ""),
                    "url": str(item.get("url") or ""),
                }
            )
    return reflected


def _markers_from_pages(
    pages: list[dict[str, object]],
    recon_payload: dict[str, object],
) -> list[str]:
    markers = set(_string_list(recon_payload.get("interesting_markers")))
    for page in pages:
        markers.update(_string_list(page.get("interesting_markers")))
        headers = page.get("headers")
        if isinstance(headers, dict):
            header_text = json.dumps(headers, sort_keys=True).lower()
            markers.update(_markers_from_text(header_text))
    return sorted(markers)


def _technologies_from_pages(
    pages: list[dict[str, object]],
    description: str,
) -> list[dict[str, str]]:
    found: dict[str, str] = {}
    text_parts = [description]
    for page in pages:
        headers = page.get("headers")
        if isinstance(headers, dict):
            for value in headers.values():
                text_parts.append(str(value))
        text_parts.append(str(page.get("title") or ""))
        text_parts.extend(_string_list(page.get("scripts")))
    text = " ".join(text_parts).lower()
    for name, pattern in (
        ("php", r"\bphp\b|phpsessid|\.php\b"),
        ("python", r"\bpython\b|flask|django|werkzeug|jinja"),
        ("node", r"\bnode\b|express|next\.js|react|vue"),
        ("java", r"\bjava\b|spring|jsessionid|jsp"),
        ("ruby", r"\bruby\b|rails|rack"),
        ("wordpress", r"wordpress|wp-content|wp-json"),
        ("sqlite", r"sqlite"),
        ("mysql", r"mysql|mariadb"),
        ("postgres", r"postgres|postgresql"),
        ("graphql", r"graphql"),
        ("xml", r"\bxml\b|soap"),
        ("jwt", r"\bjwt\b|bearer"),
    ):
        match = re.search(pattern, text)
        if match:
            found[name] = match.group(0)
    return _technology_payloads(found)


def _candidate_workflows(
    *,
    description: str,
    forms: list[dict[str, object]],
    parameters: list[dict[str, object]],
    endpoints: list[dict[str, object]],
    cookies: list[dict[str, object]],
    markers: list[str],
    reflected: list[dict[str, object]],
) -> list[dict[str, object]]:
    evidence = _workflow_evidence_text(
        description=description,
        forms=forms,
        parameters=parameters,
        endpoints=endpoints,
        markers=markers,
    )
    workflows: list[dict[str, object]] = []

    if forms or parameters:
        _add_workflow(workflows, "input mapping", "forms or parameters are reachable", 90)
    if reflected:
        _add_workflow(
            workflows, "reflection sink analysis", "recon confirmed reflected marker input", 95
        )
    if _has_auth_workflow(forms=forms, cookies=cookies):
        _add_workflow(
            workflows, "session and role workflow", "auth forms or cookies are present", 85
        )
    if _has_file_workflow(parameters=parameters, evidence=evidence):
        _add_workflow(
            workflows,
            "file read or upload workflow",
            "file-like inputs or upload markers are present",
            85,
        )
    if _has_fetch_workflow(parameters=parameters, evidence=evidence):
        _add_workflow(
            workflows,
            "server-side fetch workflow",
            "url-like inputs or webhook/fetch wording observed",
            82,
        )
    if _text_contains_one(evidence, ("xml", "soap", "svg")):
        _add_workflow(
            workflows, "structured parser workflow", "xml/soap/svg markers are present", 78
        )
    if _text_contains_one(evidence, ("template", "jinja", "render", "{{", "{%")):
        _add_workflow(
            workflows,
            "server-side rendering workflow",
            "template/rendering markers are present",
            88,
        )
    if _text_contains_one(evidence, ("sql", "sqlite", "mysql", "postgres", "query", "search")):
        _add_workflow(
            workflows, "data query workflow", "database/search/query signals are present", 82
        )
    if _text_contains_one(
        evidence,
        (
            "ping",
            "nslookup",
            "traceroute",
            "host",
            "domain",
            "command",
            "command execution",
            "code execution",
            "execute code",
            "shell",
            "rce",
            "ognl",
            "struts",
        ),
    ):
        _add_workflow(
            workflows,
            "command boundary workflow",
            "command-shaped wording or host/domain inputs observed",
            76,
        )
    if _text_contains_one(evidence, ("backup", "debug", "robots", ".git", "env", "config")):
        _add_workflow(
            workflows,
            "exposed secret workflow",
            "debug/backup/config words or markers observed",
            80,
        )
    workflows.sort(key=_workflow_sort_key)
    return workflows


def _technology_payloads(found: dict[str, str]) -> list[dict[str, str]]:
    payloads: list[dict[str, str]] = []
    for name, evidence in sorted(found.items()):
        payloads.append({"name": name, "evidence": evidence})
    return payloads


def _workflow_evidence_text(
    *,
    description: str,
    forms: list[dict[str, object]],
    parameters: list[dict[str, object]],
    endpoints: list[dict[str, object]],
    markers: list[str],
) -> str:
    parts: list[str] = [description]
    parts.append(_item_field_text(forms, "categories"))
    parts.append(_item_field_text(parameters, "hints"))
    parts.append(_item_field_text(endpoints, "hints"))
    parts.append(" ".join(markers))
    return " ".join(parts).lower()


def _item_field_text(items: list[dict[str, object]], field: str) -> str:
    values: list[str] = []
    for item in items:
        values.append(str(item.get(field) or ""))
    return " ".join(values)


def _add_workflow(
    workflows: list[dict[str, object]],
    name: str,
    reason: str,
    priority: int,
) -> None:
    workflows.append({"name": name, "reason": reason, "priority": priority})


def _has_auth_workflow(
    *,
    forms: list[dict[str, object]],
    cookies: list[dict[str, object]],
) -> bool:
    if _form_has_category(forms, "auth"):
        return True
    return bool(cookies)


def _has_file_workflow(*, parameters: list[dict[str, object]], evidence: str) -> bool:
    if _parameter_has_hint(parameters, "file"):
        return True
    return "upload" in evidence


def _has_fetch_workflow(*, parameters: list[dict[str, object]], evidence: str) -> bool:
    if _parameter_has_hint(parameters, "url"):
        return True
    return "webhook" in evidence


def _form_has_category(forms: list[dict[str, object]], category: str) -> bool:
    for form in forms:
        if category in str(form.get("categories") or ""):
            return True
    return False


def _parameter_has_hint(parameters: list[dict[str, object]], hint: str) -> bool:
    for parameter in parameters:
        if hint in str(parameter.get("hints") or ""):
            return True
    return False


def _ranked_forms(surface: dict[str, object]) -> list[dict[str, object]]:
    forms = _list_of_dicts(surface.get("forms"))
    return sorted(forms, key=_form_sort_key)


def _ranked_parameters(surface: dict[str, object]) -> list[dict[str, object]]:
    return sorted(
        _list_of_dicts(surface.get("parameters")),
        key=_parameter_sort_key,
    )


def _ranked_endpoints(surface: dict[str, object]) -> list[dict[str, object]]:
    return sorted(
        _list_of_dicts(surface.get("endpoints")),
        key=_endpoint_sort_key,
    )


def _ranked_request_templates(surface: dict[str, object]) -> list[dict[str, object]]:
    return sorted(
        _list_of_dicts(surface.get("request_templates")),
        key=_request_template_sort_key,
    )


def _request_template_sort_key(template: dict[str, object]) -> tuple[int, str, str]:
    priority = -_int_value(template.get("priority"))
    method = str(template.get("method") or "GET").upper()
    url = str(template.get("url") or "")
    return priority, method, url


def _form_priority(form: dict[str, object]) -> int:
    text = json.dumps(form, sort_keys=True).lower()
    score = 0
    for word, value in (
        ("auth", 20),
        ("upload", 18),
        ("file", 18),
        ("search", 14),
        ("comment", 12),
        ("profile", 10),
        ("csrf", 8),
    ):
        if word in text:
            score += value
    return score


def _form_sort_key(form: dict[str, object]) -> tuple[int, str]:
    priority = -_form_priority(form)
    action = str(form.get("action") or "")
    return priority, action


def _form_categories(*, action: str, names: list[str], input_types: list[str]) -> list[str]:
    text = " ".join([action, " ".join(names), " ".join(input_types)]).lower()
    categories = []
    if "password" in input_types or _text_contains_one(text, ("login", "signin", "email")):
        categories.append("auth")
    if "file" in input_types or "multipart" in text or "upload" in text:
        categories.append("upload")
    if _text_contains_one(text, ("search", "query", "q", "filter")):
        categories.append("search")
    if _text_contains_one(text, ("comment", "message", "post", "content", "body")):
        categories.append("content")
    if _has_csrf_field(names):
        categories.append("csrf")
    if _has_file_field_name(names):
        categories.append("file")
    if _text_contains_one(
        text,
        (
            "cmd",
            "command",
            "exec",
            "shell",
            "ping",
            "host",
            "domain",
            "health",
            "status",
            "validate",
        ),
    ):
        categories.append("command_boundary")
    if any(
        name.lower() in {"url", "uri", "endpoint", "target"} for name in names
    ) and _text_contains_one(
        text,
        ("add_url", "check", "validate", "status", "health", "service"),
    ):
        categories.append("command_boundary")
    if not categories:
        categories.append("generic_input")
    return sorted(set(categories))


def _has_csrf_field(names: list[str]) -> bool:
    for name in names:
        if _looks_like_csrf(name):
            return True
    return False


def _has_file_field_name(names: list[str]) -> bool:
    for name in names:
        if _looks_like_file(name):
            return True
    return False


def _parameter_hints(name: str) -> list[str]:
    lowered = name.lower()
    hints = []
    if _looks_like_file(lowered):
        hints.append("file")
    if _text_contains_one(
        lowered, ("url", "uri", "endpoint", "webhook", "callback", "next", "redirect")
    ):
        hints.append("url")
    if _text_contains_one(lowered, ("id", "uid", "user", "account", "post", "order")):
        hints.append("object_id")
    if _text_contains_one(lowered, ("q", "query", "search", "filter", "sort")):
        hints.append("query")
    if _text_contains_one(lowered, ("host", "domain", "ip", "cmd", "command", "exec", "shell")):
        hints.append("command_boundary")
    if _text_contains_one(lowered, ("xml", "data", "payload", "template", "content", "message")):
        hints.append("structured_input")
    if _looks_like_csrf(lowered):
        hints.append("csrf")
    return sorted(set(hints))


def _parameter_priority(name: str, hints: list[str], sources: set[str]) -> int:
    score = len(sources) * 4
    for hint in hints:
        score += _parameter_hint_score(hint)
    if len(name) <= 2:
        score += 2
    return score


def _parameter_hint_score(hint: str) -> int:
    return {
        "reflection": 30,
        "file": 22,
        "url": 20,
        "object_id": 16,
        "query": 14,
        "command_boundary": 18,
        "structured_input": 12,
        "csrf": -5,
    }.get(hint, 0)


def _parameter_sort_key(parameter: dict[str, object]) -> tuple[int, str]:
    priority = -_int_value(parameter.get("priority"))
    name = str(parameter.get("name") or "")
    return priority, name


def _cookie_hints(name: str, value: str) -> list[str]:
    text = f"{name} {value}".lower()
    hints = []
    if _text_contains_one(text, ("session", "auth", "token", "jwt")):
        hints.append("session")
    if "." in value and len(value.split(".")) == 3:
        hints.append("jwt-shaped")
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{20,}", value or ""):
        hints.append("encoded")
    return hints


def _endpoint_hints(url: str) -> list[str]:
    path = urlsplit(url).path.lower()
    hints = []
    for word, hint in (
        ("admin", "admin"),
        ("api", "api"),
        ("graphql", "graphql"),
        ("login", "auth"),
        ("register", "auth"),
        ("search", "query"),
        ("filter", "query"),
        ("lookup", "query"),
        ("upload", "upload"),
        ("download", "file"),
        ("file", "file"),
        ("debug", "debug"),
        ("backup", "backup"),
        ("cmd", "command_boundary"),
        ("command", "command_boundary"),
        ("exec", "command_boundary"),
        ("health", "command_boundary"),
        ("status", "command_boundary"),
        ("script", "command_boundary"),
        ("validate", "command_boundary"),
        (".map", "source_map"),
        ("wp-", "wordpress"),
    ):
        if word in path:
            hints.append(hint)
    if path.endswith((".js", ".json", ".xml", ".txt", ".bak", "~", ".old", ".zip", ".tar", ".gz")):
        hints.append("interesting_file")
    return sorted(set(hints))


def _endpoint_priority(url: str, hints: list[str], sources: set[str]) -> int:
    score = len(sources) * 3
    for hint in hints:
        score += _endpoint_hint_score(hint)
    if "?" in url:
        score += 8
    return score


def _endpoint_hint_score(hint: str) -> int:
    return {
        "admin": 20,
        "api": 14,
        "graphql": 16,
        "auth": 12,
        "query": 12,
        "upload": 18,
        "file": 18,
        "debug": 20,
        "backup": 20,
        "source_map": 18,
        "wordpress": 10,
        "interesting_file": 10,
        "command_boundary": 18,
    }.get(hint, 0)


def _endpoint_sort_key(endpoint: dict[str, object]) -> tuple[int, str]:
    priority = -_int_value(endpoint.get("priority"))
    url = str(endpoint.get("url") or "")
    return priority, url


def _workflow_sort_key(workflow: dict[str, object]) -> tuple[int, str]:
    priority = -_int_value(workflow.get("priority"))
    name = str(workflow.get("name") or "")
    return priority, name


def _markers_from_text(text: str) -> set[str]:
    markers: set[str] = set()
    for marker in ("php", "flask", "django", "express", "nginx", "apache", "jwt", "xml"):
        if marker in text:
            markers.add(marker)
    return markers


def _looks_like_csrf(name: str) -> bool:
    lowered = name.lower()
    return "csrf" in lowered or "xsrf" in lowered or "nonce" in lowered


def _looks_like_file(name: str) -> bool:
    lowered = name.lower()
    return _text_contains_one(lowered, ("file", "path", "page", "template", "include", "doc"))


def _stable_id(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned[:80] or "item"


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(dict(item))
    return items


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        text = str(item)
        if text:
            items.append(text)
    return items


def _text_contains_one(text: str, words: tuple[str, ...]) -> bool:
    for word in words:
        if word in text:
            return True
    return False


def _int_value(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0
