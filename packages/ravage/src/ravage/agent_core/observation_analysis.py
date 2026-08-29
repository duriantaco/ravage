from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState, append_unique, merge_signals
from ravage.agent_core.observation_markers import (
    APACHE_TRAVERSAL_PATTERN,
    CONFIRMATION_FINDING_TYPES,
    DATABASE_FACT_MARKERS,
    ERROR_SIGNAL_MARKERS,
    FILE_READ_FINDING_TYPES,
    SERVER_ERROR_FACT_MARKERS,
    SQL_CONFIRMATION_MARKERS,
    SQL_FACT_MARKERS,
    SURFACE_SIGNAL_MARKERS,
)
from ravage.agent_core.observation_sql import (
    sqli_boolean_template_signals,
    sqli_input_signals,
    sqli_replay_signals,
)


def extract_signals(text: str) -> dict[str, list[str]]:
    signals: dict[str, list[str]] = {}
    _collect_cookie_signals(signals, text)
    _collect_form_signals(signals, text)
    _collect_named_input_signals(signals, text)
    _collect_attribute_url_signals(signals, text)
    _collect_javascript_endpoint_signals(signals, text)
    _collect_plain_url_signals(signals, text)
    _collect_marker_signals(signals, text)
    _collect_structured_signals(signals, text)
    return signals


def observation_facts(text: str) -> list[str]:
    facts: list[str] = []
    lower = text.lower()
    if "csrf" in lower:
        facts.append("csrf token behavior observed")
    if "set-cookie:" in lower:
        facts.append("target sets cookies")
    if "access-control-allow-origin" in lower or "cors" in lower:
        facts.append("CORS policy evidence observed")
    if "localstorage" in lower or "sessionstorage" in lower:
        facts.append("browser storage behavior observed")
    if "websocket" in lower or "ws://" in lower or "wss://" in lower:
        facts.append("WebSocket behavior observed")
    if "<form" in lower:
        facts.append("forms discovered")
    if _text_contains_one(lower, DATABASE_FACT_MARKERS):
        facts.append("database error marker observed")
    if _text_contains_one(lower, SQL_FACT_MARKERS):
        facts.append("sql injection evidence observed")
    if "root:x:0:0:" in lower or "file_read_primitive" in lower:
        facts.append("local file read evidence observed")
    if APACHE_TRAVERSAL_PATTERN.search(text):
        facts.append("Apache 2.4.49/2.4.50 path traversal surface observed")
    if _text_contains_one(lower, SERVER_ERROR_FACT_MARKERS):
        facts.append("server error or debug trace observed")
    if "upload" in lower or "multipart/form-data" in lower:
        facts.append("upload workflow marker observed")
    if "graphql" in lower:
        facts.append("graphql marker observed")
    if "modulenotfounderror: no module named 'requests'" in lower:
        facts.append("python requests module unavailable; use urllib from the standard library")
    if ("host.docker.internal" in lower or "ravage-target" in lower) and _text_contains_one(
        lower,
        (
            "nodename nor servname provided",
            "name or service not known",
            "temporary failure in name resolution",
            "could not resolve hostname",
        ),
    ):
        facts.append(
            "a Docker-only target alias was used from the wrong runtime; use "
            "scoped_service_ports.host_endpoint from host tools or docker_endpoint only from "
            "Docker/tool-image code"
        )
    if (
        "unexpected eof while looking for matching" in lower
        or "syntax error: unexpected end of file" in lower
    ):
        facts.append("shell quoting failed; use Python urllib encoding for quote-heavy payloads")
    return facts


def _collect_cookie_signals(signals: dict[str, list[str]], text: str) -> None:
    for match in re.finditer(r"Set-Cookie:\s*([^;\r\n]+)", text, flags=re.IGNORECASE):
        _add_signal(signals, "cookies", match.group(1))


def _collect_form_signals(signals: dict[str, list[str]], text: str) -> None:
    for match in re.finditer(r"<form\b[^>]*>", text, flags=re.IGNORECASE):
        _add_signal(signals, "forms", match.group(0)[:300])


def _collect_named_input_signals(signals: dict[str, list[str]], text: str) -> None:
    pattern = r"<(?:input|textarea|select|button)\b[^>]*\bname=['\"]([^'\"]+)['\"]"
    for match in re.finditer(pattern, text, flags=re.IGNORECASE):
        _add_signal(signals, "parameters", match.group(1))


def _collect_attribute_url_signals(signals: dict[str, list[str]], text: str) -> None:
    pattern = r"(?:href|src|action)=['\"]([^'\"]+)['\"]"
    for match in re.finditer(pattern, text, flags=re.IGNORECASE):
        _record_link_value(signals, match.group(1))


def _collect_javascript_endpoint_signals(signals: dict[str, list[str]], text: str) -> None:
    for match in re.finditer(
        r"\bfetch\(\s*([`'\"])([^`'\"\r\n]{1,300})\1", text, flags=re.IGNORECASE
    ):
        _record_link_value(signals, match.group(2))
    for match in re.finditer(
        r"\b(?:location(?:\.href)?|window\.location(?:\.href)?)\s*=\s*([`'\"])(/[^`'\"\r\n]{1,300})\1",
        text,
        flags=re.IGNORECASE,
    ):
        _record_link_value(signals, match.group(2))
    for match in re.finditer(
        r"\b(?:url|href|action)\s*:\s*([`'\"])(/[^`'\"\r\n]{1,300})\1",
        text,
        flags=re.IGNORECASE,
    ):
        _record_link_value(signals, match.group(2))
    for template in _javascript_request_templates(text):
        _record_javascript_request_template(signals, template)
    for match in re.finditer(
        r"\bJSON\.stringify\(\s*\{([^{}]{1,800})\}\s*\)", text, flags=re.IGNORECASE
    ):
        for key in _javascript_object_keys(match.group(1)):
            _add_signal(signals, "parameters", key)
    for match in re.finditer(
        r"\bheaders\s*:\s*\{([^{}]{1,1200})\}", text, flags=re.IGNORECASE | re.DOTALL
    ):
        for name, value in _javascript_request_header_pairs(match.group(1)):
            _add_signal(signals, "auth_headers", f"{name}: {value}")


def _collect_plain_url_signals(signals: dict[str, list[str]], text: str) -> None:
    pattern = r"https?://[^\s'\"<>]+|/[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+"
    for match in re.finditer(pattern, text):
        _record_plain_url(signals, match.group(0))


def _collect_marker_signals(signals: dict[str, list[str]], text: str) -> None:
    for marker in _markers(text):
        _add_signal(signals, "markers", marker)
    if APACHE_TRAVERSAL_PATTERN.search(text):
        _add_signal(signals, "markers", "apache_2_4_path_traversal_surface")
    if _text_contains_one(text, SQL_CONFIRMATION_MARKERS):
        _add_signal(signals, "markers", "sql_injection_confirmed")
    if _text_contains_ssti_eval_signal(text):
        _add_signal(signals, "markers", "ssti_fingerprint_signal")


def _collect_structured_signals(signals: dict[str, list[str]], text: str) -> None:
    structured = _structured_result(text)
    if not structured:
        return

    _add_signal_values(signals, "sqli_inputs", sqli_input_signals(structured))
    _add_signal_values(signals, "sqli_replays", sqli_replay_signals(structured))
    _add_signal_values(signals, "sqli_boolean_templates", sqli_boolean_template_signals(structured))
    _add_signal_values(signals, "xss_contexts", _xss_context_signals(structured))
    _add_signal_values(signals, "forms", _auth_followup_form_signals(structured))
    _add_signal_values(signals, "forms", _structured_form_signals(structured))
    _add_signal_values(signals, "endpoints", _structured_endpoint_signals(structured))
    _add_signal_values(signals, "parameters", _structured_parameter_signals(structured))
    _add_signal_values(signals, "canonical_hosts", _canonical_host_signals(structured))
    _add_signal_values(signals, "cookies", _structured_cookie_signals(structured))
    _add_signal_values(signals, "auth_headers", _structured_auth_header_signals(structured))
    _add_signal_values(signals, "file_read_inputs", _file_read_input_signals(structured))
    _add_signal_values(signals, "markers", _structured_marker_signals(structured))
    _add_signal_values(signals, "reflections", _reflection_value_signals(structured))
    if _structured_has_file_read(structured):
        _add_signal(signals, "markers", "file_read_confirmed")


def _record_link_value(signals: dict[str, list[str]], value: str) -> None:
    if _looks_local_tool_path(value):
        return
    _add_signal(signals, "links", value)
    _add_signal(signals, "endpoints", value)
    _record_query_parameters(signals, value)


def _record_plain_url(signals: dict[str, list[str]], value: str) -> None:
    cleaned = value.strip().rstrip(").,;:]}>'\"")
    if _looks_local_tool_path(cleaned):
        return
    if len(cleaned) <= 1:
        return
    if _looks_malformed_endpoint(cleaned):
        return
    _add_signal(signals, "endpoints", cleaned)
    _record_query_parameters(signals, cleaned)


def _record_query_parameters(signals: dict[str, list[str]], value: str) -> None:
    for name in _query_names(value):
        _add_signal(signals, "parameters", name)


def _add_signal_values(signals: dict[str, list[str]], key: str, values: list[str]) -> None:
    for value in values:
        _add_signal(signals, key, value)


def _add_signal(signals: dict[str, list[str]], key: str, value: str) -> None:
    cleaned = re.sub(r"\s+", " ", value.strip())
    if not cleaned:
        return
    if key not in signals:
        signals[key] = []
    append_unique(signals[key], cleaned, limit=20)


def merge_recon_state(state: AgentState, recon_payload: dict[str, object]) -> None:
    pages = recon_payload.get("pages")
    if not isinstance(pages, list):
        return
    append_unique(state.facts, f"initial recon crawled {len(pages)} page(s)", limit=80)
    query_names = recon_payload.get("query_parameter_names")
    if isinstance(query_names, list) and query_names:
        merge_signals(state, {"parameters": _string_items(query_names)})
        append_unique(
            state.facts,
            "query parameters observed: " + ", ".join(_string_items(query_names[:12])),
            limit=80,
        )
    markers = recon_payload.get("interesting_markers")
    if isinstance(markers, list) and markers:
        merge_signals(state, {"markers": _string_items(markers)})
    for page in pages[:12]:
        if isinstance(page, dict):
            _merge_page(state, page)


def classify_action_result(
    *,
    ok: bool,
    repeat_count: int,
    text: str,
    trusted_target_evidence: bool = False,
) -> str:
    lower = text.lower()
    structured = _structured_result(text)
    probe = ""
    if structured and trusted_target_evidence:
        probe = str(structured.get("probe") or "")
        findings = structured.get("findings")
        if probe == "surface_map" and isinstance(findings, list) and findings:
            return "new_surface"
        if isinstance(findings, list) and findings:
            return "confirmed_signal"
    if repeat_count > 1:
        return "same_as_before"
    if structured and trusted_target_evidence:
        if structured.get("ok") is True and probe in {"surface_map", "api_behavior"}:
            return "new_surface"
        if structured.get("ok") is True and probe == "secret_sweep":
            return "observed"
    # Unstructured stderr from a failed local command is not target evidence.
    # In particular, Python tracebacks and tool-runtime exceptions share words
    # with target-side error markers. Structured findings above retain their
    # explicit evidence provenance even when the enclosing action failed.
    if not ok:
        return "blocked"
    # Raw shell/Python stdout can merely print target-looking markers. Only an
    # executor-owned probe/validator with managed request/response provenance
    # may turn those strings into a target-side confirmation signal.
    if trusted_target_evidence and _text_contains_one(lower, ERROR_SIGNAL_MARKERS):
        return "confirmed_signal"
    if trusted_target_evidence and "root:x:0:0:" in lower:
        return "confirmed_signal"
    if trusted_target_evidence and _text_contains_one(lower, SURFACE_SIGNAL_MARKERS):
        return "new_surface"
    return "observed"


def _structured_result(text: str) -> dict[str, object]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}

    if isinstance(data, dict):
        return data
    return {}


def _xss_context_signals(payload: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        signals.extend(_xss_signals_from_finding(finding))
    return signals[:12]


def _file_read_input_signals(payload: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        signal = _file_read_signal_from_finding(finding)
        if signal:
            signals.append(signal)
    return signals[:12]


def _findings(payload: dict[str, object]) -> list[dict[str, object]]:
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        return []

    findings: list[dict[str, object]] = []
    for item in raw_findings:
        if isinstance(item, dict):
            findings.append(dict(item))
    return findings


def _xss_signals_from_finding(finding: dict[str, object]) -> list[str]:
    if _finding_type(finding) not in {
        "xss_reflection_context",
        "client_side_execution",
        "client_side_proof_extraction",
    }:
        return []

    raw_input = _dict_value(finding.get("input"))
    if not raw_input:
        return []

    input_name = _input_name(raw_input)
    url = str(raw_input.get("url") or "")
    if not input_name or not url:
        return []

    signals: list[str] = []
    for context in _context_items(finding):
        signal = _xss_context_signal(
            input_name=input_name, url=url, context=context, raw_input=raw_input
        )
        if signal:
            signals.append(signal)
    filter_signal = _xss_filter_profile_signal(input_name=input_name, url=url, finding=finding)
    if filter_signal:
        signals.append(filter_signal)
    return signals


def _xss_filter_profile_signal(*, input_name: str, url: str, finding: dict[str, object]) -> str:
    raw_profile = _dict_value(finding.get("filter_profile"))
    if not raw_profile:
        return ""
    allowed = _string_list_value(raw_profile.get("allowed"))
    blocked = _string_list_value(raw_profile.get("blocked"))
    encoded = _string_list_value(raw_profile.get("encoded"))
    hints = _string_list_value(raw_profile.get("bypass_hints"))
    if not allowed and not blocked and not encoded and not hints:
        return ""
    return json.dumps(
        {
            "type": "xss_filter_profile",
            "input": input_name,
            "url": url,
            "allowed": allowed[:12],
            "blocked": blocked[:12],
            "encoded": encoded[:12],
            "bypass_hints": hints[:6],
        },
        sort_keys=True,
    )


def _context_items(finding: dict[str, object]) -> list[dict[str, object]]:
    raw_contexts = finding.get("contexts")
    if raw_contexts is None:
        raw_input = _dict_value(finding.get("input"))
        raw_contexts = raw_input.get("contexts")
    if not isinstance(raw_contexts, list):
        return []

    contexts: list[dict[str, object]] = []
    for item in raw_contexts:
        if isinstance(item, dict):
            contexts.append(dict(item))
    return contexts


def _xss_context_signal(
    *,
    input_name: str,
    url: str,
    context: dict[str, object],
    raw_input: dict[str, object] | None = None,
) -> str:
    context_name = str(context.get("context") or "")
    if not context_name:
        return ""

    payload: dict[str, object] = {
        "input": input_name,
        "url": url,
        "context": context_name,
        "tag_name": str(context.get("tag_name") or ""),
        "attribute_name": str(context.get("attribute_name") or ""),
        "quote_char": str(context.get("quote_char") or ""),
    }
    if raw_input:
        for key in ("kind", "method"):
            value = str(raw_input.get(key) or "")
            if value:
                payload[key] = value
        form = _dict_value(raw_input.get("form"))
        if form:
            payload["form"] = form
    return json.dumps(payload, sort_keys=True)


def _file_read_signal_from_finding(finding: dict[str, object]) -> str:
    if _finding_type(finding) not in FILE_READ_FINDING_TYPES:
        return ""

    primitive = _dict_value(finding.get("primitive"))
    if primitive:
        return json.dumps(primitive, sort_keys=True)

    raw_input = _dict_value(finding.get("input"))
    payload_value = str(finding.get("payload") or "")
    if not raw_input or not payload_value:
        return ""

    target = _file_read_target(raw_input)
    signal = _dict_value(finding.get("signal"))
    payload: dict[str, object] = {"target": target, "payload": payload_value, "signal": signal}
    return json.dumps(payload, sort_keys=True)


def _auth_followup_form_signals(payload: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        finding_type = _finding_type(finding)
        if finding_type in {"auth_session_followup_signal", "sqli_auth_bypass_session"}:
            raw_forms = finding.get("forms")
            if isinstance(raw_forms, list):
                for form in raw_forms:
                    if isinstance(form, dict):
                        signals.append(json.dumps(form, sort_keys=True))
        if finding_type in {
            "auth_form_submission",
            "auth_session_followup_signal",
            "sqli_auth_bypass_session",
            "captcha_form_state_replay",
        }:
            replay = _dict_value(finding.get("replay"))
            for form_signal in _replay_form_signals(finding, replay):
                signals.append(form_signal)
    return signals[:12]


def _replay_form_signals(finding: dict[str, object], replay: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for item in [replay, *_list_of_dicts(replay.get("followup_steps"))]:
        method = str(item.get("method") or "").upper()
        action = str(item.get("url") or "")
        fields = _dict_value(item.get("form"))
        if method not in {"GET", "POST"} or not action or not fields:
            continue
        headers = _replay_auth_headers(finding, item)
        form: dict[str, object] = {
            "action": action,
            "auth_headers": headers,
            "categories": ["authenticated", "auth", "browser_replay"],
            "enctype": str(item.get("encoding") or "application/x-www-form-urlencoded"),
            "id": "auth-replay-form",
            "inputs": _replay_form_inputs(fields),
            "method": method,
        }
        signals.append(json.dumps(form, sort_keys=True))
    return signals


def _replay_form_inputs(fields: dict[str, object]) -> list[dict[str, object]]:
    inputs: list[dict[str, object]] = []
    for name, value in fields.items():
        text_name = str(name)
        if not text_name:
            continue
        text_value = str(value)
        inputs.append(
            {
                "disabled": False,
                "name": text_name,
                "required": False,
                "type": _replay_input_type(text_name, text_value),
                "value": text_value,
            }
        )
    return inputs


def _replay_auth_headers(finding: dict[str, object], replay: dict[str, object]) -> dict[str, str]:
    headers: dict[str, str] = {}
    cookie_header = _combined_cookie_header(_finding_cookie_values(finding))
    if cookie_header:
        headers["Cookie"] = cookie_header
    for source in (
        _dict_value(finding.get("auth_replay_headers")),
        _dict_value(replay.get("headers")),
    ):
        for name, value in source.items():
            header = str(name).strip()
            text = str(value).strip()
            if _request_header_signal_worthy(header, text):
                if header.lower() == "cookie":
                    combined = _combined_cookie_header([headers.get("Cookie", ""), text])
                    if combined:
                        headers["Cookie"] = combined
                else:
                    headers[header] = text
    return headers


def _finding_cookie_values(finding: dict[str, object]) -> list[str]:
    values: list[str] = []
    raw_cookies = finding.get("cookies")
    if isinstance(raw_cookies, list):
        for cookie in raw_cookies:
            values.extend(_cookie_pair_values(str(cookie)))
    cookie_header = str(finding.get("cookie_header") or "")
    values.extend(_cookie_pair_values(cookie_header))
    auth_headers = _dict_value(finding.get("auth_replay_headers"))
    cookie = str(auth_headers.get("Cookie") or auth_headers.get("cookie") or "")
    values.extend(_cookie_pair_values(cookie))
    return _unique_strings(values)[:8]


_COOKIE_ATTRIBUTE_NAMES = {
    "domain",
    "expires",
    "httponly",
    "max-age",
    "path",
    "samesite",
    "secure",
}


def _cookie_pair_values(raw: str) -> list[str]:
    pairs: list[str] = []
    for line in re.split(r"[\r\n]+", raw or ""):
        text = re.sub(r"(?i)^\s*set-cookie:\s*", "", line).strip()
        if not text:
            continue
        for chunk in re.split(r",\s*(?=[A-Za-z0-9_.-]+=)", text):
            for part in chunk.split(";"):
                candidate = part.strip()
                if _cookie_pair_usable(candidate):
                    pairs.append(candidate)
    return _unique_strings(pairs)


def _cookie_pair_usable(candidate: str) -> bool:
    if "=" not in candidate:
        return False
    name, value = candidate.split("=", 1)
    name = name.strip()
    value = value.strip()
    if not name or not value:
        return False
    lowered = name.lower()
    if lowered in _COOKIE_ATTRIBUTE_NAMES:
        return False
    for char in name:
        if char.isspace() or char == ",":
            return False
    return True


def _combined_cookie_header(values: list[str]) -> str:
    cookies: dict[str, str] = {}
    for raw in values:
        for pair in _cookie_pair_values(raw):
            name, value = pair.split("=", 1)
            cookies[name.strip()] = value.strip()

    parts: list[str] = []
    for name, value in cookies.items():
        if name and value:
            parts.append(f"{name}={value}")
    return "; ".join(parts)


def _unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        unique.append(text)
    return unique


def _replay_input_type(name: str, value: str) -> str:
    lowered = name.lower()
    if "pass" in lowered or "pwd" in lowered:
        return "password"
    if lowered in {"submit", "button"}:
        return "submit"
    if value:
        return "hidden"
    return "text"


def _canonical_host_signals(payload: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        if _finding_type(finding) != "canonical_host_header_signal":
            continue
        headers = _dict_value(finding.get("headers"))
        host = str(headers.get("Host") or headers.get("host") or finding.get("host") or "").strip()
        if host:
            signals.append(host)
    return signals[:6]


def _structured_marker_signals(payload: dict[str, object]) -> list[str]:
    markers: list[str] = []
    for finding in _findings(payload):
        finding_type = _finding_type(finding)
        if finding_type in CONFIRMATION_FINDING_TYPES:
            markers.append(finding_type)
    return markers[:20]


def _structured_cookie_signals(payload: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        raw_cookies = finding.get("cookies")
        if isinstance(raw_cookies, list):
            for cookie in raw_cookies:
                if isinstance(cookie, str) and "=" in cookie:
                    signals.extend(_cookie_pair_values(cookie))
        for key in ("cookie_signal", "set_cookie", "cookie_header"):
            value = finding.get(key)
            if not isinstance(value, str) or "=" not in value:
                continue
            signals.extend(_cookie_pair_values(value))
        auth_headers = _dict_value(finding.get("auth_replay_headers"))
        cookie = str(auth_headers.get("Cookie") or auth_headers.get("cookie") or "")
        if cookie:
            signals.extend(_cookie_pair_values(cookie))
    return _unique_strings(signals)[:20]


def _structured_auth_header_signals(payload: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        for key in ("auth_replay_headers", "headers_used"):
            headers = _dict_value(finding.get(key))
            signals.extend(_request_header_signals(headers))
        raw_headers = finding.get("auth_headers")
        if isinstance(raw_headers, list):
            for item in raw_headers:
                signals.extend(_request_header_signals(_dict_value(item)))
        replay = _dict_value(finding.get("replay"))
        signals.extend(_request_header_signals(_dict_value(replay.get("headers"))))
        for step in _list_of_dicts(replay.get("followup_steps")):
            signals.extend(_request_header_signals(_dict_value(step.get("headers"))))
    return signals[:20]


def _javascript_request_header_pairs(raw: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    quoted = r"([`'\"])([^`'\"\r\n:]{1,80})\1\s*:\s*([`'\"])([^`'\"\r\n]{1,400})\3"
    unquoted = r"\b([A-Za-z][A-Za-z0-9_-]{0,79})\s*:\s*([`'\"])([^`'\"\r\n]{1,400})\2"
    for match in re.finditer(quoted, raw):
        name = match.group(2).strip()
        value = match.group(4).strip()
        if _request_header_signal_worthy(name, value):
            pairs.append((name, value))
    for match in re.finditer(unquoted, raw):
        name = match.group(1).strip()
        value = match.group(3).strip()
        if _request_header_signal_worthy(name, value):
            pairs.append((name, value))
    return pairs[:12]


def _record_javascript_request_template(
    signals: dict[str, list[str]], template: dict[str, object]
) -> None:
    url = str(template.get("url") or "").strip()
    if not url:
        return

    fields = _string_dict_value(template.get("fields"))
    _record_link_value(signals, url)

    templated_url = _javascript_request_url_with_data(url, fields)
    if templated_url != url:
        _record_link_value(signals, templated_url)

    for name in fields:
        _add_signal(signals, "parameters", name)

    headers = _string_dict_value(template.get("headers"))
    for name, value in headers.items():
        _add_signal(signals, "auth_headers", f"{name}: {value}")

    _add_signal(signals, "request_templates", json.dumps(template, sort_keys=True))


def _javascript_request_templates(text: str) -> list[dict[str, object]]:
    templates: list[dict[str, object]] = []
    templates.extend(_javascript_ajax_requests(text))
    templates.extend(_javascript_fetch_requests(text))
    return templates[:16]


def _javascript_ajax_requests(text: str) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []
    pattern = r"(?is)(?:\$|\bjQuery)\s*\.\s*ajax\s*\(\s*\{(.*?)\}\s*\)"
    for match in re.finditer(pattern, text):
        block = match.group(1)
        url = _javascript_property_string(block, "url")
        if not url:
            continue
        data = _javascript_data_object_pairs(block)
        request: dict[str, object] = {
            "source": "jquery_ajax",
            "method": _javascript_method_from_block(block, default="GET"),
            "url": url,
        }
        if data:
            request["fields"] = data
        headers = _javascript_headers_from_block(block)
        if headers:
            request["headers"] = headers
        requests.append(request)
    return requests[:12]


def _javascript_property_string(block: str, name: str) -> str:
    value = _javascript_property_string_value(block, name)
    if not _javascript_url_value_usable(value):
        return ""
    return value


def _javascript_property_string_value(block: str, name: str) -> str:
    pattern = rf"\b{name}\s*:\s*([`'\"])([^`'\"\r\n]{{1,300}})\1"
    match = re.search(pattern, block, flags=re.IGNORECASE)
    if match is None:
        return ""
    return match.group(2).strip()


def _javascript_url_value_usable(value: str) -> bool:
    if not value:
        return False
    lowered = value.lower()
    if lowered.startswith(("javascript:", "data:", "mailto:", "#")):
        return False
    if _looks_malformed_endpoint(value):
        return False
    if value.startswith(("/", "./", "../", "http://", "https://")):
        return True
    if "/" in value:
        return True
    return bool(re.search(r"\.(?:php|asp|aspx|jsp|json|html?|txt)\b", lowered))


def _javascript_method_from_block(block: str, *, default: str) -> str:
    method = _javascript_property_string_value(block, "method")
    if not method:
        method = _javascript_property_string_value(block, "type")

    upper = method.upper()
    if upper in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        return upper
    return default


def _javascript_headers_from_block(block: str) -> dict[str, str]:
    header_block = _javascript_property_object(block, "headers")
    if not header_block:
        return {}

    headers: dict[str, str] = {}
    for name, value in _javascript_request_header_pairs(header_block):
        headers[name] = value
    return headers


def _javascript_data_object_pairs(block: str) -> dict[str, str]:
    data_block = _javascript_property_object(block, "data")
    if not data_block:
        return {}
    return _javascript_payload_pairs_from_object(data_block)


def _javascript_payload_pairs_from_object(data_block: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for name, raw_value in _javascript_object_pairs(data_block):
        if not _looks_javascript_payload_key(name):
            continue
        pairs[name] = _javascript_default_value_for_pair(name, raw_value)
    return pairs


def _javascript_fetch_requests(text: str) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []
    for arguments in _javascript_fetch_call_arguments(text):
        request = _javascript_fetch_request_from_arguments(arguments)
        if request:
            requests.append(request)
    return requests[:12]


def _javascript_fetch_call_arguments(text: str) -> list[str]:
    arguments: list[str] = []
    for match in re.finditer(r"\bfetch\s*\(", text, flags=re.IGNORECASE):
        open_paren = match.end() - 1
        close_paren = _matching_javascript_paren(text, open_paren)
        if close_paren <= open_paren:
            continue
        arguments.append(text[open_paren + 1 : close_paren])
    return arguments[:12]


def _javascript_fetch_request_from_arguments(arguments: str) -> dict[str, object]:
    match = re.match(
        r"\s*([`'\"])([^`'\"\r\n]{1,300})\1\s*(?:,(?P<options>.*))?\s*$",
        arguments,
        flags=re.DOTALL,
    )
    if match is None:
        return {}

    url = match.group(2).strip()
    if not _javascript_url_value_usable(url):
        return {}

    options = _javascript_first_object_literal(match.group("options") or "")
    request: dict[str, object] = {
        "source": "fetch",
        "method": _javascript_method_from_block(options, default="GET"),
        "url": url,
    }

    fields = _javascript_fetch_body_fields(options)
    if fields:
        request["fields"] = fields

    headers = _javascript_headers_from_block(options)
    if headers:
        request["headers"] = headers

    return request


def _javascript_first_object_literal(text: str) -> str:
    match = re.search(r"\{", text)
    if match is None:
        return ""

    open_brace = match.start()
    close_brace = _matching_javascript_brace(text, open_brace)
    if close_brace <= open_brace:
        return ""
    return text[open_brace + 1 : close_brace]


def _javascript_fetch_body_fields(options: str) -> dict[str, str]:
    for body in _javascript_json_stringify_objects(options):
        fields = _javascript_payload_pairs_from_object(body)
        if fields:
            return fields

    for body in _javascript_url_search_params_objects(options):
        fields = _javascript_payload_pairs_from_object(body)
        if fields:
            return fields

    body_object = _javascript_property_object(options, "body")
    if body_object:
        return _javascript_payload_pairs_from_object(body_object)

    return {}


def _javascript_json_stringify_objects(text: str) -> list[str]:
    objects: list[str] = []
    for match in re.finditer(r"\bJSON\s*\.\s*stringify\s*\(\s*\{", text, flags=re.IGNORECASE):
        open_brace = match.end() - 1
        close_brace = _matching_javascript_brace(text, open_brace)
        if close_brace <= open_brace:
            continue
        objects.append(text[open_brace + 1 : close_brace])
    return objects[:8]


def _javascript_url_search_params_objects(text: str) -> list[str]:
    objects: list[str] = []
    pattern = r"\b(?:URLSearchParams|FormData)\s*\(\s*\{"
    for match in re.finditer(pattern, text, flags=re.IGNORECASE):
        open_brace = match.end() - 1
        close_brace = _matching_javascript_brace(text, open_brace)
        if close_brace <= open_brace:
            continue
        objects.append(text[open_brace + 1 : close_brace])
    return objects[:8]


def _javascript_property_object(block: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*:\s*\{{", block, flags=re.IGNORECASE)
    if match is None:
        return ""

    open_brace = match.end() - 1
    close_brace = _matching_javascript_brace(block, open_brace)
    if close_brace <= open_brace:
        return ""
    return block[open_brace + 1 : close_brace]


def _matching_javascript_paren(text: str, open_paren: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(open_paren, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == "(":
            depth += 1
            continue
        if char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _matching_javascript_brace(text: str, open_brace: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(open_brace, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == "{":
            depth += 1
            continue
        if char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _javascript_object_pairs(body: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    pattern = (
        r"(?:^|,)\s*"
        r"(?:([A-Za-z_$][\w$]*)|['\"]([^'\"]{1,80})['\"])\s*:\s*"
        r"([^,\r\n}]{1,200})"
    )
    for match in re.finditer(pattern, body):
        name = match.group(1) or match.group(2) or ""
        raw_value = match.group(3).strip()
        if name:
            pairs.append((name, raw_value))
    return pairs[:20]


def _javascript_default_value_for_pair(name: str, raw_value: str) -> str:
    literal = _javascript_literal_value(raw_value)
    if literal:
        return literal
    return _javascript_default_value_for_name(name)


def _javascript_literal_value(raw_value: str) -> str:
    stripped = raw_value.strip()
    quoted = re.fullmatch(r"([`'\"])(.*?)\1", stripped)
    if quoted is not None:
        return quoted.group(2)
    numeric = re.fullmatch(r"-?\d+(?:\.\d+)?", stripped)
    if numeric is not None:
        return numeric.group(0)
    if stripped in {"true", "false", "null"}:
        return stripped
    return ""


def _javascript_default_value_for_name(name: str) -> str:
    lowered = name.lower()
    if any(marker in lowered for marker in ("term", "month", "year", "duration", "limit")):
        return "1"
    if any(marker in lowered for marker in ("payment", "amount", "principal", "rate", "total")):
        return "1"
    if lowered.endswith("id") or lowered == "id":
        return "1"
    return "ravage"


def _javascript_request_url_with_data(url: str, data: dict[str, str]) -> str:
    if not data:
        return url
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url

    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    existing = {name for name, _value in pairs}
    for name, value in data.items():
        if name not in existing:
            pairs.append((name, value))
    query = urlencode(pairs)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def _request_header_signals(headers: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for name, value in headers.items():
        header = str(name).strip()
        text = str(value).strip()
        if _request_header_signal_worthy(header, text):
            signals.append(f"{header}: {text}")
    return signals


def _request_header_signal_worthy(name: str, value: str) -> bool:
    if not name or not value:
        return False
    lowered = name.strip().lower()
    if lowered in {
        "accept",
        "accept-encoding",
        "accept-language",
        "cache-control",
        "connection",
        "content-length",
        "content-type",
        "host",
        "origin",
        "pragma",
        "referer",
        "user-agent",
    }:
        return False
    if lowered.startswith("sec-"):
        return False
    if lowered in {"authorization", "cookie"}:
        return True
    if lowered.startswith("x-"):
        return True
    for token in ("auth", "token", "session", "csrf", "user", "account", "tenant", "org"):
        if token in lowered:
            return True
    return False


def _structured_endpoint_signals(payload: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        for endpoint in _string_list_value(finding.get("endpoints")):
            url = str(endpoint).strip()
            if url:
                signals.append(url)
        if _finding_type(finding) != "openapi_route_signal":
            continue
        for route in _list_of_dicts(finding.get("routes")):
            url = str(route.get("url") or "")
            if url:
                signals.append(url)
    return signals[:24]


def _structured_parameter_signals(payload: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        for endpoint in _string_list_value(finding.get("endpoints")):
            for name, _value in parse_qsl(urlsplit(str(endpoint)).query, keep_blank_values=True):
                if name:
                    signals.append(name)
        for form in _list_of_dicts(finding.get("forms")):
            for input_field in _list_of_dicts(form.get("inputs")):
                name = str(input_field.get("name") or "")
                if name:
                    signals.append(name)
        if _finding_type(finding) != "openapi_route_signal":
            continue
        for route in _list_of_dicts(finding.get("routes")):
            for parameter in _list_of_dicts(route.get("parameters")):
                name = str(parameter.get("name") or "")
                if name:
                    signals.append(name)
    return signals[:32]


def _structured_form_signals(payload: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        for form in _list_of_dicts(finding.get("forms")):
            action = str(form.get("action") or "")
            inputs = _list_of_dicts(form.get("inputs"))
            if action and inputs:
                signals.append(json.dumps(form, sort_keys=True))
    return signals[:12]


def _reflection_value_signals(payload: dict[str, object]) -> list[str]:
    signals: list[str] = []
    for finding in _findings(payload):
        if _finding_type(finding) not in {
            "reflection_value_delta",
            "reflection_value_timeout",
            "reflection_value_proof",
        }:
            continue
        raw_input = _dict_value(finding.get("input"))
        if not raw_input:
            continue
        signal = {
            "kind": str(raw_input.get("kind") or "query_param"),
            "url": str(raw_input.get("url") or ""),
            "input": _input_name(raw_input),
            "value": str(finding.get("value") or ""),
            "type": _finding_type(finding),
        }
        signals.append(json.dumps(signal, sort_keys=True))
    return signals[:12]


def _file_read_target(raw_input: dict[str, object]) -> dict[str, object]:
    target: dict[str, object] = {
        "kind": str(raw_input.get("kind") or "query_param"),
        "url": str(raw_input.get("url") or ""),
        "input": _input_name(raw_input),
        "hints": raw_input.get("hints", []),
        "priority": raw_input.get("priority", 0),
    }
    method = str(raw_input.get("method") or "").upper()
    if method:
        target["method"] = method
    fields = _dict_value(raw_input.get("fields"))
    if fields:
        target["fields"] = fields
    return target


def _finding_type(finding: dict[str, object]) -> str:
    return str(finding.get("type") or "")


def _input_name(raw_input: dict[str, object]) -> str:
    return str(raw_input.get("input") or raw_input.get("name") or "")


def _dict_value(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _string_dict_value(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}

    items: dict[str, str] = {}
    for name, raw_value in value.items():
        text_name = str(name).strip()
        if not text_name:
            continue
        items[text_name] = str(raw_value)
    return items


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []

    items: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(dict(item))
    return items


def _string_list_value(value: object) -> list[str]:
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            text = str(item)
            if text:
                items.append(text)
        return items
    if isinstance(value, str) and value:
        return [value]
    return []


def _structured_has_file_read(payload: dict[str, object]) -> bool:
    if _file_read_input_signals(payload):
        return True
    return "root:x:0:0:" in json.dumps(payload).lower()


def _merge_page(state: AgentState, page: dict[str, Any]) -> None:
    page_url = str(page.get("final_url") or page.get("url") or "")
    if page_url:
        merge_signals(state, {"pages": [page_url]})
    forms = page.get("forms")
    if isinstance(forms, list) and forms:
        append_unique(state.facts, f"{len(forms)} form(s) observed at {page_url}", limit=80)
        merge_signals(state, {"forms": _json_items(forms[:5])})
    reflected = page.get("reflected_parameters")
    if isinstance(reflected, list) and reflected:
        merge_signals(
            state,
            {"reflections": _json_items(reflected[:8])},
        )
        append_unique(state.facts, f"reflected input observed at {page_url}", limit=80)


def _markers(text: str) -> list[str]:
    lower = text.lower()
    markers = []
    for marker in (
        "sql syntax",
        "sqlite",
        "mysql",
        "postgres",
        "jinja",
        "template",
        "traceback",
        "warning:",
        "exception",
        "csrf",
        "samesite",
        "httponly",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "cors",
        "x-frame-options",
        "frame-ancestors",
        "clickjack",
        "websocket",
        "ws://",
        "wss://",
        "localstorage",
        "sessionstorage",
        "jwt",
        "base64",
        "graphql",
        "xml",
        "upload",
        "client_side_execution",
        "client_side_proof_extraction",
        "reflection_value_delta",
        "reflection_value_timeout",
        "reflection_value_proof",
        "admin",
        "backup",
        ".git",
        ".env",
        "robots.txt",
        "sitemap.xml",
        "source map",
        "filtered",
        "no results",
        "user exists",
        "preg_match",
        "array given",
        "expects parameter 2",
        "unauthorized",
        "forbidden",
    ):
        if marker in lower:
            markers.append(marker)
    return markers


def _string_items(values: list[object]) -> list[str]:
    items: list[str] = []
    for value in values:
        items.append(str(value))
    return items


def _json_items(values: list[object]) -> list[str]:
    items: list[str] = []
    for value in values:
        items.append(json.dumps(value, sort_keys=True))
    return items


def _query_names(value: str) -> list[str]:
    try:
        query = urlsplit(value).query
    except ValueError:
        return []
    names: list[str] = []
    for name, _raw in parse_qsl(query, keep_blank_values=True):
        if name:
            names.append(name)
    return names


def _javascript_object_keys(body: str) -> list[str]:
    keys: list[str] = []
    pattern = r"(?:^|,)\s*(?:([A-Za-z_$][\w$]*)|['\"]([^'\"]{1,80})['\"])\s*:"
    for match in re.finditer(pattern, body):
        key = match.group(1) or match.group(2) or ""
        if _looks_javascript_payload_key(key):
            keys.append(key)
    return keys


def _looks_javascript_payload_key(value: str) -> bool:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", value):
        return False
    return value.lower() not in {
        "body",
        "headers",
        "method",
        "credentials",
        "mode",
        "cache",
        "redirect",
        "referrer",
        "signal",
    }


def _looks_malformed_endpoint(value: str) -> bool:
    for char in ("'", '"', "`", "<", ">", "{", "}", "[", "]", "\\"):
        if char in value:
            return True
    return False


def _looks_local_tool_path(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(
        (
            "/users/",
            "/private/",
            "/var/",
            "/tmp/",
            "/home/",
            "/root/",
            "/etc/",
            "/usr/",
            "/opt/",
            "/app/",
            "/srv/",
            "/workspace/",
        )
    )


def _text_contains_one(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False


def _text_contains_ssti_eval_signal(text: str) -> bool:
    lowered = text.lower()
    if not _contains_ssti_probe_payload(lowered):
        return False
    return _contains_ssti_result_marker(text)


def _contains_ssti_probe_payload(lowered: str) -> bool:
    for payload in (
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "[[${7*7}]]",
        "*{7*7}",
    ):
        if payload in lowered:
            return True
    return False


def _contains_ssti_result_marker(text: str) -> bool:
    body_pattern = r"(?:stdout|body|body_snippet|response)[^{}]{0,240}(?<!\d)49(?!\d)"
    if re.search(body_pattern, text, flags=re.IGNORECASE | re.DOTALL):
        return True
    if re.search(r"\bhello,\s*49\b", text, flags=re.IGNORECASE):
        return True
    return False
