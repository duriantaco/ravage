from __future__ import annotations

import html
import re
import secrets
from dataclasses import dataclass
from typing import Callable, TypeVar
from urllib.parse import quote

from ravage.agent_core.agent_state import AgentState
from ravage.runtime.common import clip
from ravage.probes.specialists.shared import (
    _baseline_value,
    _generic_input_targets,
    _looks_filtered_response,
    _send_target,
    _slow_response,
    _target_brief,
    _target_replay,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, compare_responses

_ResultT = TypeVar("_ResultT")

_XSS_CONTEXT_REQUEST_BUDGET = 36


@dataclass
class _XssProbeOutcome:
    finding: dict[str, object] | None
    requests: list[dict[str, object]]
    budget: int


@dataclass
class _XssReflectionProbe:
    canary: str
    contexts: list[dict[str, object]]


@dataclass
class _XssFilterProbeResult:
    label: str
    payload: str
    response: ProbeResponse
    reflected: bool
    encoded: bool
    blocked: bool


@dataclass
class _XssFilterBuckets:
    allowed: list[str]
    blocked: list[str]
    encoded: list[str]


def probe_xss_context(
    session: ProbeSession,
    state: AgentState,
    result_cls: Callable[..., _ResultT],
) -> _ResultT:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    budget = _XSS_CONTEXT_REQUEST_BUDGET
    targets = _generic_input_targets(state, limit=4)
    for target in targets:
        if budget <= 0 or len(findings) >= 3:
            break
        outcome = _probe_xss_target(session, target, budget=budget)
        requests.extend(outcome.requests)
        budget = outcome.budget
        if outcome.finding is None:
            continue
        findings.append(outcome.finding)
    return _xss_context_result(result_cls, targets, findings, requests, budget)


def _probe_xss_target(
    session: ProbeSession,
    target: dict[str, object],
    *,
    budget: int,
) -> _XssProbeOutcome:
    requests: list[dict[str, object]] = []
    baseline_value = _baseline_value(str(target.get("input") or ""))
    baseline = _send_target(session, target, baseline_value)
    budget -= 1
    requests.append(_xss_baseline_request(baseline, target))

    reflection, reflection_requests, budget = _probe_xss_reflections(
        session,
        target,
        baseline=baseline,
        budget=budget,
    )
    requests.extend(reflection_requests)
    if reflection is None:
        return _XssProbeOutcome(finding=None, requests=requests, budget=budget)

    filter_profile, filter_requests, budget = _xss_filter_profile_for_target(
        session,
        target,
        baseline=baseline,
        budget=budget,
    )
    requests.extend(filter_requests)
    finding = _xss_reflection_finding(
        target,
        baseline_value=baseline_value,
        reflection=reflection,
        filter_profile=filter_profile,
    )
    return _XssProbeOutcome(finding=finding, requests=requests, budget=budget)


def _xss_baseline_request(
    baseline: ProbeResponse,
    target: dict[str, object],
) -> dict[str, object]:
    return baseline.summary(body_chars=120) | {
        "target": _target_brief(target),
        "probe_kind": "baseline",
    }


def _probe_xss_reflections(
    session: ProbeSession,
    target: dict[str, object],
    *,
    baseline: ProbeResponse,
    budget: int,
) -> tuple[_XssReflectionProbe | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    for canary in _xss_canaries_for_response(baseline):
        if budget <= 0:
            break
        response = _send_target(session, target, canary)
        budget -= 1
        contexts = _xss_reflection_contexts(response.body, canary)
        requests.append(_xss_canary_request(response, target, baseline, canary, contexts))
        if contexts:
            return _XssReflectionProbe(canary=canary, contexts=contexts), requests, budget
    return None, requests, budget


def _xss_canary_request(
    response: ProbeResponse,
    target: dict[str, object],
    baseline: ProbeResponse,
    canary: str,
    contexts: list[dict[str, object]],
) -> dict[str, object]:
    delta = compare_responses(baseline, response, marker=canary)
    return response.summary(body_chars=220) | {
        "target": _target_brief(target),
        "probe_kind": "xss_canary",
        "canary": canary,
        "delta": delta.to_json(),
        "contexts": _context_names(contexts),
    }


def _xss_filter_profile_for_target(
    session: ProbeSession,
    target: dict[str, object],
    *,
    baseline: ProbeResponse,
    budget: int,
) -> tuple[dict[str, object], list[dict[str, object]], int]:
    if _slow_response(baseline):
        return _slow_xss_filter_profile(), [], budget
    filter_profile, filter_requests, budget = _detect_xss_filter_profile(
        session,
        target,
        baseline=baseline,
        budget=budget,
    )
    return filter_profile, filter_requests, budget


def _slow_xss_filter_profile() -> dict[str, object]:
    return {
        "allowed": [],
        "blocked": [],
        "encoded": [],
        "bypass_hints": [
            (
                "slow reflected target; preserve the confirmed sink context and move directly "
                "to value-boundary or browser verification"
            )
        ],
    }


def _xss_reflection_finding(
    target: dict[str, object],
    *,
    baseline_value: str,
    reflection: _XssReflectionProbe,
    filter_profile: dict[str, object],
) -> dict[str, object]:
    return {
        "type": "xss_reflection_context",
        "input": _target_brief(target),
        "canary": reflection.canary,
        "contexts": reflection.contexts[:6],
        "filter_profile": filter_profile,
        "baseline_replay": _target_replay(target, baseline_value),
        "replay": _target_replay(target, reflection.canary),
        "next": (
            "Use run_probe reflection_value_boundary first to test proof/value-gated XSS "
            "branches with this exact request template; use run_probe dom_execution afterward "
            "if browser execution still needs confirmation."
        ),
    }


def _xss_context_result(
    result_cls: Callable[..., _ResultT],
    targets: list[dict[str, object]],
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
    budget: int,
) -> _ResultT:
    return result_cls(
        ok=bool(findings),
        probe="xss_context",
        summary=(
            f"tested {len(targets)} input target(s), "
            f"requests={_XSS_CONTEXT_REQUEST_BUDGET - budget}, reflected_contexts={len(findings)}"
        ),
        findings=findings[:30],
        requests=requests[:90],
    )


def _xss_canaries() -> list[str]:
    token = secrets.token_hex(4)
    return [f"xss{token}", f"XSS{token}", f"xss-{token}", f"xss_{token}"]


def _xss_canaries_for_response(response: ProbeResponse) -> list[str]:
    canaries = _xss_canaries()
    if _slow_response(response):
        return canaries[:1]
    return canaries


def _xss_reflection_contexts(response_text: str, canary: str) -> list[dict[str, object]]:
    variants = [
        (canary, "none"),
        (html.escape(canary), "html_entity"),
        (quote(canary), "url_encode"),
    ]
    reflections: list[dict[str, object]] = []
    seen: set[tuple[int, str]] = set()
    for value, encoding in variants:
        start = 0
        while value:
            position = response_text.find(value, start)
            if position < 0:
                break
            key = (position, encoding)
            if key not in seen:
                seen.add(key)
                reflections.append(
                    _xss_reflection_at(response_text, position, len(value), value, canary, encoding)
                )
            start = position + 1
    return reflections[:8]


def _xss_reflection_at(
    text: str, position: int, length: int, reflected_value: str, original_value: str, encoding: str
) -> dict[str, object]:
    before = text[max(0, position - 160) : position]
    after = text[position + length : min(len(text), position + length + 160)]
    context, tag_name, attribute_name, quote_char = _classify_xss_context(before, after)
    return {
        "position": position,
        "context": context,
        "encoding": encoding,
        "reflected_value": reflected_value,
        "original_value": original_value,
        "tag_name": tag_name,
        "attribute_name": attribute_name,
        "quote_char": quote_char,
        "context_before": clip(before, 120),
        "context_after": clip(after, 120),
        "breakout_hint": _xss_breakout_hint(context, quote_char),
    }


def _classify_xss_context(before: str, after: str) -> tuple[str, str, str, str]:
    tag_context = _script_style_or_comment_context(before, after)
    if tag_context is not None:
        return tag_context

    open_tag_context = _open_html_tag_context(before)
    if open_tag_context is not None:
        return open_tag_context

    if _looks_json_context(before, after):
        return _xss_context_tuple("json_context")
    if _looks_url_context(before, after):
        return _xss_context_tuple("url_context")
    return _xss_context_tuple("html_body")


def _script_style_or_comment_context(
    before: str,
    after: str,
) -> tuple[str, str, str, str] | None:
    lower_before = before.lower()
    lower_after = after.lower()
    if _inside_html_tag(lower_before, lower_after, "script"):
        return _xss_context_tuple(_classify_js_context(before), tag_name="script")
    if _inside_html_tag(lower_before, lower_after, "style"):
        return _xss_context_tuple("css_context", tag_name="style")
    if _inside_html_comment(before):
        return _xss_context_tuple("html_comment")
    return None


def _inside_html_comment(before: str) -> bool:
    return "<!--" in before and "-->" not in before


def _open_html_tag_context(before: str) -> tuple[str, str, str, str] | None:
    fragment = _open_html_tag_fragment(before)
    if not fragment:
        return None

    tag_name = _tag_name_from_fragment(fragment)
    attr_match = _attribute_match_from_fragment(fragment)
    if attr_match is None:
        return _xss_context_tuple("html_tag", tag_name=tag_name)

    quote_char = attr_match.group(2)
    context = _attribute_context_from_quote(quote_char)
    attribute_name = attr_match.group(1).lower()
    return _xss_context_tuple(
        context,
        tag_name=tag_name,
        attribute_name=attribute_name,
        quote_char=quote_char,
    )


def _open_html_tag_fragment(before: str) -> str:
    tag_start = before.rfind("<")
    tag_end = before.rfind(">")
    if tag_start <= tag_end:
        return ""
    return before[tag_start:]


def _tag_name_from_fragment(fragment: str) -> str:
    tag_match = re.match(r"<\s*([a-zA-Z0-9:-]+)", fragment)
    return _tag_name_from_match(tag_match)


def _attribute_match_from_fragment(fragment: str) -> re.Match[str] | None:
    return re.search(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(['\"]?)[^'\"<>]*$", fragment)


def _xss_context_tuple(
    context: str,
    *,
    tag_name: str = "",
    attribute_name: str = "",
    quote_char: str = "",
) -> tuple[str, str, str, str]:
    return context, tag_name, attribute_name, quote_char


def _inside_html_tag(before: str, after: str, tag: str) -> bool:
    return before.rfind(f"<{tag}") > before.rfind(f"</{tag}") and f"</{tag}" in after


def _classify_js_context(before: str) -> str:
    single = before.count("'") - before.count("\\'")
    double = before.count('"') - before.count('\\"')
    backtick = before.count("`") - before.count("\\`")
    if single % 2:
        return "js_string_single"
    if double % 2:
        return "js_string_double"
    if backtick % 2:
        return "js_string_template"
    return "js_code"


def _looks_json_context(before: str, after: str) -> bool:
    window = before[-80:] + after[:80]
    return (
        bool(
            re.search(r'[{,]\s*"[^"]*"\s*:\s*"?$', before[-80:])
            or re.search(r'^\s*"?\s*[,}]', after[:80])
        )
        and "{" in window
    )


def _looks_url_context(before: str, after: str) -> bool:
    window = (before[-30:] + after[:30]).lower()
    return _window_contains_marker(
        window,
        ("href=", "src=", "url(", "http://", "https://", "javascript:"),
    )


def _xss_breakout_hint(context: str, quote_char: str) -> str:
    if context == "html_body":
        return "HTML body: tag or event-handler payload can be tried if angle brackets survive."
    if context == "html_attribute_quoted":
        quote_description = _quote_description(quote_char)
        return f"Quoted attribute: close {quote_description} before adding a handler or tag."
    if context == "html_attribute_unquoted":
        return (
            "Unquoted attribute: whitespace plus handler may be enough if event attributes survive."
        )
    if context.startswith("js_string"):
        return "JavaScript string: close the string and preserve syntax before calling the execution binding."
    if context == "js_code":
        return (
            "JavaScript code: expression or statement payload may execute if punctuation survives."
        )
    return (
        "Use the reflected context and filter profile to choose a minimal browser-verified payload."
    )


def _context_names(contexts: list[dict[str, object]]) -> list[object]:
    names: list[object] = []
    for item in contexts:
        names.append(item["context"])
    return names


def _tag_name_from_match(match: re.Match[str] | None) -> str:
    if match is None:
        return ""
    return match.group(1).lower()


def _attribute_context_from_quote(quote_char: str) -> str:
    if quote_char in {"'", '"'}:
        return "html_attribute_quoted"
    return "html_attribute_unquoted"


def _window_contains_marker(window: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in window:
            return True
    return False


def _quote_description(quote_char: str) -> str:
    if quote_char:
        return quote_char
    return "the quote"


def _detect_xss_filter_profile(
    session: ProbeSession,
    target: dict[str, object],
    *,
    baseline: ProbeResponse,
    budget: int,
    slow_safe: bool = False,
) -> tuple[dict[str, object], list[dict[str, object]], int]:
    probes = _xss_filter_probe_payloads(slow_safe=slow_safe)
    buckets = _new_xss_filter_buckets()
    requests: list[dict[str, object]] = []
    for label, payload in probes.items():
        if budget <= 0:
            break
        probe_result, budget = _run_xss_filter_probe(
            session,
            target,
            baseline=baseline,
            label=label,
            payload=payload,
            budget=budget,
        )
        _record_xss_filter_probe(buckets, probe_result)
        requests.append(_xss_filter_probe_request(target, probe_result))
    return _xss_filter_profile_from_buckets(buckets), requests, budget


def _new_xss_filter_buckets() -> _XssFilterBuckets:
    return _XssFilterBuckets(allowed=[], blocked=[], encoded=[])


def _run_xss_filter_probe(
    session: ProbeSession,
    target: dict[str, object],
    *,
    baseline: ProbeResponse,
    label: str,
    payload: str,
    budget: int,
) -> tuple[_XssFilterProbeResult, int]:
    response = _send_target(session, target, payload)
    budget -= 1
    reflected = payload in response.body
    encoded = _xss_payload_html_encoded(payload, response)
    blocked = _xss_filter_probe_blocked(
        response,
        baseline=baseline,
        reflected=reflected,
        encoded=encoded,
    )
    return (
        _XssFilterProbeResult(
            label=label,
            payload=payload,
            response=response,
            reflected=reflected,
            encoded=encoded,
            blocked=blocked,
        ),
        budget,
    )


def _xss_payload_html_encoded(payload: str, response: ProbeResponse) -> bool:
    encoded_payload = html.escape(payload)
    if encoded_payload == payload:
        return False
    return encoded_payload in response.body


def _xss_filter_probe_blocked(
    response: ProbeResponse,
    *,
    baseline: ProbeResponse,
    reflected: bool,
    encoded: bool,
) -> bool:
    if _looks_filtered_response(response.body):
        return True
    if reflected or encoded:
        return False
    return len(response.body) + 20 < len(baseline.body)


def _record_xss_filter_probe(
    buckets: _XssFilterBuckets,
    probe_result: _XssFilterProbeResult,
) -> None:
    if probe_result.reflected:
        buckets.allowed.append(probe_result.label)
        return
    if probe_result.encoded:
        buckets.encoded.append(probe_result.label)
        return
    if probe_result.blocked:
        buckets.blocked.append(probe_result.label)


def _xss_filter_probe_request(
    target: dict[str, object],
    probe_result: _XssFilterProbeResult,
) -> dict[str, object]:
    return probe_result.response.summary(body_chars=160) | {
        "target": _target_brief(target),
        "probe_kind": "xss_filter_probe",
        "label": probe_result.label,
        "payload": probe_result.payload,
        "reflected": probe_result.reflected,
        "encoded": probe_result.encoded,
        "blocked": probe_result.blocked,
    }


def _xss_filter_profile_from_buckets(buckets: _XssFilterBuckets) -> dict[str, object]:
    return {
        "allowed": buckets.allowed,
        "blocked": buckets.blocked,
        "encoded": buckets.encoded,
        "bypass_hints": _xss_bypass_hints(
            allowed=buckets.allowed,
            blocked=buckets.blocked,
            encoded=buckets.encoded,
        ),
    }


def _xss_bypass_hints(*, allowed: list[str], blocked: list[str], encoded: list[str]) -> list[str]:
    hints: list[str] = []
    _add_common_tag_blacklist_hints(hints, allowed=allowed, blocked=blocked)
    _add_tag_event_hint(hints, allowed=allowed)
    _add_quote_handling_hint(hints, blocked=blocked, encoded=encoded)
    _add_alternate_tag_hint(hints, allowed=allowed, blocked=blocked)
    _add_url_sink_hint(hints, allowed=allowed)
    return hints[:6]


def _add_common_tag_blacklist_hints(
    hints: list[str],
    *,
    allowed: list[str],
    blocked: list[str],
) -> None:
    common_tags = {"script_tag", "svg_tag", "img_tag", "input_tag", "source_tag"}
    if common_tags.intersection(blocked) and "custom_tag" in allowed:
        hints.append(
            "common tag-name blacklist detected; custom/unknown element event payloads "
            "may still be worth browser verification"
        )
    if common_tags.intersection(blocked) and "angle_brackets" in allowed:
        hints.append(
            "angle brackets survive but common tags are filtered; keep XSS focus and "
            "vary tag family or parser syntax"
        )


def _add_tag_event_hint(hints: list[str], *, allowed: list[str]) -> None:
    if "angle_brackets" not in allowed:
        return
    if _allowed_has_event_payload_path(allowed):
        hints.append("tag/event payloads are worth browser verification")


def _allowed_has_event_payload_path(allowed: list[str]) -> bool:
    for label in ("event_handler", "svg_tag", "img_tag"):
        if label in allowed:
            return True
    return False


def _add_quote_handling_hint(
    hints: list[str],
    *,
    blocked: list[str],
    encoded: list[str],
) -> None:
    if "quotes" in blocked or "quotes" in encoded:
        hints.append("avoid quote breakouts; try unquoted attributes or backtick/URL contexts")


def _add_alternate_tag_hint(
    hints: list[str],
    *,
    allowed: list[str],
    blocked: list[str],
) -> None:
    if "script_tag" in blocked and "svg_tag" in allowed:
        hints.append("script tag appears blocked but alternate tags may survive")


def _add_url_sink_hint(hints: list[str], *, allowed: list[str]) -> None:
    if "javascript_protocol" in allowed:
        hints.append("URL sinks may accept javascript: payloads")


def _xss_filter_probe_payloads(*, slow_safe: bool) -> dict[str, str]:
    probes = {
        "angle_brackets": "<>",
        "script_tag": "<script>",
        "svg_tag": "<svg>",
        "img_tag": "<img>",
        "input_tag": "<input>",
        "custom_tag": "<x>",
        "event_handler": "onerror=",
        "javascript_protocol": "javascript:",
        "alert_keyword": "alert",
        "quotes": "\"'",
        "parentheses": "()",
        "source_tag": "<source>",
    }
    if slow_safe:
        return {
            key: probes[key]
            for key in (
                "angle_brackets",
                "script_tag",
                "svg_tag",
                "img_tag",
                "input_tag",
                "custom_tag",
                "event_handler",
                "javascript_protocol",
            )
        }
    return probes
