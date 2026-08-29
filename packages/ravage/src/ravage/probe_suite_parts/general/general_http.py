from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    ResponseDelta,
    compare_responses,
    form_defaults,
    inject_query_param,
)
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import (
    _contains_word,
    _form_brief,
    _form_input_names,
    _form_targets,
    _parameter_targets,
)


@dataclass(frozen=True)
class _FormMarkerResult:
    responses: list[ProbeResponse]
    finding: dict[str, object] | None


def input_payload_probe(
    session: ProbeSession,
    state: AgentState,
    *,
    probe_name: str,
    payloads: dict[str, str],
    target_filter: Callable[[dict[str, object]], bool],
    finding_type: str,
    signal_fn: Callable[[ProbeResponse, str, str, ResponseDelta], bool] | None = None,
    fallback_to_all_parameters: bool = True,
) -> ProbeRunResult:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    signal = signal_fn or payload_signal
    targets = _filtered_parameter_targets(state, target_filter)
    if not targets and fallback_to_all_parameters:
        targets = _parameter_targets(state, limit=8)
    for target in targets[:10]:
        baseline = safe_get(session, str(target["url"]))
        requests.append(baseline.summary(body_chars=100))
        for payload, expected in payloads.items():
            probe_url = inject_query_param(str(target["url"]), str(target["name"]), payload)
            response = safe_get(session, probe_url)
            requests.append(response.summary(body_chars=160))
            delta = compare_responses(baseline, response, marker=payload)
            if signal(response, expected, payload, delta):
                findings.append(
                    {
                        "type": finding_type,
                        "input": target,
                        "payload": payload,
                        "expected": expected,
                        "url": probe_url.replace(payload, "PAYLOAD"),
                        "replay": _input_payload_query_replay(target, payload),
                        "delta": delta.to_json(),
                        "response": response.summary(body_chars=220),
                    }
                )
                break
    for form in _form_targets(state, limit=8):
        for input_field in _form_input_names(form):
            synthetic: dict[str, object] = {"name": input_field, "hints": [], "locations": [form.get("action", "")]}
            if not target_filter(synthetic):
                continue
            baseline = submit_form(session, form, form_defaults(form))
            requests.append(baseline.summary(body_chars=100))
            for payload, expected in payloads.items():
                fields = form_defaults(form, marker_name=input_field, marker=payload)
                response = submit_form(session, form, fields)
                requests.append(response.summary(body_chars=160))
                delta = compare_responses(baseline, response, marker=payload)
                if signal(response, expected, payload, delta):
                    findings.append(
                        {
                            "type": finding_type,
                            "form": _form_brief(form),
                            "input": input_field,
                            "payload": payload,
                            "expected": expected,
                            "replay": _input_payload_form_replay(form, input_field, fields),
                            "delta": delta.to_json(),
                            "response": response.summary(body_chars=220),
                        }
                    )
                    break
            if findings and findings[-1].get("form") == _form_brief(form):
                break
    return ProbeRunResult(
        ok=bool(findings),
        probe=probe_name,
        summary=f"tested {len(targets)} parameter target(s) and forms; findings={len(findings)}",
        findings=findings[:30],
        requests=requests[:50],
    )

def _input_payload_query_replay(target: dict[str, object], payload: str) -> dict[str, object]:
    return {
        "method": "GET",
        "url": str(target.get("url") or ""),
        "payload_field": str(target.get("name") or target.get("input") or ""),
        "payload": payload,
        "replay_hint": "Replay this request template verbatim; change only payload_field.",
    }


def _input_payload_form_replay(
    form: dict[str, object],
    input_field: str,
    fields: dict[str, str],
) -> dict[str, object]:
    form_fields: dict[str, str] = {}
    required_fields: list[str] = []
    for name, value in fields.items():
        field_name = str(name)
        form_fields[field_name] = str(value)
        required_fields.append(field_name)

    replay_hint = (
        "Replay this form template verbatim; preserve hidden/submit fields "
        "and change only payload_field."
    )
    replay: dict[str, object] = {
        "method": str(form.get("method") or "GET").upper(),
        "url": str(form.get("action") or ""),
        "payload_field": input_field,
        "form": form_fields,
        "required_fields": sorted(required_fields),
        "encoding": str(form.get("enctype") or "application/x-www-form-urlencoded"),
        "replay_hint": replay_hint,
    }
    headers = form.get("auth_headers")
    if isinstance(headers, dict):
        replay_headers: dict[str, str] = {}
        for name, value in headers.items():
            replay_headers[str(name)] = str(value)
        replay["headers"] = replay_headers
    return replay


def submit_form(session: ProbeSession, form: dict[str, object], fields: dict[str, str]) -> ProbeResponse:
    method = str(form.get("method") or "GET").upper()
    action = str(form.get("action") or session.target_url)
    if method == "POST":
        return session.post_form(action, fields)
    query_url = action
    for name, value in fields.items():
        query_url = inject_query_param(query_url, name, value)
    return safe_get(session, query_url)

def payload_signal(
    response: ProbeResponse,
    expected: str,
    payload: str,
    delta: ResponseDelta,
) -> bool:
    body = response.body.lower()
    expected_lower = expected.lower()
    if expected and expected_lower in body and payload.lower() not in expected_lower:
        return True
    rendered_delta = json.dumps(delta.to_json()).lower()
    if _contains_word(body, ("sql syntax", "sqlite", "mysql", "postgres", "traceback", "exception")):
        return True
    return "new_error_markers" in rendered_delta and "[]" not in rendered_delta

def safe_get(session: ProbeSession, url: str) -> ProbeResponse:
    return session.get(url)

def _filtered_parameter_targets(
    state: AgentState,
    target_filter: Callable[[dict[str, object]], bool],
    *,
    limit: int = 16,
) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for target in _parameter_targets(state, limit=limit):
        if target_filter(target):
            targets.append(target)
    return targets

def _submit_form_marker(session: ProbeSession, form: dict[str, object], marker: str) -> _FormMarkerResult:
    baseline = submit_form(session, form, form_defaults(form))
    for input_name in _form_input_names(form):
        fields = form_defaults(form, marker_name=input_name, marker=marker)
        response = submit_form(session, form, fields)
        delta = compare_responses(baseline, response, marker=marker)
        if delta.marker_reflected or delta.status_changed or abs(delta.length_delta) > 20 or delta.new_error_markers:
            return _FormMarkerResult(
                responses=[baseline, response],
                finding={
                    "type": "form_input_delta",
                    "form": _form_brief(form),
                    "input": input_name,
                    "delta": delta.to_json(),
                    "response": response.summary(body_chars=220),
                },
            )
    return _FormMarkerResult(responses=[baseline], finding=None)
