from __future__ import annotations

import html

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeSession, inject_query_param
from ravage.probe_suite_parts.command.command_payloads import (
    _chained_json_eval_proof_commands,
    _python_eval_json_command_payload,
)
from ravage.probe_suite_parts.command.command_sessions import _short_command_session
from ravage.probe_suite_parts.command.command_signals import _command_body_is_stored_eval_payload
from ravage.probe_suite_parts.command.command_targets import (
    _command_consumer_urls,
    _command_reachable_getter_urls,
    _command_target_is_text_setter,
    _command_target_is_url_setter,
    _command_text_getter_urls,
)
from ravage.probe_suite_parts.general import safe_get
from ravage.probe_suite_parts.support import _dedupe
from ravage.web_core.proof_recognizer import recognize_proofs


def _command_url_setters(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    url_setters: list[dict[str, object]] = []
    for target in targets:
        if _command_target_is_url_setter(target):
            url_setters.append(target)
    return url_setters

def _command_text_setters(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    text_setters: list[dict[str, object]] = []
    for target in targets:
        if _command_target_is_text_setter(target):
            text_setters.append(target)
    return text_setters

def _probe_command_chained_json_eval(
    session: ProbeSession,
    state: AgentState,
    targets: list[dict[str, object]],
    marker: str,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    """Close stored fetch/eval command chains assembled from discovered setters.

    This handles the common dashboard pattern where one endpoint stores an
    arbitrary URL, another endpoint stores text, and a consumer later fetches
    the URL and evaluates a JSON field from the controlled text endpoint.
    """
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    url_setters = _command_url_setters(targets)
    value_setters = _command_text_setters(targets)
    if not url_setters or not value_setters:
        return findings, requests, budget

    active_session = _short_command_session(session)
    signal_payload = _python_eval_json_command_payload(f"echo {marker}")
    for value_setter in value_setters[:4]:
        getter_urls, getter_requests = _command_controlled_getters(
            active_session,
            value_setter,
            signal_payload,
            marker=marker,
        )
        requests.extend(getter_requests)
        if not getter_urls:
            continue
        for url_setter in url_setters[:4]:
            for getter_url in getter_urls[:4]:
                for fetch_url in _command_reachable_getter_urls(session, state, url_setter, getter_url)[:10]:
                    signal_set = safe_get(
                        active_session,
                        inject_query_param(str(url_setter["url"]), str(url_setter["name"]), fetch_url),
                    )
                    requests.append(signal_set.summary(body_chars=240) | {"probe_kind": "command_chain_url_set"})
                    signal_findings, signal_requests = _command_fetch_consumers_for_marker(
                        active_session,
                        state,
                        url_setter,
                        value_setter,
                        signal_payload,
                        fetch_url,
                        marker,
                    )
                    requests.extend(signal_requests)
                    if not signal_findings:
                        continue
                    findings.extend(signal_findings)
                    proof_findings, proof_requests, budget = _probe_command_chained_json_eval_proofs(
                        active_session,
                        state,
                        url_setter,
                        value_setter,
                        fetch_url,
                        marker,
                        budget,
                    )
                    findings.extend(proof_findings)
                    requests.extend(proof_requests)
                    return findings, requests, budget
    return findings, requests, budget

def _probe_command_chained_json_eval_proofs(
    session: ProbeSession,
    state: AgentState,
    url_setter: dict[str, object],
    value_setter: dict[str, object],
    fetch_url: str,
    marker: str,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for command in _chained_json_eval_proof_commands():
        if budget <= 0:
            break
        budget -= 1
        payload = _python_eval_json_command_payload(command)
        value_url = inject_query_param(str(value_setter["url"]), str(value_setter["name"]), payload)
        value_response = safe_get(session, value_url)
        requests.append(value_response.summary(body_chars=240) | {"probe_kind": "command_chain_value_set"})
        url_response = safe_get(session, inject_query_param(str(url_setter["url"]), str(url_setter["name"]), fetch_url))
        requests.append(url_response.summary(body_chars=240) | {"probe_kind": "command_chain_url_set"})
        for consumer_url in _command_consumer_urls(session, state, url_setter):
            response = safe_get(session, consumer_url)
            requests.append(response.summary(body_chars=500) | {"probe_kind": "command_chain_consumer"})
            proofs = recognize_proofs(response.body)
            if not proofs:
                continue
            findings.append(
                {
                    "type": "command_boundary_proof",
                    "input": {"url_setter": url_setter, "value_setter": value_setter},
                    "payload": "JSON_SCRIPT_COMMAND_PAYLOAD",
                    "probe_kind": "chained_json_eval",
                    "proofs": proofs[:5],
                    "replay": {
                        "set_value_url": value_url.replace(payload, "PAYLOAD"),
                        "set_fetch_url": str(url_setter["url"]).replace(fetch_url, "FETCH_URL"),
                        "fetch_url_value": fetch_url,
                        "consumer_url": consumer_url,
                    },
                    "response": response.summary(body_chars=900),
                }
            )
            return findings, requests, budget
    return findings, requests, budget

def _command_fetch_consumers_for_marker(
    session: ProbeSession,
    state: AgentState,
    url_setter: dict[str, object],
    value_setter: dict[str, object],
    payload: str,
    fetch_url: str,
    marker: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for consumer_url in _command_consumer_urls(session, state, url_setter):
        response = safe_get(session, consumer_url)
        requests.append(response.summary(body_chars=420) | {"probe_kind": "command_chain_consumer"})
        if marker not in response.body and marker not in html.unescape(response.body):
            continue
        if _command_body_is_stored_eval_payload(response.body, marker):
            continue
        findings.append(
            {
                "type": "command_boundary_signal",
                "input": {"url_setter": url_setter, "value_setter": value_setter},
                "payload": "JSON_SCRIPT_COMMAND_PAYLOAD",
                "expected": marker,
                "probe_kind": "chained_json_eval",
                "replay": {
                    "value_payload": payload,
                    "fetch_url_value": fetch_url,
                    "consumer_url": consumer_url,
                },
                "response": response.summary(body_chars=700),
            }
        )
        break
    return findings, requests

def _command_controlled_getters(
    session: ProbeSession,
    setter: dict[str, object],
    payload: str,
    *,
    marker: str,
) -> tuple[list[str], list[dict[str, object]]]:
    requests: list[dict[str, object]] = []
    setter_url = inject_query_param(str(setter["url"]), str(setter["name"]), payload)
    response = safe_get(session, setter_url)
    requests.append(response.summary(body_chars=240) | {"probe_kind": "command_chain_value_set"})
    getters: list[str] = []
    for url in _command_text_getter_urls(session, setter):
        getter_response = safe_get(session, url)
        requests.append(getter_response.summary(body_chars=360) | {"probe_kind": "command_chain_value_get"})
        body = getter_response.body
        if marker in body or '"script"' in body or "'script'" in body:
            getters.append(url)
    return _dedupe(getters), requests
