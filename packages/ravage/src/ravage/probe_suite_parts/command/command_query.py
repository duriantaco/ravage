from __future__ import annotations

from ravage.web_core.http_probe import ProbeResponse, ProbeSession, inject_query_param
from ravage.probe_suite_parts.command.command_payloads import (
    _COMMAND_TIMING_EXTRACTION_BUDGET,
    _command_file_drop_payloads,
    _command_proof_payloads,
    _command_timing_payload_pairs,
)
from ravage.probe_suite_parts.command.command_signals import _command_timing_signal, _has_command_proof
from ravage.probe_suite_parts.command.command_targets import _command_state_followup_urls
from ravage.probe_suite_parts.command.command_timing import _command_timing_extraction
from ravage.probe_suite_parts.general import safe_get
from ravage.web_core.proof_recognizer import recognize_proofs


def _probe_command_query_timing(
    session: ProbeSession,
    target: dict[str, object],
    marker: str,
    payloads: dict[str, str],
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for control_payload, timing_payload in _command_timing_payload_pairs(payloads, marker):
        control_url = inject_query_param(str(target["url"]), str(target["name"]), control_payload)
        timing_url = inject_query_param(str(target["url"]), str(target["name"]), timing_payload)
        control = safe_get(session, control_url)
        timed = safe_get(session, timing_url)
        requests.append(control.summary(body_chars=180) | {"probe_kind": "command_boundary_timing_control"})
        requests.append(timed.summary(body_chars=180) | {"probe_kind": "command_boundary_timing"})
        if not _command_timing_signal(control, timed):
            continue
        findings.append(
            {
                "type": "command_boundary_timing_signal",
                "input": target,
                "payload": timing_payload,
                "control_payload": control_payload,
                "elapsed_delta_ms": timed.elapsed_ms - control.elapsed_ms,
                "url": timing_url.replace(timing_payload, "PAYLOAD"),
                "control_response": control.summary(body_chars=220),
                "response": timed.summary(body_chars=220),
            }
        )
        if not _has_command_proof(findings) and budget > 0:
            proof_findings, proof_requests, budget = _probe_command_query_proofs(
                session,
                target,
                timing_payload,
                marker,
                budget,
            )
            findings.extend(proof_findings)
            requests.extend(proof_requests)
        if not _has_command_proof(findings):
            def send_query_payload(payload: str) -> ProbeResponse:
                probe_url = inject_query_param(str(target["url"]), str(target["name"]), payload)
                return safe_get(session, probe_url)

            extract_findings, extract_requests, _extract_budget = _command_timing_extraction(
                send_payload=send_query_payload,
                timing_payload=timing_payload,
                marker=marker,
                baseline_ms=control.elapsed_ms,
                target_brief=target,
                budget=max(budget, _COMMAND_TIMING_EXTRACTION_BUDGET),
            )
            findings.extend(extract_findings)
            requests.extend(extract_requests)
        break
    return findings, requests, budget

def _probe_command_query_proofs(
    session: ProbeSession,
    target: dict[str, object],
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
        probe_url = inject_query_param(str(target["url"]), str(target["name"]), payload)
        response = safe_get(session, probe_url)
        requests.append(response.summary(body_chars=260) | {"probe_kind": "command_boundary_proof"})
        proofs = recognize_proofs(response.body)
        followup_findings, followup_requests = _probe_command_query_followups(
            session,
            target,
            marker=marker,
            payload=payload,
            probe_url=probe_url,
            proof_mode=True,
        )
        requests.extend(followup_requests)
        if proofs:
            findings.append(
                {
                    "type": "command_boundary_proof",
                    "input": target,
                    "payload": payload,
                    "proofs": proofs[:5],
                    "replay": {
                        "method": "GET",
                        "url": probe_url.replace(payload, "PAYLOAD"),
                    },
                    "response": response.summary(body_chars=520),
                }
            )
            break
        if followup_findings:
            findings.extend(followup_findings)
            break
    if findings:
        return findings, requests, budget
    for payload, fetch_paths in _command_file_drop_payloads(signal_payload, marker):
        if budget <= 0:
            break
        budget -= 1
        probe_url = inject_query_param(str(target["url"]), str(target["name"]), payload)
        response = safe_get(session, probe_url)
        requests.append(response.summary(body_chars=220) | {"probe_kind": "command_boundary_file_drop_write"})
        followup_findings, followup_requests = _probe_command_query_followups(
            session,
            target,
            marker=marker,
            payload=payload,
            probe_url=probe_url,
            proof_mode=True,
        )
        requests.extend(followup_requests)
        if followup_findings:
            findings.extend(followup_findings)
            break
        for fetch_path in fetch_paths:
            fetched = safe_get(session, session.absolute(fetch_path))
            requests.append(fetched.summary(body_chars=260) | {"probe_kind": "command_boundary_file_drop_fetch"})
            proofs = recognize_proofs(fetched.body)
            if not proofs:
                continue
            findings.append(
                {
                    "type": "command_boundary_proof",
                    "input": target,
                    "payload": payload,
                    "proofs": proofs[:5],
                    "probe_kind": "file_drop",
                    "replay": {
                        "method": "GET",
                        "url": probe_url.replace(payload, "PAYLOAD"),
                        "fetch_url": session.absolute(fetch_path),
                    },
                    "response": fetched.summary(body_chars=520),
                }
            )
            break
        if findings:
            break
    return findings, requests, budget

def _probe_command_query_followups(
    session: ProbeSession,
    target: dict[str, object],
    *,
    marker: str,
    payload: str,
    probe_url: str,
    proof_mode: bool = False,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for url in _command_state_followup_urls(session, target):
        response = safe_get(session, url)
        requests.append(response.summary(body_chars=300) | {"probe_kind": "command_state_followup"})
        proofs = recognize_proofs(response.body)
        if proofs:
            findings.append(
                {
                    "type": "command_boundary_proof",
                    "input": target,
                    "payload": payload,
                    "probe_kind": "state_followup",
                    "proofs": proofs[:5],
                    "replay": {"method": "GET", "url": probe_url.replace(payload, "PAYLOAD"), "followup_url": url},
                    "response": response.summary(body_chars=700),
                }
            )
            break
        if not proof_mode and marker and marker in response.body:
            findings.append(
                {
                    "type": "command_boundary_signal",
                    "input": target,
                    "payload": payload,
                    "probe_kind": "state_followup",
                    "expected": marker,
                    "replay": {"method": "GET", "url": probe_url.replace(payload, "PAYLOAD"), "followup_url": url},
                    "response": response.summary(body_chars=420),
                }
            )
            break
    return findings, requests
