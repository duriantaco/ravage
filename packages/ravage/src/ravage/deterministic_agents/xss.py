from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Callable, cast
from urllib.parse import urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, form_defaults, inject_query_param
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import (
    _dedupe,
    _form_input_names,
    _form_targets,
    _int_value,
    _list_of_dicts,
    _parameter_targets,
    _string_items,
)
from ravage.web_core.proof_recognizer import recognize_proofs
from ravage.runtime.browser import BrowserObservation, BrowserStatus
from ravage.deterministic_agents.xss_payloads import (
    _XSS_PROOF_TOKENS,
    _dom_exec_payloads,
)


_DOM_EXEC_NAV_BUDGET = 16
_DOM_EXEC_PER_TARGET = 16
_DOM_EXEC_FOLLOWUP_BUDGET = 8

BrowserStatusFn = Callable[[], BrowserStatus]
RenderUrlFn = Callable[..., BrowserObservation]
RenderRequestFn = Callable[..., BrowserObservation]


@dataclass
class _DomExecutionRun:
    token: str
    budget: int = _DOM_EXEC_NAV_BUDGET
    initial_budget: int = _DOM_EXEC_NAV_BUDGET
    per_target: int = _DOM_EXEC_PER_TARGET
    findings: list[dict[str, object]] = field(default_factory=list)
    requests: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    best_execution: dict[str, object] | None = None
    best_telemetry: BrowserObservation | None = None


def probe_dom_execution(
    session: ProbeSession,
    state: AgentState,
    *,
    exec_binding: str,
    browser_backend_status_fn: BrowserStatusFn,
    render_url_fn: RenderUrlFn,
    render_request_fn: RenderRequestFn | None = None,
) -> ProbeRunResult:
    status = browser_backend_status_fn()
    if not status.available:
        return ProbeRunResult(
            ok=False,
            probe="dom_execution",
            summary=f"browser backend unavailable: {status.reason}",
            errors=[
                status.reason,
                "enable with: pip install playwright && playwright install chromium",
            ],
        )
    initial_budget = _dom_execution_budget_for_backend(status)
    run = _DomExecutionRun(
        token=_marker("XSSEXEC"),
        budget=initial_budget,
        initial_budget=initial_budget,
        per_target=min(_DOM_EXEC_PER_TARGET, initial_budget),
    )
    unavailable_result = _run_dom_execution_targets(
        session=session,
        state=state,
        exec_binding=exec_binding,
        render_url_fn=render_url_fn,
        render_request_fn=render_request_fn,
        run=run,
    )
    if unavailable_result is not None:
        return unavailable_result
    _append_best_dom_execution(run)
    return _dom_execution_result(run)


def _dom_execution_budget_for_backend(status: BrowserStatus) -> int:
    reason = status.reason.lower()
    if "chrome devtools fallback" in reason:
        return 1
    return _DOM_EXEC_NAV_BUDGET


def _run_dom_execution_targets(
    *,
    session: ProbeSession,
    state: AgentState,
    exec_binding: str,
    render_url_fn: RenderUrlFn,
    render_request_fn: RenderRequestFn | None,
    run: _DomExecutionRun,
) -> ProbeRunResult | None:
    for target in _dom_targets(state):
        if run.budget <= 0:
            break
        name = str(target.get("name") or "")
        base = str(target.get("url") or "")
        if not name or not base:
            continue
        unavailable_result = _run_dom_execution_target(
            session=session,
            state=state,
            target=target,
            name=name,
            base=base,
            exec_binding=exec_binding,
            render_url_fn=render_url_fn,
            render_request_fn=render_request_fn,
            run=run,
        )
        if unavailable_result is not None:
            return unavailable_result
        if run.findings:
            break
    return None


def _run_dom_execution_target(
    *,
    session: ProbeSession,
    state: AgentState,
    target: dict[str, object],
    name: str,
    base: str,
    exec_binding: str,
    render_url_fn: RenderUrlFn,
    render_request_fn: RenderRequestFn | None,
    run: _DomExecutionRun,
) -> ProbeRunResult | None:
    contexts = _dom_target_contexts(target, state)
    payloads = _dom_exec_payloads(run.token, exec_binding, contexts)
    for payload in payloads[: run.per_target]:
        if run.budget <= 0:
            break
        unavailable_result = _attempt_dom_execution_payload(
            session=session,
            target=target,
            name=name,
            base=base,
            contexts=contexts,
            payload=payload,
            render_url_fn=render_url_fn,
            render_request_fn=render_request_fn,
            run=run,
        )
        if unavailable_result is not None:
            return unavailable_result
        if run.findings:
            break
    return None


def _attempt_dom_execution_payload(
    *,
    session: ProbeSession,
    target: dict[str, object],
    name: str,
    base: str,
    contexts: list[dict[str, object]],
    payload: str,
    render_url_fn: RenderUrlFn,
    render_request_fn: RenderRequestFn | None,
    run: _DomExecutionRun,
) -> ProbeRunResult | None:
    probe_request = _dom_probe_request(target, name, payload)
    observation = _render_and_record_dom_probe(
        session=session,
        probe_request=probe_request,
        name=name,
        render_url_fn=render_url_fn,
        render_request_fn=render_request_fn,
        run=run,
    )
    if not observation.available:
        return _dom_execution_backend_unavailable_result(observation.reason, run.requests)

    proofs = _collect_dom_payload_proofs(
        session=session,
        target=target,
        name=name,
        payload=payload,
        probe_request=probe_request,
        observation=observation,
        run=run,
    )
    _record_dom_payload_outcome(
        target=target,
        name=name,
        base=base,
        contexts=contexts,
        payload=payload,
        probe_request=probe_request,
        observation=observation,
        proofs=proofs,
        run=run,
    )
    return None


def _render_and_record_dom_probe(
    *,
    session: ProbeSession,
    probe_request: dict[str, object],
    name: str,
    render_url_fn: RenderUrlFn,
    render_request_fn: RenderRequestFn | None,
    run: _DomExecutionRun,
) -> BrowserObservation:
    run.budget -= 1
    observation = _render_dom_probe_request(
        session=session,
        probe_request=probe_request,
        token=run.token,
        render_url_fn=render_url_fn,
        render_request_fn=render_request_fn,
    )
    run.requests.append(_dom_render_request_event(name, probe_request, observation))
    if observation.error:
        run.errors.append(observation.error)
    run.best_telemetry = _remember_fetch_telemetry(run.best_telemetry, observation)
    return observation


def _collect_dom_payload_proofs(
    *,
    session: ProbeSession,
    target: dict[str, object],
    name: str,
    payload: str,
    probe_request: dict[str, object],
    observation: BrowserObservation,
    run: _DomExecutionRun,
) -> list[str]:
    proofs = _proofs_from_dom_observation(session, observation, run)
    if proofs:
        return proofs
    if not _should_recheck_response_after_render(
        probe_request,
        observation,
        payload=payload,
    ):
        return []
    return _recheck_dom_response_proofs(
        session=session,
        target=target,
        name=name,
        payload=payload,
        current_proofs=proofs,
        run=run,
    )


def _record_dom_payload_outcome(
    *,
    target: dict[str, object],
    name: str,
    base: str,
    contexts: list[dict[str, object]],
    payload: str,
    probe_request: dict[str, object],
    observation: BrowserObservation,
    proofs: list[str],
    run: _DomExecutionRun,
) -> None:
    if proofs:
        _append_dom_proof_finding(
            target=target,
            name=name,
            base=base,
            contexts=contexts,
            payload=payload,
            probe_request=probe_request,
            observation=observation,
            proofs=proofs,
            run=run,
        )
        return
    _remember_best_dom_execution(
        target=target,
        name=name,
        base=base,
        contexts=contexts,
        payload=payload,
        probe_request=probe_request,
        observation=observation,
        run=run,
    )


def _render_dom_probe_request(
    *,
    session: ProbeSession,
    probe_request: dict[str, object],
    token: str,
    render_url_fn: RenderUrlFn,
    render_request_fn: RenderRequestFn | None,
) -> BrowserObservation:
    method = str(probe_request.get("method") or "GET").upper()
    url = str(probe_request.get("url") or "")
    if method == "POST" and render_request_fn is not None:
        return render_request_fn(
            url,
            method=method,
            fields=probe_request.get("fields"),
            token=token,
            origin=session.target_url,
            page_url=str(probe_request.get("page_url") or ""),
            timeout_seconds=session.timeout_seconds,
            settle_ms=500,
            allow_remote_target=session.allow_remote_target,
            in_scope=session.scope_in_scope,
            out_of_scope=session.scope_out_of_scope,
        )
    return render_url_fn(
        url,
        token=token,
        origin=session.target_url,
        timeout_seconds=session.timeout_seconds,
        settle_ms=500,
        allow_remote_target=session.allow_remote_target,
        in_scope=session.scope_in_scope,
        out_of_scope=session.scope_out_of_scope,
    )


def _dom_render_request_event(
    name: str,
    probe_request: dict[str, object],
    observation: BrowserObservation,
) -> dict[str, object]:
    return {
        "input": name,
        "method": str(probe_request.get("method") or "GET"),
        "request_template": probe_request,
        "rendered": observation.to_json(),
    }


def _proofs_from_dom_observation(
    session: ProbeSession,
    observation: BrowserObservation,
    run: _DomExecutionRun,
) -> list[str]:
    observation_payload = observation.to_json()
    followup_proofs, followup_requests = _browser_followup_proofs(
        session,
        observation_payload,
    )
    run.requests.extend(followup_requests)
    return _dedupe(_browser_observation_proofs(observation_payload) + followup_proofs)


def _recheck_dom_response_proofs(
    *,
    session: ProbeSession,
    target: dict[str, object],
    name: str,
    payload: str,
    current_proofs: list[str],
    run: _DomExecutionRun,
) -> list[str]:
    response = _http_replay_target(session, target, name, payload)
    run.requests.append(
        response.summary(body_chars=700)
        | {
            "probe_kind": "dom_execution_response_recheck",
            "input": name,
            "payload": payload,
        }
    )
    return _dedupe(current_proofs + recognize_proofs(response.body))


def _append_dom_proof_finding(
    *,
    target: dict[str, object],
    name: str,
    base: str,
    contexts: list[dict[str, object]],
    payload: str,
    probe_request: dict[str, object],
    observation: BrowserObservation,
    proofs: list[str],
    run: _DomExecutionRun,
) -> None:
    run.findings.append(
        _dom_execution_finding(
            target=target,
            name=name,
            base=base,
            contexts=contexts,
            payload=payload,
            probe_url=str(probe_request.get("url") or ""),
            request_template=probe_request,
            observation=observation,
            telemetry_observation=run.best_telemetry,
            proofs=proofs,
            finding_type="client_side_proof_extraction",
        )
    )


def _remember_best_dom_execution(
    *,
    target: dict[str, object],
    name: str,
    base: str,
    contexts: list[dict[str, object]],
    payload: str,
    probe_request: dict[str, object],
    observation: BrowserObservation,
    run: _DomExecutionRun,
) -> None:
    if run.best_execution is not None:
        return
    if not _dom_execution_observed(observation):
        return
    run.best_execution = _dom_execution_finding(
        target=target,
        name=name,
        base=base,
        contexts=contexts,
        payload=payload,
        probe_url=str(probe_request.get("url") or ""),
        request_template=probe_request,
        observation=observation,
        telemetry_observation=run.best_telemetry,
        proofs=[],
        finding_type="client_side_execution",
    )


def _dom_execution_observed(observation: BrowserObservation) -> bool:
    if observation.token_executed:
        return True
    return _deliberate_dialog_observed(observation)


def _append_best_dom_execution(run: _DomExecutionRun) -> None:
    if run.findings:
        return
    if run.best_execution is None:
        return
    if run.best_telemetry is not None:
        _attach_fetch_scan(run.best_execution, run.best_telemetry)
    run.findings.append(run.best_execution)


def _dom_execution_backend_unavailable_result(
    reason: str,
    requests: list[dict[str, object]],
) -> ProbeRunResult:
    return ProbeRunResult(
        ok=False,
        probe="dom_execution",
        summary=f"browser backend unavailable: {reason}",
        errors=[reason],
        requests=requests,
    )


def _dom_execution_result(run: _DomExecutionRun) -> ProbeRunResult:
    return ProbeRunResult(
        ok=bool(run.findings),
        probe="dom_execution",
        summary=(
            f"rendered {run.initial_budget - run.budget} navigation(s) in a real browser; "
            f"confirmed executions={len(run.findings)}"
        ),
        findings=run.findings[:20],
        requests=run.requests[:40],
        errors=run.errors[:12],
    )


def _dom_execution_finding(
    *,
    target: dict[str, object],
    name: str,
    base: str,
    contexts: list[dict[str, object]],
    payload: str,
    probe_url: str,
    request_template: dict[str, object],
    observation: BrowserObservation,
    telemetry_observation: BrowserObservation | None,
    proofs: list[str],
    finding_type: str,
) -> dict[str, object]:
    return {
        "type": finding_type,
        "input": {
            "name": name,
            "url": base,
            "hints": _string_items(target.get("hints")),
            "contexts": contexts,
        },
        "method": str(target.get("method") or "GET"),
        "payload": payload,
        "probe_url": probe_url,
        "request_template": request_template,
        "verification": _dom_verification_message(finding_type),
        "proofs": proofs,
        "evidence": _browser_evidence(observation, telemetry_observation=telemetry_observation),
        "next": (
            "If proofs is non-empty, capture that exact proof string. "
            "RAVAGE_XSSEXEC values and fetch-scan labels are verifier evidence, not target proofs. "
            "If proofs is empty, keep this request template and use the fetch_scan console telemetry "
            "to choose the next same-origin endpoint or state-changing workflow."
        ),
    }


def _browser_evidence(
    observation: BrowserObservation,
    *,
    telemetry_observation: BrowserObservation | None,
) -> dict[str, object]:
    evidence: dict[str, object] = {
        "token_executed": observation.token_executed,
        "executed_values": observation.executed_values,
        "dialogs": observation.dialogs,
        "console": observation.console,
        "final_url": observation.final_url,
        "body_snippet": observation.body_snippet,
    }
    telemetry = telemetry_observation or observation
    fetch_scan = _fetch_scan_console(telemetry)
    if fetch_scan:
        evidence["fetch_scan_console"] = fetch_scan
    return evidence


def _remember_fetch_telemetry(
    current: BrowserObservation | None,
    observation: BrowserObservation,
) -> BrowserObservation | None:
    if _fetch_scan_console(observation):
        return observation
    return current


def _attach_fetch_scan(
    finding: dict[str, object],
    telemetry_observation: BrowserObservation,
) -> None:
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        return
    fetch_scan = _fetch_scan_console(telemetry_observation)
    if fetch_scan:
        evidence["fetch_scan_console"] = fetch_scan


def _fetch_scan_console(observation: BrowserObservation) -> list[str]:
    messages: list[str] = []
    for message in observation.console:
        if "RAVAGE_FETCH_SCAN" in message or "RAVAGE_BROWSER_SCAN" in message:
            messages.append(message)
    return messages[:4]


def _dom_verification_message(finding_type: str) -> str:
    if finding_type == "client_side_proof_extraction":
        return "headless chromium observed a recognizer-matched proof in browser telemetry"
    return "headless chromium confirmed the unique token executed in the DOM"



def _dom_target_contexts(target: dict[str, object], state: AgentState) -> list[dict[str, object]]:
    name = str(target.get("name") or "")
    url = str(target.get("url") or "")
    contexts: list[dict[str, object]] = []
    for value in state.signals.get("xss_contexts", []):
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        context = cast(dict[str, object], payload)
        if str(context.get("input") or "") != name:
            continue
        context_url = str(context.get("url") or "")
        if context_url and url and _same_path_url(context_url, url):
            contexts.append(context)
    if contexts:
        return contexts[:6]
    text = _recent_state_text(state)
    if name and name.lower() in text:
        if "iframe" in text and "src" in text:
            return [{"context": "iframe_src", "tag_name": "iframe", "attribute_name": "src"}]
        if "javascript:" in text or "url_context" in text or "url sink" in text:
            return [{"context": "url_context", "attribute_name": "src"}]
        if "double-quoted string" in text or "js_string_double" in text or "javascript double" in text:
            return [{"context": "js_string_double", "quote_char": '"'}]
        if "single-quoted string" in text or "js_string_single" in text:
            return [{"context": "js_string_single", "quote_char": "'"}]
        if "script" in text and "string" in text:
            return [
                {"context": "js_string_double", "quote_char": '"'},
                {"context": "js_string_single", "quote_char": "'"},
            ]
    return []


def _same_path_url(first: str, second: str) -> bool:
    try:
        a = urlsplit(first)
        b = urlsplit(second)
    except ValueError:
        return first == second
    return (a.scheme, a.netloc, a.path) == (b.scheme, b.netloc, b.path)


def _browser_observation_proofs(payload: dict[str, object]) -> list[str]:
    text = json.dumps(payload, sort_keys=True)
    return recognize_proofs(text)[:8]


def _deliberate_dialog_observed(observation: BrowserObservation) -> bool:
    for value in observation.dialogs:
        if str(value) in _XSS_PROOF_TOKENS:
            return True
    return False


def _should_recheck_response_after_render(
    request: dict[str, object],
    observation: BrowserObservation,
    *,
    payload: str = "",
) -> bool:
    method = str(request.get("method") or "").upper()
    if method not in {"GET", "POST"}:
        return False
    if _deliberate_dialog_observed(observation) or observation.token_executed:
        return True
    if _payload_has_computed_dialog_signal(payload):
        return True
    if observation.error:
        return True
    if method == "GET" and _payload_contains_proof_token(payload):
        return True
    if _post_render_lacked_browser_evidence(method, observation):
        return True
    return False


def _post_render_lacked_browser_evidence(
    method: str,
    observation: BrowserObservation,
) -> bool:
    if method != "POST":
        return False
    if observation.body_snippet:
        return False
    if observation.dialogs:
        return False
    return not observation.executed_values


def _payload_has_computed_dialog_signal(payload: str) -> bool:
    for marker in _COMPUTED_DIALOG_MARKERS:
        if marker in payload:
            return True
    return False


def _payload_contains_proof_token(payload: str) -> bool:
    for token in _XSS_PROOF_TOKENS:
        if token in payload:
            return True
    return False


_COMPUTED_DIALOG_MARKERS = (
    "String.fromCharCode(88,83,83)",
    "String.fromCharCode(83,85,67,67,69,83,83)",
    "String.fromCharCode(97,108,101,114,116)",
    "\\x58\\x53\\x53",
    "\\u0058\\u0053\\u0053",
)


def _browser_followup_proofs(
    session: ProbeSession,
    observation_payload: dict[str, object],
) -> tuple[list[str], list[dict[str, object]]]:
    proofs: list[str] = []
    requests: list[dict[str, object]] = []
    for path in _same_origin_paths_from_browser_payload(observation_payload):
        if len(requests) >= _DOM_EXEC_FOLLOWUP_BUDGET:
            break
        url = session.absolute(path)
        if not session.in_scope(url):
            continue
        response = session.get(url)
        requests.append(
            response.summary(body_chars=520)
            | {
                "probe_kind": "dom_execution_followup",
                "path": path,
            }
        )
        proofs.extend(recognize_proofs(response.body))
        if proofs:
            break
    return _dedupe(proofs)[:8], requests


def _same_origin_paths_from_browser_payload(payload: dict[str, object]) -> list[str]:
    text = json.dumps(payload, sort_keys=True)
    paths: list[str] = []
    for match in re.finditer(r"(?<![A-Za-z0-9])(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{2,220})", text):
        path = match.group(1).replace("\\/", "/")
        cleaned = _clean_followup_path(path)
        if _looks_like_followup_path(cleaned):
            paths.append(cleaned)
    return _dedupe(paths)[:_DOM_EXEC_FOLLOWUP_BUDGET]


def _clean_followup_path(path: str) -> str:
    cleaned = path.strip()
    cleaned = cleaned.rstrip(".,;:)'\"<>]}\\")
    if "#" in cleaned:
        cleaned = cleaned.split("#", 1)[0]
    return cleaned


def _looks_like_followup_path(path: str) -> bool:
    lowered = path.lower()
    if not path.startswith("/") or len(path) < 3:
        return False
    if _followup_path_has_sensitive_marker(lowered):
        return True
    if lowered.endswith((".html", ".txt", ".json", ".php", ".bak", ".old")):
        return True
    return bool(re.search(r"/[a-f0-9]{16,}\.(?:html|txt|json|php)$", lowered))


def _followup_path_has_sensitive_marker(path: str) -> bool:
    for marker in ("flag", "proof", "secret", "admin", "debug"):
        if marker in path:
            return True
    return False


def _dom_targets(state: AgentState) -> list[dict[str, object]]:
    reflected = _reflected_names(state)
    targets = _parameter_targets(state, limit=16)
    client_xss_objective = _state_has_client_xss_objective(state)
    for form in _form_targets(state, limit=8):
        method = str(form.get("method") or "GET").upper()
        action = str(form.get("action") or state.surface.get("target_url") or "")
        for input_name in _form_input_names(form):
            hints = ["form_input"]
            if client_xss_objective and method == "POST":
                hints.append("xss_objective_form")
            targets.append(
                {
                    "name": input_name,
                    "url": action,
                    "page_url": str(form.get("page") or ""),
                    "hints": hints,
                    "method": method,
                    "form": form,
                    "priority": _dom_form_target_priority(method),
                }
            )
    targets = _sort_dom_targets(targets, reflected)
    return targets


def _dom_form_target_priority(method: str) -> int:
    if method == "POST":
        return 48
    return 40


def _dom_probe_request(target: dict[str, object], name: str, payload: str) -> dict[str, object]:
    method = str(target.get("method") or "GET").upper()
    url = str(target.get("url") or "")
    if method == "POST" and isinstance(target.get("form"), dict):
        form = cast(dict[str, object], target.get("form"))
        fields = form_defaults(form, marker_name=name, marker=payload)
        return {
            "method": "POST",
            "url": url,
            "page_url": str(target.get("page_url") or form.get("page") or ""),
            "payload_field": name,
            "fields": fields,
            "encoding": "application/x-www-form-urlencoded",
        }
    return {
        "method": "GET",
        "url": inject_query_param(url, name, payload),
        "payload_field": name,
        "fields": {},
        "encoding": "query",
    }


def _http_replay_target(session: ProbeSession, target: dict[str, object], name: str, payload: str) -> ProbeResponse:
    request = _dom_probe_request(target, name, payload)
    if request["method"] == "POST":
        return session.post_form(str(request["url"]), cast(dict[str, str], request["fields"]))
    return session.get(str(request["url"]))


def _recent_state_text(state: AgentState) -> str:
    values: list[str] = []
    values.extend(state.facts[-12:])
    values.extend(state.hypotheses[-12:])
    return " ".join(values).lower()


def _dom_target_sort_key(
    target: dict[str, object],
    reflected: set[str],
) -> tuple[int, int, str]:
    reflected_rank = 1
    if "xss_objective_form" in _string_items(target.get("hints")):
        reflected_rank = -1
    if reflected_rank > 0 and str(target.get("name")) in reflected:
        reflected_rank = 0
    priority = -_int_value(target.get("priority"))
    name = str(target.get("name"))
    return reflected_rank, priority, name


def _sort_dom_targets(
    targets: list[dict[str, object]],
    reflected: set[str],
) -> list[dict[str, object]]:
    keyed: list[tuple[tuple[int, int, str], dict[str, object]]] = []
    for target in targets:
        keyed.append((_dom_target_sort_key(target, reflected), target))
    keyed.sort(key=_keyed_dom_target_sort_key)
    sorted_targets: list[dict[str, object]] = []
    for _sort_key, target in keyed:
        sorted_targets.append(target)
    return sorted_targets


def _keyed_dom_target_sort_key(
    item: tuple[tuple[int, int, str], dict[str, object]],
) -> tuple[int, int, str]:
    return item[0]


def _state_has_client_xss_objective(state: AgentState) -> bool:
    description = str(state.surface.get("visible_description") or "").lower()
    return any(
        marker in description
        for marker in (
            "xss",
            "cross-site scripting",
            "client-side script",
            "script execution",
            "alert(",
        )
    )


def _reflected_names(state: AgentState) -> set[str]:
    names: set[str] = set()
    for reflection in _list_of_dicts(state.surface.get("reflections")):
        for key in ("name", "parameter", "input"):
            value = str(reflection.get(key) or "").strip()
            if value:
                names.add(value)
    return names


def _marker(prefix: str) -> str:
    import secrets

    return f"RAVAGE_{prefix}_{secrets.token_hex(5)}"
