# Compatibility re-exports in this module are consumed by the probe registry.
# ruff: noqa: F401
from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    compare_responses,
    inject_query_param,
    response_secrets,
)
from ravage.deterministic_agents.auth_session import probe_auth_session, probe_default_credentials
from ravage.deterministic_agents.idor import probe_idor_boundary
from ravage.deterministic_agents.ssti import probe_ssti_fingerprint
from ravage.probes.file_read import (
    probe_file_fetch_parser as probe_file_fetch_parser_specialist,
    probe_file_read_extract,
)
from ravage.probes.specialists.xss import (
    probe_xss_context as run_xss_context_specialist,
)
from ravage.probe_suite_parts.general.general_api import (
    _api_candidate_endpoints,
    probe_api_behavior,
)
from ravage.probe_suite_parts.general.general_exposure import probe_direct_exposure
from ravage.probe_suite_parts.general.general_http import (
    _filtered_parameter_targets,
    _submit_form_marker,
    input_payload_probe,
    payload_signal,
    safe_get,
    submit_form,
)
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import (
    _canonical_host_headers,
    _canonical_host_signal_findings,
    _common_paths,
    _common_secret_paths,
    _contains_word,
    _dedupe,
    _extend_response_summaries,
    _form_targets,
    _form_text,
    _get_many,
    _get_many_with_headers,
    _has_ok_response,
    _marker,
    _notable_response,
    _parameter_targets,
    _response_summaries,
    _script_urls,
    _string_items,
    _surface_endpoints,
)


def probe_surface_map(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    urls = _surface_map_urls(session, state)
    responses = _get_many(session, urls, limit=30)
    host_findings = _canonical_host_signal_findings(session, responses)
    for headers in _canonical_host_headers(session, state, responses):
        responses.extend(_get_many_with_headers(session, urls, headers=headers, limit=18))
    notable = [*host_findings, *_notable_responses(responses)]
    response_count = sum(response.status is not None for response in responses)
    request_count = len(responses)
    return ProbeRunResult(
        ok=response_count > 0,
        probe="surface_map",
        summary=_surface_map_summary(
            request_count=request_count,
            response_count=response_count,
            notable_count=len(notable),
        ),
        findings=notable[:40],
        requests=_response_summaries(responses, body_chars=220),
        errors=_surface_map_transport_errors(responses) if response_count == 0 else [],
    )


def probe_secret_sweep(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    urls = _secret_sweep_urls(session, state)
    responses = _get_many(session, urls, limit=40)
    findings: list[dict[str, object]] = []
    for response in responses:
        secrets_found = response_secrets(response)
        if secrets_found:
            findings.append(
                {
                    "type": "secret_or_path",
                    "url": response.url,
                    "status": response.status,
                    "matches": secrets_found[:12],
                }
            )
    return ProbeRunResult(
        ok=bool(findings) or _has_ok_response(responses),
        probe="secret_sweep",
        summary=f"checked {len(responses)} URL(s), findings={len(findings)}",
        findings=findings[:40],
        requests=_response_summaries(responses, body_chars=180),
    )


def probe_input_reflection(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    marker = _marker("REFLECT")
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for target in _parameter_targets(state, limit=12):
        baseline = safe_get(session, str(target["url"]))
        probe_url = inject_query_param(str(target["url"]), str(target["name"]), marker)
        probed = safe_get(session, probe_url)
        delta = compare_responses(baseline, probed, marker=marker)
        requests.extend([baseline.summary(body_chars=120), probed.summary(body_chars=160)])
        if (
            delta.marker_reflected
            or delta.status_changed
            or abs(delta.length_delta) > 20
            or delta.new_error_markers
        ):
            findings.append(
                {
                    "type": "input_delta",
                    "input": target,
                    "probe_url": probe_url.replace(marker, "MARKER"),
                    "delta": delta.to_json(),
                }
            )
    for form in _form_targets(state, limit=8):
        result = _submit_form_marker(session, form, marker)
        _extend_response_summaries(requests, result.responses, body_chars=140)
        if result.finding is not None:
            findings.append(result.finding)
    return ProbeRunResult(
        ok=bool(findings),
        probe="input_reflection",
        summary=f"tested marker on parameters/forms; findings={len(findings)}",
        findings=findings[:40],
        requests=requests[:40],
    )


def probe_xss_context(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    return run_xss_context_specialist(session, state, ProbeRunResult)


def probe_stateful_session(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    return probe_auth_session(session, state)


def probe_default_credentials_runner(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    return probe_default_credentials(session, state)


def probe_server_rendering(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    return probe_ssti_fingerprint(session, state, ProbeRunResult, probe_name="server_rendering")


def probe_ssti_fingerprint_runner(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    return probe_ssti_fingerprint(session, state, ProbeRunResult, probe_name="ssti_fingerprint")


def probe_file_fetch_parser(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    return probe_file_fetch_parser_specialist(session, state, ProbeRunResult)


def probe_file_read_extract_runner(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    return probe_file_read_extract(session, state, ProbeRunResult)


def probe_idor_boundary_runner(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    return probe_idor_boundary(session, state, ProbeRunResult)


def _surface_map_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls: list[str] = [session.target_url]
    urls.extend(_common_paths(session))
    urls.extend(_surface_endpoints(state))
    return _dedupe(urls)


def _surface_map_summary(
    *,
    request_count: int,
    response_count: int,
    notable_count: int,
) -> str:
    if response_count == request_count:
        return f"fetched {request_count} URL(s), notable={notable_count}"
    return f"received {response_count}/{request_count} HTTP response(s), notable={notable_count}"


def _surface_map_transport_errors(responses: list[ProbeResponse]) -> list[str]:
    counts: dict[str, int] = {}
    for response in responses:
        if response.status is not None:
            continue
        detail = " ".join(response.error.split())[:240].strip()
        if not detail:
            detail = "request returned no HTTP status"
        counts[detail] = counts.get(detail, 0) + 1

    errors: list[str] = []
    for detail, count in list(counts.items())[:3]:
        request_label = "request" if count == 1 else "requests"
        errors.append(f"transport error ({count} {request_label}): {detail}")
    omitted = len(counts) - len(errors)
    if omitted > 0:
        errors.append(f"{omitted} additional transport error type(s) omitted")
    return errors


def _secret_sweep_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls: list[str] = []
    urls.extend(_common_secret_paths(session))
    urls.extend(_script_urls(state))
    urls.extend(_surface_endpoints(state))
    return _dedupe(urls)


def _notable_responses(responses: list[ProbeResponse]) -> list[dict[str, object]]:
    notable: list[dict[str, object]] = []
    for response in responses:
        if response.status in {200, 204, 301, 302, 307, 308, 401, 403, 500}:
            notable.append(_notable_response(response))
    return notable


def _auth_forms(state: AgentState) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for form in _form_targets(state, limit=12):
        if _form_looks_auth_related(form):
            forms.append(form)
    return forms


def _form_looks_auth_related(form: dict[str, object]) -> bool:
    categories = _string_items(form.get("categories"))
    if "auth" in categories:
        return True
    text = _form_text(form)
    if "login" in text:
        return True
    return "register" in text


def _auth_field_value(name: str, username: str) -> str:
    lowered = name.lower()
    if _contains_word(lowered, ("user", "login")):
        return username
    if "email" in lowered:
        return f"{username}@example.test"
    if "pass" in lowered:
        return "RavagePass123!"
    return ""


def _auth_submission_succeeded(response: ProbeResponse) -> bool:
    if response.status in {200, 201, 302, 303}:
        return True
    text = response.body.lower()
    return _contains_word(text, ("logout", "profile", "account", "welcome", "dashboard"))
