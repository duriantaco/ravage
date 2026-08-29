from __future__ import annotations

# ruff: noqa: E501,I001,PERF401,PLR2004,S324,SIM103,SIM110,TC001

import base64
import hashlib
import html
import json
import re
import secrets
import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.auth_forms import _auth_form_brief, _forms_from_html, _submit_form
from ravage.traffic.policy import TrafficOutcome, TrafficPolicyBlocked
from ravage.web_core.http_probe import (
    ControlledTransportRequest,
    ControlledTransportResult,
    ProbeResponse,
    ProbeSession,
    _connect_pinned_socket,
    form_defaults,
    response_secrets,
)
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import (
    _dedupe,
    _form_targets,
    _list_of_dicts,
    _script_urls,
    _surface_endpoints,
)
from ravage.web_core.proof_recognizer import recognize_proofs

_CSRF_REQUEST_BUDGET = 48
_BROWSER_BOUNDARY_REQUEST_BUDGET = 54
_MAX_WEBSOCKET_HANDSHAKE_BYTES = 16_384
_EVIL_ORIGIN = "https://evil.example"
_CSRF_FIELD_MARKERS = ("csrf", "xsrf", "_token", "authenticity_token", "nonce")
_STATE_CHANGE_MARKERS = (
    "admin",
    "change",
    "create",
    "delete",
    "edit",
    "email",
    "invite",
    "password",
    "profile",
    "reset",
    "save",
    "settings",
    "submit",
    "transfer",
    "update",
)
_REJECTION_MARKERS = (
    "bad csrf",
    "csrf failed",
    "csrf token missing",
    "csrf token invalid",
    "denied",
    "expired csrf",
    "forbidden",
    "invalid csrf",
    "invalid token",
    "missing csrf",
    "missing token",
    "unauthorized",
)
_ACCEPTANCE_MARKERS = (
    "accepted",
    "changed",
    "created",
    "dashboard",
    "done",
    "flag{",
    "logout",
    "ok",
    "saved",
    "success",
    "updated",
    "welcome",
)
_SESSION_COOKIE_NAME_MARKERS = ("session", "sess", "sid", "auth", "token", "jwt")
_SENSITIVE_PAGE_MARKERS = (
    "admin",
    "account",
    "api",
    "console",
    "dashboard",
    "flag",
    "login",
    "me",
    "profile",
    "settings",
    "user",
)
_COMMON_BOUNDARY_PATHS = (
    "/",
    "/admin",
    "/account",
    "/api",
    "/api/admin",
    "/api/me",
    "/api/profile",
    "/api/session",
    "/api/user",
    "/console",
    "/dashboard",
    "/me",
    "/profile",
    "/settings",
    "/storage",
    "/transfer",
    "/update",
    "/change",
    "/profile/edit",
    "/ws",
    "/socket",
    "/socket.io/?EIO=4&transport=websocket",
)


@dataclass
class _ProbeOutcome:
    findings: list[dict[str, object]]
    requests: list[dict[str, object]]
    stop: bool = False

    @classmethod
    def empty(cls) -> _ProbeOutcome:
        return cls(findings=[], requests=[])

    def absorb(self, other: _ProbeOutcome) -> None:
        self.findings.extend(other.findings)
        self.requests.extend(other.requests)
        if other.stop:
            self.stop = True


@dataclass(frozen=True)
class _CsrfBaselineProbe:
    response: ProbeResponse
    outcome: _ProbeOutcome


@dataclass(frozen=True)
class _CsrfReuseProbe:
    session: ProbeSession
    first: ProbeResponse
    second: ProbeResponse
    outcome: _ProbeOutcome


@dataclass(frozen=True)
class _CsrfOmissionEvidence:
    form: dict[str, object]
    csrf_names: list[str]
    omit_fields: dict[str, str]
    baseline: ProbeResponse
    omitted: ProbeResponse
    proofs: list[str]


@dataclass(frozen=True)
class _StorageEvidence:
    response: ProbeResponse
    storage: str
    key: str
    value: str
    proofs: list[str]
    secret_like: bool


@dataclass(frozen=True)
class _FormMatchProfile:
    method: str
    action: str
    names: set[str]


def probe_csrf_session(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    pages = _seed_pages(session, state, limit=24)
    seed_outcome = _csrf_seed_observations(pages, request_budget=_CSRF_REQUEST_BUDGET)
    forms = _csrf_candidate_forms(session, state, pages)
    form_outcome = _probe_csrf_forms(
        session,
        state,
        forms,
        existing_request_count=len(seed_outcome.requests),
    )
    outcome = _combined_outcome(seed_outcome, form_outcome)
    return _csrf_session_result(forms, outcome)


def probe_browser_boundary(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    pages = _browser_boundary_pages(session, state)
    seed_outcome = _probe_browser_seed_pages(pages, request_budget=_BROWSER_BOUNDARY_REQUEST_BUDGET)
    cors_outcome = _probe_cors_candidates(
        session,
        state,
        pages,
        request_budget=_BROWSER_BOUNDARY_REQUEST_BUDGET - len(seed_outcome.requests),
    )
    websocket_outcome = _probe_websocket_candidates(session, state, pages)
    outcome = _combined_outcome(seed_outcome, cors_outcome, websocket_outcome)
    return _browser_boundary_result(outcome)


def _csrf_seed_observations(
    pages: list[ProbeResponse],
    *,
    request_budget: int,
) -> _ProbeOutcome:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for page in pages:
        if len(requests) >= request_budget:
            break
        requests.append(_csrf_seed_request(page))
        findings.extend(_cookie_attribute_findings(page))
    return _ProbeOutcome(findings=findings, requests=requests)


def _csrf_seed_request(page: ProbeResponse) -> dict[str, object]:
    request = page.summary(body_chars=260)
    request["probe_kind"] = "csrf_session_seed"
    return request


def _probe_csrf_forms(
    session: ProbeSession,
    state: AgentState,
    forms: list[dict[str, object]],
    *,
    existing_request_count: int,
) -> _ProbeOutcome:
    outcome = _ProbeOutcome.empty()
    for form in forms[:10]:
        total_requests = existing_request_count + len(outcome.requests)
        if total_requests >= _CSRF_REQUEST_BUDGET:
            break

        form_outcome = _probe_csrf_form(session, state, form)
        outcome.absorb(form_outcome)
        if outcome.stop:
            break
    return outcome


def _probe_csrf_form(
    session: ProbeSession,
    state: AgentState,
    form: dict[str, object],
) -> _ProbeOutcome:
    csrf_names = _csrf_field_names(form)
    if not csrf_names:
        return _ProbeOutcome.empty()

    outcome = _ProbeOutcome.empty()
    baseline = _csrf_valid_baseline(session, form, csrf_names)
    outcome.absorb(baseline.outcome)

    omission = _csrf_omission_probe(session, form, csrf_names, baseline.response)
    outcome.absorb(omission)
    if outcome.stop:
        return outcome

    reuse = _csrf_reuse_probe(session, form, csrf_names)
    outcome.absorb(reuse.outcome)
    if outcome.stop:
        return outcome

    logout = _logout_invalidation_outcome(
        reuse.session,
        state,
        responses=[baseline.response, reuse.first, reuse.second],
    )
    outcome.absorb(logout)
    return outcome


def _combined_outcome(*outcomes: _ProbeOutcome) -> _ProbeOutcome:
    combined = _ProbeOutcome.empty()
    for outcome in outcomes:
        combined.absorb(outcome)
    return combined


def _csrf_session_result(
    forms: list[dict[str, object]],
    outcome: _ProbeOutcome,
) -> ProbeRunResult:
    return ProbeRunResult(
        ok=bool(outcome.findings),
        probe="csrf_session",
        summary=f"checked {len(forms[:10])} state-changing form(s), findings={len(outcome.findings)}",
        findings=_prioritize_boundary_findings(outcome.findings)[:30],
        requests=outcome.requests[:_CSRF_REQUEST_BUDGET],
    )


def _browser_boundary_result(outcome: _ProbeOutcome) -> ProbeRunResult:
    return ProbeRunResult(
        ok=bool(outcome.findings),
        probe="browser_boundary",
        summary=f"checked browser trust boundaries; findings={len(outcome.findings)}",
        findings=_prioritize_boundary_findings(outcome.findings)[:30],
        requests=outcome.requests[:_BROWSER_BOUNDARY_REQUEST_BUDGET],
    )


def _csrf_valid_baseline(
    session: ProbeSession,
    form: dict[str, object],
    csrf_names: list[str],
) -> _CsrfBaselineProbe:
    baseline_session, baseline_form = _fresh_form_session(session, form)
    baseline_fields = form_defaults(baseline_form)
    baseline = _submit_form(baseline_session, baseline_form, baseline_fields)
    request = _csrf_valid_baseline_request(baseline, baseline_form, csrf_names)
    findings = _proof_findings(baseline, channel="csrf_valid_baseline")
    outcome = _ProbeOutcome(findings=findings, requests=[request])
    return _CsrfBaselineProbe(response=baseline, outcome=outcome)


def _csrf_valid_baseline_request(
    response: ProbeResponse,
    form: dict[str, object],
    csrf_names: list[str],
) -> dict[str, object]:
    request = response.summary(body_chars=360)
    request.update(
        {
            "probe_kind": "csrf_valid_baseline",
            "form": _auth_form_brief(form),
            "csrf_fields": csrf_names,
        }
    )
    return request


def _csrf_omission_probe(
    session: ProbeSession,
    form: dict[str, object],
    csrf_names: list[str],
    baseline: ProbeResponse,
) -> _ProbeOutcome:
    omit_session, omit_form = _fresh_form_session(session, form)
    omit_fields = _without_csrf_fields(form_defaults(omit_form), csrf_names)
    omitted = _submit_form(omit_session, omit_form, omit_fields)
    request = _csrf_omission_request(omitted, omit_form, csrf_names)
    proofs = recognize_proofs(omitted.body)

    if not proofs and not _csrf_bypass_accepted(baseline=baseline, response=omitted):
        return _ProbeOutcome(findings=[], requests=[request])

    evidence = _CsrfOmissionEvidence(
        form=omit_form,
        csrf_names=csrf_names,
        omit_fields=omit_fields,
        baseline=baseline,
        omitted=omitted,
        proofs=proofs,
    )
    finding = _csrf_omission_finding(evidence)
    return _ProbeOutcome(findings=[finding], requests=[request], stop=bool(proofs))


def _csrf_omission_request(
    response: ProbeResponse,
    form: dict[str, object],
    csrf_names: list[str],
) -> dict[str, object]:
    request = response.summary(body_chars=560)
    request.update(
        {
            "probe_kind": "csrf_omitted_submit",
            "form": _auth_form_brief(form),
            "csrf_fields": csrf_names,
        }
    )
    return request


def _csrf_omission_finding(evidence: _CsrfOmissionEvidence) -> dict[str, object]:
    finding_type = "csrf_omission_accepted"
    if evidence.proofs:
        finding_type = "csrf_omission_extracted_proof"

    return {
        "type": finding_type,
        "form": _auth_form_brief(evidence.form),
        "csrf_fields": evidence.csrf_names,
        "proofs": evidence.proofs,
        "matches": response_secrets(evidence.omitted)[:10],
        "baseline": evidence.baseline.summary(body_chars=360),
        "response": evidence.omitted.summary(body_chars=700),
        "replay": _csrf_replay_template(evidence.form, evidence.omit_fields),
        "next": "Replay this state-changing request without the CSRF fields and sweep the resulting session/page for proof.",
    }


def _csrf_replay_template(form: dict[str, object], fields: dict[str, str]) -> dict[str, object]:
    return {
        "method": str(form.get("method") or "GET").upper(),
        "url": str(form.get("action") or ""),
        "form": fields,
        "encoding": "application/x-www-form-urlencoded",
    }


def _csrf_reuse_probe(
    session: ProbeSession,
    form: dict[str, object],
    csrf_names: list[str],
) -> _CsrfReuseProbe:
    reuse_session, reuse_form = _fresh_form_session(session, form)
    reuse_fields = form_defaults(reuse_form)
    first = _submit_form(reuse_session, reuse_form, reuse_fields)
    second = _submit_form(reuse_session, reuse_form, reuse_fields)
    request = _csrf_reuse_request(second, reuse_form, csrf_names)
    proofs = recognize_proofs(first.body + "\n" + second.body)

    if not proofs and not (_mutation_accepted(first) and _mutation_accepted(second)):
        outcome = _ProbeOutcome(findings=[], requests=[request])
        return _CsrfReuseProbe(session=reuse_session, first=first, second=second, outcome=outcome)

    finding = _csrf_reuse_finding(reuse_form, csrf_names, first, second, proofs)
    outcome = _ProbeOutcome(findings=[finding], requests=[request], stop=bool(proofs))
    return _CsrfReuseProbe(session=reuse_session, first=first, second=second, outcome=outcome)


def _csrf_reuse_request(
    response: ProbeResponse,
    form: dict[str, object],
    csrf_names: list[str],
) -> dict[str, object]:
    request = response.summary(body_chars=360)
    request.update(
        {
            "probe_kind": "csrf_reused_submit",
            "form": _auth_form_brief(form),
            "csrf_fields": csrf_names,
        }
    )
    return request


def _csrf_reuse_finding(
    form: dict[str, object],
    csrf_names: list[str],
    first: ProbeResponse,
    second: ProbeResponse,
    proofs: list[str],
) -> dict[str, object]:
    finding_type = "csrf_token_reuse_signal"
    if proofs:
        finding_type = "csrf_token_reuse_extracted_proof"

    return {
        "type": finding_type,
        "form": _auth_form_brief(form),
        "csrf_fields": csrf_names,
        "proofs": proofs,
        "first": first.summary(body_chars=300),
        "second": second.summary(body_chars=520),
        "next": "The same CSRF value was accepted more than once; preserve the replay template and check whether state changes can be repeated cross-session.",
    }


def _browser_boundary_pages(session: ProbeSession, state: AgentState) -> list[ProbeResponse]:
    pages = _seed_pages(session, state, limit=18)
    script_urls = _page_script_urls(session, state, pages)
    for script_url in script_urls[:12]:
        pages.append(session.get(script_url))
    return pages


def _probe_browser_seed_pages(
    pages: list[ProbeResponse],
    *,
    request_budget: int,
) -> _ProbeOutcome:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for response in pages:
        if len(requests) >= request_budget:
            break
        requests.append(_browser_seed_request(response))
        findings.extend(_browser_storage_findings(response))
        frame_finding = _clickjacking_finding(response)
        if frame_finding:
            findings.append(frame_finding)
    return _ProbeOutcome(findings=findings, requests=requests)


def _browser_seed_request(response: ProbeResponse) -> dict[str, object]:
    request = response.summary(body_chars=340)
    request["probe_kind"] = "browser_boundary_seed"
    return request


def _probe_cors_candidates(
    session: ProbeSession,
    state: AgentState,
    pages: list[ProbeResponse],
    *,
    request_budget: int,
) -> _ProbeOutcome:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for url in _cors_candidate_urls(session, state, pages)[:18]:
        if len(requests) >= request_budget:
            break
        get_response, options_response = _cors_probe_responses(session, url)
        requests.extend(_cors_probe_requests(get_response, options_response))
        finding = _cors_finding(get_response, options_response)
        if not finding:
            continue
        findings.append(finding)
        if finding.get("proofs"):
            return _ProbeOutcome(findings=findings, requests=requests, stop=True)
    return _ProbeOutcome(findings=findings, requests=requests)


def _cors_probe_responses(
    session: ProbeSession,
    url: str,
) -> tuple[ProbeResponse, ProbeResponse]:
    get_response = session.get(url, headers={"Origin": _EVIL_ORIGIN})
    options_response = session.request("OPTIONS", url, headers=_cors_preflight_headers())
    return get_response, options_response


def _cors_preflight_headers() -> dict[str, str]:
    return {
        "Origin": _EVIL_ORIGIN,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-Ravage-Probe",
    }


def _cors_probe_requests(
    get_response: ProbeResponse,
    options_response: ProbeResponse,
) -> list[dict[str, object]]:
    get_request = get_response.summary(body_chars=520)
    get_request.update({"probe_kind": "cors_origin_get", "origin": _EVIL_ORIGIN})

    options_request = options_response.summary(body_chars=260)
    options_request.update({"probe_kind": "cors_preflight", "origin": _EVIL_ORIGIN})
    return [get_request, options_request]


def _probe_websocket_candidates(
    session: ProbeSession,
    state: AgentState,
    pages: list[ProbeResponse],
) -> _ProbeOutcome:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for ws_url in _websocket_candidate_urls(session, state, pages)[:8]:
        handshake = _websocket_handshake(
            session,
            ws_url,
            origin=_EVIL_ORIGIN,
            timeout_seconds=min(session.timeout_seconds, 4),
        )
        requests.append(_websocket_handshake_request(handshake))
        if handshake.get("accepted"):
            findings.append(_websocket_handshake_finding(ws_url, handshake))
            break
    return _ProbeOutcome(findings=findings, requests=requests)


def _websocket_handshake_request(handshake: dict[str, object]) -> dict[str, object]:
    request = dict(handshake)
    request["probe_kind"] = "websocket_origin_handshake"
    return request


def _websocket_handshake_finding(ws_url: str, handshake: dict[str, object]) -> dict[str, object]:
    return {
        "type": "websocket_cross_origin_handshake_signal",
        "url": ws_url,
        "origin": _EVIL_ORIGIN,
        "status_line": handshake.get("status_line", ""),
        "headers": handshake.get("headers", {}),
        "detail": "WebSocket upgrade accepted a cross-origin Origin value; verify auth and message-level access next.",
    }


def _seed_pages(session: ProbeSession, state: AgentState, *, limit: int) -> list[ProbeResponse]:
    urls: list[str] = [session.target_url]
    urls.extend(_common_boundary_urls(session))
    urls.extend(_surface_endpoints(state))
    urls.extend(_script_urls(state))
    pages: list[ProbeResponse] = []
    for url in _same_origin_http_urls(session, urls)[:limit]:
        pages.append(session.get(url))
    return pages


def _csrf_candidate_forms(
    session: ProbeSession,
    state: AgentState,
    pages: list[ProbeResponse],
) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    forms.extend(_form_targets(state, limit=16))
    for page in pages:
        for form in _forms_from_html(page.final_url or page.url, page.body, auth_headers={}, base_categories=()):
            form["source_url"] = page.final_url or page.url
            forms.append(form)
    deduped: dict[str, dict[str, object]] = {}
    for form in forms:
        if not _same_origin_http(session, str(form.get("action") or session.target_url)):
            continue
        if not _state_changing_form(form):
            continue
        key = json.dumps(
            {
                "method": str(form.get("method") or "GET").upper(),
                "action": str(form.get("action") or ""),
                "inputs": sorted(_input_names(form)),
            },
            sort_keys=True,
        )
        deduped.setdefault(key, form)
    return list(deduped.values())[:16]


def _state_changing_form(form: dict[str, object]) -> bool:
    method = str(form.get("method") or "GET").upper()
    text = json.dumps(form, sort_keys=True).lower()
    if method == "POST":
        return True
    return _contains_marker(text, _STATE_CHANGE_MARKERS)


def _input_names(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    for field in _list_of_dicts(form.get("inputs")):
        name = str(field.get("name") or "")
        if name:
            names.append(name)
    return names


def _csrf_field_names(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    for field in _list_of_dicts(form.get("inputs")):
        name = str(field.get("name") or "")
        if _field_is_csrf_token(name):
            names.append(name)
    return _dedupe(names)[:6]


def _field_is_csrf_token(name: str) -> bool:
    if not name:
        return False
    lowered = name.lower()
    return _contains_marker(lowered, _CSRF_FIELD_MARKERS)


def _without_csrf_fields(fields: dict[str, str], csrf_names: list[str]) -> dict[str, str]:
    csrf_set = set(csrf_names)
    filtered: dict[str, str] = {}
    for name, value in fields.items():
        if name in csrf_set:
            continue
        filtered[name] = value
    return filtered


def _fresh_form_session(session: ProbeSession, form: dict[str, object]) -> tuple[ProbeSession, dict[str, object]]:
    fork = session.fork(timeout_seconds=session.timeout_seconds)
    match = _fresh_form_from_source(fork, form)
    if match:
        return fork, match

    match = _fresh_form_from_action(fork, form, fallback_url=session.target_url)
    if match:
        return fork, match

    return fork, form


def _fresh_form_from_source(
    session: ProbeSession,
    form: dict[str, object],
) -> dict[str, object] | None:
    source_url = str(form.get("source_url") or "")
    if not source_url:
        return None
    return _fresh_matching_form(session, form, source_url)


def _fresh_form_from_action(
    session: ProbeSession,
    form: dict[str, object],
    *,
    fallback_url: str,
) -> dict[str, object] | None:
    action = str(form.get("action") or fallback_url)
    return _fresh_matching_form(session, form, action)


def _fresh_matching_form(
    session: ProbeSession,
    original: dict[str, object],
    url: str,
) -> dict[str, object] | None:
    page = session.get(url)
    candidates = _forms_from_html(
        page.final_url or url,
        page.body,
        auth_headers={},
        base_categories=(),
    )
    match = _matching_form(original, candidates)
    if match:
        match["source_url"] = page.final_url or url
    return match


def _matching_form(original: dict[str, object], candidates: list[dict[str, object]]) -> dict[str, object] | None:
    original_profile = _form_match_profile(original)
    best: tuple[int, dict[str, object]] | None = None
    for candidate in candidates:
        score = _form_match_score(original_profile, candidate)
        if score <= 0:
            continue
        if best is None or score > best[0]:
            best = (score, candidate)
    return best[1] if best else None


def _form_match_profile(form: dict[str, object]) -> _FormMatchProfile:
    return _FormMatchProfile(
        method=_form_method(form),
        action=_form_action(form),
        names=set(_input_names(form)),
    )


def _form_match_score(original: _FormMatchProfile, candidate: dict[str, object]) -> int:
    score = 0
    if _form_method(candidate) == original.method:
        score += 2
    if _form_action(candidate) == original.action:
        score += 3

    overlap = _form_input_overlap(original, candidate)
    if overlap == 0:
        return 0
    return score + overlap


def _form_method(form: dict[str, object]) -> str:
    return str(form.get("method") or "GET").upper()


def _form_action(form: dict[str, object]) -> str:
    return str(form.get("action") or "")


def _form_input_overlap(original: _FormMatchProfile, candidate: dict[str, object]) -> int:
    candidate_names = set(_input_names(candidate))
    return len(original.names & candidate_names)


def _csrf_bypass_accepted(*, baseline: ProbeResponse, response: ProbeResponse) -> bool:
    if not _mutation_accepted(response):
        return False
    if _csrf_rejected(baseline):
        return bool(recognize_proofs(response.body) or response_secrets(response))
    if recognize_proofs(response.body):
        return True
    baseline_rejected = _csrf_rejected(baseline)
    response_rejected = _csrf_rejected(response)
    if baseline_rejected != response_rejected:
        return not response_rejected
    return _acceptance_score(response) >= max(1, _acceptance_score(baseline) - 1)


def _mutation_accepted(response: ProbeResponse) -> bool:
    if response.status is None:
        return False
    if response.status in {400, 401, 403, 419, 422}:
        return False
    if _csrf_rejected(response):
        return False
    return 200 <= response.status < 400 or _acceptance_score(response) > 0


def _csrf_rejected(response: ProbeResponse) -> bool:
    lowered = response.body.lower()
    return _contains_marker(lowered, _REJECTION_MARKERS)


def _acceptance_score(response: ProbeResponse) -> int:
    text = response.body.lower()
    score = 0
    if response.status is not None and 200 <= response.status < 400:
        score += 1
    for marker in _ACCEPTANCE_MARKERS:
        if marker in text:
            score += 1
    return score


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False


def _proof_findings(response: ProbeResponse, *, channel: str) -> list[dict[str, object]]:
    proofs = recognize_proofs(response.body)
    if not proofs:
        return []
    finding = {
        "type": "csrf_session_extracted_proof",
        "channel": channel,
        "url": response.url,
        "proofs": proofs,
        "response": response.summary(body_chars=700),
    }
    return [finding]


def _logout_invalidation_outcome(
    session: ProbeSession,
    state: AgentState,
    *,
    responses: list[ProbeResponse],
) -> _ProbeOutcome:
    finding, requests = _logout_invalidation_check(session, state, responses=responses)
    findings: list[dict[str, object]] = []
    stop = False
    if finding:
        findings.append(finding)
        stop = bool(finding.get("proofs"))
    return _ProbeOutcome(findings=findings, requests=requests, stop=stop)


def _logout_invalidation_check(
    session: ProbeSession,
    state: AgentState,
    *,
    responses: list[ProbeResponse],
) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    cookie_header = _cookie_header(session)
    if not cookie_header:
        return None, []
    if not _logout_surface_observed(state, responses):
        return None, []

    candidate_urls = _logout_candidate_urls(session, state)
    followup_urls = _post_logout_followup_urls(session, state, responses)
    requests: list[dict[str, object]] = []
    for logout_url in candidate_urls[:3]:
        logout_response = session.get(logout_url)
        requests.append(_logout_request_record(logout_response))
        finding, replay_requests = _replay_old_cookie_after_logout(
            session,
            logout_url=logout_url,
            followup_urls=followup_urls,
            cookie_header=cookie_header,
        )
        requests.extend(replay_requests)
        if finding:
            return finding, requests
    return None, requests


def _logout_surface_observed(state: AgentState, responses: list[ProbeResponse]) -> bool:
    response_text = "\n".join(response.body for response in responses).lower()
    if "logout" in response_text:
        return True

    for value in state.signals.get("endpoints", []):
        if "logout" in str(value).lower():
            return True
    return False


def _logout_candidate_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls = [session.absolute("/logout")]
    for value in state.signals.get("endpoints", []):
        text = str(value)
        if "logout" in text.lower():
            urls.append(session.absolute(text))
    return _dedupe(urls)


def _logout_request_record(response: ProbeResponse) -> dict[str, object]:
    request = response.summary(body_chars=180)
    request["probe_kind"] = "logout_request"
    return request


def _replay_old_cookie_after_logout(
    session: ProbeSession,
    *,
    logout_url: str,
    followup_urls: list[str],
    cookie_header: str,
) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    requests: list[dict[str, object]] = []
    for followup_url in followup_urls[:6]:
        replay = session.get(followup_url, headers={"Cookie": cookie_header})
        requests.append(_logout_replay_request(replay, followup_url))
        proofs = recognize_proofs(replay.body)
        if proofs or _authenticated_body(replay):
            finding = _logout_invalidation_finding(logout_url, followup_url, replay, proofs)
            return finding, requests
    return None, requests


def _logout_replay_request(response: ProbeResponse, followup_url: str) -> dict[str, object]:
    request = response.summary(body_chars=420)
    request.update({"probe_kind": "logout_old_cookie_replay", "url": followup_url})
    return request


def _logout_invalidation_finding(
    logout_url: str,
    followup_url: str,
    replay: ProbeResponse,
    proofs: list[str],
) -> dict[str, object]:
    return {
        "type": "logout_invalidation_failed",
        "logout_url": logout_url,
        "replay_url": followup_url,
        "proofs": proofs,
        "response": replay.summary(body_chars=650),
        "detail": "A pre-logout cookie still reached an authenticated-looking page after logout.",
    }


def _post_logout_followup_urls(
    session: ProbeSession,
    state: AgentState,
    responses: list[ProbeResponse],
) -> list[str]:
    urls: list[str] = []
    for response in responses:
        if response.final_url:
            urls.append(response.final_url)
        urls.extend(_same_origin_links(session, response.final_url or response.url, response.body))
    urls.extend(_surface_endpoints(state))
    urls.extend(_post_logout_common_urls(session))
    return _same_origin_http_urls(session, urls)


def _post_logout_common_urls(session: ProbeSession) -> list[str]:
    paths = ("/dashboard", "/profile", "/account", "/settings", "/admin")
    urls: list[str] = []
    for path in paths:
        urls.append(session.absolute(path))
    return urls


def _same_origin_http_urls(session: ProbeSession, urls: list[str]) -> list[str]:
    filtered: list[str] = []
    for url in _dedupe(urls):
        if _same_origin_http(session, url):
            filtered.append(url)
    return filtered


def _authenticated_body(response: ProbeResponse) -> bool:
    if response.status is None or response.status in {401, 403}:
        return False
    lowered = response.body.lower()
    for marker in ("logout", "dashboard", "profile", "account", "settings", "admin"):
        if marker in lowered:
            return True
    return False


def _cookie_header(session: ProbeSession) -> str:
    parts: list[str] = []
    for cookie in session.cookies:
        if cookie.name and cookie.value:
            parts.append(f"{cookie.name}={cookie.value}")
    return "; ".join(parts)


def _cookie_attribute_findings(response: ProbeResponse) -> list[dict[str, object]]:
    raw = response.headers.get("set-cookie", "")
    if not raw:
        return []
    findings: list[dict[str, object]] = []
    for line in raw.splitlines():
        cookie = _parse_set_cookie_line(line)
        if cookie is None:
            continue
        name, head, raw_attrs = cookie
        if not _session_cookie_name(name):
            continue
        attrs = _cookie_attrs_by_name(raw_attrs)
        missing = _missing_cookie_security_attrs(response, attrs)
        if missing:
            findings.append(_cookie_attribute_finding(response, name, head, raw_attrs, missing))
    return findings


def _parse_set_cookie_line(line: str) -> tuple[str, str, list[str]] | None:
    parts: list[str] = []
    for part in line.split(";"):
        stripped = part.strip()
        if stripped:
            parts.append(stripped)
    if not parts:
        return None

    head = parts[0]
    if "=" not in head:
        return None

    name, _value = head.split("=", 1)
    return name, head, parts[1:]


def _session_cookie_name(name: str) -> bool:
    lowered = name.lower()
    for marker in _SESSION_COOKIE_NAME_MARKERS:
        if marker in lowered:
            return True
    return False


def _cookie_attrs_by_name(raw_attrs: list[str]) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for attr in raw_attrs:
        name = attr.split("=", 1)[0].strip().lower()
        attrs[name] = attr
    return attrs


def _missing_cookie_security_attrs(response: ProbeResponse, attrs: dict[str, str]) -> list[str]:
    missing: list[str] = []
    if "httponly" not in attrs:
        missing.append("HttpOnly")
    if "samesite" not in attrs:
        missing.append("SameSite")
    if _same_site_none_without_secure(attrs):
        missing.append("Secure for SameSite=None")
    if _https_cookie_without_secure(response, attrs):
        missing.append("Secure")
    return missing


def _same_site_none_without_secure(attrs: dict[str, str]) -> bool:
    same_site = str(attrs.get("samesite") or "").lower()
    return "none" in same_site and "secure" not in attrs


def _https_cookie_without_secure(response: ProbeResponse, attrs: dict[str, str]) -> bool:
    return urlsplit(response.url).scheme == "https" and "secure" not in attrs


def _cookie_attribute_finding(
    response: ProbeResponse,
    name: str,
    head: str,
    raw_attrs: list[str],
    missing: list[str],
) -> dict[str, object]:
    return {
        "type": "session_cookie_attribute_signal",
        "url": response.url,
        "cookie": name,
        "missing": missing,
        "set_cookie": head + "; " + "; ".join(raw_attrs),
        "detail": "Session-like cookie is missing browser security attributes relevant to theft/CSRF containment.",
    }


def _browser_storage_findings(response: ProbeResponse) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for storage, key, value in _storage_assignments(response.body):
        proofs = recognize_proofs(value)
        secret_like = _storage_value_secret_like(key, value)
        if not proofs and not secret_like:
            continue
        evidence = _StorageEvidence(
            response=response,
            storage=storage,
            key=key,
            value=value,
            proofs=proofs,
            secret_like=secret_like,
        )
        finding = _browser_storage_finding(evidence)
        findings.append(finding)
    return findings


def _browser_storage_finding(evidence: _StorageEvidence) -> dict[str, object]:
    return {
        "type": "browser_storage_secret_exposure",
        "url": evidence.response.url,
        "storage": evidence.storage,
        "key": evidence.key,
        "proofs": evidence.proofs,
        "matches": _browser_storage_matches(evidence),
        "detail": "Client-side storage contains proof or secret-like material accessible to same-origin script.",
    }


def _browser_storage_matches(evidence: _StorageEvidence) -> list[str]:
    if evidence.proofs or not evidence.secret_like:
        return []
    match = f"storage:{evidence.key}={_clip_secret(evidence.value)}"
    return [match]


def _storage_assignments(body: str) -> list[tuple[str, str, str]]:
    assignments: list[tuple[str, str, str]] = []
    assignments.extend(_storage_set_item_assignments(body))
    assignments.extend(_storage_bracket_assignments(body))
    assignments.extend(_storage_property_assignments(body))
    return assignments[:20]


def _storage_set_item_assignments(body: str) -> list[tuple[str, str, str]]:
    pattern = r"""(?is)\b(localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*(['"])(.*?)\2\s*,\s*(['"])(.*?)\4\s*\)"""
    assignments: list[tuple[str, str, str]] = []
    for match in re.finditer(pattern, body):
        assignments.append(_storage_assignment(match.group(1), match.group(3), match.group(5)))
    return assignments


def _storage_bracket_assignments(body: str) -> list[tuple[str, str, str]]:
    pattern = r"""(?is)\b(localStorage|sessionStorage)\s*\[\s*(['"])(.*?)\2\s*\]\s*=\s*(['"])(.*?)\4"""
    assignments: list[tuple[str, str, str]] = []
    for match in re.finditer(pattern, body):
        assignments.append(_storage_assignment(match.group(1), match.group(3), match.group(5)))
    return assignments


def _storage_property_assignments(body: str) -> list[tuple[str, str, str]]:
    pattern = r"""(?is)\b(localStorage|sessionStorage)\s*\.\s*([A-Za-z_$][\w$-]*)\s*=\s*(['"])(.*?)\3"""
    assignments: list[tuple[str, str, str]] = []
    for match in re.finditer(pattern, body):
        assignments.append(_storage_assignment(match.group(1), match.group(2), match.group(4)))
    return assignments


def _storage_assignment(storage: str, key: str, value: str) -> tuple[str, str, str]:
    return storage, html.unescape(key), html.unescape(value)


def _storage_value_secret_like(key: str, value: str) -> bool:
    lowered = f"{key} {value}".lower()
    secret_markers = ("flag", "secret", "token", "jwt", "api_key", "apikey", "password")
    for marker in secret_markers:
        if marker in lowered:
            return len(value.strip()) >= 8
    return False


def _clip_secret(value: str) -> str:
    stripped = value.strip()
    normalized = re.sub(r"\s+", " ", stripped)
    return normalized[:160]


def _clickjacking_finding(response: ProbeResponse) -> dict[str, object] | None:
    if not _clickjacking_response_eligible(response):
        return None
    if not _sensitive_html_page(response):
        return None
    if _frame_policy_present(response):
        return None
    return {
        "type": "clickjacking_frame_policy_missing",
        "url": response.url,
        "status": response.status,
        "detail": "Sensitive-looking HTML response lacks X-Frame-Options and CSP frame-ancestors controls.",
        "response": response.summary(body_chars=360),
    }


def _clickjacking_response_eligible(response: ProbeResponse) -> bool:
    if response.status is None:
        return False
    if response.status >= 400:
        return False
    content_type = str(response.headers.get("content-type") or "").lower()
    if not content_type:
        return True
    if "html" in content_type:
        return True
    return False


def _sensitive_html_page(response: ProbeResponse) -> bool:
    text = (response.url + " " + response.body[:1200]).lower()
    sensitive = False
    for marker in _SENSITIVE_PAGE_MARKERS:
        if marker in text:
            sensitive = True
            break
    return sensitive


def _frame_policy_present(response: ProbeResponse) -> bool:
    x_frame_options = str(response.headers.get("x-frame-options") or "").strip()
    if x_frame_options:
        return True

    content_security_policy = str(response.headers.get("content-security-policy") or "").lower()
    return "frame-ancestors" in content_security_policy


def _cors_candidate_urls(
    session: ProbeSession,
    state: AgentState,
    pages: list[ProbeResponse],
) -> list[str]:
    urls: list[str] = []
    urls.extend(_common_boundary_urls(session))
    urls.extend(_surface_endpoints(state))
    for response in pages:
        urls.extend(_cors_urls_from_page(session, response))
    return _dynamic_same_origin_urls(session, urls)


def _common_boundary_urls(session: ProbeSession) -> list[str]:
    urls: list[str] = []
    for path in _COMMON_BOUNDARY_PATHS:
        urls.append(session.absolute(path))
    return urls


def _cors_urls_from_page(session: ProbeSession, response: ProbeResponse) -> list[str]:
    base_url = response.final_url or response.url
    urls = [base_url]
    urls.extend(_same_origin_links(session, base_url, response.body))
    return urls


def _dynamic_same_origin_urls(session: ProbeSession, urls: list[str]) -> list[str]:
    filtered: list[str] = []
    for url in _dedupe(urls):
        if not _same_origin_http(session, url):
            continue
        if _path_static(url):
            continue
        filtered.append(url)
    return filtered


def _cors_finding(get_response: ProbeResponse, options_response: ProbeResponse) -> dict[str, object] | None:
    headers = _combined_cors_headers(get_response, options_response)
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if not _cors_origin_permissive(acao):
        return None

    proofs = recognize_proofs(get_response.body)
    matches = response_secrets(get_response)
    return {
        "type": _cors_finding_type(proofs),
        "url": get_response.url,
        "origin": _EVIL_ORIGIN,
        "allow_origin": acao,
        "allow_credentials": acac,
        "credentialed": _cors_allows_credentials(acac),
        "proofs": proofs,
        "matches": matches[:10],
        "response": get_response.summary(body_chars=720),
        "preflight": options_response.summary(body_chars=260),
        "detail": "Target reflects or broadly allows a cross-origin Origin; credentialed CORS is especially actionable.",
    }


def _combined_cors_headers(
    get_response: ProbeResponse,
    options_response: ProbeResponse,
) -> dict[str, str]:
    headers = _lower_headers(options_response.headers)
    headers.update(_lower_headers(get_response.headers))
    return headers


def _cors_finding_type(proofs: list[str]) -> str:
    if proofs:
        return "cors_extracted_proof"
    return "cors_misconfiguration_signal"


def _cors_allows_credentials(value: str) -> bool:
    return value.lower() == "true"


def _cors_origin_permissive(value: str) -> bool:
    text = value.strip()
    return text == "*" or text.lower() == _EVIL_ORIGIN.lower()


def _lower_headers(headers: dict[str, str]) -> dict[str, str]:
    lowered: dict[str, str] = {}
    for name, value in headers.items():
        lowered[name.lower()] = value
    return lowered


def _page_script_urls(
    session: ProbeSession,
    state: AgentState,
    pages: list[ProbeResponse],
) -> list[str]:
    urls: list[str] = []
    urls.extend(_script_urls(state))
    for page in pages:
        urls.extend(_script_urls_from_page(page))
    return _same_origin_script_urls(session, urls)


def _script_urls_from_page(page: ProbeResponse) -> list[str]:
    urls: list[str] = []
    base_url = page.final_url or page.url
    pattern = r"""(?is)<script\b[^>]*\bsrc\s*=\s*(['"])(.*?)\1"""
    for match in re.finditer(pattern, page.body):
        value = html.unescape(match.group(2).strip())
        if value:
            urls.append(urljoin(base_url, value))
    return urls


def _same_origin_script_urls(session: ProbeSession, urls: list[str]) -> list[str]:
    filtered: list[str] = []
    for url in _dedupe(urls):
        if _same_origin_http(session, url):
            filtered.append(url)
    return filtered


def _websocket_candidate_urls(
    session: ProbeSession,
    state: AgentState,
    pages: list[ProbeResponse],
) -> list[str]:
    urls: list[str] = []
    urls.extend(_websocket_urls_from_state(state))
    for page in pages:
        urls.extend(_websocket_urls_from_text(page.body, base_url=page.final_url or page.url))
    urls.extend(_common_websocket_urls(session))
    return _same_origin_websocket_urls(session, urls)


def _websocket_urls_from_state(state: AgentState) -> list[str]:
    urls: list[str] = []
    for value in state.signals.get("endpoints", []):
        text = str(value)
        if text.startswith(("ws://", "wss://")):
            urls.append(text)
    return urls


def _common_websocket_urls(session: ProbeSession) -> list[str]:
    paths = ("/ws", "/socket", "/socket.io/?EIO=4&transport=websocket")
    urls: list[str] = []
    for path in paths:
        urls.append(_http_to_ws(session.absolute(path)))
    return urls


def _same_origin_websocket_urls(session: ProbeSession, urls: list[str]) -> list[str]:
    filtered: list[str] = []
    for url in _dedupe(urls):
        if _same_origin_ws(session, url):
            filtered.append(url)
    return filtered


def _websocket_urls_from_text(text: str, *, base_url: str) -> list[str]:
    urls: list[str] = []
    urls.extend(_websocket_constructor_urls(text, base_url=base_url))
    urls.extend(_absolute_websocket_urls(text))
    return urls


def _websocket_constructor_urls(text: str, *, base_url: str) -> list[str]:
    urls: list[str] = []
    pattern = r"""(?is)(?:new\s+WebSocket\s*\(|\bWebSocket\s*\()\s*(['"])(.*?)\1"""
    for match in re.finditer(pattern, text):
        urls.append(_resolve_ws_url(match.group(2), base_url=base_url))
    return urls


def _absolute_websocket_urls(text: str) -> list[str]:
    urls: list[str] = []
    for match in re.finditer(r"""(?is)\b(wss?://[^'"\s<>)]+)""", text):
        urls.append(match.group(1))
    return urls


def _resolve_ws_url(value: str, *, base_url: str) -> str:
    text = html.unescape(value.strip())
    if text.startswith(("ws://", "wss://")):
        return text
    if text.startswith("/"):
        return _http_to_ws(urljoin(base_url, text))
    return _http_to_ws(urljoin(base_url, text))


def _http_to_ws(url: str) -> str:
    parts = urlsplit(url)
    scheme = "wss" if parts.scheme == "https" else "ws"
    return urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _websocket_handshake(
    session: ProbeSession,
    ws_url: str,
    *,
    origin: str,
    timeout_seconds: int,
) -> dict[str, object]:
    try:
        parts = urlsplit(ws_url)
        if not parts.hostname:
            return {"url": ws_url, "accepted": False, "error": "missing host"}
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        policy_url = urlunsplit(
            (
                "https" if parts.scheme == "wss" else "http",
                parts.netloc,
                parts.path or "/",
                parts.query,
                "",
            )
        )
        transport_result = session.run_external_transport(
            "GET",
            policy_url,
            _websocket_controlled_exchange,
            headers={
                "Connection": "Upgrade",
                "Origin": origin,
                "Sec-WebSocket-Key": key,
                "Sec-WebSocket-Version": "13",
                "Upgrade": "websocket",
            },
            timeout_seconds=timeout_seconds,
            lane="websocket",
            retryable=True,
        )
        raw = transport_result.response_bytes
    except (OSError, TrafficPolicyBlocked) as exc:
        return {"url": ws_url, "accepted": False, "error": str(exc)[:240]}

    return _websocket_handshake_result(ws_url, raw, key)


def _websocket_handshake_request_bytes(
    parts: SplitResult,
    *,
    headers: Mapping[str, str],
) -> bytes:
    path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    lines = [f"GET {path} HTTP/1.1"]
    lines.extend(f"{name}: {value}" for name, value in headers.items())
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")


def _websocket_controlled_exchange(
    request: ControlledTransportRequest,
) -> ControlledTransportResult:
    parts = urlsplit(request.url)
    request_bytes = _websocket_handshake_request_bytes(parts, headers=request.headers)
    raw = _websocket_send_handshake(
        parts,
        request_bytes,
        pinned_addresses=request.pins,
        timeout_seconds=request.timeout_seconds,
    )
    return ControlledTransportResult(
        response_bytes=raw,
        outcome=_websocket_traffic_outcome(raw),
    )


def _websocket_send_handshake(
    parts: SplitResult,
    request: bytes,
    *,
    pinned_addresses: tuple[str, ...],
    timeout_seconds: float,
) -> bytes:
    host = parts.hostname or ""
    secure = parts.scheme in {"https", "wss"}
    port = parts.port or (443 if secure else 80)
    with _connect_pinned_socket(
        pinned_addresses,
        port,
        timeout=timeout_seconds,
        source_address=None,
    ) as sock:
        sock.settimeout(timeout_seconds)
        if secure:
            return _websocket_send_tls_handshake(sock, host, request)
        sock.sendall(request)
        return _read_websocket_headers(sock)


def _websocket_send_tls_handshake(sock: socket.socket, host: str, request: bytes) -> bytes:
    context = ssl.create_default_context()
    with context.wrap_socket(sock, server_hostname=host) as tls_sock:
        tls_sock.sendall(request)
        return _read_websocket_headers(tls_sock)


def _read_websocket_headers(sock: socket.socket) -> bytes:
    response = bytearray()
    while len(response) < _MAX_WEBSOCKET_HANDSHAKE_BYTES:
        remaining = _MAX_WEBSOCKET_HANDSHAKE_BYTES - len(response)
        chunk = sock.recv(min(4096, remaining))
        if not chunk:
            break
        response.extend(chunk)
        header_end = response.find(b"\r\n\r\n")
        if header_end >= 0:
            return bytes(response[: header_end + 4])
    return bytes(response)


def _websocket_traffic_outcome(raw: bytes) -> TrafficOutcome:
    text = raw.decode("iso-8859-1", errors="replace")
    headers = _parse_raw_headers(text)
    if b"\r\n\r\n" not in raw:
        return TrafficOutcome(status=None, headers=headers, transport_error=True)
    status_line = text.partition("\r\n")[0]
    match = re.fullmatch(r"HTTP/\d(?:\.\d)? ([1-5]\d\d)(?: [^\r\n]*)?", status_line)
    if match is None or not _websocket_headers_well_formed(text):
        return TrafficOutcome(status=None, headers=headers, transport_error=True)
    return TrafficOutcome(status=int(match.group(1)), headers=headers)


def _websocket_headers_well_formed(text: str) -> bool:
    header_block = text.partition("\r\n\r\n")[0]
    for line in header_block.split("\r\n")[1:]:
        if ":" not in line:
            return False
        name, _value = line.split(":", 1)
        if re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name) is None:
            return False
    return True


def _websocket_handshake_result(ws_url: str, raw: bytes, key: str) -> dict[str, object]:
    text = raw.decode("iso-8859-1", errors="replace")
    status_line = text.splitlines()[0] if text.splitlines() else ""
    headers = _parse_raw_headers(text)
    accepted = _websocket_upgrade_accepted(status_line, headers)
    return {
        "url": ws_url,
        "accepted": accepted,
        "status_line": status_line,
        "headers": headers,
        "accept_valid": _websocket_accept_valid(headers.get("sec-websocket-accept", ""), key),
    }


def _websocket_upgrade_accepted(status_line: str, headers: dict[str, str]) -> bool:
    if " 101 " not in f" {status_line} ":
        return False
    return headers.get("upgrade", "").lower() == "websocket"


def _websocket_accept_valid(value: str, key: str) -> bool:
    expected = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
    ).decode("ascii")
    return value.strip() == expected


def _parse_raw_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in text.split("\r\n")[1:]:
        if not line:
            break
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def _same_origin_links(session: ProbeSession, base_url: str, body: str) -> list[str]:
    urls: list[str] = []
    urls.extend(_same_origin_attribute_links(session, base_url, body))
    urls.extend(_same_origin_fetch_links(session, base_url, body))
    return urls[:24]


def _same_origin_attribute_links(session: ProbeSession, base_url: str, body: str) -> list[str]:
    urls: list[str] = []
    pattern = r"""(?is)\b(?:href|src|action)\s*=\s*(['"])(.*?)\1"""
    for match in re.finditer(pattern, body):
        value = html.unescape(match.group(2).strip())
        if _ignored_link_value(value):
            continue
        url = urljoin(base_url, value)
        if _same_origin_http(session, url):
            urls.append(url)
    return urls


def _same_origin_fetch_links(session: ProbeSession, base_url: str, body: str) -> list[str]:
    urls: list[str] = []
    pattern = r"""(?is)\bfetch\s*\(\s*(['"])(.*?)\1"""
    for match in re.finditer(pattern, body):
        value = html.unescape(match.group(2).strip())
        if _ignored_link_value(value):
            continue
        url = urljoin(base_url, value)
        if _same_origin_http(session, url):
            urls.append(url)
    return urls


def _ignored_link_value(value: str) -> bool:
    if not value:
        return True
    return value.startswith(("javascript:", "data:", "mailto:", "#"))


def _same_origin_http(session: ProbeSession, url: str) -> bool:
    try:
        parts = urlsplit(session.absolute(url))
        target = urlsplit(session.target_url)
    except ValueError:
        return False
    return parts.scheme in {"http", "https"} and (parts.scheme, parts.netloc) == (target.scheme, target.netloc)


def _same_origin_ws(session: ProbeSession, url: str) -> bool:
    try:
        parts = urlsplit(url)
        target = urlsplit(session.target_url)
    except ValueError:
        return False
    if parts.scheme not in {"ws", "wss"}:
        return False
    expected_scheme = "wss" if target.scheme == "https" else "ws"
    return parts.scheme == expected_scheme and parts.netloc == target.netloc


def _path_static(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map"))


def _prioritize_boundary_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    def priority(finding: dict[str, object]) -> int:
        if finding.get("proofs"):
            return 0
        if str(finding.get("type") or "").endswith("_extracted_proof"):
            return 0
        if str(finding.get("type") or "") in {"cors_extracted_proof", "browser_storage_secret_exposure"}:
            return 0
        return 1

    return sorted(findings, key=priority)
