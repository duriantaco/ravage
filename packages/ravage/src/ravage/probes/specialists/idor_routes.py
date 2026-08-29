from __future__ import annotations

import html
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.probes.specialists.idor_auth import _idor_auth_header_contexts
from ravage.probes.specialists.idor_signals import (
    _auth_blocked,
    _idor_access_signal,
    _looks_like_missing_object_response,
)
from ravage.probes.specialists.idor_targets import _object_id_counter_candidates
from ravage.probes.specialists.shared import (
    _dedupe,
    _int_value,
    _looks_mongo_object_id,
    _name_looks_idor,
    _replace_path_segment,
    _signal_endpoints,
    _surface_endpoints,
    _target_brief,
    _target_headers,
    _target_replay,
    _value_looks_idor_id,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs

_IDOR_AUTH_OBJECT_SEED_PATHS = (
    "/account",
    "/accounts",
    "/admin",
    "/dashboard",
    "/documents",
    "/downloads",
    "/files",
    "/history",
    "/home",
    "/invoices",
    "/me",
    "/orders",
    "/profile",
    "/records",
    "/receipts",
    "/settings",
    "/transactions",
    "/users",
)


@dataclass
class _ProbeBatch:
    findings: list[dict[str, object]]
    requests: list[dict[str, object]]
    budget: int
    stop: bool = False


@dataclass
class _AuthenticatedRouteWork:
    queued: list[str]
    queued_set: set[str]
    seen: set[str]
    listed_object_urls: set[str]


@dataclass
class _TransitionCandidateAttempt:
    batch: _ProbeBatch
    response: ProbeResponse | None
    url: str


def _probe_authenticated_object_routes(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    auth_contexts = _idor_auth_header_contexts(state)
    if not auth_contexts:
        return [], [], budget

    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    seed_urls = _authenticated_object_seed_urls(session, state)
    for auth_headers in auth_contexts[:3]:
        context_result = _probe_authenticated_routes_for_context(
            session,
            seed_urls,
            auth_headers=auth_headers,
            budget=budget,
        )
        findings.extend(context_result.findings)
        requests.extend(context_result.requests)
        budget = context_result.budget
        if context_result.stop:
            return findings, requests, budget
    return findings, requests, budget


def _probe_authenticated_routes_for_context(
    session: ProbeSession,
    seed_urls: list[str],
    *,
    auth_headers: dict[str, str],
    budget: int,
) -> _ProbeBatch:
    work = _new_authenticated_route_work()
    result = _ProbeBatch(findings=[], requests=[], budget=budget)

    seed_result = _probe_authenticated_seed_urls(
        session,
        seed_urls,
        auth_headers=auth_headers,
        work=work,
        budget=result.budget,
    )
    _merge_probe_batch(result, seed_result)
    if result.stop:
        return result

    followup_result = _probe_authenticated_followup_queue(
        session,
        auth_headers=auth_headers,
        work=work,
        budget=result.budget,
    )
    _merge_probe_batch(result, followup_result)
    return result


def _new_authenticated_route_work() -> _AuthenticatedRouteWork:
    return _AuthenticatedRouteWork(
        queued=[],
        queued_set=set(),
        seen=set(),
        listed_object_urls=set(),
    )


def _probe_authenticated_seed_urls(
    session: ProbeSession,
    seed_urls: list[str],
    *,
    auth_headers: dict[str, str],
    work: _AuthenticatedRouteWork,
    budget: int,
) -> _ProbeBatch:
    result = _ProbeBatch(findings=[], requests=[], budget=budget)
    for url in seed_urls[:24]:
        if result.budget <= 0:
            break
        seed_result = _probe_authenticated_seed_url(
            session,
            url,
            auth_headers=auth_headers,
            work=work,
            budget=result.budget,
        )
        _merge_probe_batch(result, seed_result)
        if result.stop:
            return result
    return result


def _probe_authenticated_seed_url(
    session: ProbeSession,
    url: str,
    *,
    auth_headers: dict[str, str],
    work: _AuthenticatedRouteWork,
    budget: int,
) -> _ProbeBatch:
    response = session.get(url, headers=auth_headers or None)
    result = _ProbeBatch(findings=[], requests=[], budget=budget - 1)
    work.seen.add(response.final_url or response.url)
    result.requests.append(_authenticated_seed_request(response, url, auth_headers))

    proofs = recognize_proofs(response.body)
    matches = response_secrets(response)
    if proofs or matches:
        result.findings.append(
            _authenticated_object_route_finding(
                response,
                url=url,
                auth_headers=auth_headers,
                proofs=proofs,
                matches=matches,
                signal={"kind": "proof_or_secret_on_authenticated_object_seed"},
            )
        )
        if proofs:
            result.stop = True
            return result

    if _response_cannot_drive_idor_followup(response):
        return result

    transition_result = _probe_state_transition_batch(
        session,
        response.final_url or url,
        response.body,
        auth_headers=auth_headers,
        budget=result.budget,
    )
    _merge_probe_batch(result, transition_result)
    if result.stop:
        return result

    _record_listed_object_urls(session, response.final_url or url, response.body, work)
    _queue_response_followups(session, response.final_url or url, response.body, "", work)
    return result


def _authenticated_seed_request(
    response: ProbeResponse,
    url: str,
    auth_headers: dict[str, str],
) -> dict[str, object]:
    return response.summary(body_chars=320) | {
        "probe_kind": "idor_authenticated_seed",
        "url": url,
        "authenticated": bool(auth_headers),
    }


def _response_cannot_drive_idor_followup(response: ProbeResponse) -> bool:
    if _auth_blocked(response):
        return True
    return _looks_like_missing_object_response(response)


def _record_listed_object_urls(
    session: ProbeSession,
    base_url: str,
    body: str,
    work: _AuthenticatedRouteWork,
) -> None:
    for link in _same_origin_idor_links(session, base_url, body):
        work.listed_object_urls.add(_canonical_url_for_idor(link))


def _queue_response_followups(
    session: ProbeSession,
    base_url: str,
    body: str,
    candidate_id: str,
    work: _AuthenticatedRouteWork,
) -> None:
    for discovered in _idor_response_followup_urls(session, base_url, body, candidate_id):
        _queue_idor_url(
            discovered,
            queued=work.queued,
            queued_set=work.queued_set,
            seen=work.seen,
        )


def _probe_authenticated_followup_queue(
    session: ProbeSession,
    *,
    auth_headers: dict[str, str],
    work: _AuthenticatedRouteWork,
    budget: int,
) -> _ProbeBatch:
    result = _ProbeBatch(findings=[], requests=[], budget=budget)
    while work.queued and result.budget > 0 and len(work.seen) < 96:
        url = work.queued.pop(0)
        work.queued_set.discard(url)
        if url in work.seen:
            continue
        work.seen.add(url)
        followup_result = _probe_authenticated_followup_url(
            session,
            url,
            auth_headers=auth_headers,
            work=work,
            budget=result.budget,
        )
        _merge_probe_batch(result, followup_result)
        if result.stop:
            return result
    return result


def _probe_authenticated_followup_url(
    session: ProbeSession,
    url: str,
    *,
    auth_headers: dict[str, str],
    work: _AuthenticatedRouteWork,
    budget: int,
) -> _ProbeBatch:
    response = session.get(url, headers=auth_headers or None)
    result = _ProbeBatch(findings=[], requests=[], budget=budget - 1)
    result.requests.append(_authenticated_followup_request(response, url, auth_headers))

    proofs = recognize_proofs(response.body)
    matches = response_secrets(response)
    signal = _authenticated_object_route_signal(
        response,
        requested_url=url,
        listed_object_urls=work.listed_object_urls,
    )
    if proofs or matches or signal:
        result.findings.append(
            _authenticated_object_route_finding(
                response,
                url=url,
                auth_headers=auth_headers,
                proofs=proofs,
                matches=matches,
                signal=signal,
            )
        )
        if proofs:
            result.stop = True
            return result

    if _response_cannot_drive_idor_followup(response):
        return result

    transition_result = _probe_state_transition_batch(
        session,
        response.final_url or url,
        response.body,
        auth_headers=auth_headers,
        budget=result.budget,
    )
    _merge_probe_batch(result, transition_result)
    if result.stop:
        return result

    _queue_response_followups(session, response.final_url or url, response.body, "", work)
    return result


def _authenticated_followup_request(
    response: ProbeResponse,
    url: str,
    auth_headers: dict[str, str],
) -> dict[str, object]:
    return response.summary(body_chars=360) | {
        "probe_kind": "idor_authenticated_object_followup",
        "url": url,
        "authenticated": bool(auth_headers),
    }


def _merge_probe_batch(target: _ProbeBatch, source: _ProbeBatch) -> None:
    target.findings.extend(source.findings)
    target.requests.extend(source.requests)
    target.budget = source.budget
    target.stop = target.stop or source.stop


def _probe_idor_state_transition_pairs(
    session: ProbeSession,
    base_url: str,
    body: str,
    *,
    auth_headers: dict[str, str],
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    result = _probe_state_transition_batch(
        session,
        base_url,
        body,
        auth_headers=auth_headers,
        budget=budget,
    )
    return result.findings, result.requests, result.budget


def _probe_state_transition_batch(
    session: ProbeSession,
    base_url: str,
    body: str,
    *,
    auth_headers: dict[str, str],
    budget: int,
) -> _ProbeBatch:
    object_ids = _idor_html_object_ids(body)
    if not object_ids:
        return _ProbeBatch(findings=[], requests=[], budget=budget)

    pairs = _state_transition_pairs_from_body(session, base_url, body)
    if not pairs:
        return _ProbeBatch(findings=[], requests=[], budget=budget)

    result = _ProbeBatch(findings=[], requests=[], budget=budget)
    seen: set[tuple[str, str]] = set()
    candidates = _clustered_idor_transition_candidates(object_ids)
    for transition_template, read_templates in pairs[:4]:
        pair_result = _probe_state_transition_template_pair(
            session,
            base_url,
            transition_template,
            read_templates,
            candidates,
            auth_headers=auth_headers,
            seen=seen,
            budget=result.budget,
        )
        _merge_probe_batch(result, pair_result)
        if result.stop:
            return result
    return result


def _state_transition_pairs_from_body(
    session: ProbeSession,
    base_url: str,
    body: str,
) -> list[tuple[str, list[str]]]:
    same_origin_links = _same_origin_idor_links(session, base_url, body)
    templates = _dedupe(
        [
            *_idor_client_side_object_templates(body),
            *_idor_object_templates_from_urls(same_origin_links),
        ]
    )
    return _idor_transition_template_pairs(templates)


def _probe_state_transition_template_pair(
    session: ProbeSession,
    base_url: str,
    transition_template: str,
    read_templates: list[str],
    candidates: list[str],
    *,
    auth_headers: dict[str, str],
    seen: set[tuple[str, str]],
    budget: int,
) -> _ProbeBatch:
    result = _ProbeBatch(findings=[], requests=[], budget=budget)
    for object_id in candidates[:64]:
        if result.budget <= 1:
            return result
        transition_attempt = _probe_state_transition_candidate(
            session,
            base_url,
            transition_template,
            object_id,
            auth_headers=auth_headers,
            seen=seen,
            budget=result.budget,
        )
        _merge_probe_batch(result, transition_attempt.batch)
        if transition_attempt.response is None:
            continue
        if not _transition_response_allows_read(transition_attempt.response):
            continue

        read_result = _probe_state_transition_reads(
            session,
            base_url,
            read_templates,
            object_id,
            transition_attempt.url,
            auth_headers=auth_headers,
            seen=seen,
            budget=result.budget,
        )
        _merge_probe_batch(result, read_result)
        if result.stop:
            return result
    return result


def _probe_state_transition_candidate(
    session: ProbeSession,
    base_url: str,
    transition_template: str,
    object_id: str,
    *,
    auth_headers: dict[str, str],
    seen: set[tuple[str, str]],
    budget: int,
) -> _TransitionCandidateAttempt:
    result = _ProbeBatch(findings=[], requests=[], budget=budget)
    transition_url = _template_url(base_url, transition_template, object_id)
    key = ("transition", _canonical_url_for_idor(transition_url))
    if key in seen or not session.in_scope(transition_url):
        return _TransitionCandidateAttempt(batch=result, response=None, url=transition_url)

    seen.add(key)
    transition = session.get(transition_url, headers=auth_headers or None)
    result.budget -= 1
    result.requests.append(_state_transition_request(transition, transition_url, object_id))
    return _TransitionCandidateAttempt(batch=result, response=transition, url=transition_url)


def _template_url(base_url: str, template: str, object_id: str) -> str:
    replaced = template.replace("{id}", quote(object_id, safe=""))
    return urljoin(base_url, replaced)


def _state_transition_request(
    transition: ProbeResponse,
    transition_url: str,
    object_id: str,
) -> dict[str, object]:
    return transition.summary(body_chars=300) | {
        "probe_kind": "idor_state_transition_candidate",
        "url": transition_url,
        "candidate_id": object_id,
    }


def _transition_response_allows_read(transition: ProbeResponse) -> bool:
    if _auth_blocked(transition):
        return False
    if _looks_like_missing_object_response(transition):
        return False
    if transition.status is None:
        return False
    return transition.status < 500


def _probe_state_transition_reads(
    session: ProbeSession,
    base_url: str,
    read_templates: list[str],
    object_id: str,
    transition_url: str,
    *,
    auth_headers: dict[str, str],
    seen: set[tuple[str, str]],
    budget: int,
) -> _ProbeBatch:
    result = _ProbeBatch(findings=[], requests=[], budget=budget)
    for read_template in read_templates[:4]:
        if result.budget <= 0:
            return result
        read_result = _probe_state_transition_read(
            session,
            base_url,
            read_template,
            object_id,
            transition_url,
            auth_headers=auth_headers,
            seen=seen,
            budget=result.budget,
        )
        _merge_probe_batch(result, read_result)
        if result.stop:
            return result
    return result


def _probe_state_transition_read(
    session: ProbeSession,
    base_url: str,
    read_template: str,
    object_id: str,
    transition_url: str,
    *,
    auth_headers: dict[str, str],
    seen: set[tuple[str, str]],
    budget: int,
) -> _ProbeBatch:
    result = _ProbeBatch(findings=[], requests=[], budget=budget)
    read_url = _template_url(base_url, read_template, object_id)
    read_key = ("read", _canonical_url_for_idor(read_url))
    if read_key in seen or not session.in_scope(read_url):
        return result

    seen.add(read_key)
    read_response = session.get(read_url, headers=auth_headers or None)
    result.budget -= 1
    result.requests.append(
        _state_transition_read_request(read_response, read_url, object_id, transition_url)
    )

    proofs = recognize_proofs(read_response.body)
    matches = response_secrets(read_response)
    signal = _authenticated_object_route_signal(
        read_response,
        requested_url=read_url,
        listed_object_urls=set(),
    )
    if not (proofs or matches or signal):
        return result

    result.findings.append(
        _state_transition_read_finding(
            read_response,
            read_url=read_url,
            transition_url=transition_url,
            auth_headers=auth_headers,
            proofs=proofs,
            matches=matches,
            signal=signal,
        )
    )
    if proofs:
        result.stop = True
    return result


def _state_transition_read_request(
    read_response: ProbeResponse,
    read_url: str,
    object_id: str,
    transition_url: str,
) -> dict[str, object]:
    return read_response.summary(body_chars=420) | {
        "probe_kind": "idor_post_transition_read",
        "url": read_url,
        "candidate_id": object_id,
        "transition_url": transition_url,
    }


def _state_transition_read_finding(
    read_response: ProbeResponse,
    *,
    read_url: str,
    transition_url: str,
    auth_headers: dict[str, str],
    proofs: list[str],
    matches: list[str],
    signal: dict[str, object],
) -> dict[str, object]:
    transition_signal = dict(signal)
    transition_signal["transition"] = "state_action_then_read"
    transition_signal["transition_url"] = transition_url
    finding = _authenticated_object_route_finding(
        read_response,
        url=read_url,
        auth_headers=auth_headers,
        proofs=proofs,
        matches=matches,
        signal=transition_signal,
    )
    finding["type"] = _state_transition_finding_type(proofs, matches)
    return finding


def _state_transition_finding_type(proofs: list[str], matches: list[str]) -> str:
    if proofs or matches:
        return "idor_authenticated_transition_exposed_secret"
    return "idor_authenticated_transition_signal"


def _idor_transition_template_pairs(templates: list[str]) -> list[tuple[str, list[str]]]:
    transitions = _state_transition_templates(templates)
    reads = _object_read_templates(templates)
    pairs: list[tuple[str, list[str]]] = []
    for transition in transitions:
        transition_root = _template_object_root(transition)
        companions = _companion_read_templates(reads, transition, transition_root)
        if companions:
            pairs.append((transition, companions))
    return pairs[:8]


def _findings_include_proofs(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("proofs"):
            return True
    return False


def _state_transition_templates(templates: list[str]) -> list[str]:
    transitions: list[str] = []
    for template in templates:
        if _template_looks_state_transition(template):
            transitions.append(template)
    return transitions


def _object_read_templates(templates: list[str]) -> list[str]:
    reads: list[str] = []
    for template in templates:
        if _template_looks_object_read(template):
            reads.append(template)
    return reads


def _companion_read_templates(
    reads: list[str],
    transition: str,
    transition_root: str,
) -> list[str]:
    companions: list[str] = []
    for template in reads:
        if template == transition:
            continue
        if _template_object_root(template) == transition_root:
            companions.append(template)
    return companions


def _template_object_root(template: str) -> str:
    prefix, _sep, _suffix = template.partition("{id}")
    return prefix


def _template_looks_state_transition(template: str) -> bool:
    try:
        path = urlsplit(template).path.lower()
    except ValueError:
        return False
    return _path_has_template_action(
        path,
        (
            "accept",
            "activate",
            "add",
            "approve",
            "archive",
            "assign",
            "borrow",
            "checkout",
            "claim",
            "enable",
            "favorite",
            "grant",
            "join",
            "publish",
            "restore",
            "save",
            "share",
            "subscribe",
            "take",
            "transfer",
        ),
    )


def _template_looks_object_read(template: str) -> bool:
    try:
        path = urlsplit(template).path.lower()
    except ValueError:
        return False
    return _path_has_template_action(
        path,
        (
            "account",
            "detail",
            "details",
            "document",
            "download",
            "file",
            "flag",
            "invoice",
            "profile",
            "proof",
            "receipt",
            "record",
            "secret",
            "view",
        ),
    )


def _path_has_template_action(path: str, tokens: tuple[str, ...]) -> bool:
    for token in tokens:
        if f"/{token}" in path or path.endswith(token):
            return True
    return False


def _clustered_idor_transition_candidates(values: list[str]) -> list[str]:
    candidates = _deduped_idor_values(values)
    numeric = _sorted_numeric_values(candidates)
    salient_offsets = (1, 2, 3, 5, 8, 10, 13, 16, 20, 25, 32)
    for value in numeric[:8]:
        for offset in salient_offsets:
            for candidate in (value - offset, value + offset):
                if candidate >= 0:
                    candidates.append(str(candidate))
    for left, right in zip(numeric, numeric[1:]):
        gap = right - left
        if gap <= 1 or gap > 2_000:
            continue
        for numerator, denominator in ((1, 2), (1, 3), (2, 3), (1, 4), (3, 4)):
            center = left + (gap * numerator // denominator)
            for offset in _idor_near_offsets(radius=8):
                candidate = center + offset
                if left < candidate < right:
                    candidates.append(str(candidate))
    return _dedupe(candidates)[:160]


def _authenticated_object_seed_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls: list[str] = []
    for endpoint in [*_surface_endpoints(state), *_signal_endpoints(state)]:
        text = str(endpoint).strip()
        if not text:
            continue
        absolute = session.absolute(text)
        if session.in_scope(absolute) and _url_looks_idor_followup(absolute):
            urls.append(absolute)
    for path in _IDOR_AUTH_OBJECT_SEED_PATHS:
        urls.append(session.absolute(path))
    return _dedupe(urls)[:40]


def _queue_idor_url(
    url: str,
    *,
    queued: list[str],
    queued_set: set[str],
    seen: set[str],
) -> None:
    canonical = _canonical_url_for_idor(url)
    if not canonical or canonical in queued_set or canonical in seen:
        return
    queued.append(canonical)
    queued_set.add(canonical)


def _canonical_url_for_idor(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _authenticated_object_route_signal(
    response: ProbeResponse,
    *,
    requested_url: str,
    listed_object_urls: set[str],
) -> dict[str, object]:
    if response.status is None or response.status >= 400:
        return {}
    if _auth_blocked(response) or _looks_like_missing_object_response(response):
        return {}
    canonical = _canonical_url_for_idor(response.final_url or requested_url)
    if canonical in listed_object_urls:
        return {}
    try:
        path = urlsplit(canonical).path
    except ValueError:
        return {}
    ids = re.findall(r"/(\d{1,12})(?:/|$)", path)
    if not ids:
        return {}
    return {
        "kind": "authenticated_unlisted_object_route_accessible",
        "object_ids": ids[:4],
        "status": response.status,
        "body_len": len(response.body),
    }


def _authenticated_object_route_finding(
    response: ProbeResponse,
    *,
    url: str,
    auth_headers: dict[str, str],
    proofs: list[str],
    matches: list[str],
    signal: dict[str, object],
) -> dict[str, object]:
    finding_type = (
        "idor_authenticated_object_exposed_secret"
        if proofs or matches
        else "idor_authenticated_object_route_signal"
    )
    replay: dict[str, object] = {"method": "GET", "url": url}
    if auth_headers:
        replay["headers"] = auth_headers
    return {
        "type": finding_type,
        "url": url,
        "signal": signal,
        "proofs": proofs,
        "matches": matches,
        "response": response.summary(body_chars=520),
        "replay": replay,
        "next": (
            "This authenticated object route is accessible outside the listed object set. "
            "Continue enumerating sibling object IDs and proof/detail suffixes with the same authenticated context."
        ),
    }


def _prioritize_idor_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    def sort_key(finding: dict[str, object]) -> tuple[int, str]:
        if finding.get("proofs") or finding.get("matches"):
            return (0, str(finding.get("url") or ""))
        if "exposed_secret" in str(finding.get("type") or ""):
            return (1, str(finding.get("url") or ""))
        if _target_headers({"form": finding.get("input")}):
            return (2, str(finding.get("url") or ""))
        return (3, str(finding.get("url") or ""))

    return sorted(findings, key=sort_key)


def _probe_idor_followups(
    session: ProbeSession,
    target: dict[str, object],
    candidate_id: str,
    *,
    baseline: ProbeResponse,
    response: ProbeResponse,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    headers = _target_headers(target)
    followup_headers = _followup_headers(headers, response)
    followup_urls = _dedupe(
        [
            *_idor_followup_urls(target, candidate_id),
            *_response_redirect_followup_urls(session, response),
            *_response_redirect_followup_urls(session, baseline),
            *_idor_response_followup_urls(
                session,
                response.final_url or str(target.get("url") or ""),
                response.body,
                candidate_id,
            ),
            *_idor_response_followup_urls(
                session,
                baseline.final_url or str(target.get("url") or ""),
                baseline.body,
                candidate_id,
            ),
        ]
    )
    queued_urls = set(followup_urls)
    index = 0
    while index < len(followup_urls) and index < 64:
        if budget <= 0:
            break
        url = followup_urls[index]
        index += 1
        followup = session.get(url, headers=followup_headers or None)
        budget -= 1
        requests.append(
            followup.summary(body_chars=260)
            | {
                "probe_kind": "idor_followup",
                "url": url,
                "candidate_id": candidate_id,
                "target": _target_brief(target),
            }
        )
        proofs = recognize_proofs(followup.body)
        secrets_found = response_secrets(followup)
        signal = _idor_access_signal(
            baseline=baseline,
            response=followup,
            original_id=str(target.get("baseline_id") or ""),
            candidate_id=candidate_id,
        )
        if not (proofs or secrets_found or signal):
            continue
        findings.append(
            {
                "type": "idor_boundary_followup_exposed_secret"
                if proofs or secrets_found
                else "idor_boundary_followup_signal",
                "input": _target_brief(target),
                "candidate_id": candidate_id,
                "url": url,
                "signal": signal,
                "proofs": proofs,
                "matches": secrets_found,
                "source_response": response.summary(body_chars=260),
                "response": followup.summary(body_chars=420),
                "replay": {"method": "GET", "url": url},
                "next": "A neighboring object route is accessible; keep this object context and fetch sibling detail/proof/admin routes.",
            }
        )
        for discovered_url in _idor_response_followup_urls(
            session,
            followup.final_url or url,
            followup.body,
            candidate_id,
        ):
            if discovered_url in queued_urls or len(followup_urls) >= 64:
                continue
            queued_urls.add(discovered_url)
            followup_urls.append(discovered_url)
        if proofs:
            break
    return findings, requests, budget


def _headers_without_cookie(headers: dict[str, str]) -> dict[str, str]:
    filtered: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() != "cookie":
            filtered[name] = value
    return filtered


def _followup_headers(headers: dict[str, str], response: ProbeResponse) -> dict[str, str]:
    if _response_sets_cookie(response):
        return _headers_without_cookie(headers)
    return headers


def _response_sets_cookie(response: ProbeResponse) -> bool:
    return bool(
        str(response.headers.get("set-cookie") or response.headers.get("Set-Cookie") or "").strip()
    )


def _response_redirect_followup_urls(session: ProbeSession, response: ProbeResponse) -> list[str]:
    location = str(response.headers.get("location") or response.headers.get("Location") or "")
    if not location:
        return []
    absolute = urljoin(response.final_url or response.url or session.target_url, location)
    if not session.in_scope(absolute):
        return []
    return [absolute]


def _idor_response_followup_urls(
    session: ProbeSession, base_url: str, body: str, candidate_id: str
) -> list[str]:
    urls: list[str] = []
    object_ids = _idor_html_object_ids(body)
    if _value_looks_idor_id(candidate_id):
        object_ids.append(candidate_id)
    same_origin_links = _same_origin_idor_links(session, base_url, body)
    for url in same_origin_links:
        urls.append(url)
    templates = _dedupe(
        [
            *_idor_client_side_object_templates(body),
            # Preserve an observed query-string object route (for example,
            # /api/invoices?id=9001) and mutate that parameter in place before
            # falling back to guessed object routes.
            *_idor_object_templates_from_urls([base_url, *same_origin_links]),
        ]
    )
    if _values_include_idor_id(object_ids):
        templates = _dedupe([*templates, *_common_object_id_read_templates()])
    candidate_pool = _dedupe(
        [*_clustered_idor_candidates(object_ids), *_object_id_hint_candidates_from_text(body)]
    )
    for template in templates:
        for object_id in candidate_pool:
            urls.append(urljoin(base_url, template.replace("{id}", quote(object_id, safe=""))))
    return _deduped_idor_followup_urls(urls)[:96]


def _values_include_idor_id(values: list[str]) -> bool:
    for value in values:
        if _value_looks_idor_id(value):
            return True
    return False


def _deduped_idor_followup_urls(urls: list[str]) -> list[str]:
    followups: list[str] = []
    for url in urls:
        if _url_looks_idor_followup(url):
            followups.append(url)
    return _dedupe(followups)


def _common_object_id_read_templates() -> list[str]:
    return [
        "/company/{id}",
        "/company/{id}/jobs",
        "/companies/{id}",
        "/companies/{id}/jobs",
        "/profile/{id}",
        "/profiles/{id}",
        "/user/{id}",
        "/users/{id}",
        "/account/{id}",
        "/accounts/{id}",
        "/tenant/{id}",
        "/tenants/{id}",
        "/workspace/{id}",
        "/workspaces/{id}",
        "/job/{id}",
        "/jobs/{id}",
        "/api/company/{id}",
        "/api/company/{id}/jobs",
        "/api/companies/{id}",
        "/api/companies/{id}/jobs",
        "/api/profile/{id}",
        "/api/user/{id}",
        "/api/users/{id}",
        "/company?id={id}",
        "/profile?id={id}",
        "/user?id={id}",
        "/account?id={id}",
    ]


def _object_id_hint_candidates_from_text(text: str) -> list[str]:
    raw_ids = _idor_html_object_ids(text)
    object_ids = _mongo_object_ids(raw_ids)
    numeric_ids = _numeric_id_strings(raw_ids)
    distances: list[int] = []
    for pattern in (
        r"""(?is)["'](?:distance|delta|diff|offset|counter_delta|counterDiff)["']\s*:\s*(-?\d{1,9})""",
        r"""(?is)\byou\s+are\s+(-?\d{1,9})\s+from\b""",
        r"""(?is)\b(-?\d{1,9})\s+from\s+(?:your\s+)?target\b""",
    ):
        for match in re.finditer(pattern, text or ""):
            try:
                value = int(match.group(1))
            except ValueError:
                continue
            if 0 < abs(value) <= 1_000_000:
                distances.append(value)
    timestamp_prefixes: list[str] = []
    for pattern in (
        r"""(?is)\b(?:appStartTimestamp|startTimestamp|createdTimestamp|unix\s+timestamp)\b[^0-9]{0,80}(\d{9,11})""",
        r"""(?is)["'](?:startTime|start_time|createdAt|created_at)["']\s*:\s*["']?(\d{9,11})""",
    ):
        for match in re.finditer(pattern, text or ""):
            try:
                timestamp = int(match.group(1))
            except ValueError:
                continue
            if 0 <= timestamp <= 0xFFFFFFFF:
                timestamp_prefixes.append(f"{timestamp:08x}")
    candidates: list[str] = []
    if numeric_ids:
        candidates.extend(_clustered_idor_candidates(numeric_ids)[:32])
    for object_id in object_ids[:6]:
        middle = object_id[8:18]
        current_counter = int(object_id[-6:], 16)
        prefixes = _dedupe([*timestamp_prefixes, object_id[:8]])[:4]
        for distance in _deduped_distance_strings(distances)[:6]:
            delta = int(distance)
            for candidate_counter in (current_counter - delta, current_counter + delta):
                if not 0 <= candidate_counter <= 0xFFFFFF:
                    continue
                for prefix in prefixes:
                    candidates.append(f"{prefix}{middle}{candidate_counter:06x}")
    return _deduped_idor_values(candidates)[:48]


def _mongo_object_ids(values: list[str]) -> list[str]:
    object_ids: list[str] = []
    for value in values:
        if _looks_mongo_object_id(value):
            object_ids.append(value)
    return object_ids


def _numeric_id_strings(values: list[str]) -> list[str]:
    numeric_ids: list[str] = []
    for value in values:
        if re.fullmatch(r"\d+", value or ""):
            numeric_ids.append(value)
    return numeric_ids


def _deduped_distance_strings(distances: list[int]) -> list[str]:
    values: list[str] = []
    for distance in distances:
        values.append(str(distance))
    return _dedupe(values)


def _same_origin_idor_links(session: ProbeSession, base_url: str, body: str) -> list[str]:
    urls: list[str] = []
    for pattern in (
        r"""(?is)\b(?:href|src|action)\s*=\s*(['"])([^'"]{1,500})\1""",
        r"""(?is)(['"])(/[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{1,500})\1""",
    ):
        for match in re.finditer(pattern, body):
            value = html.unescape(match.group(2).strip())
            if not value or value.startswith(("javascript:", "data:", "mailto:", "#")):
                continue
            absolute = urljoin(base_url, value)
            if session.in_scope(absolute):
                urls.append(absolute)
    return _dedupe(urls)[:24]


def _idor_html_object_ids(body: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"""(?is)\bdata-[a-z0-9_-]*id\s*=\s*(['"])([^'"]{1,80})\1""", body):
        values.append(html.unescape(match.group(2)))
    for match in re.finditer(
        r"""(?is)<input\b[^>]*\bname\s*=\s*(['"])([^'"]*id[^'"]*)\1[^>]*\bvalue\s*=\s*(['"])([^'"]{1,80})\3""",
        body,
    ):
        values.append(html.unescape(match.group(4)))
    for match in re.finditer(r"""(?is)/(?:[^'"\s<>/]+/)*(\d{1,12})(?:[/?#'"\s<>]|$)""", body):
        values.append(match.group(1))
    for match in re.finditer(
        r"""(?is)["'](?:[a-z0-9_-]*id|_id|objectId|object_id|profileId|profile_id|accountId|account_id|companyId|company_id|tenantId|tenant_id|workspaceId|workspace_id)["']\s*[:=]\s*["']?([a-f0-9]{24}|\d{1,12})["']?""",
        body,
    ):
        values.append(match.group(1).lower())
    for match in re.finditer(r"""(?is)/(?:[^'"\s<>/]+/)*([a-f0-9]{24})(?:[/?#'"\s<>]|$)""", body):
        values.append(match.group(1).lower())
    return _deduped_idor_values(values)[:24]


def _idor_client_side_object_templates(body: str) -> list[str]:
    templates: list[str] = []
    string_concat = re.compile(
        r"""(?is)(['"])(/[^'"]*/)\1\s*\+\s*[A-Za-z_$][\w$]*(?:\.[\w$().'-]+)?\s*\+\s*(['"])([^'"]*)\3"""
    )
    for match in string_concat.finditer(body):
        template = match.group(2) + "{id}" + match.group(4)
        if _template_looks_idor_object_route(template):
            templates.append(template)
    template_literal = re.compile(r"""(?is)`(/[^`$]*?)\$\{[^}]+\}([^`]*)`""")
    for match in template_literal.finditer(body):
        template = match.group(1) + "{id}" + match.group(2)
        if _template_looks_idor_object_route(template):
            templates.append(template)
    href_template = re.compile(
        r"""(?is)\b(?:href|src|action)\s*=\s*(['"])(/[^'"]*\{id\}[^'"]*)\1"""
    )
    for match in href_template.finditer(body):
        template = html.unescape(match.group(2))
        if _template_looks_idor_object_route(template):
            templates.append(template)
    return _dedupe(templates)[:8]


def _idor_object_templates_from_urls(urls: list[str]) -> list[str]:
    templates: list[str] = []
    for url in urls:
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        segments = parts.path.split("/")
        for index, segment in enumerate(segments):
            if not (re.fullmatch(r"\d{1,12}", segment) or _looks_mongo_object_id(segment)):
                continue
            candidate_segments = list(segments)
            candidate_segments[index] = "{id}"
            template = urlunsplit(("", "", "/".join(candidate_segments), parts.query, ""))
            if _template_looks_idor_object_route(template):
                templates.append(template)
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        for index, (name, value) in enumerate(query_pairs):
            if not (_name_looks_idor(name, url) or _value_looks_idor_id(value)):
                continue
            candidate_pairs = list(query_pairs)
            candidate_pairs[index] = (name, "{id}")
            query = urlencode(candidate_pairs, doseq=True).replace("%7Bid%7D", "{id}")
            template = urlunsplit(("", "", parts.path or "/", query, ""))
            if _template_looks_idor_object_route(template):
                templates.append(template)
    return _dedupe(templates)[:12]


def _template_looks_idor_object_route(template: str) -> bool:
    return "{id}" in template and _url_looks_idor_followup(template)


def _url_looks_idor_followup(url: str) -> bool:
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return False
    if not path or path.endswith(
        (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")
    ):
        return False
    return _path_contains_token(
        path,
        (
            "account",
            "admin",
            "case",
            "claim",
            "company",
            "detail",
            "document",
            "download",
            "file",
            "flag",
            "invoice",
            "job",
            "order",
            "profile",
            "proof",
            "receipt",
            "record",
            "secret",
            "tenant",
            "user",
            "workspace",
        ),
    )


def _clustered_idor_candidates(values: list[str]) -> list[str]:
    candidates = _deduped_idor_values(values)
    numeric = _sorted_numeric_values(candidates)
    object_ids = _mongo_object_ids(candidates)
    for object_id in object_ids[:8]:
        candidates.extend(_object_id_counter_candidates(object_id))
    # Enumerated neighbours are the highest-value first move for an observed
    # object identifier. Keep them ahead of broad gap interpolation so a tight
    # request budget cannot starve id=9001 -> id=9002 style checks.
    for value in numeric[:10]:
        for offset in _idor_near_offsets(radius=12):
            if offset == 0:
                continue
            candidate = value + offset
            if candidate >= 0:
                candidates.append(str(candidate))
    gap_pairs = _numeric_gap_pairs(numeric)
    for _gap, left, right in sorted(gap_pairs, reverse=True)[:8]:
        gap = right - left
        for numerator, denominator in ((1, 2), (1, 3), (2, 3), (1, 4), (3, 4)):
            center = left + (gap * numerator // denominator)
            for offset in _idor_near_offsets(radius=8):
                candidate = center + offset
                if left < candidate < right:
                    candidates.append(str(candidate))
    return _dedupe(candidates)[:128]


def _idor_near_offsets(*, radius: int) -> list[int]:
    offsets = [0]
    for distance in range(1, radius + 1):
        offsets.extend((-distance, distance))
    return offsets


def _idor_followup_urls(target: dict[str, object], candidate_id: str) -> list[str]:
    kind = str(target.get("kind") or "")
    if kind == "path_segment":
        candidate_url = _replace_path_segment(
            str(target.get("url") or ""),
            _int_value(target.get("path_index")),
            candidate_id,
        )
    else:
        replay_url = _target_replay(target, candidate_id).get("url")
        candidate_url = _string_replay_url(replay_url)
    if not candidate_url:
        return []
    try:
        parts = urlsplit(candidate_url)
    except ValueError:
        return []
    base_path = parts.path.rstrip("/") or "/"
    paths = [base_path]
    if kind == "path_segment":
        segments = base_path.split("/")
        index = _int_value(target.get("path_index"))
        if 0 <= index < len(segments):
            object_root = "/".join(segments[: index + 1]) or "/"
            paths.append(object_root)
            for suffix in (
                "flag",
                "proof",
                "secret",
                "admin",
                "details",
                "detail",
                "profile",
                "account",
                "jobs",
                "files",
                "documents",
                "settings",
            ):
                paths.append(object_root.rstrip("/") + "/" + suffix)
    urls = _urls_from_paths(parts.scheme, parts.netloc, parts.query, paths)
    return _dedupe(urls)


def _deduped_idor_values(values: list[str]) -> list[str]:
    candidates: list[str] = []
    for value in values:
        if _value_looks_idor_id(value):
            candidates.append(value)
    return _dedupe(candidates)


def _sorted_numeric_values(values: list[str]) -> list[int]:
    numeric: set[int] = set()
    for value in values:
        if re.fullmatch(r"\d+", value or ""):
            numeric.add(int(value))
    return sorted(numeric)


def _path_contains_token(path: str, tokens: tuple[str, ...]) -> bool:
    for token in tokens:
        if token in path:
            return True
    return False


def _numeric_gap_pairs(numeric: list[int]) -> list[tuple[int, int, int]]:
    gap_pairs: list[tuple[int, int, int]] = []
    for left, right in zip(numeric, numeric[1:]):
        gap = right - left
        if 1 < gap <= 2_000:
            gap_pairs.append((gap, left, right))
    return gap_pairs


def _string_replay_url(replay_url: object) -> str:
    if isinstance(replay_url, str):
        return replay_url
    return ""


def _urls_from_paths(
    scheme: str,
    netloc: str,
    query: str,
    paths: list[str],
) -> list[str]:
    urls: list[str] = []
    for path in paths:
        urls.append(urlunsplit((scheme, netloc, path, query, "")))
    return urls
