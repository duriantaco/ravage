from __future__ import annotations

import html
import json
import re
from urllib.parse import urljoin

from ravage.deterministic_agents.auth_credentials import _dedupe_pairs
from ravage.deterministic_agents.auth_materials import _redact_auth_headers
from ravage.deterministic_agents.auth_object_targets import (
    _clustered_numeric_candidates,
    _looks_numeric_id,
    _optional_headers,
    _proof_or_secret_finding_type,
)
from ravage.deterministic_agents.auth_session_support import IdentityDelta
from ravage.probe_suite_parts.support import _dedupe
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs

__all__ = [
    "_client_side_authenticated_followup",
    "_client_side_object_templates",
    "_html_object_ids",
    "_looks_identity_header_name",
]

_CLIENT_SIDE_FOLLOWUP_LIMIT = 64
_OBJECT_ROUTE_TOKENS = (
    "account",
    "case",
    "claim",
    "company",
    "document",
    "file",
    "invoice",
    "job",
    "order",
    "profile",
    "receipt",
    "record",
    "user",
)
_MUTATING_ROUTE_TOKENS = (
    "archive",
    "assign",
    "claim",
    "delete",
    "remove",
    "restore",
    "share",
    "transfer",
    "approve",
    "submit",
)
_ROUTE_SIGNAL_MARKERS = (
    "receipt",
    "invoice",
    "order",
    "record",
    "account",
    "document",
    "company",
    "job",
)


def _client_side_authenticated_followup(
    *,
    session: ProbeSession,
    response: ProbeResponse,
    headers: dict[str, str],
    object_ids: list[str] | None = None,
    object_templates: list[str] | None = None,
) -> IdentityDelta:
    requests: list[dict[str, object]] = []
    route_result = _client_side_object_routes_followup(
        session=session,
        response=response,
        headers=headers,
        object_ids=object_ids,
        object_templates=object_templates,
    )
    requests.extend(route_result.requests)
    if route_result.finding:
        return route_result

    header_result = _trusted_identity_header_followup(session=session, response=response, headers=headers)
    requests.extend(header_result.requests)
    if header_result.finding:
        return header_result
    return IdentityDelta(finding=None, requests=requests)


def _client_side_object_routes_followup(
    *,
    session: ProbeSession,
    response: ProbeResponse,
    headers: dict[str, str],
    object_ids: list[str] | None = None,
    object_templates: list[str] | None = None,
) -> IdentityDelta:
    local_ids = _html_object_ids(response.body)
    ids = _route_candidate_ids(local_ids, object_ids)
    templates = _route_templates(response.body, object_templates)
    requests: list[dict[str, object]] = []
    if not ids or not templates:
        return IdentityDelta(finding=None, requests=requests)

    candidates = _clustered_numeric_candidates(ids)
    if not local_ids:
        candidates = candidates[:8]
    return _client_side_route_candidates(
        session=session,
        response=response,
        headers=headers,
        templates=templates,
        candidates=candidates,
        requests=requests,
    )


def _route_candidate_ids(local_ids: list[str], object_ids: list[str] | None) -> list[str]:
    ids: list[str] = []
    if local_ids:
        ids.extend(local_ids)
    elif object_ids:
        ids.extend(object_ids)
    return _dedupe(ids)[:24]


def _route_templates(body: str, object_templates: list[str] | None) -> list[str]:
    templates: list[str] = []
    if object_templates:
        templates.extend(object_templates)
    templates.extend(_client_side_object_templates(body))
    return _dedupe(templates)[:12]


def _client_side_route_candidates(
    *,
    session: ProbeSession,
    response: ProbeResponse,
    headers: dict[str, str],
    templates: list[str],
    candidates: list[str],
    requests: list[dict[str, object]],
) -> IdentityDelta:
    spent = 0
    best_signal: dict[str, object] | None = None
    seen: set[str] = set()
    for candidate in candidates:
        for template in templates[:4]:
            if spent >= _CLIENT_SIDE_FOLLOWUP_LIMIT:
                break
            result = _probe_client_side_route(
                session=session,
                response=response,
                headers=headers,
                candidate=candidate,
                template=template,
                templates=templates,
                seen=seen,
                requests=requests,
            )
            spent += result.requests_spent
            if result.delta is not None:
                return result.delta
            if best_signal is None and result.signal is not None:
                best_signal = result.signal
        if spent >= _CLIENT_SIDE_FOLLOWUP_LIMIT:
            break
    return IdentityDelta(finding=best_signal, requests=requests)


class _RouteProbeResult:
    def __init__(
        self,
        *,
        requests_spent: int,
        delta: IdentityDelta | None = None,
        signal: dict[str, object] | None = None,
    ) -> None:
        self.requests_spent = requests_spent
        self.delta = delta
        self.signal = signal


def _probe_client_side_route(
    *,
    session: ProbeSession,
    response: ProbeResponse,
    headers: dict[str, str],
    candidate: str,
    template: str,
    templates: list[str],
    seen: set[str],
    requests: list[dict[str, object]],
) -> _RouteProbeResult:
    url = urljoin(response.final_url, template.replace("{id}", candidate))
    if not session.in_scope(url):
        return _RouteProbeResult(requests_spent=0)

    route_key = json.dumps({"url": url, "headers": headers}, sort_keys=True)
    if route_key in seen:
        return _RouteProbeResult(requests_spent=0)

    seen.add(route_key)
    probe = session.get(url, headers=_optional_headers(headers))
    requests.append(_client_route_request(probe, response.final_url, template, candidate, headers))
    finding = _client_object_route_finding(
        probe=probe,
        source_url=response.final_url,
        template=template,
        candidate=candidate,
        url=url,
        headers=headers,
    )
    if finding:
        return _RouteProbeResult(
            requests_spent=1,
            delta=IdentityDelta(finding=finding, requests=requests),
        )

    readback = _client_side_mutation_readback(
        session=session,
        response=response,
        headers=headers,
        candidate=candidate,
        template=template,
        templates=templates,
        requests=requests,
    )
    if readback.delta is not None:
        return _RouteProbeResult(requests_spent=1 + readback.requests_spent, delta=readback.delta)

    signal = None
    if _object_route_signal(probe, candidate):
        signal = _client_side_route_signal(response.final_url, template, candidate, probe, url, headers)
    return _RouteProbeResult(requests_spent=1 + readback.requests_spent, signal=signal)


def _client_route_request(
    probe: ProbeResponse,
    source_url: str,
    template: str,
    candidate: str,
    headers: dict[str, str],
) -> dict[str, object]:
    payload = probe.summary(body_chars=520)
    payload["probe_kind"] = "auth_client_side_object_route"
    payload["source_url"] = source_url
    payload["template"] = template
    payload["candidate_id"] = candidate
    payload["headers_used"] = _redact_auth_headers(headers)
    return payload


class _MutationReadbackResult:
    def __init__(
        self,
        *,
        requests_spent: int,
        delta: IdentityDelta | None = None,
    ) -> None:
        self.requests_spent = requests_spent
        self.delta = delta


def _client_side_mutation_readback(
    *,
    session: ProbeSession,
    response: ProbeResponse,
    headers: dict[str, str],
    candidate: str,
    template: str,
    templates: list[str],
    requests: list[dict[str, object]],
) -> _MutationReadbackResult:
    if not _template_looks_mutating_route(template):
        return _MutationReadbackResult(requests_spent=0)

    spent = 0
    for read_template in templates[:4]:
        if read_template == template or _template_looks_mutating_route(read_template):
            continue
        read_url = urljoin(response.final_url, read_template.replace("{id}", candidate))
        if not session.in_scope(read_url):
            continue

        read_probe = session.get(read_url, headers=_optional_headers(headers))
        spent += 1
        requests.append(_client_readback_request(read_probe, response.final_url, read_template, candidate, template, headers))
        finding = _client_object_route_finding(
            probe=read_probe,
            source_url=response.final_url,
            template=read_template,
            candidate=candidate,
            url=read_url,
            headers=headers,
        )
        if finding:
            return _MutationReadbackResult(
                requests_spent=spent,
                delta=IdentityDelta(finding=finding, requests=requests),
            )
    return _MutationReadbackResult(requests_spent=spent)


def _client_readback_request(
    probe: ProbeResponse,
    source_url: str,
    template: str,
    candidate: str,
    after_template: str,
    headers: dict[str, str],
) -> dict[str, object]:
    payload = probe.summary(body_chars=520)
    payload["probe_kind"] = "auth_client_side_object_route_readback"
    payload["source_url"] = source_url
    payload["template"] = template
    payload["candidate_id"] = candidate
    payload["after_template"] = after_template
    payload["headers_used"] = _redact_auth_headers(headers)
    return payload


def _client_side_route_signal(
    source_url: str,
    template: str,
    candidate: str,
    probe: ProbeResponse,
    url: str,
    headers: dict[str, str],
) -> dict[str, object]:
    return {
        "type": "session_client_side_idor_signal",
        "source_url": source_url,
        "template": template,
        "candidate_id": candidate,
        "response": probe.summary(body_chars=520),
        "replay": {"method": "GET", "url": url, "headers": _redact_auth_headers(headers)},
        "next": "Continue bounded object-ID enumeration with the authenticated session and this client-side route template.",
    }


def _client_object_route_finding(
    *,
    probe: ProbeResponse,
    source_url: str,
    template: str,
    candidate: str,
    url: str,
    headers: dict[str, str],
) -> dict[str, object] | None:
    proofs = recognize_proofs(probe.body)
    secrets_found = response_secrets(probe)
    if not proofs and not secrets_found:
        return None

    finding_type = _proof_or_secret_finding_type(
        has_proof=bool(proofs),
        proof_type="session_client_side_idor_proof",
        secret_type="session_client_side_idor_secret",
    )
    return {
        "type": finding_type,
        "source_url": source_url,
        "template": template,
        "candidate_id": candidate,
        "proofs": proofs,
        "matches": secrets_found,
        "response": probe.summary(body_chars=900),
        "replay": {"method": "GET", "url": url, "headers": _redact_auth_headers(headers)},
    }


def _template_looks_mutating_route(template: str) -> bool:
    lowered = template.lower()
    for token in _MUTATING_ROUTE_TOKENS:
        if token in lowered:
            return True
    return False


def _trusted_identity_header_followup(
    *,
    session: ProbeSession,
    response: ProbeResponse,
    headers: dict[str, str],
) -> IdentityDelta:
    observed = _observed_identity_headers(response.body, headers)
    requests: list[dict[str, object]] = []
    if not observed:
        return IdentityDelta(finding=None, requests=requests)

    urls = _identity_header_followup_urls(session, response)
    spent = 0
    for header, current_value in observed[:4]:
        for candidate in _identity_header_candidates(current_value):
            for url in urls[:3]:
                if spent >= 54:
                    return IdentityDelta(finding=None, requests=requests)
                if not session.in_scope(url):
                    continue
                result = _probe_identity_header(
                    session=session,
                    url=url,
                    header=header,
                    candidate=candidate,
                    requests=requests,
                )
                spent += 1
                if result is not None:
                    return result
    return IdentityDelta(finding=None, requests=requests)


def _probe_identity_header(
    *,
    session: ProbeSession,
    url: str,
    header: str,
    candidate: str,
    requests: list[dict[str, object]],
) -> IdentityDelta | None:
    probe = session.get(url, headers={header: candidate})
    requests.append(_identity_header_request(probe, url, header, candidate))
    proofs = recognize_proofs(probe.body)
    secrets_found = response_secrets(probe)
    if not proofs and not secrets_found:
        return None

    finding_type = _proof_or_secret_finding_type(
        has_proof=bool(proofs),
        proof_type="session_identity_header_idor_proof",
        secret_type="session_identity_header_idor_secret",
    )
    return IdentityDelta(
        finding={
            "type": finding_type,
            "url": url,
            "header": header,
            "candidate_id": candidate,
            "proofs": proofs,
            "matches": secrets_found,
            "response": probe.summary(body_chars=900),
            "replay": {"method": "GET", "url": url, "headers": {header: candidate}},
        },
        requests=requests,
    )


def _identity_header_request(
    probe: ProbeResponse,
    url: str,
    header: str,
    candidate: str,
) -> dict[str, object]:
    payload = probe.summary(body_chars=520)
    payload["probe_kind"] = "auth_identity_header_idor"
    payload["url"] = url
    payload["header"] = header
    payload["candidate_id"] = candidate
    return payload


def _identity_header_followup_urls(session: ProbeSession, response: ProbeResponse) -> list[str]:
    urls: list[str] = []
    if response.final_url:
        urls.append(response.final_url)
    urls.append(session.absolute("/dashboard"))
    urls.append(session.absolute("/account"))
    urls.append(session.absolute("/profile"))
    return _dedupe(urls)


def _html_object_ids(body: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"""(?is)\bdata-[a-z0-9_-]*id\s*=\s*(['"])([^'"]{1,80})\1""", body):
        values.append(html.unescape(match.group(2)))
    for match in re.finditer(
        r"""(?is)<input\b[^>]*\bname\s*=\s*(['"])([^'"]*id[^'"]*)\1[^>]*\bvalue\s*=\s*(['"])([^'"]{1,80})\3""",
        body,
    ):
        values.append(html.unescape(match.group(4)))

    numeric_values: list[str] = []
    for value in values:
        if _looks_numeric_id(value):
            numeric_values.append(value)
    return _dedupe(numeric_values)[:12]


def _client_side_object_templates(body: str) -> list[str]:
    templates: list[str] = []
    templates.extend(_string_concat_templates(body))
    templates.extend(_template_literal_routes(body))
    templates.extend(_href_templates(body))
    return _dedupe(templates)[:8]


def _string_concat_templates(body: str) -> list[str]:
    templates: list[str] = []
    pattern = re.compile(
        r"""(?is)(['"])(/[^'"]*/)\1\s*\+\s*[A-Za-z_$][\w$]*(?:\.[\w$().'-]+)?\s*\+\s*(['"])([^'"]*)\3"""
    )
    for match in pattern.finditer(body):
        template = match.group(2) + "{id}" + match.group(4)
        if _template_looks_object_route(template):
            templates.append(template)
    return templates


def _template_literal_routes(body: str) -> list[str]:
    templates: list[str] = []
    pattern = re.compile(r"""(?is)`(/[^`$]*?)\$\{[^}]+\}([^`]*)`""")
    for match in pattern.finditer(body):
        template = match.group(1) + "{id}" + match.group(2)
        if _template_looks_object_route(template):
            templates.append(template)
    return templates


def _href_templates(body: str) -> list[str]:
    templates: list[str] = []
    pattern = re.compile(r"""(?is)\b(?:href|src)\s*=\s*(['"])(/[^'"]*\{id\}[^'"]*)\1""")
    for match in pattern.finditer(body):
        template = html.unescape(match.group(2))
        if _template_looks_object_route(template):
            templates.append(template)
    return templates


def _template_looks_object_route(template: str) -> bool:
    lowered = template.lower()
    if "{id}" not in template or not template.startswith("/"):
        return False
    for token in _OBJECT_ROUTE_TOKENS:
        if token in lowered:
            return True
    return False


def _object_route_signal(response: ProbeResponse, candidate: str) -> bool:
    if response.status not in {200, 201, 202, 206}:
        return False
    body = response.body
    if candidate and candidate in body and len(body.strip()) > 20:
        return True

    lowered = body.lower()
    for marker in _ROUTE_SIGNAL_MARKERS:
        if marker in lowered:
            return True
    return False


def _observed_identity_headers(body: str, headers: dict[str, str]) -> list[tuple[str, str]]:
    observed: list[tuple[str, str]] = []
    for name, value in headers.items():
        if _looks_identity_header_name(name) and _looks_numeric_id(value):
            observed.append((name, value))
    hidden_ids = _html_object_ids(body)
    for header in ("X-UserId", "X-User-Id", "X-Account-Id", "X-Customer-Id"):
        for value in hidden_ids:
            observed.append((header, value))
    return _dedupe_pairs(observed)[:8]


def _identity_header_candidates(current_value: str) -> list[str]:
    if not _looks_numeric_id(current_value):
        return ["1", "2", "3", "0"]
    current = int(current_value)
    values: list[str] = []
    for offset in _identity_header_offsets():
        candidate = current + offset
        if candidate >= 0:
            values.append(str(candidate))
    values.extend(["0", "1", "2", "3"])
    return _identity_header_candidate_filter(values, current_value)


def _identity_header_offsets() -> tuple[int, ...]:
    return (-1, 1, -2, 2, -5, 5, -10, 10, -20, 20, -50, 50, -100, 100)


def _identity_header_candidate_filter(values: list[str], current_value: str) -> list[str]:
    filtered: list[str] = []
    for value in values:
        if value != current_value:
            filtered.append(value)
    return _dedupe(filtered)[:18]


def _looks_identity_header_name(name: str) -> bool:
    lowered = name.lower()
    if not lowered.startswith("x-"):
        return False
    for token in ("user", "account", "customer", "identity", "member", "profile", "id"):
        if token in lowered:
            return True
    return False
