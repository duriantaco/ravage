from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.auth_forms import _submit_form
from ravage.deterministic_agents.auth_object_targets import (
    _dedupe_scoped_urls,
    _object_sibling_urls,
    _optional_headers,
)
from ravage.deterministic_agents.auth_session_support import IdentityDelta
from ravage.probe_suite_parts.support import _dedupe, _form_brief, _list_of_dicts, _surface_endpoints
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, form_defaults, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs

__all__ = ["_authenticated_privilege_form_followup"]

_PRIVILEGE_FIELD_MARKERS = (
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
)
_PRIVILEGED_READBACK_MARKERS = (
    "admin",
    "dashboard",
    "profile",
    "account",
    "settings",
    "company",
    "jobs",
)
_DEFAULT_READBACK_PATHS = (
    "/dashboard",
    "/profile",
    "/account",
    "/settings",
    "/admin",
    "/jobs",
    "/companies",
)


def _authenticated_privilege_form_followup(
    *,
    session: ProbeSession,
    state: AgentState,
    username: str,
    seed_url: str,
    forms: list[dict[str, object]],
    headers: dict[str, str],
) -> IdentityDelta:
    requests: list[dict[str, object]] = []
    for form in forms[:4]:
        result = _submit_privilege_fields_for_form(
            session=session,
            state=state,
            username=username,
            seed_url=seed_url,
            form=form,
            headers=headers,
            requests=requests,
        )
        if result is not None:
            return result
    return IdentityDelta(finding=None, requests=requests)


def _submit_privilege_fields_for_form(
    *,
    session: ProbeSession,
    state: AgentState,
    username: str,
    seed_url: str,
    form: dict[str, object],
    headers: dict[str, str],
    requests: list[dict[str, object]],
) -> IdentityDelta | None:
    privilege_fields = _privilege_form_fields(form)
    if not privilege_fields:
        return None

    for field_name in privilege_fields[:2]:
        result = _submit_privilege_field_values(
            session=session,
            state=state,
            username=username,
            seed_url=seed_url,
            form=form,
            headers=headers,
            field_name=field_name,
            requests=requests,
        )
        if result is not None:
            return result
    return None


def _submit_privilege_field_values(
    *,
    session: ProbeSession,
    state: AgentState,
    username: str,
    seed_url: str,
    form: dict[str, object],
    headers: dict[str, str],
    field_name: str,
    requests: list[dict[str, object]],
) -> IdentityDelta | None:
    for value in _privilege_values_for_field(field_name)[:3]:
        fields = form_defaults(form)
        fields[field_name] = value
        submitted = _submit_form(session, form, fields, headers=_optional_headers(headers))
        requests.append(_privilege_submit_request(submitted, username, form, field_name, value))

        proofs = recognize_proofs(submitted.body)
        if proofs:
            return IdentityDelta(
                finding=_authenticated_privilege_form_finding(
                    form=form,
                    field_name=field_name,
                    fields=fields,
                    response=submitted,
                    proofs=proofs,
                    matches=[],
                    source="form_response",
                ),
                requests=requests,
            )

        result = _privilege_readback_followup(
            session=session,
            state=state,
            seed_url=seed_url,
            form=form,
            headers=headers,
            username=username,
            field_name=field_name,
            fields=fields,
            requests=requests,
        )
        if result is not None:
            return result
    return None


def _privilege_submit_request(
    submitted: ProbeResponse,
    username: str,
    form: dict[str, object],
    field_name: str,
    value: str,
) -> dict[str, object]:
    payload = submitted.summary(body_chars=260)
    payload["probe_kind"] = "authenticated_privilege_form_submit"
    payload["username"] = username
    payload["form"] = _form_brief(form)
    payload["privilege_field"] = field_name
    payload["privilege_value"] = value
    return payload


def _privilege_readback_followup(
    *,
    session: ProbeSession,
    state: AgentState,
    seed_url: str,
    form: dict[str, object],
    headers: dict[str, str],
    username: str,
    field_name: str,
    fields: dict[str, str],
    requests: list[dict[str, object]],
) -> IdentityDelta | None:
    for read_url in _post_privilege_readback_urls(session, state, seed_url, form):
        response = session.get(read_url, headers=_optional_headers(headers))
        requests.append(_privilege_readback_request(response, username, read_url, field_name))
        proofs = recognize_proofs(response.body)
        matches = response_secrets(response)
        if proofs or matches:
            return IdentityDelta(
                finding=_authenticated_privilege_form_finding(
                    form=form,
                    field_name=field_name,
                    fields=fields,
                    response=response,
                    proofs=proofs,
                    matches=matches,
                    source=read_url,
                ),
                requests=requests,
            )
    return None


def _privilege_readback_request(
    response: ProbeResponse,
    username: str,
    read_url: str,
    field_name: str,
) -> dict[str, object]:
    payload = response.summary(body_chars=320)
    payload["probe_kind"] = "authenticated_privilege_readback"
    payload["username"] = username
    payload["url"] = read_url
    payload["privilege_field"] = field_name
    return payload


def _privilege_form_fields(form: dict[str, object]) -> list[str]:
    fields: list[str] = []
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        if name and _looks_like_privilege_field(name):
            fields.append(name)
    return _dedupe(fields)


def _looks_like_privilege_field(name: str) -> bool:
    lowered = name.lower()
    for marker in _PRIVILEGE_FIELD_MARKERS:
        if marker in lowered:
            return True
    return False


def _privilege_values_for_field(field_name: str) -> list[str]:
    lowered = field_name.lower()
    if "role" in lowered or "privilege" in lowered or "permission" in lowered:
        return ["admin", "1", "true"]
    if "level" in lowered or "tier" in lowered or "plan" in lowered:
        return ["1", "premium", "9"]
    return ["1", "true", "on"]


def _post_privilege_readback_urls(
    session: ProbeSession,
    state: AgentState,
    seed_url: str,
    form: dict[str, object],
) -> list[str]:
    urls: list[str] = []
    action = str(form.get("action") or "")
    urls.extend(_object_sibling_urls(session, action))
    urls.extend(_object_sibling_urls(session, seed_url))
    urls.append(seed_url)
    _append_state_readback_urls(urls, state)
    _append_default_readback_urls(urls, session)
    return _dedupe_scoped_urls(session, urls, limit=10)


def _append_state_readback_urls(urls: list[str], state: AgentState) -> None:
    for endpoint in _surface_endpoints(state):
        if _looks_like_privileged_readback_url(endpoint):
            urls.append(endpoint)


def _append_default_readback_urls(urls: list[str], session: ProbeSession) -> None:
    for path in _DEFAULT_READBACK_PATHS:
        urls.append(session.absolute(path))


def _looks_like_privileged_readback_url(url: str) -> bool:
    lowered = url.lower()
    for marker in _PRIVILEGED_READBACK_MARKERS:
        if marker in lowered:
            return True
    return False


def _authenticated_privilege_form_finding(
    *,
    form: dict[str, object],
    field_name: str,
    fields: dict[str, str],
    response: ProbeResponse,
    proofs: list[str],
    matches: list[str],
    source: str,
) -> dict[str, object]:
    finding_type = _authenticated_privilege_form_finding_type(proofs=proofs, matches=matches)
    return {
        "type": finding_type,
        "field": field_name,
        "submitted_value": fields.get(field_name, ""),
        "form": _form_brief(form),
        "proofs": proofs,
        "matches": matches,
        "source": source,
        "response": response.summary(body_chars=700),
        "replay": _authenticated_privilege_form_replay(form, fields, field_name),
    }


def _authenticated_privilege_form_replay(
    form: dict[str, object],
    fields: dict[str, str],
    field_name: str,
) -> dict[str, object]:
    return {
        "method": str(form.get("method") or "GET").upper(),
        "url": str(form.get("action") or ""),
        "form": fields,
        "privilege_field": field_name,
        "encoding": "application/x-www-form-urlencoded",
    }


def _authenticated_privilege_form_finding_type(*, proofs: list[str], matches: list[str]) -> str:
    if proofs or matches:
        return "authenticated_privilege_form_proof"
    return "authenticated_privilege_form_signal"
