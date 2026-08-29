from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from ravage.web_core.http_probe import ProbeResponse, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs

_IDOR_SIGNAL_STATUSES = {200, 201, 202, 204, 206, 302, 303}

_SENSITIVE_OBJECT_MARKERS = ("admin", "password", "email", "username")

_SESSION_COOKIE_NAMES = ("session", "sid", "connect.sid", "sessionid", "auth")
_MISSING_OBJECT_MARKERS = (
    "not found",
    "no such",
    "does not exist",
    "invalid id",
    "invalid object",
    "missing",
)
_AUTH_BLOCK_MARKERS = ("unauthorized", "forbidden", "access denied", "login required")
_AUTH_GATE_PATH_MARKERS = ("login", "signin", "sign-in", "auth")


def _looks_like_missing_object_response(response: ProbeResponse) -> bool:
    if response.status in {404, 410}:
        return True
    lower = response.body[:2_000].lower()
    return _contains_marker(lower, _MISSING_OBJECT_MARKERS)


def _auth_blocked(response: ProbeResponse) -> bool:
    lowered = response.body.lower()
    if response.status in {401, 403}:
        return True
    if _contains_marker(lowered, _AUTH_BLOCK_MARKERS):
        return True
    if response.status in {301, 302, 303, 307, 308}:
        location = str(response.headers.get("location") or response.headers.get("Location") or "")
        if _redirect_looks_auth_gate(response.url, location):
            return True
    return False


def _redirect_looks_auth_gate(source_url: str, location: str) -> bool:
    if not location:
        return False
    try:
        target = urlsplit(urljoin(source_url, location))
        source = urlsplit(source_url)
    except ValueError:
        return False
    target_path = (target.path or "/").rstrip("/") or "/"
    source_path = (source.path or "/").rstrip("/") or "/"
    if _contains_marker(target_path.lower(), _AUTH_GATE_PATH_MARKERS):
        return True
    return target_path == "/" and source_path not in {"/", "/login", "/signin", "/sign-in", "/auth"}


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in text:
            return True
    return False


def _idor_access_signal(
    *,
    baseline: ProbeResponse,
    response: ProbeResponse,
    original_id: str,
    candidate_id: str,
) -> dict[str, object]:
    if response.status is None or _auth_blocked(response):
        return {}

    proof_signal = _proof_or_secret_signal(response)
    if proof_signal:
        return proof_signal
    if response.status not in _IDOR_SIGNAL_STATUSES:
        return {}
    if _auth_workflow_delta(baseline, response):
        return {}

    if _auth_cookie_identity_changed(baseline, response):
        return _auth_cookie_identity_signal(response)

    object_delta = _object_access_delta(
        baseline=baseline,
        response=response,
        original_id=original_id,
        candidate_id=candidate_id,
    )
    if object_delta:
        return object_delta

    sensitive_delta = _sensitive_object_marker_delta(baseline, response)
    if sensitive_delta:
        return sensitive_delta
    return {}


def _proof_or_secret_signal(response: ProbeResponse) -> dict[str, object]:
    proofs = recognize_proofs(response.body)
    secrets_found = response_secrets(response)
    if not proofs and not secrets_found:
        return {}
    return {
        "kind": "proof_or_secret",
        "proofs": proofs,
        "matches": secrets_found,
    }


def _auth_cookie_identity_signal(response: ProbeResponse) -> dict[str, object]:
    return {
        "kind": "auth_cookie_identity_delta",
        "status": response.status,
        "location": _header_value(response, "location"),
    }


def _object_access_delta(
    *,
    baseline: ProbeResponse,
    response: ProbeResponse,
    original_id: str,
    candidate_id: str,
) -> dict[str, object]:
    candidate_reflected = _candidate_id_reflected(
        response.body,
        baseline.body,
        candidate_id,
    )
    object_markers = _object_access_markers(response.body)
    baseline_markers = _object_access_markers(baseline.body)
    new_markers = _new_object_markers(object_markers, baseline_markers)
    original_disappeared = _original_id_disappeared(
        response.body,
        baseline.body,
        original_id,
    )
    length_delta = len(response.body) - len(baseline.body)
    length_changed = abs(length_delta) >= 25
    if not _object_delta_is_signal(
        candidate_reflected=candidate_reflected,
        new_markers=new_markers,
        length_changed=length_changed,
        original_disappeared=original_disappeared,
        object_markers=object_markers,
    ):
        return {}
    return {
        "kind": "object_access_delta",
        "candidate_reflected": candidate_reflected,
        "original_disappeared": original_disappeared,
        "new_markers": new_markers[:8],
        "length_delta": length_delta,
    }


def _candidate_id_reflected(response_body: str, baseline_body: str, candidate_id: str) -> bool:
    if not candidate_id:
        return False
    return candidate_id in response_body and candidate_id not in baseline_body


def _original_id_disappeared(response_body: str, baseline_body: str, original_id: str) -> bool:
    if not original_id:
        return False
    return original_id in baseline_body and original_id not in response_body


def _new_object_markers(
    response_markers: list[str],
    baseline_markers: list[str],
) -> list[str]:
    new_markers: list[str] = []
    for marker in response_markers:
        if marker not in baseline_markers:
            new_markers.append(marker)
    return new_markers


def _object_delta_is_signal(
    *,
    candidate_reflected: bool,
    new_markers: list[str],
    length_changed: bool,
    original_disappeared: bool,
    object_markers: list[str],
) -> bool:
    if candidate_reflected:
        return True
    if new_markers and length_changed:
        return True
    return original_disappeared and bool(object_markers)


def _sensitive_object_marker_delta(
    baseline: ProbeResponse,
    response: ProbeResponse,
) -> dict[str, object]:
    body_lower = response.body.lower()
    baseline_lower = baseline.body.lower()
    if body_lower == baseline_lower:
        return {}
    if not _contains_sensitive_object_marker(body_lower):
        return {}
    return {
        "kind": "sensitive_object_marker_delta",
        "length_delta": len(response.body) - len(baseline.body),
    }


def _contains_sensitive_object_marker(body_lower: str) -> bool:
    for marker in _SENSITIVE_OBJECT_MARKERS:
        if marker in body_lower:
            return True
    return False


def _auth_workflow_delta(baseline: ProbeResponse, response: ProbeResponse) -> bool:
    if response.status != 200 or baseline.status not in {301, 302, 303, 307, 308}:
        return False
    baseline_location = str(
        baseline.headers.get("location") or baseline.headers.get("Location") or ""
    )
    if not baseline_location:
        return False
    return _body_looks_auth_page(response.body) and _location_looks_auth_step(baseline_location)


def _body_looks_auth_page(body: str) -> bool:
    lowered = body.lower()
    if "<form" not in lowered:
        return False
    for token in ("login", "signin", "sign in", "username", "password"):
        if token in lowered:
            return True
    return False


def _location_looks_auth_step(location: str) -> bool:
    lowered = location.lower()
    for token in ("login", "signin", "sign-in", "password", "auth"):
        if token in lowered:
            return True
    return False


def _auth_cookie_identity_changed(baseline: ProbeResponse, response: ProbeResponse) -> bool:
    if response.status not in {302, 303}:
        return False
    baseline_cookie = _session_cookie_payload_hint(baseline)
    response_cookie = _session_cookie_payload_hint(response)
    return bool(response_cookie and baseline_cookie and response_cookie != baseline_cookie)


def _session_cookie_payload_hint(response: ProbeResponse) -> str:
    raw = _header_value(response, "set-cookie")
    return _first_cookie_payload(raw, _SESSION_COOKIE_NAMES)


def _header_value(response: ProbeResponse, name: str) -> str:
    wanted = name.lower()
    for header_name, value in response.headers.items():
        if header_name.lower() == wanted:
            return str(value)
    return ""


def _first_cookie_payload(raw_header: str, names: tuple[str, ...]) -> str:
    if not raw_header:
        return ""
    for cookie_name in names:
        value = _cookie_payload(raw_header, cookie_name)
        if value:
            return value
    return ""


def _cookie_payload(raw_header: str, cookie_name: str) -> str:
    pattern = rf"""(?i)(?:^|[;,\s]){re.escape(cookie_name)}=([^;,\s]+)"""
    match = re.search(pattern, raw_header)
    if match is None:
        return ""
    return match.group(1)


def _object_access_markers(body: str) -> list[str]:
    lowered = body.lower()
    markers: list[str] = []
    for marker in (
        "username",
        "email",
        "account",
        "profile",
        "order",
        "invoice",
        "admin",
        "role",
        "document",
        "download",
        "message",
        "company",
        "tenant",
        "organization",
        "workspace",
        "job",
        "jobs",
        "data",
        "success",
    ):
        if marker in lowered:
            markers.append(marker)
    return markers
