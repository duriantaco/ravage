from __future__ import annotations

import re
from collections.abc import Callable
from typing import cast

from ravage.probes.cookie.cookie_deserialization import classify_cookie_value
from ravage.web_core.http_probe import ProbeResponse, ProbeSession
from ravage.web_core.proof_recognizer import recognize_proofs

__all__ = [
    "IdentityDelta",
    "IdentityResult",
    "SecondStepResult",
    "access_score",
    "cookie_is_privilege_like",
    "fork_session",
    "has_auth_proof",
    "ordered_admin_urls",
    "privilege_cookie_variants",
    "rebuild_cookie_header",
    "record_auth_proof",
    "serialized_auth_cookie_findings",
    "session_cookie_pairs",
    "set_cookie_pairs",
]

_PRIVILEGE_VALUE_MAP: dict[str, tuple[str, ...]] = {
    "user": ("admin", "administrator", "superuser", "root"),
    "users": ("admin",),
    "guest": ("admin",),
    "member": ("admin",),
    "regular": ("admin",),
    "viewer": ("admin",),
    "customer": ("admin",),
    "0": ("1",),
    "false": ("true",),
    "no": ("yes",),
    "off": ("on",),
    "none": ("admin",),
}
_PRIVILEGE_COOKIE_NAME_MARKERS = (
    "role",
    "admin",
    "priv",
    "level",
    "group",
    "type",
    "is_",
    "staff",
    "super",
    "auth",
    "perm",
)
_ACCESS_MARKERS = ("flag{", "admin", "welcome", "dashboard", "logout", "authorized", "settings")
_ADMIN_URL_PRIORITY = ("/admin", "/settings", "/dashboard", "/account", "/me", "/user", "/profile")
_PRIVILEGE_FOLLOWUP_URL_MARKERS = _ADMIN_URL_PRIORITY
_COOKIE_ATTRIBUTE_NAMES = {
    "path",
    "domain",
    "expires",
    "max-age",
    "samesite",
    "secure",
    "httponly",
}


class IdentityResult:
    def __init__(
        self,
        *,
        session: ProbeSession,
        username: str,
        auth_headers: list[dict[str, str]],
        authenticated: bool,
        findings: list[dict[str, object]],
        requests: list[dict[str, object]],
    ) -> None:
        self.session = session
        self.username = username
        self.auth_headers = auth_headers
        self.authenticated = authenticated
        self.findings = findings
        self.requests = requests


class IdentityDelta:
    def __init__(
        self,
        *,
        finding: dict[str, object] | None,
        requests: list[dict[str, object]],
    ) -> None:
        self.finding = finding
        self.requests = requests


class SecondStepResult:
    def __init__(
        self,
        *,
        final_response: ProbeResponse | None,
        requests: list[dict[str, object]],
        auth_headers: list[dict[str, str]],
        replay_steps: list[dict[str, object]],
    ) -> None:
        self.final_response = final_response
        self.requests = requests
        self.auth_headers = auth_headers
        self.replay_steps = replay_steps


def fork_session(
    base_session: ProbeSession,
    timeout_seconds: int,
    *,
    session_factory: Callable[..., ProbeSession] = ProbeSession,
) -> ProbeSession:
    fork = getattr(base_session, "fork", None)
    if callable(fork):
        forked = fork(timeout_seconds=timeout_seconds)
        return cast(ProbeSession, forked)

    headers = getattr(base_session, "default_headers", None)
    if headers:
        return session_factory(base_session.target_url, timeout_seconds=timeout_seconds, default_headers=headers)

    return session_factory(base_session.target_url, timeout_seconds=timeout_seconds)


def ordered_admin_urls(urls: list[str]) -> list[str]:
    privileged: list[str] = []
    for url in urls:
        if _url_has_privileged_marker(url):
            privileged.append(url)

    if not privileged:
        return urls[:4]

    return sorted(privileged, key=_admin_url_rank)


def _url_has_privileged_marker(url: str) -> bool:
    for marker in _PRIVILEGE_FOLLOWUP_URL_MARKERS:
        if marker in url:
            return True
    return False


def _admin_url_rank(url: str) -> int:
    for index, marker in enumerate(_ADMIN_URL_PRIORITY):
        if marker in url:
            return index
    return len(_ADMIN_URL_PRIORITY)


def record_auth_proof(body: str, findings: list[dict[str, object]], *, channel: str, detail: object) -> bool:
    proofs = recognize_proofs(body)
    if not proofs:
        return False

    findings.append(
        {
            "type": "auth_extracted_proof",
            "channel": channel,
            "detail": detail,
            "proof": proofs[0],
            "proofs": proofs,
        }
    )
    return True


def has_auth_proof(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("type") == "auth_extracted_proof":
            return True
        if finding.get("proofs"):
            return True
    return False


def access_score(response: ProbeResponse) -> int:
    if response.status is None:
        return -1

    score = 0
    if 200 <= response.status < 300:
        score = 2
    if response.status in (401, 403):
        score -= 2

    lowered = response.body.lower()
    for marker in _ACCESS_MARKERS:
        if marker in lowered:
            score += 1
    return score


def cookie_is_privilege_like(name: str, value: str) -> bool:
    lowered_name = name.lower()
    for marker in _PRIVILEGE_COOKIE_NAME_MARKERS:
        if marker in lowered_name:
            return True
    return value.lower() in _PRIVILEGE_VALUE_MAP


def privilege_cookie_variants(value: str) -> list[str]:
    lowered = value.lower()
    mapped_values = _PRIVILEGE_VALUE_MAP.get(lowered)
    if mapped_values:
        return list(mapped_values)

    if len(value) <= 16 and value.isalnum():
        return ["admin", "true", "1"]

    return []


def set_cookie_pairs(raw: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for chunk in re.split(r",(?=[^;]+=)", raw):
        head = chunk.split(";", 1)[0].strip()
        if "=" not in head:
            continue

        name, value = head.split("=", 1)
        name = name.strip()
        value = value.strip()

        if not name or not value:
            continue
        if name.lower() in _COOKIE_ATTRIBUTE_NAMES:
            continue

        pairs.append((name, value))
    return pairs


def session_cookie_pairs(session: ProbeSession) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for cookie in session.cookies:
        if not cookie.name or not cookie.value:
            continue
        if cookie.name in seen:
            continue

        seen.add(cookie.name)
        pairs.append((cookie.name, cookie.value))
    return pairs


def serialized_auth_cookie_findings(cookie_pairs: list[tuple[str, str]]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for name, value in cookie_pairs:
        fmt = classify_cookie_value(value)
        if not fmt.exploitable:
            continue

        findings.append(
            {
                "type": "insecure_deserialization_cookie_signal",
                "cookie": name,
                "format": fmt.kind,
                "signed": fmt.signed,
                "encoding": fmt.encoding,
                "cookie_signal": f"{name}={value}",
                "set_cookie": f"Set-Cookie: {name}={value}; Path=/",
                "source": "authenticated_session_cookie",
                "next": "Run cookie_deserialization against the authenticated serialized cookie and replay a generic tamper/forge.",
            }
        )
    return findings


def rebuild_cookie_header(cookies: dict[str, str], target_name: str, target_value: str) -> str:
    parts: list[str] = []
    for name, value in cookies.items():
        if name == target_name:
            parts.append(f"{name}={target_value}")
            continue
        parts.append(f"{name}={value}")
    return "; ".join(parts)
