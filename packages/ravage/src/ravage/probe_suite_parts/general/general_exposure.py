from __future__ import annotations

import html
import re
import secrets
from urllib.parse import urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import (
    ProbeResponse,
    ProbeSession,
    inject_query_param,
    response_secrets,
)
from ravage.probe_suite_parts.general.general_http import safe_get
from ravage.probe_suite_parts.general.general_openapi import _openapi_route_findings
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import (
    _body_words,
    _dedupe,
    _direct_exposure_urls,
    _interesting_exposure_body,
    _looks_like_baseline_404,
    _surface_endpoints,
)
from ravage.web_core.proof_recognizer import recognize_proofs


_DIRECT_FILE_PARAM_NAMES = (
    "file",
    "path",
    "filename",
    "doc",
    "document",
    "page",
    "include",
    "view",
    "content",
)
_SENSITIVE_LISTED_FILE_MARKERS = (
    "flag",
    "proof",
    "secret",
    "token",
    "key",
    "credential",
    "config",
    "backup",
    "dump",
    "env",
    "passwd",
)


def probe_direct_exposure(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    urls = _dedupe([*_direct_exposure_urls(session, state), *_surface_endpoints(state)])
    baseline_404 = safe_get(session, session.absolute("/ravage-missing-" + secrets.token_hex(4)))
    requests: list[dict[str, object]] = [baseline_404.summary(body_chars=120) | {"probe_kind": "baseline_404"}]
    findings: list[dict[str, object]] = []
    for url in urls[:60]:
        response = safe_get(session, url)
        requests.append(response.summary(body_chars=260) | {"probe_kind": "direct_exposure_candidate"})
        if _looks_like_baseline_404(response, baseline_404):
            continue
        findings.extend(_openapi_route_findings(session, response, url))
        listed_file_findings, listed_file_requests = _direct_listed_file_followups(session, response, url)
        findings.extend(listed_file_findings)
        requests.extend(listed_file_requests)
        proofs = recognize_proofs(response.body)
        matches = response_secrets(response)
        interesting_status = response.status in {200, 401, 403, 500}
        interesting_body = _interesting_exposure_body(response.body, url)
        has_interesting_response = interesting_status and interesting_body
        if proofs or matches or has_interesting_response:
            finding_type = "direct_exposure_candidate"
            if proofs:
                finding_type = "direct_exposure_proof"
            findings.append(
                {
                    "type": finding_type,
                    "url": url,
                    "status": response.status,
                    "proofs": proofs[:5],
                    "matches": matches[:16],
                    "body_markers": _body_words(
                        response.body,
                        (
                            "flag",
                            "admin",
                            "password",
                            "secret",
                            "token",
                            "config",
                            "database",
                            "mysqli",
                            "traceback",
                            "warning",
                        ),
                    ),
                    "response": response.summary(body_chars=520),
                }
            )
    return ProbeRunResult(
        ok=bool(findings),
        probe="direct_exposure",
        summary=f"checked {len(urls[:60])} direct exposure URL(s), findings={len(findings)}",
        findings=findings[:30],
        requests=requests[:80],
    )


_DIRECT_FILE_PARAM_NAMES = ("file", "path", "filename", "doc", "document", "page", "include", "view", "content")
_SENSITIVE_LISTED_FILE_MARKERS = (
    "flag",
    "proof",
    "secret",
    "token",
    "key",
    "credential",
    "config",
    "backup",
    "dump",
    "env",
    "passwd",
)

def _direct_listed_file_followups(
    session: ProbeSession,
    response: ProbeResponse,
    source_url: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    filenames = _sensitive_listed_filenames(response.body)
    if not filenames:
        return [], []
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    for fetch_url in _direct_file_param_urls(source_url, filenames)[:28]:
        fetched = safe_get(session, fetch_url)
        requests.append(fetched.summary(body_chars=360) | {"probe_kind": "direct_exposure_listed_file_fetch"})
        proofs = recognize_proofs(fetched.body)
        matches = response_secrets(fetched)
        if not proofs and not matches:
            continue
        finding_type = "direct_exposure_listed_file_secret"
        if proofs:
            finding_type = "direct_exposure_listed_file_proof"
        findings.append(
            {
                "type": finding_type,
                "url": fetch_url,
                "source_url": source_url,
                "fetch_url": fetch_url,
                "filenames": filenames[:10],
                "proofs": proofs[:5],
                "matches": matches[:12],
                "response": fetched.summary(body_chars=800),
                "replay": {"method": "GET", "url": fetch_url},
            }
        )
        break
    return findings, requests

def _sensitive_listed_filenames(body: str) -> list[str]:
    text = html.unescape(re.sub(r"<[^>]+>", " ", body))
    candidates: list[str] = []
    for match in re.finditer(r"\b[A-Za-z0-9_.-]{1,120}\b", text):
        token = match.group(0).strip(".")
        if _looks_sensitive_filename(token):
            candidates.append(token)
    for match in re.finditer(r"""(?is)\b(?:href|src)=["']([^"']{1,240})["']""", body):
        value = html.unescape(match.group(1)).split("?", 1)[0].rstrip("/")
        token = value.rsplit("/", 1)[-1]
        if _looks_sensitive_filename(token):
            candidates.append(token)
    return _dedupe(candidates)[:12]

def _looks_sensitive_filename(value: str) -> bool:
    if not value or "/" in value or "\\" in value:
        return False
    lowered = value.lower()
    name_markers = ("flag", "secret", "token", "passwd")
    has_sensitive_name_marker = False
    for marker in name_markers:
        if marker in lowered:
            has_sensitive_name_marker = True
            break
    if "." not in lowered and not has_sensitive_name_marker:
        return False
    for marker in _SENSITIVE_LISTED_FILE_MARKERS:
        if marker in lowered:
            return True
    return False

def _direct_file_param_urls(source_url: str, filenames: list[str]) -> list[str]:
    urls: list[str] = []
    for filename in filenames:
        for name in _DIRECT_FILE_PARAM_NAMES:
            urls.append(inject_query_param(source_url, name, filename))
    parts = urlsplit(source_url)
    if parts.query:
        stripped = urlunsplit((parts.scheme, parts.netloc, parts.path, "", parts.fragment))
        for filename in filenames[:4]:
            for name in _DIRECT_FILE_PARAM_NAMES[:5]:
                urls.append(inject_query_param(stripped, name, filename))
    return _dedupe(urls)
