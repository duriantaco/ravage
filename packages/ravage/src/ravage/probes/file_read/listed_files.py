from __future__ import annotations

import html
import json
import re
from urllib.parse import urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, inject_query_param, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs

_LIST_ACTION_VALUES = ("list", "ls", "files", "index")
_LISTED_FILE_PARAM_NAMES = ("file", "path", "filename", "doc", "document", "page", "include", "view", "content")
_LISTING_ENDPOINT_PATHS = (
    "/private",
    "/private.php",
    "/files",
    "/files.php",
    "/download",
    "/download.php",
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


def _probe_listed_file_param_readbacks(
    session: ProbeSession,
    state: AgentState,
    *,
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []

    for endpoint in _listed_file_candidate_endpoints(session, state)[:8]:
        if budget <= 0:
            break
        finding, endpoint_requests, budget = _probe_listed_file_endpoint(
            session,
            endpoint,
            budget=budget,
        )
        requests.extend(endpoint_requests)
        if finding:
            findings.append(finding)
            return findings, requests, budget

    return findings, requests, budget


def _probe_listed_file_endpoint(
    session: ProbeSession,
    endpoint: str,
    *,
    budget: int,
) -> tuple[dict[str, object] | None, list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    filenames, list_requests, budget = _discover_sensitive_filenames(
        session,
        endpoint,
        budget=budget,
    )
    requests.extend(list_requests)

    for fetch_url in _listed_file_fetch_urls(endpoint, filenames)[:24]:
        if budget <= 0:
            break
        fetched = session.get(fetch_url)
        budget -= 1
        requests.append(
            fetched.summary(body_chars=420)
            | {
                "probe_kind": "file_read_listed_file_fetch",
                "url": fetch_url,
            }
        )

        proofs = recognize_proofs(fetched.body)
        matches = response_secrets(fetched)
        if not proofs and not matches:
            continue

        return _listed_file_finding(endpoint, fetch_url, filenames, fetched, proofs, matches), requests, budget

    return None, requests, budget


def _discover_sensitive_filenames(
    session: ProbeSession,
    endpoint: str,
    *,
    budget: int,
) -> tuple[list[str], list[dict[str, object]], int]:
    filenames: list[str] = []
    requests: list[dict[str, object]] = []

    for list_url in _list_action_urls(endpoint)[:5]:
        if budget <= 0:
            break

        response = session.get(list_url)
        budget -= 1
        requests.append(
            response.summary(body_chars=260)
            | {
                "probe_kind": "file_read_list_action",
                "url": list_url,
            }
        )
        filenames = _dedupe([*filenames, *_sensitive_listed_filenames(response.body)])[:12]
        if filenames:
            break

    return filenames, requests, budget


def _listed_file_finding(
    endpoint: str,
    fetch_url: str,
    filenames: list[str],
    response: ProbeResponse,
    proofs: list[str],
    matches: list[str],
) -> dict[str, object]:
    return {
        "type": "file_read_listed_file_proof" if proofs else "file_read_listed_file_secret",
        "endpoint": endpoint,
        "fetch_url": fetch_url,
        "filenames": filenames[:10],
        "proofs": proofs[:5],
        "matches": matches[:12],
        "response": response.summary(body_chars=900),
        "replay": {"method": "GET", "url": fetch_url},
    }


def _listed_file_candidate_endpoints(session: ProbeSession, state: AgentState) -> list[str]:
    urls: list[str] = []
    for url in _file_param_candidate_endpoint_urls(state):
        if _endpoint_looks_listing_candidate(url):
            urls.append(url)
    if _state_has_listing_hint(state):
        for path in _LISTING_ENDPOINT_PATHS:
            urls.append(session.absolute(path))
    return _dedupe([url for url in urls if _session_url_in_scope(session, url)])


def _file_param_candidate_endpoint_urls(state: AgentState) -> list[str]:
    urls: list[str] = []
    for endpoint in _list_of_dicts(state.surface.get("endpoints")):
        url = str(endpoint.get("url") or "")
        if url:
            urls.append(url)
    for page in _list_of_dicts(state.surface.get("pages")):
        for key in ("final_url", "url"):
            url = str(page.get(key) or "")
            if url:
                urls.append(url)
    for value in state.signals.get("endpoints", []):
        if value:
            urls.append(str(value))
    return urls


def _endpoint_looks_listing_candidate(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    lowered = (parts.path + "?" + parts.query).lower()
    return any(marker in lowered for marker in ("private", "file", "files", "download", "doc", "document", "list"))


def _state_has_listing_hint(state: AgentState) -> bool:
    signal_text = " ".join(str(value).lower() for values in state.signals.values() for value in values)
    text = json.dumps(state.surface, sort_keys=True).lower() + " " + signal_text
    return any(marker in text for marker in ("private", "file", "files", "download", "directory", "listing"))


def _session_url_in_scope(session: ProbeSession, url: str) -> bool:
    in_scope = getattr(session, "in_scope", None)
    if callable(in_scope):
        return bool(in_scope(url))
    origin = str(getattr(session, "origin", "") or getattr(session, "target_url", "") or "")
    return _url_in_scope(url, origin)


def _list_action_urls(endpoint: str) -> list[str]:
    urls = [endpoint]
    for value in _LIST_ACTION_VALUES:
        urls.append(inject_query_param(endpoint, "action", value))
        urls.append(inject_query_param(endpoint, "list", value))
    return _dedupe(urls)


def _listed_file_fetch_urls(endpoint: str, filenames: list[str]) -> list[str]:
    urls: list[str] = []
    for filename in filenames:
        for name in _LISTED_FILE_PARAM_NAMES:
            urls.append(inject_query_param(endpoint, name, filename))
    return _dedupe(urls)


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
    if "." not in lowered and not any(marker in lowered for marker in ("flag", "secret", "token", "passwd")):
        return False
    return any(marker in lowered for marker in _SENSITIVE_LISTED_FILE_MARKERS)


def _url_in_scope(url: str, origin: str) -> bool:
    if not url or not origin:
        return True
    try:
        url_parts = urlsplit(url)
        origin_parts = urlsplit(origin)
    except ValueError:
        return False
    if not url_parts.scheme and not url_parts.netloc:
        return True
    return (url_parts.scheme, url_parts.netloc) == (origin_parts.scheme, origin_parts.netloc)


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result
