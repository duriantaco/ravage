from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

from ravage.agent_core.agent_state import AgentState
from ravage.deterministic_agents.auth_materials import _redact_auth_headers
from ravage.deterministic_agents.auth_session_support import IdentityDelta
from ravage.probe_suite_parts.support import _dedupe, _surface_endpoints
from ravage.web_core.http_probe import ProbeResponse, ProbeSession, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs

__all__ = [
    "_clustered_numeric_candidates",
    "_dedupe_scoped_urls",
    "_looks_mongo_object_id",
    "_looks_numeric_id",
    "_object_id_hint_followup",
    "_object_sibling_urls",
    "_optional_headers",
    "_proof_or_secret_finding_type",
]

_MONGO_OBJECT_ID_RE = re.compile(r"(?i)\b[a-f0-9]{24}\b")
_OBJECT_ID_COUNTER_OFFSETS = (
    1,
    -1,
    2,
    -2,
    3,
    -3,
    4,
    -4,
    5,
    -5,
    8,
    -8,
    10,
    -10,
    16,
    -16,
    32,
    -32,
    50,
    -50,
    100,
    -100,
)
_NUMERIC_CANDIDATE_OFFSETS = (
    -1,
    1,
    -2,
    2,
    -3,
    3,
    -5,
    5,
    -8,
    8,
    -10,
    10,
    -13,
    13,
    -16,
    16,
    -20,
    20,
    -25,
    25,
    -50,
    50,
    -75,
    75,
    -100,
    100,
)


def _object_id_hint_followup(
    *,
    session: ProbeSession,
    state: AgentState | None,
    responses: list[ProbeResponse],
    headers: dict[str, str],
) -> IdentityDelta:
    hints = _object_id_hints_from_responses(responses)
    candidates = _object_id_hint_candidates(hints)
    templates = _object_id_route_templates(session, state, responses)
    requests: list[dict[str, object]] = []
    if not candidates or not templates:
        return IdentityDelta(finding=None, requests=requests)

    seen: set[str] = set()
    spent = 0
    for candidate in candidates[:36]:
        for template in templates[:10]:
            if spent >= 36:
                return IdentityDelta(finding=None, requests=requests)

            result = _probe_object_id_template(
                session=session,
                headers=headers,
                candidate=candidate,
                template=template,
                seen=seen,
                requests=requests,
            )
            spent += result.requests_spent
            if result.delta is not None:
                return result.delta

    return IdentityDelta(finding=None, requests=requests)


class _ObjectIdProbeResult:
    def __init__(
        self,
        *,
        requests_spent: int,
        delta: IdentityDelta | None = None,
    ) -> None:
        self.requests_spent = requests_spent
        self.delta = delta


def _probe_object_id_template(
    *,
    session: ProbeSession,
    headers: dict[str, str],
    candidate: str,
    template: str,
    seen: set[str],
    requests: list[dict[str, object]],
) -> _ObjectIdProbeResult:
    url = urljoin(session.target_url, template.replace("{id}", candidate))
    if not session.in_scope(url):
        return _ObjectIdProbeResult(requests_spent=0)

    key = json.dumps({"url": url, "headers": headers}, sort_keys=True)
    if key in seen:
        return _ObjectIdProbeResult(requests_spent=0)

    seen.add(key)
    response = session.get(url, headers=_optional_headers(headers))
    requests.append(_object_id_probe_request(response, url, template, candidate, headers))
    finding = _object_id_probe_finding(response, candidate, template, url, headers)
    if finding is None:
        return _ObjectIdProbeResult(requests_spent=1)

    return _ObjectIdProbeResult(
        requests_spent=1,
        delta=IdentityDelta(finding=finding, requests=requests),
    )


def _object_id_probe_request(
    response: ProbeResponse,
    url: str,
    template: str,
    candidate: str,
    headers: dict[str, str],
) -> dict[str, object]:
    payload = response.summary(body_chars=520)
    payload["probe_kind"] = "auth_object_id_hint_route"
    payload["url"] = url
    payload["template"] = template
    payload["candidate_id"] = candidate
    payload["headers_used"] = _redact_auth_headers(headers)
    return payload


def _object_id_probe_finding(
    response: ProbeResponse,
    candidate: str,
    template: str,
    url: str,
    headers: dict[str, str],
) -> dict[str, object] | None:
    proofs = recognize_proofs(response.body)
    matches = response_secrets(response)
    if not proofs and not matches:
        return None

    return {
        "type": _proof_or_secret_finding_type(
            has_proof=bool(proofs),
            proof_type="auth_object_id_hint_proof",
            secret_type="auth_object_id_hint_secret",
        ),
        "candidate_id": candidate,
        "template": template,
        "proofs": proofs,
        "matches": matches,
        "response": response.summary(body_chars=900),
        "replay": {"method": "GET", "url": url, "headers": _redact_auth_headers(headers)},
    }


def _object_id_hints_from_responses(responses: list[ProbeResponse]) -> dict[str, list[str]]:
    ids: list[str] = []
    distances: list[str] = []
    timestamps: list[str] = []
    for response in responses:
        text = _object_id_hint_text(response)
        ids.extend(_object_ids_from_text(text))
        for distance in _object_counter_distances(text):
            distances.append(str(distance))
        for timestamp in _unix_timestamps_from_text(text):
            timestamps.append(str(timestamp))

    return {
        "ids": _dedupe(ids)[:12],
        "distances": _dedupe(distances)[:8],
        "timestamps": _dedupe(timestamps)[:8],
    }


def _object_id_hint_text(response: ProbeResponse) -> str:
    location = str(response.headers.get("location") or response.headers.get("Location") or "")
    return "\n".join(
        [
            response.url or "",
            response.final_url or "",
            location,
            response.body or "",
        ]
    )


def _object_ids_from_text(text: str) -> list[str]:
    values: list[str] = []
    keyed = re.compile(
        r"""(?is)["'](?:[a-z0-9_-]*id|_id|objectId|object_id|profileId|profile_id|accountId|account_id|companyId|company_id)["']\s*[:=]\s*["']?([a-f0-9]{24}|\d{1,12})["']?"""
    )
    for match in keyed.finditer(text or ""):
        values.append(match.group(1).lower())
    for match in re.finditer(r"""(?i)/(?:[^/?#\s'"<>]+/)*([a-f0-9]{24})(?=[/?#\s'"<>]|$)""", text or ""):
        values.append(match.group(1).lower())
    numeric_path = re.compile(
        r"""(?i)/(?:company|companies|account|accounts|user|users|profile|profiles|order|orders|invoice|invoices|record|records|job|jobs)/(\d{1,12})(?=[/?#\s'"<>]|$)"""
    )
    for match in numeric_path.finditer(text or ""):
        values.append(match.group(1))
    return _valid_object_id_values(values)


def _valid_object_id_values(values: list[str]) -> list[str]:
    valid: list[str] = []
    for value in values:
        if _looks_mongo_object_id(value) or _looks_numeric_id(value):
            valid.append(value)
    return _dedupe(valid)


def _object_counter_distances(text: str) -> list[int]:
    values: list[int] = []
    for pattern in _object_counter_distance_patterns():
        for match in re.finditer(pattern, text or ""):
            value = _bounded_int(match.group(1), maximum=1_000_000)
            if value is not None:
                values.append(value)
    return list(dict.fromkeys(values))


def _object_counter_distance_patterns() -> tuple[str, ...]:
    return (
        r"""(?is)["'](?:distance|delta|diff|offset|counter_delta|counterDiff)["']\s*:\s*(-?\d{1,9})""",
        r"""(?is)\byou\s+are\s+(-?\d{1,9})\s+from\b""",
        r"""(?is)\b(-?\d{1,9})\s+from\s+(?:your\s+)?target\b""",
    )


def _unix_timestamps_from_text(text: str) -> list[int]:
    values: list[int] = []
    for pattern in _timestamp_patterns():
        for match in re.finditer(pattern, text or ""):
            value = _timestamp_value(match.group(1))
            if value is not None:
                values.append(value)
    return list(dict.fromkeys(values))


def _timestamp_patterns() -> tuple[str, ...]:
    return (
        r"""(?is)\b(?:appStartTimestamp|startTimestamp|createdTimestamp|unix\s+timestamp)\b[^0-9]{0,80}(\d{9,11})""",
        r"""(?is)["'](?:startTime|start_time|createdAt|created_at)["']\s*:\s*["']?(\d{9,11})""",
    )


def _timestamp_value(raw: str) -> int | None:
    try:
        value = int(raw)
    except ValueError:
        return None
    if 946_684_800 <= value <= 4_102_444_800:
        return value
    return None


def _object_id_hint_candidates(hints: dict[str, list[str]]) -> list[str]:
    mongo_ids: list[str] = []
    numeric_ids: list[str] = []
    for value in hints.get("ids", []):
        if _looks_mongo_object_id(value):
            mongo_ids.append(value)
        elif _looks_numeric_id(value):
            numeric_ids.append(value)

    distances = _bounded_distances(hints.get("distances", []))
    timestamp_prefixes = _timestamp_prefixes(hints.get("timestamps", []))
    candidates: list[str] = []
    if numeric_ids:
        candidates.extend(_clustered_numeric_candidates(numeric_ids)[:24])
    for object_id in mongo_ids[:6]:
        candidates.extend(_mongo_object_id_candidates(object_id, distances, timestamp_prefixes))
    return _valid_object_id_values(candidates)[:64]


def _bounded_distances(values: list[str]) -> list[int]:
    distances: list[int] = []
    for raw in values:
        value = _bounded_int(raw, maximum=1_000_000)
        if value is not None:
            distances.append(value)
    return distances


def _bounded_int(raw: str, *, maximum: int) -> int | None:
    try:
        value = int(raw)
    except ValueError:
        return None
    if 0 < abs(value) <= maximum:
        return value
    return None


def _timestamp_prefixes(values: list[str]) -> list[str]:
    prefixes: list[str] = []
    for raw in values:
        try:
            timestamp = int(raw)
        except ValueError:
            continue
        if 0 <= timestamp <= 0xFFFFFFFF:
            prefixes.append(f"{timestamp:08x}")
    return prefixes


def _mongo_object_id_candidates(object_id: str, distances: list[int], timestamp_prefixes: list[str]) -> list[str]:
    current_counter = int(object_id[-6:], 16)
    middle = object_id[8:18]
    prefixes = _mongo_prefixes(object_id, timestamp_prefixes)

    candidates = [object_id]
    for counter in _neighbor_counters(current_counter, distances):
        if not 0 <= counter <= 0xFFFFFF:
            continue
        for prefix in prefixes:
            candidates.append(f"{prefix}{middle}{counter:06x}")
    return candidates


def _mongo_prefixes(object_id: str, timestamp_prefixes: list[str]) -> list[str]:
    prefix_candidates: list[str] = []
    prefix_candidates.extend(timestamp_prefixes)
    prefix_candidates.append(object_id[:8])
    return _dedupe(prefix_candidates)[:4]


def _neighbor_counters(current_counter: int, distances: list[int]) -> list[int]:
    counters: list[int] = []
    for distance in distances[:6]:
        counters.append(current_counter - distance)
        counters.append(current_counter + distance)
    for offset in _OBJECT_ID_COUNTER_OFFSETS:
        counters.append(current_counter + offset)
    return counters


def _object_id_route_templates(
    session: ProbeSession,
    state: AgentState | None,
    responses: list[ProbeResponse],
) -> list[str]:
    templates = _default_object_id_route_templates()
    urls = _object_route_template_urls(session, state, responses)
    for url in urls:
        template = _object_id_template_from_url(url)
        if template:
            templates.insert(0, template)
    return _dedupe(templates)[:18]


def _default_object_id_route_templates() -> list[str]:
    return [
        "/profile/{id}",
        "/profiles/{id}",
        "/user/{id}",
        "/users/{id}",
        "/account/{id}",
        "/accounts/{id}",
        "/api/profile/{id}",
        "/api/user/{id}",
        "/api/users/{id}",
        "/profile?id={id}",
        "/user?id={id}",
        "/account?id={id}",
    ]


def _object_route_template_urls(
    session: ProbeSession,
    state: AgentState | None,
    responses: list[ProbeResponse],
) -> list[str]:
    urls: list[str] = []
    for response in responses:
        urls.append(response.url or "")
        urls.append(response.final_url or "")
        location = str(response.headers.get("location") or response.headers.get("Location") or "")
        if location:
            urls.append(session.absolute(location))
    if state is not None:
        urls.extend(_surface_endpoints(state))
    return urls


def _object_id_template_from_url(url: str) -> str:
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""

    path = parts.path
    segments: list[str] = []
    replaced = False
    for segment in path.split("/"):
        if _segment_is_object_id(segment, path):
            segments.append("{id}")
            replaced = True
        else:
            segments.append(segment)

    query = re.sub(r"(?i)\b[a-f0-9]{24}\b", "{id}", parts.query)
    if query != parts.query:
        replaced = True
    if not replaced:
        return ""
    return urlunsplit(("", "", "/".join(segments), query, ""))


def _segment_is_object_id(segment: str, path: str) -> bool:
    if _looks_mongo_object_id(segment):
        return True
    if not _looks_numeric_id(segment):
        return False
    return _path_looks_object_route(path)


def _path_looks_object_route(path: str) -> bool:
    lowered = path.lower()
    for token in _OBJECT_ROUTE_TOKENS:
        if token in lowered:
            return True
    return False


_OBJECT_ROUTE_TOKENS = (
    "account",
    "case",
    "claim",
    "company",
    "document",
    "file",
    "invoice",
    "job",
    "order",
    "profile",
    "receipt",
    "record",
    "user",
)


def _dedupe_scoped_urls(session: ProbeSession, urls: list[str], *, limit: int) -> list[str]:
    scoped: list[str] = []
    for url in urls:
        if session.in_scope(url):
            scoped.append(url)
    return _dedupe(scoped)[:limit]


def _object_sibling_urls(session: ProbeSession, url: str) -> list[str]:
    if not url:
        return []
    absolute = session.absolute(url)
    parts = urlsplit(absolute)
    object_ids = _object_ids_from_path(parts.path)
    urls: list[str] = []
    for object_id in object_ids[:2]:
        urls.extend(_object_sibling_urls_for_id(session, object_id))
    return urls


def _object_sibling_urls_for_id(session: ProbeSession, object_id: str) -> list[str]:
    urls: list[str] = []
    for path in _object_sibling_paths(object_id):
        urls.append(session.absolute(path))
    return urls


def _object_sibling_paths(object_id: str) -> tuple[str, ...]:
    return (
        f"/edit_profile/{object_id}",
        f"/profile/{object_id}",
        f"/account/{object_id}",
        f"/user/{object_id}",
        f"/users/{object_id}",
        f"/company/{object_id}/jobs",
        f"/companies/{object_id}/jobs",
        f"/jobs/{object_id}",
    )


def _object_ids_from_path(path: str) -> list[str]:
    ids: list[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        if re.fullmatch(r"\d+", segment) or _looks_mongo_object_id(segment):
            ids.append(segment)
    return ids


def _clustered_numeric_candidates(values: list[str]) -> list[str]:
    observed = _observed_numeric_values(values)
    candidates: list[str] = []
    for value in observed:
        candidates.append(str(value))
    if not observed:
        return candidates

    numeric = sorted(set(observed))
    for anchor in _prioritized_numeric_anchors(numeric):
        _append_numeric_offsets(candidates, anchor)
    _append_numeric_span_candidates(candidates, numeric)
    return _dedupe(candidates)[:48]


def _observed_numeric_values(values: list[str]) -> list[int]:
    observed: list[int] = []
    for value in values:
        if _looks_numeric_id(value):
            observed.append(int(value))
    return list(dict.fromkeys(observed))


def _append_numeric_offsets(candidates: list[str], anchor: int) -> None:
    for offset in _NUMERIC_CANDIDATE_OFFSETS:
        candidate = anchor + offset
        if candidate >= 0:
            candidates.append(str(candidate))


def _append_numeric_span_candidates(candidates: list[str], numeric: list[int]) -> None:
    if len(numeric) < 2:
        return
    low = numeric[0]
    high = numeric[-1]
    span = high - low
    if not 0 < span <= 1_000:
        return
    for numerator, denominator in ((1, 2), (1, 3), (2, 3), (1, 4), (3, 4)):
        candidate = low + (span * numerator // denominator)
        candidates.append(str(candidate))


def _prioritized_numeric_anchors(numeric: list[int]) -> list[int]:
    if not numeric:
        return []
    center = (len(numeric) - 1) // 2
    ordered: list[int] = []
    for distance in range(len(numeric)):
        for index in (center + distance, center - distance):
            if 0 <= index < len(numeric):
                ordered.append(numeric[index])
    return list(dict.fromkeys(ordered))


def _looks_mongo_object_id(value: str) -> bool:
    return bool(_MONGO_OBJECT_ID_RE.fullmatch(value or ""))


def _looks_numeric_id(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,12}", value or ""))


def _proof_or_secret_finding_type(*, has_proof: bool, proof_type: str, secret_type: str) -> str:
    if has_proof:
        return proof_type
    return secret_type


def _optional_headers(headers: dict[str, str]) -> dict[str, str] | None:
    if headers:
        return headers
    return None
